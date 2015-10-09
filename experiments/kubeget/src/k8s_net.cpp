//
// k8s_net.cpp
//


#include "k8s_net.h"
#include "k8s_component.h"
#include "k8s.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/KeyConsoleHandler.h"
#include "Poco/Net/ConsoleCertificateHandler.h"
#include "Poco/Net/NetException.h"
#include "Poco/String.h"
#include "Poco/Delegate.h"
#include "Poco/EventArgs.h"
#include <sstream>
#include <utility>
#include <memory>
#include <iostream>


using Poco::Net::HTTPClientSession;
using Poco::Net::HTTPSClientSession;
using Poco::Net::SSLManager;
using Poco::Net::Context;
using Poco::Net::KeyConsoleHandler;
using Poco::Net::PrivateKeyPassphraseHandler;
using Poco::Net::InvalidCertificateHandler;
using Poco::Net::ConsoleCertificateHandler;
using Poco::Net::HTTPRequest;
using Poco::Net::HTTPResponse;
using Poco::Net::HTTPMessage;
using Poco::Net::WebSocket;
using Poco::Net::WebSocketException;
using Poco::Net::StreamSocket;
using Poco::StreamCopier;
using Poco::SharedPtr;
using Poco::URI;
using Poco::Path;
using Poco::format;
using Poco::replaceInPlace;
using Poco::delegate;
using Poco::EventArgs;
using Poco::Exception;


class SSLInitializer
{
public:
	SSLInitializer()
	{
		Poco::Net::initializeSSL();
	}
	
	~SSLInitializer()
	{
		Poco::Net::uninitializeSSL();
	}
};


k8s_net::k8s_net(k8s& kube, const std::string& uri, const std::string& api) : m_k8s(kube),
		m_uri(uri + api),
		m_credentials(0),
		m_session(0),
		m_stopped(true)
{
	init();
}

k8s_net::~k8s_net()
{
	delete m_session;
	delete m_credentials;
}

void k8s_net::init()
{
	m_uri.normalize();

	std::string username;
	std::string password;
	Poco::Net::HTTPCredentials::extractCredentials(m_uri, username, password);

	m_credentials = new Poco::Net::HTTPCredentials(username, password);
	if (!m_credentials)
	{
		throw Poco::NullPointerException("HTTP credentials.");
	}
	
	m_session = get_http_session();
}

HTTPClientSession* k8s_net::get_http_session()
{
	if (is_secure())
	{
		SSLInitializer sslInitializer;
		SharedPtr<InvalidCertificateHandler> ptrCert = new ConsoleCertificateHandler(false); // ask the user via console
		Context::Ptr ptrContext = new Context(Context::CLIENT_USE, "", "", "rootcert.pem", Context::VERIFY_NONE/*VERIFY_RELAXED*/, 9, false, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
		SSLManager::instance().initializeClient(0, ptrCert, ptrContext);
	
		return new HTTPSClientSession(m_uri.getHost(), m_uri.getPort());
	}
	else
	{
		return new HTTPClientSession(m_uri.getHost(), m_uri.getPort());
	}

	if (!m_session)
	{
		throw Poco::NullPointerException("HTTP session.");
	}
}

void k8s_net::start_watching()
{
	if (m_stopped)
	{
		subscribe();
		m_stopped = false;
		m_thread = std::move(std::thread(&k8s_net::dispatch_events, this));
	}
}
	
void k8s_net::subscribe()
{
	std::string path;
	for (auto& component : k8s_component::list)
	{
		path = m_uri.toString() +  "watch/" + component.second;
		g_logger.log(std::string("Connecting to ") + path, sinsp_logger::SEV_INFO);

		std::unique_ptr<HTTPClientSession> session(get_http_session());
		HTTPRequest request(HTTPRequest::HTTP_GET, path);
		HTTPResponse response;
		session->sendRequest(request);
		session->receiveResponse(response);
		if (response.getStatus() == Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED)
		{
			m_credentials->authenticate(request, response);
			session->sendRequest(request);
			session->receiveResponse(response);
			if (response.getStatus() != Poco::Net::HTTPResponse::HTTP_OK)
			{
				if (response.getStatus() == Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED)
				{
					throw Poco::Net::NotAuthenticatedException();
				}
				else 
				{
					throw Poco::Net::HTTPException();
				}
			}
		}
		m_sockets[session->detachSocket()] = component.first;
	}
}

void k8s_net::stop_watching()
{
	if (!m_stopped)
	{
		m_stopped = true;
		unsubscribe();
		m_thread.join();
	}
}
	
void k8s_net::unsubscribe()
{
	for (auto& socket : m_sockets)
	{
		socket.first.impl()->shutdown();
		socket.first.impl()->close();
	}
}

void k8s_net::dispatch_events()
{
	Poco::Net::Socket::SocketList sockets;
	for (auto& socket : m_sockets)
	{
		sockets.push_back(socket.first);
	}

	while (!m_stopped)
	{
		try
		{
			Poco::Net::Socket::SocketList readList(sockets);
			Poco::Net::Socket::SocketList writeList;
			Poco::Net::Socket::SocketList exceptList(sockets);
		
			Poco::Timespan timeout(500);
			int n = Poco::Net::Socket::select(readList, writeList, exceptList, timeout);
			if (n > 0)
			{
				for (Poco::Net::Socket::SocketList::iterator it = readList.begin(); it != readList.end(); ++it)
				{
					const int len = 4096;
					char buf[len-1] = { 0 };
					int c = it->impl()->receiveBytes(buf, len);
					if (c > 0)
					{
						m_k8s.on_watch_data(k8s_event_data(m_sockets[*it], buf, c));
					}
				}
			}
			readList = sockets;
			exceptList = sockets;
		}
		catch (std::exception& exc)
		{
			g_logger.log(std::string("Exception in main thread: ") + exc.what(), sinsp_logger::SEV_ERROR);
		}
	}
	g_logger.log("Thread done.", sinsp_logger::SEV_DEBUG);
}

void k8s_net::get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out)
{
	std::string path = m_uri.toString() + component.second;
	HTTPRequest request(HTTPRequest::HTTP_GET, path, HTTPMessage::HTTP_1_1);
	HTTPResponse response;
	if (!send_request(*m_session, request, response, out))
	{
		m_credentials->authenticate(request, response);
		if (!send_request(*m_session, request, response, out))
		{
			throw Poco::InvalidAccessException("Invalid username/password.");
		}
	}
}

bool k8s_net::send_request(HTTPClientSession& session, HTTPRequest& request,
	HTTPResponse& response,
	std::ostream& out)
{
	session.sendRequest(request);
	std::istream& rs = session.receiveResponse(response);
	if (response.getStatus() != Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED)
	{
		StreamCopier::copyStream(rs, out);
		return true;
	}
	else
	{
		Poco::NullOutputStream null;
		StreamCopier::copyStream(rs, null);
		return false;
	}
}
