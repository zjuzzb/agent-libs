//
// k8s_net.cpp
//


#include "k8s_net.h"
#include "k8s_component.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/Net/KeyConsoleHandler.h"
#include "Poco/Net/ConsoleCertificateHandler.h"
#include "Poco/Net/NetException.h"
#include "Poco/String.h"
#include "Poco/Delegate.h"
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


const k8s_component::component_map k8s_net::m_components =
{
	{ k8s_component::K8S_NODES, "nodes" },
	{ k8s_component::K8S_NAMESPACES, "namespaces" },
	{ k8s_component::K8S_PODS, "pods" },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_SERVICES, "services" }
};


k8s_net::k8s_net(const std::string& uri, const std::string& api) :
		m_uri(uri + api),
		m_credentials(0),
		m_session(0),
		m_dispatcher(*this, &k8s_net::dispatch_events),
		m_stopped(false)
{
	init();
}

k8s_net::~k8s_net()
{
	m_stopped = true;
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

	//subscribe();
	//m_dispatch_thread.join();
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

void k8s_net::subscribe()
{
	std::string path;
	for (auto& component : m_components)
	{
		path = m_uri.toString() +  "watch/" + component.second;
		std::cout << "Connecting to " << path << std::endl;

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
		m_sockets.emplace_back(session->detachSocket());
	}
	std::cout << "Watching " << m_sockets.size() << " sockets." << std::endl;
	m_watch_event += delegate(this, &k8s_net::on_watch_data);
	m_dispatch_thread.start(m_dispatcher);
}

void k8s_net::dispatch_events()
{
	while (!m_stopped)
	{
		try
		{
			Poco::Net::Socket::SocketList readList(m_sockets);
			Poco::Net::Socket::SocketList writeList;
			Poco::Net::Socket::SocketList exceptList(m_sockets);
		
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
						std::string data(buf, c);
						m_watch_event.notifyAsync(this, data);
					}
				}
			}
			readList = m_sockets;
			exceptList = m_sockets;
		}
		catch (Poco::Exception& exc)
		{
			//_pContext->logger().error("Exception in main thread: " + exc.displayText());
		}
	}
}

void k8s_net::on_watch_data(const void*, const std::string& data)
{
	std::cout << data << std::flush;
}

void k8s_net::get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out)
{
	std::string path = m_uri.toString() + component.second;
	HTTPRequest request(HTTPRequest::HTTP_GET, path, HTTPMessage::HTTP_1_1);
	HTTPResponse response;
	if (!send_request(*m_session, request, response, component, out))
	{
		m_credentials->authenticate(request, response);
		if (!send_request(*m_session, request, response, component, out))
		{
			throw Poco::InvalidAccessException("Invalid username/password.");
		}
	}
}

bool k8s_net::send_request(HTTPClientSession& session, HTTPRequest& request,
	HTTPResponse& response,
	const k8s_component::component_map::value_type& component,
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
