//
// k8s_net.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#ifdef K8S_STANDALONE
#include "logger.h"
#endif

#include "Poco/Net/HTTPSClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/Net/WebSocket.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/StreamCopier.h"
#include "Poco/NullStream.h"
#include "Poco/SharedPtr.h"
#include "Poco/URI.h"
#include "Poco/Path.h"
#include "Poco/Format.h"
#include "Poco/Exception.h"
#include "k8s_component.h"
#include "k8s_event_data.h"
#include <thread>
#include <sstream>
#include <utility>


class k8s;


class k8s_net
{
public:
	k8s_net(k8s& kube, const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/");

	~k8s_net();

	void get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out);

	void start_watching();
	
	void stop_watching();

	bool is_watching() const;

private:
	Poco::Net::HTTPClientSession* get_http_session();

	void subscribe();
	
	void unsubscribe();

	void dispatch_events();

	void init();

	bool send_request(Poco::Net::HTTPClientSession& session,
		Poco::Net::HTTPRequest& request,
		Poco::Net::HTTPResponse& response,
		std::ostream& out);

	bool is_secure();

	void on_watch_data(const void*, k8s_event_data& msg);

	typedef std::map<Poco::Net::Socket, k8s_component::type> socket_map;

	k8s&                           m_k8s;
	Poco::URI                      m_uri;
	Poco::Net::HTTPCredentials*    m_credentials;
	Poco::Net::HTTPClientSession*  m_session;
	socket_map                     m_sockets;
	std::thread                    m_thread;
	bool                           m_stopped;
};

inline bool k8s_net::is_secure()
{
	return m_uri.getScheme() == "https";
}

inline bool k8s_net::is_watching() const
{
	return !m_stopped;
}