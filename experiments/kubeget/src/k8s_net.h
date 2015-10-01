//
// k8s_net.h
//
// connects and gets the data from k8s_net REST API interface
//
#pragma once

#include "Poco/Net/HTTPSClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/Net/WebSocket.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/StreamCopier.h"
#include "Poco/NullStream.h"
#include "Poco/SharedPtr.h"
#include "Poco/RunnableAdapter.h"
#include "Poco/BasicEvent.h"
#include "Poco/URI.h"
#include "Poco/Path.h"
#include "Poco/Format.h"
#include "Poco/Exception.h"
#include "k8s_component.h"
#include <sstream>
#include <utility>


class k8s_net
{
public:
	k8s_net(const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/");

	~k8s_net();

	void get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out);

private:
	Poco::Net::HTTPClientSession* get_http_session();

	void subscribe();

	void dispatch_events();

	void init();

	bool send_request(Poco::Net::HTTPClientSession& session,
		Poco::Net::HTTPRequest& request,
		Poco::Net::HTTPResponse& response,
		const k8s_component::component_map::value_type& component,
		std::ostream& out);

	bool is_secure();

	void on_watch_data(const void*, const std::string& data);

	Poco::URI                                 m_uri;
	Poco::Net::HTTPCredentials*               m_credentials;
	Poco::Net::HTTPClientSession*             m_session;
	Poco::Net::Socket::SocketList             m_sockets;
	Poco::RunnableAdapter<k8s_net>            m_dispatcher;
	Poco::Thread                              m_dispatch_thread;
	Poco::BasicEvent<const std::string>       m_watch_event;
	bool                                      m_stopped;
	static const k8s_component::component_map m_components;
};


inline bool k8s_net::is_secure()
{
	return m_uri.getScheme() == "https";
}
