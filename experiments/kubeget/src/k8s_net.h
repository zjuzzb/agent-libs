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


class k8s;


class k8s_net
{
public:
	class event_args
	{
	public:
		event_args() = delete;
		
		event_args(k8s_component::type component, const char* data, int len):
			m_component(component),
			m_data(data, len)
		{
		}
/*
		event_args(const event_args& other):
			m_component(other.m_component),
			m_data(other.m_data)
		{
		}

		event_args(event_args&& other):
			m_component(std::move(other.m_component)),
			m_data(std::move(other.m_data))
		{
		}

		event_args& operator=(event_args&& other)
		{
			if (this != &other)
			{
				m_component = other.m_component;
				m_data = other.m_data;
			}
			return *this;
		}
*/
		k8s_component::type component() const
		{
			return m_component;
		}
		
		const std::string& data() const
		{
			return m_data;
		}

	private:
		k8s_component::type m_component;
		std::string         m_data;
	};

	k8s_net(k8s& kube, const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/");

	~k8s_net();

	void get_all_data(const k8s_component::component_map::value_type& component, std::ostream& out);

	void start();
	
	void stop();

private:
	Poco::Net::HTTPClientSession* get_http_session();

	void subscribe();
	
	void unsubscribe();

	void dispatch_events();

	void init();

	bool send_request(Poco::Net::HTTPClientSession& session,
		Poco::Net::HTTPRequest& request,
		Poco::Net::HTTPResponse& response,
		const k8s_component::component_map::value_type& component,
		std::ostream& out);

	bool is_secure();

	void on_watch_data(const void*, event_args& msg);

	typedef std::map<Poco::Net::Socket, k8s_component::type> socket_map;
	typedef Poco::BasicEvent<event_args>                     watch_event;

	k8s&                           m_k8s;
	Poco::URI                      m_uri;
	Poco::Net::HTTPCredentials*    m_credentials;
	Poco::Net::HTTPClientSession*  m_session;
	socket_map                     m_sockets;
	Poco::RunnableAdapter<k8s_net> m_dispatcher;
	Poco::Thread                   m_dispatch_thread;
	bool                           m_stopped;
};


inline bool k8s_net::is_secure()
{
	return m_uri.getScheme() == "https";
}
