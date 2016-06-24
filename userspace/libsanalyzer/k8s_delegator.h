//
// k8s_delegator.h
//

#pragma once

#include "json/json.h"
#include "socket_collector.h"
#include "uri.h"
#include "sinsp_curl.h"
#include "json_query.h"
#include <sstream>
#include <utility>
#include <unordered_set>

class sinsp;

class k8s_delegator
{
public:
	typedef std::vector<std::string>        uri_list_t;
	typedef std::shared_ptr<Json::Value>    json_ptr_t;
	typedef sinsp_curl::ssl::ptr_t          ssl_ptr_t;
	typedef sinsp_curl::bearer_token::ptr_t bt_ptr_t;

	static const int default_timeout_ms = 1000L;

	k8s_delegator(sinsp* inspector,
		std::string url,
		int delegate_count = 3,
		const std::string& http_version = "1.0",
		int timeout_ms = default_timeout_ms,
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0,
		bool curl_debug = false);

	~k8s_delegator();

	bool is_alive() const;
	void set_event_json(json_ptr_t json, const std::string&);
	const std::string& get_id() const;

	void send_data_request(bool collect = true);
	void collect_data();
	void set_machine_id(const std::string& machine_id);
	const std::string& get_machine_id() const;

	bool is_delegated(bool trace = false);

private:
	typedef void (k8s_delegator::*callback_func_t)(json_ptr_t, const std::string&);
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;

	typedef socket_data_handler<k8s_delegator> handler_t;
	typedef handler_t::ptr_t                   handler_ptr_t;
	typedef socket_collector<handler_t>        collector_t;
	typedef std::vector<json_ptr_t>            event_list_t;
	typedef std::unordered_set<std::string>    ip_addr_list_t;
	// nodes may have same creation timestamps, thus multimap
	typedef std::set<std::string> node_ip_addr_list_t;
	typedef std::multimap<time_t, node_ip_addr_list_t> node_map_t;

	void refresh_ipv4_list();
	bool is_ip_address(const std::string& addr);
	node_ip_addr_list_t get_node_addresses(const Json::Value& addrs);
	bool add_node(time_t timestamp, const Json::Value& addrs);
	bool remove_node(time_t timestamp, const Json::Value& addrs);
	ip_addr_list_t hostname_to_ip(const std::string& hostname);

	void connect();
	void send_event_data_request();
	void check_collector_status(int expected);

	void handle_json(Json::Value&& root);

	template <typename T>
	bool connect(T http, typename T::element_type::json_callback_func_t func, int expected_connections)
	{
		if(http)
		{
			if(m_collector.has(http))
			{
				if(!http->is_connected())
				{
					m_collector.remove(http);
				}
			}
			if(!m_collector.has(http))
			{
				http->set_json_callback(func);
				m_collector.add(http);
			}
			check_collector_status(expected_connections);
			return m_collector.has(http);
		}
		return false;
	}

	const std::string& translate_name(const std::string& event_name);

	sinsp*         m_inspector;
	std::string    m_id;
	handler_ptr_t  m_http;
	collector_t    m_collector;
	std::string    m_event_uri;
	event_list_t   m_events;
	long           m_timeout_ms;
	std::string    m_machine_id;
	ip_addr_list_t m_local_ip_addrs;
	node_map_t     m_nodes;
	sinsp_curl     m_curl;
	json_query     m_jq;
	int            m_delegate_count;
};

inline const std::string& k8s_delegator::get_id() const
{
	return m_id;
}

inline void k8s_delegator::set_machine_id(const std::string& machine_id)
{
	m_machine_id = machine_id;
}

inline const std::string& k8s_delegator::get_machine_id() const
{
	return m_machine_id;
}
