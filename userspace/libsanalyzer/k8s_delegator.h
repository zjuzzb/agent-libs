//
// k8s_delegator.h
//

#pragma once

#include "json/json.h"
#include "sinsp_auth.h"
#include "k8s_handler.h"

class sinsp;

class k8s_delegator : public k8s_handler
{
public:
	typedef std::vector<std::string>     uri_list_t;
	typedef std::shared_ptr<Json::Value> json_ptr_t;
	typedef sinsp_ssl::ptr_t             ssl_ptr_t;
	typedef sinsp_bearer_token::ptr_t    bt_ptr_t;

	k8s_delegator(sinsp* inspector,
		std::string url,
		int delegate_count = 2,
		const std::string& http_version = "1.0",
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0);

	~k8s_delegator();

	bool is_delegated(bool trace = false);

private:
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;

	// nodes may have same creation timestamps, thus multimap
	typedef std::set<std::string> node_ip_addr_list_t;
	typedef std::multimap<time_t, node_ip_addr_list_t> node_map_t;

	void refresh_ipv4_list();
	node_ip_addr_list_t get_node_addresses(const Json::Value& addrs);
	bool add_node(time_t timestamp, const Json::Value& addrs);
	bool remove_node(time_t timestamp, const Json::Value& addrs);

	void handle_json(Json::Value&& root);
	bool handle_component(const Json::Value& json, const msg_data* data = 0);

	sinsp*          m_inspector;
	ip_addr_list_t  m_local_ip_addrs;
	node_map_t      m_nodes;
	int             m_delegate_count;
};
