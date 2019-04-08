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
		const std::string& http_version = "1.1",
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0);

	~k8s_delegator();

	bool is_delegated(bool trace = false, bool log_delegated = false);

private:
	static std::string EVENT_FILTER;
	static std::string STATE_FILTER;

	enum k8s_taint
	{
		NO_TAINT = 0,
		PREFER_NOSCHEDULE,
		NOSCHEDULE,
		NOEXECUTE,
	};

	class k8s_node_key
	{
	public:
		k8s_node_key(time_t ts, k8s_taint max_taint)
			: m_ts(ts),
			m_max_taint(max_taint)
			{}
		bool operator<(const k8s_node_key& rhs) const
		{
			return (m_max_taint == rhs.m_max_taint) ?
				(m_ts < rhs.m_ts) :
				(m_max_taint < rhs.m_max_taint);
		}
		bool operator==(const k8s_node_key& rhs) const
		{
			return m_ts == rhs.m_ts && m_max_taint == rhs.m_max_taint;
		}

		time_t get_ts() const { return m_ts; }
		k8s_taint get_max_taint() const { return m_max_taint; }
	private:
		const time_t m_ts;
		k8s_taint m_max_taint;
	};

	// nodes may have same creation timestamps, thus multimap
	typedef std::set<std::string> node_ip_addr_list_t;
	typedef std::multimap<k8s_node_key, node_ip_addr_list_t> node_map_t;

	void refresh_ipv4_list();
	node_ip_addr_list_t get_node_addresses(const Json::Value& addrs);
	k8s_taint get_max_taint(const Json::Value& taints);
	bool add_node(time_t timestamp, const Json::Value& addrs,
		      const Json::Value& taints);
	bool maybe_modify_node(time_t timestamp, const Json::Value& addrs,
			       const Json::Value& taints);
	bool remove_node(time_t timestamp, const Json::Value& addrs);

	void handle_json(Json::Value&& root);
	bool handle_component(const Json::Value& json, const msg_data* data = 0);

	sinsp*          m_inspector;
	ip_addr_list_t  m_local_ip_addrs;
	node_map_t      m_nodes;
	int             m_delegate_count;
};
