#pragma once

#include "connectinfo.h"
#include "secure_netsec_cg.h"
#include "secure_netsec_util.h"

#include <chrono>
#include <ostream>
#include <ratio>

class secure_netsec_cidr;
class conn_message_split;

class log_guard;
template<typename P>
class log_guard_sp;

class secure_netsec_conn
{
private:
	using pod_owner_ptr = std::unique_ptr<secure::K8SPodOwner>;
	using netsec_conn_ptr_t = std::unique_ptr<secure_netsec_conn>;
	using owner_clbk_t = std::function<void(std::string kind, std::string id)>;

public:
	static netsec_conn_ptr_t create(const sinsp_conn_message& msg,
									const secure_netsec_cidr& cidr,
									const infrastructure_state& infra,
									owner_clbk_t on_owner,
									const std::string& key,
									secure_netsec_metric_stats& metrics);

	~secure_netsec_conn();

	// connection events
	void accept_conn_msg(const sinsp_conn_message& msg);

	void on_container(const std::string& s);

	// serialize
	void serialize(secure::K8SClusterCommunication* cluster,
                   secure_netsec_metric_stats& metrics,
	               const std::function<void(const secure::K8SPodOwner&)>& on_owner);

	// create unique key, depends on the owners resolved
	std::string get_key() const { return m_key; }

	std::string to_string() const;

	friend ostream& operator<<(ostream& os, const secure_netsec_conn& conn);

	// get connection age
	std::chrono::milliseconds age() const
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(infra_clock::now() -
		                                                             m_created_at);
	}

private:
	// ctor
	secure_netsec_conn(const sinsp_conn_message& msg,
					   const infrastructure_state& infra,
					   const secure_netsec_cidr& cidr,
					   owner_clbk_t on_owner_resolved,
					   std::string key);

	const std::string m_key;

    int erase_cont_id(const std::string& cont_id);

	void parse_conn_state(const sinsp_conn_message&);

	bool is_local_comm() const { return m_tuple.m_fields.m_sip == m_tuple.m_fields.m_dip; }

	// check active
	bool is_active() const { return m_state == active; }

	enum conn_state
	{
		pending,
		active,
		closed,
		failed
	};

	const std::string& str_state() const
	{
		static const std::string state_str[] = {"pending", "active", "closed", "failed"};
		return state_str[m_state];
	};

	struct owner_info;

    friend ostream& operator<<(ostream& os, const owner_info& info);

    std::string to_string(const owner_info& info)
    {
		std::stringstream ss;
		ss << info;
		return ss.str();
	}

	std::unique_ptr<owner_info> egress_owner;
    std::unique_ptr<owner_info> ingress_owner;

	const uint64_t m_conn_id;
	const ipv4tuple m_tuple;

	const infra_time_point_t m_created_at{};
	const infrastructure_state& m_infra;

	conn_state m_state;
	uint64_t m_dup_count = 0;

};
