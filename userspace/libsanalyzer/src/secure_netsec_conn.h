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
	~secure_netsec_conn();

	// connection events
	void accept_conn_msg(const sinsp_conn_message& msg);

	// container group events
	bool accept_cg(const cg_ptr_t& cg, const std::string& ip, infra_time_point_t insertion_ts);

	// serialize
	void serialize(secure::K8SClusterCommunication* cluster,
                   secure_netsec_metric_stats& metrics,
	               const std::function<void(const secure::K8SPodOwner&)>& on_owner);

	// create unique key, depends on the owners resolved
	std::string get_key() const { return m_key; }

	bool is_ripen() const
	{
		// return true;
		return age() > std::chrono::seconds(60) ||
		       (!is_active() && age() > std::chrono::seconds(10));
	}

	void on_crop();

	std::string to_string() const;

	friend ostream& operator<<(ostream& os, const secure_netsec_conn& conn);

	static netsec_conn_ptr_t create(const sinsp_conn_message& msg,
	                                const secure_netsec_cidr& cidr,
	                                const infrastructure_state& infra,
	                                owner_clbk_t on_owner,
	                                const std::string& key,
                                    secure_netsec_metric_stats& metrics);

	void on_container(const std::string& s);

	// get connection age
	std::chrono::milliseconds age() const
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(infra_clock::now() -
		                                                             m_created_at);
	}

private:
	const std::string m_key;

	friend class log_guard_sp<secure_netsec_conn>;
	typedef log_guard_sp<secure_netsec_conn> log_guard_;

	// ctor
	secure_netsec_conn(const sinsp_conn_message& msg,
	                   const infrastructure_state& infra,
	                   const secure_netsec_cidr& cidr,
	                   owner_clbk_t on_owner_resolved,
	                   std::string key);

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

	struct conn_end_point
	{
		std::string ip_str;
		std::string container_id;
		std::string command;
		std::string cont_pod;
		std::string ip_pod;
		bool is_black_listed = false;
		bool is_active_side = false;
		void init(const conn_message_split& msg_split);
		void update(const conn_message_split& msg_split);
	};

	conn_end_point cli_info{};
	conn_end_point srv_info{};

	struct owner_info
	{
		owner_info(const infrastructure_state& infra_, const owner_clbk_t& clbk)
		    : owner_clbk(clbk),
		      infra(infra_)
		{
		}

		owner_clbk_t owner_clbk;
		const infrastructure_state& infra;
		std::string ip_str;
		std::string container_id;

		bool is_node = false;
		bool is_container_owner = false;
		pod_owner_ptr k8s_owner{};

		void init(const conn_message_split& msg_split, infra_time_point_t conn_created_at);
		void on_container_info(const std::string& s, infra_time_point_t conn_created_at);
		void on_crop(infra_time_point_t conn_created_at);
	};
    friend ostream& operator<<(ostream& os, const owner_info& info);

	owner_info egress_owner;
	owner_info ingress_owner;

	const uint64_t m_conn_id;
	const ipv4tuple m_tuple;
	const infra_time_point_t m_created_at{};
	const infrastructure_state& m_infra;
	const secure_netsec_cidr& m_cidr;
	conn_state m_state;
	uint64_t m_dup_count = 0;

	void log_events(const std::string& header, std::stringstream& ss) const;

	std::stringstream ev_ss;
	void save_log_event(const std::string& e);
	void gress_to_stream(conn_end_point& ci, const owner_info& oi_info, const std::string& cs);

};
