
#pragma once

#include "connectinfo.h"
#include "infrastructure_state.h"

#include <utility>
class s_log_sink;
class log_sink;

class secure_netsec_cidr;
class secure_netsec_cg;
typedef std::unique_ptr<secure_netsec_cg> netsec_cg_ptr_t;

/*
 * Connection/tuple client/server split helper
 */
class conn_message_split
{
public:
	enum split_side
	{
		CLI,
		SRV
	};

	conn_message_split() = default;
	virtual ~conn_message_split() = default;
	virtual const shared_ptr<sinsp_threadinfo>& get_t_info() const = 0;
	virtual uint32_t get_ip_int() const = 0;
	virtual infra_time_point_t get_msg_tp() const = 0;
	virtual bool is_active_side() const = 0;

	static std::string ip2str(uint32_t ip)
	{
		char buff[32];
		return inet_ntop(AF_INET, &ip, buff, sizeof(buff));
	}

	std::string get_ip_str() const { return ip2str(get_ip_int()); }

	sinsp_threadinfo* get_main_thread() const
	{
		auto t_info = get_t_info();
		return t_info == nullptr ? nullptr : t_info->get_main_thread();
	}

	bool has_container() const
	{
		auto t_info = get_main_thread();
		return t_info != nullptr && !t_info->m_container_id.empty();
	}

	std::string get_container_id() const
	{
		auto t_info = get_main_thread();
		return t_info == nullptr ? "" : t_info->m_container_id;
	}

	std::string get_command() const
	{
		auto t_info = get_main_thread();
		return t_info == nullptr ? "" : t_info->get_comm();
	}

	bool is_blacklisted() const
	{
		auto t_info = get_main_thread();
		return t_info != nullptr ? is_command_filtered(t_info->get_comm()) : false;
	}

	static bool is_command_filtered(const std::string& cmd);

	bool is_in_cidr(const secure_netsec_cidr& cidr) const;

	netsec_cg_ptr_t find_pod_by_ip(const infrastructure_state& infra) const;

	netsec_cg_ptr_t find_pod_by_container(const infrastructure_state& infra) const;

	bool is_node_ip(const infrastructure_state& infra) const;
};

/*
 * Split side (client/server) specialization
 */
template<conn_message_split::split_side>
class conn_message_split_side : public conn_message_split
{
public:
	explicit conn_message_split_side(const sinsp_conn_message& msg) : conn_message_split(), msg(msg)
	{
	}

	uint32_t get_ip_int() const override;

	const shared_ptr<sinsp_threadinfo>& get_t_info() const override;

	bool is_active_side() const override;

	infra_time_point_t get_msg_tp() const override
	{
		return infra_time_point_t(std::chrono::nanoseconds(msg.conn->m_timestamp));
	}

private:
	const sinsp_conn_message& msg;
};

template<>
inline uint32_t conn_message_split_side<conn_message_split::CLI>::get_ip_int() const
{
	return msg.key.m_fields.m_sip;
}

template<>
inline uint32_t conn_message_split_side<conn_message_split::SRV>::get_ip_int() const
{
	return msg.key.m_fields.m_dip;
}

template<>
inline const shared_ptr<sinsp_threadinfo>&
conn_message_split_side<conn_message_split::CLI>::get_t_info() const
{
	return msg.conn->m_sproc;
}

template<>
inline const shared_ptr<sinsp_threadinfo>&
conn_message_split_side<conn_message_split::SRV>::get_t_info() const
{
	return msg.conn->m_dproc;
}

template<>
inline bool conn_message_split_side<conn_message_split::CLI>::is_active_side() const
{
	return msg.conn->is_client_and_server() || msg.conn->is_client_only();
}

template<>
inline bool conn_message_split_side<conn_message_split::SRV>::is_active_side() const
{
	return msg.conn->is_client_and_server() || msg.conn->is_server_only();
}

typedef conn_message_split_side<conn_message_split::CLI> conn_message_split_cli;
typedef conn_message_split_side<conn_message_split::SRV> conn_message_split_srv;

/*
 * Scoped log helper
 * the idea is to have log to report things when leaving the scope
 */
class log_guard
{
public:
	explicit log_guard(std::string hdr) : header(std::move(hdr)) {}
	virtual ~log_guard() = default;

	template<typename T>
	log_guard& operator<<(const T& s)
	{
		// ss << s;
		return *this;
	}

	log_guard& operator<<(const infra_time_point_t& tp)
	{
		// ss << secure_netsec_util::epoch_milli(tp);
		return *this;
	}

	log_guard& operator<<(const std::chrono::nanoseconds& dur)
	{
		// ss << std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
		return *this;
	}

protected:
	std::stringstream ss;
	const std::string header;
};

/*
 * log helper spec to using class
 */
template<typename P>
class log_guard_sp : public log_guard
{
public:
	log_guard_sp(const P& p, std::string e) : log_guard(e), m_parent(p) {}

	~log_guard_sp() override
	{
		// m_parent.log_events(header, ss);
	}

private:
	const P& m_parent;
};

/*
 * Static utils
 */
class secure_netsec_util
{
public:
	static std::string ip2str(uint32_t ip)
	{
		char buff[32];
		return inet_ntop(AF_INET, &ip, buff, sizeof(buff));
	}

	static uint64_t epoch_sec(const infra_time_point_t& ns)
	{
		return std::chrono::duration_cast<std::chrono::seconds>(ns.time_since_epoch()).count();
	}

	/*
	 * generate unique (netsec realm) connection key
	 */
	static std::string sinsp_conn_message_key(const sinsp_conn_message& msg)
	{
		// client port is currently irrelevant to netsec:  ":" << msg.key.m_fields.m_sport
		std::stringstream ss;
		ss << ip2str(msg.key.m_fields.m_sip)  << "@"
		   << conn_message_split_cli(msg).get_container_id() << "-"
		   << ip2str(msg.key.m_fields.m_dip) << ":" << msg.key.m_fields.m_dport << "@"
		   << conn_message_split_srv(msg).get_container_id();

		return ss.str();
	}

	static netsec_cg_ptr_t find_pod_by_ip(const infrastructure_state& infra, const std::string& op);

	static netsec_cg_ptr_t find_pod_by_container(const infrastructure_state& infra,
	                                             const std::string& cont_id);
};
