
#include "secure_netsec_conn.h"

#include "secure_netsec.h"
#include "secure_netsec_cidr.h"
#include "secure_netsec_obj.h"
#include "secure_netsec_util.h"

#include <utility>

COMMON_LOGGER("netsec");


// protocol validator
static bool validate_scap_l4_protocol(const uint8_t scap_l4)
{
	// We pick up TCP and all potentially unknown/mislabeled scap protocols
	return (scap_l4 == SCAP_L4_UNKNOWN || scap_l4 == SCAP_L4_NA || scap_l4 == SCAP_L4_TCP);
}

/*
 * conn builder/verifier
 */
secure_netsec_conn::netsec_conn_ptr_t secure_netsec_conn::create(
    const sinsp_conn_message& msg,
    const secure_netsec_cidr& cidr,
    const infrastructure_state& infra,
    owner_clbk_t on_owner_resolved,
    const std::string& key,
    secure_netsec_metric_stats& metrics)
{
	if (msg.message == sinsp_conn_message::failed || msg.message == sinsp_conn_message::closed ||
	    msg.flags_to_type() == sinsp_conn_message::failed ||
	    msg.flags_to_type() == sinsp_conn_message::closed || msg.is_pending())
	{
		return nullptr;
	}

	if (secure_helper::is_localhost(msg.key) || !secure_helper::is_valid_tuple(msg.key) ||
	    !validate_scap_l4_protocol(msg.key.m_fields.m_l4proto))
	{
		metrics.comm_invalid();
		return nullptr;
	}

	if (!cidr.is_configured())
	{
		LOG_DEBUG( "cidr is not configured");
	}
	else if (!cidr.is_tuple_in_k8s_cidr(msg.key))
	{
		LOG_DEBUG("out of cidr");
		metrics.cidr_out();
		return nullptr;
	}
	else
	{
		metrics.cidr_in();
	}

	conn_message_split_cli cli(msg);
	conn_message_split_srv srv(msg);

	if (!cli.has_container() && !srv.has_container())
	{
		return nullptr;
	}

	if (cli.is_blacklisted() && srv.is_blacklisted())
	{
		return nullptr;
	}

	return std::unique_ptr<secure_netsec_conn>(
	    new secure_netsec_conn(msg, infra, cidr, on_owner_resolved, key));
}

/*============================================================
 *
 *============================================================*/

std::multimap<std::string, secure_netsec_conn*> conns_by_container_id;

int
secure_netsec_conn::erase_cont_id(const std::string &cont_id)
{
	int n_erased = 0;

	if (cont_id.empty())
	{
		return 0;
	}

	for (auto iter = conns_by_container_id.lower_bound(cont_id);
	     iter != conns_by_container_id.end();)
	{
		if (iter->first != cont_id)
		{
			break;
		}

		if (iter->second == this)
		{
			iter = conns_by_container_id.erase(iter);
			++n_erased;
		}
		else
		{
			++iter;
		}
	}
	return n_erased;
};

secure_netsec_conn::~secure_netsec_conn()
{
	int num_clear = erase_cont_id(cli_info.container_id);
	num_clear += erase_cont_id(srv_info.container_id);

	if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		std::string out = ev_ss.str();
		LOG_DEBUG("\n~secure_netsec_conn(%ld/%d): %s",
		          conns_by_container_id.size(),
		          num_clear,
		          out.c_str());
	}
}

void secure_netsec_conn::gress_to_stream(conn_end_point& ci, const owner_info& oi_info, const std::string& cs)
{
	if (ci.cont_pod.empty() && !ci.container_id.empty())
	{
		auto cg_wrap = secure_netsec_util::find_pod_by_container(m_infra, ci.container_id);
		if (cg_wrap != nullptr)
		{
			ev_ss << "\n\t\t" << cs << "_cont_pod=" << (*cg_wrap)->uid().id();
			ci.cont_pod = (*cg_wrap)->uid().id();
			bool is_node = false;
			for (auto i = (*cg_wrap)->ip_addresses().begin(),
				     i_end = (*cg_wrap)->ip_addresses().end();
			     i != i_end;
			     ++i)
			{
				if (cg_wrap->is_node(*i))
				{
					ev_ss << " is_node=true";
					is_node = true;
					break;
				}
			}
			if (!is_node)
			{
				auto owner = m_infra.get_pod_owner(cg_wrap->get());
				if (owner != nullptr)
				{
					ev_ss << " owner=" << owner->uid().kind() << "/" << owner->uid().id();
					if (oi_info.is_container_owner && oi_info.k8s_owner != nullptr)
					{
						ev_ss << "\n\t\t\t" << oi_info.k8s_owner->ShortDebugString();
					}
				}
			}
		}
	}

	if (ci.ip_pod.empty())
	{
		auto cg_wrap = secure_netsec_util::find_pod_by_ip(m_infra, ci.ip_str);
		bool is_node = false;
		if (cg_wrap != nullptr)
		{
			ev_ss << "\n\t\t" << cs << "_ip_pod=" << (*cg_wrap)->uid().id();
			ci.ip_pod = (*cg_wrap)->uid().id();
			if (cg_wrap->is_node(ci.ip_str))
			{
				ev_ss << " is_node=true";
			}
			if (!is_node)
			{
				auto owner = m_infra.get_pod_owner(cg_wrap->get());
				if (owner != nullptr)
				{
					ev_ss << " owner=" << owner->uid().kind() << "/" << owner->uid().id();
					if (!oi_info.is_container_owner && oi_info.k8s_owner != nullptr)
					{
						ev_ss << "\n\t\t\t" << oi_info.k8s_owner->ShortDebugString();
					}
				}
			}
		}
	}
}

void secure_netsec_conn::save_log_event(const std::string& e)
{
	if (!LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		return;
	}

	auto d = std::chrono::duration_cast<std::chrono::milliseconds>(infra_clock::now() - m_created_at).count();

	ev_ss << "\n\t" << double(d) / 1000. << " :" << e << ": " << get_key();

	gress_to_stream(cli_info, egress_owner, "cli");
	gress_to_stream(srv_info, ingress_owner, "srv");
	ev_ss << "\n";
}

// ctor
secure_netsec_conn::secure_netsec_conn(const sinsp_conn_message& msg,
                                       const infrastructure_state& infra,
                                       const secure_netsec_cidr& cidr,
                                       owner_clbk_t on_owner_resolved,
                                       std::string key)
    : m_key(std::move(key)),
      egress_owner(infra, on_owner_resolved),
      ingress_owner(infra, on_owner_resolved),
      m_conn_id(msg.conn->conn_id),
      m_tuple(msg.key),
      m_created_at(std::chrono::nanoseconds(msg.conn->m_timestamp)),
      m_infra(infra),
      m_cidr(cidr),
      m_state(conn_state::active)
{
	conn_message_split_cli cli(msg);
	conn_message_split_srv srv(msg);

	cli_info.init(cli);
	srv_info.init(srv);
	egress_owner.init(cli, m_created_at);
	ingress_owner.init(srv, m_created_at);

	parse_conn_state(msg);
}

void secure_netsec_conn::conn_end_point::init(const conn_message_split& msg_split)
{
	ip_str = msg_split.get_ip_str();
	container_id = msg_split.get_container_id();
	command = msg_split.get_command();
	is_black_listed = msg_split.is_blacklisted();
	is_active_side = msg_split.is_active_side();
}

void secure_netsec_conn::conn_end_point::update(const conn_message_split& msg_split)
{
	if (container_id.empty())
	{
		container_id = msg_split.get_container_id();
	}
	if (command.empty())
	{
		command = msg_split.get_command();
		is_black_listed |= msg_split.is_blacklisted();
	}
	is_active_side |= msg_split.is_active_side();
}

void secure_netsec_conn::parse_conn_state(const sinsp_conn_message& msg)
{
	conn_message_split_cli cli(msg);
	conn_message_split_srv srv(msg);

	cli_info.update(cli);
	srv_info.update(srv);

	bool updated = false;
	auto set_cont_id = [&](const std::string& src, std::string& dest)
	{
		if (!src.empty())
		{
			erase_cont_id(dest);
			dest = src;
			conns_by_container_id.insert({dest, this});
			updated = true;
		}
	};

	set_cont_id(cli.get_container_id(), cli_info.container_id);
	set_cont_id(srv.get_container_id(), srv_info.container_id);

	if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		if (updated)
		{
			save_log_event("conn_id=" + std::to_string(m_conn_id) +
				": msg=" + sinsp_conn_message::type_str(msg.flags_to_type()));
		}
		else
		{
			save_log_event(sinsp_conn_message::type_str(msg.flags_to_type()));
		}
	}
}

// conn status notifications
void secure_netsec_conn::accept_conn_msg(const sinsp_conn_message& msg)
{
	if (msg.conn->conn_id != m_conn_id)
	{
		m_dup_count++;
		return;
	}

	if (m_state != conn_state::active)
	{
		return;
	}

    m_state = msg.is_pending() ? conn_state::pending : conn_state::active;

	switch (msg.flags_to_type())
	{
	case sinsp_conn_message::client_info:
	case sinsp_conn_message::server_info:
	case sinsp_conn_message::state_info:
		parse_conn_state(msg);
		break;

	case sinsp_conn_message::deleted:
	case sinsp_conn_message::closed:
		m_state = conn_state::closed;
		parse_conn_state(msg);
		save_log_event("closed");
		break;

	case sinsp_conn_message::failed:
		m_state = conn_state::failed;
		save_log_event("failed");
		break;
	}
}

void secure_netsec_conn::owner_info::init(const conn_message_split& msg_split,
                                          infra_time_point_t conn_created_at)
{
	ip_str = msg_split.get_ip_str();
	container_id = msg_split.get_container_id();

	is_node = msg_split.is_node_ip(infra);

	if (is_node)
	{
		return;
	}

	if (!container_id.empty())
	{
		const auto& cg_wrap = msg_split.find_pod_by_container(infra);
		if (cg_wrap != nullptr)
		{
			k8s_owner = cg_wrap->get_k8s_owner();
			is_container_owner = k8s_owner != nullptr;
		}
	}

	if (!is_container_owner && !ip_str.empty())
	{
		const auto& cg_wrap = msg_split.find_pod_by_ip(infra);
		if (cg_wrap != nullptr && cg_wrap->pod_creation_tp() < conn_created_at)
		{
			k8s_owner = cg_wrap->get_k8s_owner();
		}
	}

	if (k8s_owner != nullptr)
	{
		owner_clbk(k8s_owner->metadata().kind(), k8s_owner->metadata().uid());
	}
}

void secure_netsec_conn::owner_info::on_container_info(const std::string& new_cont_id,
                                                       infra_time_point_t conn_created_at)
{
	if (is_node)
	{
		return;
	}
	bool new_owner = false;

	if (!is_container_owner && !container_id.empty() && new_cont_id == container_id)
	{
		const auto& cg_wrap = secure_netsec_util::find_pod_by_container(infra, new_cont_id);
		if (cg_wrap != nullptr)
		{
			auto k8s_test_owner = cg_wrap->get_k8s_owner();
			if (k8s_test_owner != nullptr)
			{
				k8s_owner = std::move(k8s_test_owner);
				is_container_owner = true;
				new_owner = true;
			}
		}
	}

	if (!is_container_owner && !ip_str.empty() && k8s_owner == nullptr)
	{
		const auto& cg_wrap = secure_netsec_util::find_pod_by_ip(infra, ip_str);
		if (cg_wrap != nullptr && cg_wrap->pod_creation_tp() < conn_created_at)
		{
			k8s_owner = cg_wrap->get_k8s_owner();
			new_owner = true;
		}
	}

	if (new_owner && k8s_owner != nullptr)
	{
		owner_clbk(k8s_owner->metadata().kind(), k8s_owner->metadata().uid());
	}
}

void secure_netsec_conn::owner_info::on_crop(infra_time_point_t conn_created_at)
{
	// reevaluate container info;
	on_container_info(container_id, conn_created_at);
}

ostream& operator<<(ostream& os, const secure_netsec_conn::owner_info& info)
{
    if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		os << "ip_str: " << info.ip_str << " container_id: " << info.container_id
		   << " is_node: " << std::boolalpha << info.is_node
		   << " is_container_owner: " << std::boolalpha << info.is_container_owner;

		if (info.k8s_owner != nullptr)
		{
			os << " k8s_owner: (" << info.k8s_owner->metadata().name() << ":"
			   << info.k8s_owner->metadata().kind() << ":" << info.k8s_owner->metadata().uid()
			   << ")";
		}
	}
	return os;
}

void secure_netsec_conn::on_container(const std::string& container_id)
{
	save_log_event("on_container_id=" + container_id);
	egress_owner.on_container_info(container_id, m_created_at);
	ingress_owner.on_container_info(container_id, m_created_at);
}

void secure_netsec_conn::on_crop()
{
	save_log_event("on_crop");
	egress_owner.on_crop(m_created_at);
	ingress_owner.on_crop(m_created_at);
}

// new cg notifications
bool secure_netsec_conn::accept_cg(const cg_ptr_t& cg,
                                   const std::string& ip,
                                   infra_time_point_t insertion_ts)
{
	return false;
}

void secure_netsec_conn::serialize(secure::K8SClusterCommunication* cluster,
                                   secure_netsec_metric_stats& metrics,
                                   const std::function<void(const secure::K8SPodOwner&)>& on_owner)
{
	if (egress_owner.k8s_owner == nullptr && ingress_owner.k8s_owner == nullptr)
	{
		save_log_event("serialize skipped: owners not resolved");
		return;
	}

	auto k8s_comm = secure::K8SCommunication();
	k8s_comm.set_is_self_local(is_local_comm());
	k8s_comm.set_l4_protocol(secure_helper::scap_l4_to_ip_l4(m_tuple.m_fields.m_l4proto));

	// client data
	k8s_comm.set_client_ipv4(ntohl(m_tuple.m_fields.m_sip));
	if (!cli_info.command.empty())
	{
		k8s_comm.set_client_comm(cli_info.command);
	}

	// server data
	k8s_comm.set_server_ipv4(ntohl(m_tuple.m_fields.m_dip));
	k8s_comm.set_server_port(m_tuple.m_fields.m_dport);
	if (!srv_info.command.empty())
	{
		k8s_comm.set_server_comm(srv_info.command);
	}

	bool skip_host_activity =
		k8s_cluster_communication::c_network_topology_skip_host_activity.get_value() &&
			(egress_owner.is_node || ingress_owner.is_node);

	if (cli_info.is_active_side && !skip_host_activity)
	{
		if (egress_owner.k8s_owner != nullptr)
		{
			k8s_comm.set_client_owner_uid(egress_owner.k8s_owner->metadata().uid());
			on_owner(*egress_owner.k8s_owner);
			metrics.owner_resolved();
		}

		cluster->add_egresses()->CopyFrom(k8s_comm);
		metrics.egress_added();
	}

	if (srv_info.is_active_side && !skip_host_activity)
	{
		if (ingress_owner.k8s_owner != nullptr)
		{
			k8s_comm.set_server_owner_uid(ingress_owner.k8s_owner->metadata().uid());
			on_owner(*ingress_owner.k8s_owner);
			metrics.owner_resolved();
		}

		cluster->add_ingresses()->CopyFrom(k8s_comm);
		metrics.ingress_added();
	}

	if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		std::stringstream ss;
		ss << "serialize: (" << std::to_string(m_dup_count) << ")"
		   << "skip hosts=" << std::boolalpha << skip_host_activity
		   << "\n\t\t egress:" << egress_owner
		   << "\n\t\t ingress:" << ingress_owner
		   << "\n\t\t" << k8s_comm.ShortDebugString();

		save_log_event(ss.str());
	}
}

std::string secure_netsec_conn::to_string() const
{
	std::stringstream ss;
	ss << *this;
	return ss.str();
}

ostream& operator<<(ostream& os, const secure_netsec_conn& conn)
{
	os << " conn_id=" << conn.m_conn_id
	   << " age=" << conn.age().count()
	   << " state=" << conn.str_state();
	return os;
}

void secure_netsec_conn::log_events(const std::string& header, std::stringstream& events) const
{
    if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		std::stringstream ss;
		ss << header << ":  conn_id=" << m_conn_id << ", age=" << age().count()
		   << ", state=" << str_state() << ", key=" << get_key() << ", details=[" << events.str()
		   << "]";
		cout << ss.str() << "\n";
		LOG_DEBUG("%s", ss.str().c_str());
	}
}
