
#include "secure_netsec_conn.h"

#include "secure_netsec.h"
#include "secure_netsec_cidr.h"
#include "secure_netsec_obj.h"
#include "secure_netsec_util.h"

#include <utility>

COMMON_LOGGER("netsec");

const std::string COMMAND_NA("<NA>");


struct secure_netsec_conn::owner_info
{
	owner_info(const infrastructure_state& infra_, const owner_clbk_t& clbk)
	    : m_owner_clbk(clbk),
	      m_infra_(infra_)
	{
	}

	owner_clbk_t m_owner_clbk;
	const infrastructure_state& m_infra_;

	infra_time_point_t m_conn_ts{};
	std::string m_command;

	bool m_is_active_side = false;
	bool m_is_node = false;

	std::string m_ip_str;
	std::string m_ip_masq;
	std::string m_container_id;

	pod_owner_ptr m_k8s_owner{};

	void init(const conn_message_split& msg_split)
	{
		m_ip_str = msg_split.get_ip_str();
		m_container_id = msg_split.get_container_id();
		m_is_node = msg_split.is_node_ip(m_infra_);
		m_conn_ts = infra_time_point_t(std::chrono::nanoseconds(msg_split.get_conn_ts()));
		m_command = msg_split.get_command();
		m_is_active_side = msg_split.is_active_side();

		if (m_command.empty())
		{
			m_command = COMMAND_NA;
		}

		if (m_is_node)
		{
			return;
		}
		update_owner();
	}

	void update(const conn_message_split& msg_split)
	{
		if (m_command == COMMAND_NA && !msg_split.get_command().empty())
		{
			m_command = msg_split.get_command();
		}

		if (m_k8s_owner == nullptr)
		{
			update_owner();
		}
	}

	void on_container_info(const std::string& new_cont_id, infra_time_point_t conn_created_at)
	{
		if (m_is_node)
		{
			return;
		}

		if (m_k8s_owner == nullptr)
		{
			update_owner();
		}
	}

	void on_crop()
	{
		if (m_is_node)
		{
			return;
		}

		if (m_k8s_owner == nullptr)
		{
			update_owner();
		}
	}

	void update_owner()
	{
		const auto cont_pod = secure_netsec_util::find_pod_by_container(m_infra_, m_container_id);

		if (cont_pod != nullptr)
		{
			bool ip_match = false;
			for (auto ip : cont_pod->get()->ip_addresses())
			{
				if ((ip_match = ip == m_ip_str))
				{
					m_k8s_owner = cont_pod->get_k8s_owner();
					m_owner_clbk(m_k8s_owner->metadata().kind(), m_k8s_owner->metadata().uid());
					break;
				}
			}
			if (!ip_match)
			{
				for (auto ip : cont_pod->get()->ip_addresses())
				{
					bool dummy = true;
					const auto cg_ptr = m_infra_.match_from_addr(ip, &dummy);
					if (cg_ptr != nullptr && secure_netsec_cg(m_infra_, cg_ptr).is_node())
					{
						m_ip_masq = ip;
						m_is_node = true;
						LOG_DEBUG("possible ip masq detected for ip='%s' and container='%s'(%s)",
						          m_ip_str.c_str(),
						          m_container_id.c_str(),
						          cont_pod->get()->uid().id().c_str());
						return;
					}
				}
			}
		}

		if (m_k8s_owner == nullptr)
		{
			const auto ip_pod = secure_netsec_util::find_pod_by_ip(m_infra_, m_ip_str);
			if (ip_pod != nullptr)
			{
				// check pod creation time
				if (ip_pod->pod_creation_tp() < m_conn_ts)
				{
					m_k8s_owner = ip_pod->get_k8s_owner();
					m_owner_clbk(m_k8s_owner->metadata().kind(), m_k8s_owner->metadata().uid());
				}
			}
		}
	}
};

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
	// check cons state
	if (msg.message == sinsp_conn_message::failed ||
	    msg.message == sinsp_conn_message::closed ||
	    msg.flags_to_type() == sinsp_conn_message::failed ||
	    msg.flags_to_type() == sinsp_conn_message::closed ||
	    msg.is_pending())
	{
		return nullptr;
	}

	// check client/server info
	if (msg.conn->m_refcount == 0)
	{
		// no client or server info
		return nullptr;
	}

	// check other things
	if (secure_helper::is_localhost(msg.key) ||
	    !secure_helper::is_valid_tuple(msg.key) ||
	    !validate_scap_l4_protocol(msg.key.m_fields.m_l4proto))
	{
		metrics.comm_invalid();
		return nullptr;
	}

	if (!cidr.is_configured())
	{
		// do nothing it's a possible configuration
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

	// ignore port select
	if (srv.get_port() == 0)
	{
		return nullptr;
	}

	// no containers on both sides
	if (!cli.has_container() && !srv.has_container())
	{
		return nullptr;
	}

	if (cli.is_blacklisted() || srv.is_blacklisted())
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

int secure_netsec_conn::erase_cont_id(const std::string& cont_id)
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
	int num_clear = erase_cont_id(egress_owner->m_container_id);
	num_clear += erase_cont_id(ingress_owner->m_container_id);

	if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		LOG_DEBUG("\n~secure_netsec_conn(%ld/%d)",
		          conns_by_container_id.size(),
		          num_clear);
	}
}

// ctor
secure_netsec_conn::secure_netsec_conn(const sinsp_conn_message& msg,
                                       const infrastructure_state& infra,
                                       const secure_netsec_cidr& cidr,
                                       owner_clbk_t on_owner_resolved,
                                       std::string key)
    : m_key(std::move(key)),
      egress_owner(make_unique<secure_netsec_conn::owner_info>(infra, on_owner_resolved)),
      ingress_owner(make_unique<secure_netsec_conn::owner_info>(infra, on_owner_resolved)),
      m_conn_id(msg.conn->conn_id),
      m_tuple(msg.key),
      m_created_at(std::chrono::nanoseconds(msg.conn->m_timestamp)),
      m_infra(infra),
      m_state(conn_state::active)
{
	conn_message_split_cli cli(msg);
	conn_message_split_srv srv(msg);

	egress_owner->init(cli);
	ingress_owner->init(srv);

	parse_conn_state(msg);
}

void secure_netsec_conn::parse_conn_state(const sinsp_conn_message& msg)
{
	conn_message_split_cli cli(msg);
	conn_message_split_srv srv(msg);

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

	set_cont_id(cli.get_container_id(), egress_owner->m_container_id);
	set_cont_id(srv.get_container_id(), ingress_owner->m_container_id);
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
		break;

	case sinsp_conn_message::failed:
		m_state = conn_state::failed;
		break;
	}
}

void secure_netsec_conn::on_container(const std::string& container_id)
{
	egress_owner->on_container_info(container_id, m_created_at);
	ingress_owner->on_container_info(container_id, m_created_at);
}

ostream& operator<<(ostream& os, const secure_netsec_conn::owner_info& info)
{
	os << "\n\tip_str: " << info.m_ip_str << "\n\tis_node: " << std::boolalpha << info.m_is_node
	   << "\n\tip_masq: " << info.m_ip_masq << "\n\tcontainer_id: " << info.m_container_id
	   << "\n\tcommand: " << info.m_command;

	if (!info.m_ip_str.empty())
	{
		const auto& cg_wrap = secure_netsec_util::find_pod_by_ip(info.m_infra_, info.m_ip_str);
		if (cg_wrap != nullptr)
		{
			os << "\n\tIP_pod: [" << cg_wrap->name() << ", " << cg_wrap->get()->uid().kind() << ", "
			   << cg_wrap->get()->uid().id() << "]";
		}
	}

	if (!info.m_container_id.empty())
	{
		const auto& cg_wrap =
		    secure_netsec_util::find_pod_by_container(info.m_infra_, info.m_container_id);

		if (cg_wrap != nullptr)
		{
			os << "\n\tcontainer_pod: [" << cg_wrap->name() << ", " << cg_wrap->get()->uid().kind()
			   << ", " << cg_wrap->get()->uid().id() << "]";
		}
	}

	if (info.m_k8s_owner != nullptr)
	{
		os << "\n\tk8s_owner: [" << info.m_k8s_owner->metadata().name() << ", "
		   << info.m_k8s_owner->metadata().kind() << ", " << info.m_k8s_owner->metadata().uid() << "]";
	}
	return os;
}

void secure_netsec_conn::serialize(secure::K8SClusterCommunication* cluster,
                                   secure_netsec_metric_stats& metrics,
                                   const std::function<void(const secure::K8SPodOwner&)>& on_owner)
{
	LOG_DEBUG("serializing communication: \nclient: %s \nserver: %s",
	          to_string(*egress_owner).c_str(),
	          to_string(*ingress_owner).c_str());

	if (egress_owner->m_k8s_owner == nullptr && ingress_owner->m_k8s_owner == nullptr)
	{
		LOG_DEBUG("%s","serialize skipped: owners not resolved");
		return;
	}

	auto k8s_comm = secure::K8SCommunication();
	k8s_comm.set_is_self_local(is_local_comm());
	k8s_comm.set_l4_protocol(secure_helper::scap_l4_to_ip_l4(m_tuple.m_fields.m_l4proto));

	// client data
	k8s_comm.set_client_ipv4(ntohl(m_tuple.m_fields.m_sip));
	if (!egress_owner->m_command.empty())
	{
		k8s_comm.set_client_comm(egress_owner->m_command);
	}

	// server data
	k8s_comm.set_server_ipv4(ntohl(m_tuple.m_fields.m_dip));
	k8s_comm.set_server_port(m_tuple.m_fields.m_dport);
	if (!ingress_owner->m_command.empty())
	{
		k8s_comm.set_server_comm(ingress_owner->m_command);
	}

	//
	bool skip_host_activity =
	    k8s_cluster_communication::c_network_topology_skip_host_activity.get_value() &&
	    (egress_owner->m_is_node || ingress_owner->m_is_node);

	bool egress_added = false;
	if (!skip_host_activity && egress_owner->m_is_active_side &&
	    (egress_owner->m_command != COMMAND_NA || egress_owner->m_k8s_owner != nullptr))
	{
		if (egress_owner->m_k8s_owner != nullptr)
		{
			k8s_comm.set_client_owner_uid(egress_owner->m_k8s_owner->metadata().uid());
			on_owner(*egress_owner->m_k8s_owner);
			metrics.owner_resolved();
		}

		cluster->add_egresses()->CopyFrom(k8s_comm);
		egress_added = true;
		metrics.egress_added();
	}

	bool ingress_added = false;
	if (!skip_host_activity  && ingress_owner->m_is_active_side && m_tuple.m_fields.m_dport != 0)
	{
		if (ingress_owner->m_k8s_owner != nullptr)
		{
			k8s_comm.set_server_owner_uid(ingress_owner->m_k8s_owner->metadata().uid());
			on_owner(*ingress_owner->m_k8s_owner);
			metrics.owner_resolved();
		}
		cluster->add_ingresses()->CopyFrom(k8s_comm);
		ingress_added = true;
		metrics.ingress_added();
	}

	if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		std::stringstream ss;
		ss << "\nserialize done:"
		   << " skip_hosts=" << std::boolalpha << skip_host_activity
		   << ", server_port=" << m_tuple.m_fields.m_dport << ", egress=" << std::boolalpha
		   << egress_added << ", ingress=" << std::boolalpha << ingress_added
		   << "\n\tk8s_comm=" << k8s_comm.ShortDebugString();

		LOG_DEBUG("%s\n", ss.str().c_str());
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
	os << " conn_id=" << conn.m_conn_id << " age=" << conn.age().count()
	   << " state=" << conn.str_state();
	return os;
}

