#include "secure_netsec.h"

#include "analyzer.h"
#include "common_logger.h"
#include "infrastructure_state.h"
#include "secure_netsec_obj.h"
#include "secure_netsec_v2.h"

#include <random>

COMMON_LOGGER("netsec");

type_config<uint64_t> secure_netsec::c_secure_netsec_report_interval(
    NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL,
    "Network Security report interval",
    "network_topology",
    "report_interval");

type_config<std::string> secure_netsec::c_secure_netsec_cluster_cidr(
    "",
    "Network Security Cluster CIDR",
    "network_topology",
    "cluster_cidr");

type_config<std::string> secure_netsec::c_secure_netsec_service_cidr(
    "",
    "Network Security Service CIDR",
    "network_topology",
    "service_cidr");

/* As secure_netsec relies on the sinsp_connection class to keep state
   of active connection, this value shouldn't be greater then
   connectinfo.cpp:L7 connection.max_count. */
type_config<int> secure_netsec::c_secure_netsec_connections_limit(
    65536,
    "limit on numbers of connections in every message sent - 0 means no limit",
    "network_topology",
    "connections_limit");

type_config<std::vector<std::string>> secure_netsec::c_secure_netsec_filtered_process_names(
    {"kubelet"},
    "List of process names that will be filtered out",
    "network_topology",
    "filtered_process_names");

type_config<bool> secure_netsec::c_secure_netsec_randomize_start(
    true,
    "Use randomized delay before first reporting",
    "network_topology",
    "randomize_start");

type_config<bool> secure_netsec::c_secure_netsec_v2(true,
                                                    "Use v2 netsec v2",
                                                    "network_topology",
                                                    "netsec_v2");
secure_netsec::secure_netsec()
	: m_k8s_cidrs_configured(false),
	  m_cluster_cidr_netip(0),
	  m_cluster_cidr_netmask(0),
	  m_service_cidr_netip(0),
	  m_service_cidr_netmask(0),
	  m_k8s_communication_summary(new secure::K8SCommunicationSummary),
	  m_get_events_interval(nullptr)
{
	clear();
}

secure_netsec::~secure_netsec()
{
	delete m_k8s_communication_summary;
}

void secure_netsec::set_data_handler(secure_netsec_data_ready_handler* handler)
{
	m_netsec_data_handler = handler;
}

void secure_netsec::set_internal_metrics(secure_netsec_internal_metrics* internal_metrics)
{
	m_netsec_internal_metrics = internal_metrics;
}

void secure_netsec::set_cluster_id(const std::string& cluster_id)
{
	m_cluster_id = cluster_id;
}

void secure_netsec::set_cluster_name(const std::string& cluster_name)
{
	m_cluster_name = cluster_name;
}

void secure_netsec::clear()
{
	m_k8s_cluster_communication.clear();
	m_k8s_communication_summary->Clear();
}

static bool validate_scap_l4_protocol(const uint8_t scap_l4)
{
	// We pick up TCP and all potentially unknown/mislabeld scap
	// protocols
	if (scap_l4 == SCAP_L4_UNKNOWN ||
	    scap_l4 == SCAP_L4_NA ||
	    scap_l4 == SCAP_L4_TCP)
	{
		return true;
	}

	return false;
}

void secure_netsec::clear_after_flush(uint64_t ts)
{
	// Flush both the in-memory map and protobuf
	m_k8s_cluster_communication.clear();
	m_k8s_communication_summary->Clear();

	// If not set in the config, and not already discovered, try
	// and update Cluster/Service CIDR with what's in the
	// infrastructure_state
	if (!c_secure_netsec_cluster_cidr.is_set_in_config() && !m_k8s_cidrs_configured &&
	    m_infrastructure_state->is_k8s_cidr_discovered())
	{
		auto k8s_cluster_cidr_configured =
		    parse_k8s_cidr(m_infrastructure_state->get_command_k8s_cluster_cidr(),
		                   &m_cluster_cidr_netip,
		                   &m_cluster_cidr_netmask);
		auto k8s_service_cidr_configured =
		    parse_k8s_cidr(m_infrastructure_state->get_command_k8s_service_cidr(),
		                   &m_service_cidr_netip,
		                   &m_service_cidr_netmask);

		m_k8s_cidrs_configured = k8s_cluster_cidr_configured && k8s_service_cidr_configured;

		if (m_k8s_cidrs_configured)
		{
			LOG_INFO("Kubernetes Cluster/Service CIDR has been discovered");
		}
	}  // else  if we have already attempted X flush, we may want
	   //       to develop a fallback on a heuristic to discover
	   //       the Cluster/Service CIDR to improve performance by
	   //       reducing lookups

	// Loop over every connection in the connection table, and
	// insert them back. We start the new interval with all the
	// relevant connections (i.e. intra-kubernetes-cluster) that
	// are stored in the connection manager.
	if (m_connection_manager != nullptr)
	{
		for (auto& it : m_connection_manager->m_connections)
		{
			if (validate_scap_l4_protocol(it.first.m_fields.m_l4proto))
			{
				add_connection(it.second, it.first);
			}
		}
	}

	// At the end of a flush cycle, endpoints, service and
	// namespaces have been cleared, hence we need to fetch them
	// again from the infrastructure state.
	fetch_cgs("k8s_endpoints");
	fetch_cgs("k8s_namespace");
	fetch_cgs("k8s_service");
	fetch_cgs("k8s_cronjob");
	fetch_cgs("k8s_networkpolicy");
}

// Fetching cgs from infrastructure_state and adding them to the
// secure_netsec state.
void secure_netsec::fetch_cgs(const std::string& kind)
{
	if (m_infrastructure_state)
	{
		m_infrastructure_state->get_congroups_by_kind(kind, [this](const cg_ptr_t& cg){add_cg(cg);});
	}
}

void secure_netsec::flush(uint64_t ts)
{
	m_netsec_sent = false;
	m_netsec_run = false;

	if (!(feature_manager::instance().get_enabled(NETWORK_TOPOLOGY)) ||
	    m_get_events_interval == nullptr)
	{
		return;
	}

	uint64_t flush_start_time = sinsp_utils::get_current_time_ns();
	if (flush_start_time < m_randomized_flush_start)
	{
		return;
	}

	if (m_netsec_v2 != nullptr)
	{
		m_netsec_v2->flush();
	}

	m_get_events_interval->run(
		[this, ts, flush_start_time]() {
			m_netsec_run = true;
			is_empty_flash = false;

			serialize_protobuf();

			auto secure_netsec_summary = get_netsec_summary(ts);

			if (secure_netsec_summary)
			{
				m_netsec_data_handler->secure_netsec_data_ready(ts, secure_netsec_summary);
				m_netsec_sent = true;
			}

			clear_after_flush(ts);

			uint64_t flush_time_ms =
				(sinsp_utils::get_current_time_ns() - flush_start_time) / 1000000;

			if (m_netsec_sent)
			{
				m_netsec_internal_metrics->set_secure_netsec_internal_metrics(1, flush_time_ms);
				LOG_INFO("secure_netsec: flushing fl.ms=%ld ", flush_time_ms);
			}
			m_netsec_internal_metrics->set_secure_netsec_sent_counters(
				m_connection_dropped_count,
				m_connection_count,
				m_communication_invalid,
				m_communication_cidr_out,
				m_communication_cidr_in,
				m_communication_ingress_count,
				m_communication_egress_count,
				m_resolved_owner);
			reset_counters();
		},
		ts);

	if (!m_netsec_sent)
	{
		m_netsec_internal_metrics->set_secure_netsec_internal_metrics(0, 0);
	}
	if (!m_netsec_run)
	{
		m_netsec_internal_metrics->set_secure_netsec_sent_counters(0, 0, 0, 0, 0, 0, 0, 0);
	}
}

bool secure_netsec::is_tuple_in_k8s_cidr(const ipv4tuple &tuple) const
{
	bool src_in_k8s = (is_addr_in_cidr(m_cluster_cidr_netip, m_cluster_cidr_netmask, htonl(tuple.m_fields.m_sip)) ||
			   is_addr_in_cidr(m_service_cidr_netip, m_service_cidr_netmask, htonl(tuple.m_fields.m_sip)));

	bool dst_in_k8s = (is_addr_in_cidr(m_cluster_cidr_netip, m_cluster_cidr_netmask, htonl(tuple.m_fields.m_dip)) ||
			   is_addr_in_cidr(m_service_cidr_netip, m_service_cidr_netmask, htonl(tuple.m_fields.m_dip)));

	return src_in_k8s || dst_in_k8s;
}

secure_netsec::secure_netsec(infrastructure_state* infrastructure_state)
	: m_k8s_communication_summary(new secure::K8SCommunicationSummary),
	  m_infrastructure_state(infrastructure_state)
{
}

void secure_netsec::init(sinsp_ipv4_connection_manager* conn,
						 infrastructure_state* infrastructure_state)
{
	bool k8s_cluster_cidr_configured = false;
	bool k8s_service_cidr_configured = false;
	m_k8s_cidrs_configured = false;

	m_infrastructure_state = infrastructure_state;
	m_connection_manager = conn;

	/* Kubernetes CIDR */
	if (c_secure_netsec_cluster_cidr.is_set_in_config())
	{
		k8s_cluster_cidr_configured = parse_k8s_cidr(c_secure_netsec_cluster_cidr.get_value(),
							     &m_cluster_cidr_netip, &m_cluster_cidr_netmask);
	}

	if (c_secure_netsec_service_cidr.is_set_in_config())
	{
		k8s_service_cidr_configured = parse_k8s_cidr(c_secure_netsec_service_cidr.get_value(),
							     &m_service_cidr_netip, &m_service_cidr_netmask);
	}

	m_k8s_cidrs_configured = k8s_cluster_cidr_configured && k8s_service_cidr_configured;

	if (m_k8s_cidrs_configured)
	{
		LOG_INFO("Kubernetes Cluster/Service CIDR has been configured");
	}

	/* Report interval */
	if (c_secure_netsec_report_interval.get_value() < NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MIN ||
	    c_secure_netsec_report_interval.get_value() > NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MAX)
	{
		c_secure_netsec_report_interval.set(NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL);
		LOG_ERROR("Invalid secure netsec report interval (resetting it to default %ld ns)", NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL);
	}

	if (c_secure_netsec_randomize_start.get_value())
	{
		// set randomized flush start time to random in [now, now + c_secure_netsec_report_interval)
		std::random_device rd;
		std::uniform_int_distribution<uint64_t> dist(0,
		                                             c_secure_netsec_report_interval.get_value());
		m_randomized_flush_start = dist(rd) + sinsp_utils::get_current_time_ns();

		std::string first_flush_date_time;
		sinsp_utils::ts_to_string(m_randomized_flush_start, &first_flush_date_time, true, false);
		LOG_INFO("First flush at: %s", first_flush_date_time.c_str());
	}

	m_get_events_interval = make_unique<run_on_interval>(c_secure_netsec_report_interval.get_value(),
							     NETWORK_TOPOLOGY_FREQUENCY_THRESHOLD_NS);

	/* Registering to the tcp callback */
	if (m_connection_manager == nullptr)
	{
		SINSP_WARNING("secure_netsec failed registering add connection callback");
		return;
	}

    if (infrastructure_state != nullptr && c_secure_netsec_v2.get_value())
    {
        m_netsec_v2 = make_unique<secure_netsec_v2>(m_connection_manager, infrastructure_state, *this);
        m_connection_manager->add_conn_message_handler([this](const sinsp_conn_message& msg)
                                                       { on_conn_message(msg); });
    }

	if (m_netsec_v2 == nullptr)
	{
		m_connection_manager->subscribe_on_new_tcp_connection(
		    [this](const _ipv4tuple& tuple,
		           sinsp_connection& conn,
		           sinsp_connection::state_transition transition)
		    { add_connection_async(tuple, conn, transition); });
	}
}

void secure_netsec::on_conn_message(const sinsp_conn_message& msg)
{
	if (feature_manager::instance().get_enabled(NETWORK_TOPOLOGY) && m_netsec_v2 != nullptr)
	{
		if (!is_empty_flash)
		{
			m_netsec_v2->on_conn_event(msg);
		}
	}
}

void secure_netsec::add_connection_async(const _ipv4tuple& tuple,
                                         sinsp_connection& conn,
                                         sinsp_connection::state_transition transition)
{
	if (!(feature_manager::instance().get_enabled(NETWORK_TOPOLOGY)))
	{
		return;
	}

	if (c_secure_netsec_connections_limit.get_value() == 0 ||
	    (m_connection_count <= c_secure_netsec_connections_limit.get_value()))
	{
        add_connection(conn, tuple);
	}
	else
	{
		m_connection_dropped_count++;
	}
}

void convert_label_selector(secure::K8SLabelSelector *secure_label_selector,
			    draiosproto::K8SLabelSelector label_selector)
{
	auto& match_labels = *secure_label_selector->mutable_match_labels();
	for (const auto& ml : label_selector.match_labels())
	{
		match_labels[ml.first] = ml.second;
	}

	auto match_expressions = secure_label_selector->mutable_match_expressions();
	for (const auto& me : label_selector.match_expressions())
	{
		auto p = match_expressions->Add();
		p->set_key(me.key());
		p->set_match_operator(me.match_operator());
		p->mutable_values()->CopyFrom(me.values());
	}
}

bool secure_netsec::congroup_to_pod_owner(std::shared_ptr<draiosproto::container_group> cg,
					  const string &tag_name,
					  secure::K8SPodOwner* k8s_pod_owner)
{
	auto tag = cg->tags().find(tag_name);

	if (tag != cg->tags().end())
	{
		auto meta = k8s_pod_owner->mutable_metadata();
		congroup_to_metadata(cg, meta);
		meta->set_name(tag->second.c_str());
		meta->set_kind(cg->uid().kind());

		convert_label_selector(k8s_pod_owner->mutable_label_selector(), cg->label_selector());

		// Additional step for jobs--find the parent cronjob and add info about it
		if (cg->uid().kind() == "k8s_job")
		{
			for (const auto &p_uid : cg->parents())
			{
				if(p_uid.kind() == "k8s_cronjob")
				{
					m_k8s_cluster_communication.add_job_to_cronjob(p_uid.id(), cg->uid().id());
				}
			}
		}

		for (const auto &it : cg->pod_template_labels())
		{
			(*k8s_pod_owner->mutable_template_labels())[it.first] = it.second;
		}

		return true;
	}
	return false;
}

// Enrich a connection by resolving potential pod owners. If any pod
// owners are found, they will be added to the pod owner set. If
// force_resolution flag is not set, resolution will take place only
// for not resolved owners. Otherwise, the resolution status of the
// communication will be discarded.
void secure_netsec::enrich_connection(k8s_communication* k8s_comm,
				      bool force_resolution = false)
{
	k8s_pod_owner owner_cli, owner_srv;
	auto tuple = k8s_comm->get_key();

	// Client
	if ((force_resolution || !k8s_comm->is_client_resolved()))
	{
		if (enrich_endpoint(k8s_comm, &owner_cli, tuple.m_fields.m_sip))
		{
			k8s_comm->add_owner_client(owner_cli.metadata().uid());
		}
	}

	// Server
	if ((force_resolution || !k8s_comm->is_server_resolved()))
	{
		if (enrich_endpoint(k8s_comm, &owner_srv, tuple.m_fields.m_dip))
		{
			k8s_comm->add_owner_server(owner_srv.metadata().uid());
		}
	}
}

// Insert or update a pod owner in the pod owner set. This method
// takes care of updating the resolved_owner metrics.
bool secure_netsec::insert_or_update_pod_owner(const k8s_pod_owner& k8s_pod_owner)
{
	bool is_new_entry = false;

	// Only add fully resolved owners
	if (m_k8s_cluster_communication.add_owner(k8s_pod_owner))
	{
		m_resolved_owner += 1;
		is_new_entry = true;
	}

	return is_new_entry;
}

bool secure_netsec::enrich_endpoint(k8s_communication* k8s_comm,
				    k8s_pod_owner* owner,
				    uint32_t ip)
{
	std::string tag;
	bool found = false;
	bool has_valid_owner = false;

	auto cg = resolve_ip_to_cg(ip, &found);

	if (found &&
	    nullptr != cg)
	{
		if (cg->uid().kind() == "node" ||
		    cg->uid().kind() == "k8s_node")
		{
			k8s_comm->set_is_host_activity(true);
		}
		else if (validate_pod_owner(cg->uid().kind(), tag) &&
			 congroup_to_pod_owner(cg, tag, owner))
		{
			has_valid_owner = true;
			insert_or_update_pod_owner(*owner);
		}
	}

	return has_valid_owner;
}

// Resolve an ip endpoint to corresponding congroup
std::shared_ptr<draiosproto::container_group>
secure_netsec::resolve_ip_to_cg(const uint32_t &ip, bool *found)
{
	*found = false;

	std::shared_ptr<draiosproto::container_group> cg = nullptr;
	char addrbuff[32];

	const auto addr = inet_ntop(AF_INET, &ip, addrbuff, sizeof(addrbuff));

	if (m_infrastructure_state)
	{
		cg = m_infrastructure_state->match_from_addr(addr, found);
	}

	return cg;
}

// Validate the pod owner congroup, and fill out the associated label
// tag for the given congroup type
bool secure_netsec::validate_pod_owner(const std::string &kind,
				       std::string &tag)
{
	const static std::unordered_map<std::string, std::string> m_k8s_name_to_label_tag
	{
		// List of valid pod owners
		{"k8s_deployment",        "kubernetes.deployment.name"},
		{"k8s_daemonset",         "kubernetes.daemonSet.name"},
		{"k8s_statefulset",       "kubernetes.statefulset.name"},
		{"k8s_job",               "kubernetes.job.name"}
	};

	auto it = m_k8s_name_to_label_tag.find(kind);
	if (it != m_k8s_name_to_label_tag.end())
	{
		tag = it->second;
		return true;
	}

	return false;
}

// Validate that the connection is coming from a container. In order
// to satisfy this condition, at least one of the connection endpoint
// needs to have a threadinfo with a non-empty container_id.
bool secure_netsec::validate_container(sinsp_connection& conn)
{
	bool connection_is_from_container = false;

	if (conn.m_sproc != nullptr)
	{
		auto t = conn.m_sproc->get_main_thread();
		if (t != nullptr)
		{
			connection_is_from_container |= !t->m_container_id.empty();
		}
	}

	if (conn.m_dproc != nullptr)
	{
		auto t = conn.m_dproc->get_main_thread();
		if (t != nullptr)
		{
			connection_is_from_container |= !t->m_container_id.empty();
		}
	}

	return connection_is_from_container;
}

// Validate the command, and fill out the communication
bool secure_netsec::validate_comm(sinsp_connection& conn,
				  k8s_communication* k8s_comm)
{
	std::string comm_cli, comm_srv;
	std::vector<std::string> vargs;

	if (conn.m_sproc != nullptr)
	{
		auto t = conn.m_sproc->get_main_thread();
		if (t != nullptr &&
			!t->get_comm().empty())
		{
			comm_cli = t->get_comm();
			if (!t->m_args.empty())
			{
				vargs = t->m_args;
			}
		}
		else
		{
			if (conn.is_client_and_server())
			{
				LOG_DEBUG("secure_netsec: missing client comm (is_client_and_server)");
				comm_cli = "default_command";
			}
			else if (conn.is_client_only())
			{
				LOG_DEBUG("secure_netsec: missing client comm (is_client)");
				comm_cli = "default_command";
			}
		}
	}

	if (conn.m_dproc != nullptr)
	{
		auto t = conn.m_dproc->get_main_thread();
		if (t != nullptr &&
			!t->get_comm().empty())
		{
			comm_srv = t->get_comm();
		}
		else
		{
			if (conn.is_client_and_server())
			{
				LOG_ERROR("secure_netsec: missing server comm (is_client_and_server)");
				comm_srv = "<N/A>";
			}
			else if (conn.is_server_only())
			{
				LOG_ERROR("secure_netsec: missing server comm (is_server)");
				comm_srv = "<N/A>";
			}
		}
	}

	// Filter out blacklisted process activity
	auto bl = c_secure_netsec_filtered_process_names.get_value();
	if (std::find(bl.begin(), bl.end(), comm_cli) != bl.end() ||
		std::find(bl.begin(), bl.end(), comm_srv) != bl.end())
	{
		return false;
	}

	if (!comm_cli.empty())
	{
		k8s_comm->add_comm_client(comm_cli);
	}

	if (!comm_srv.empty())
	{
		k8s_comm->add_comm_server(comm_srv);
	}

	return true;
}

// Adding a k8s communication from a sinsp connection. This method is
// responsible for performing validation checks, and metadata enrichment.
bool secure_netsec::add_connection(sinsp_connection& conn,
				   ipv4tuple tuple)
{

	if (!feature_manager::instance().get_enabled(NETWORK_TOPOLOGY))
	{
		return false;
	}

	k8s_communication k8s_comm(tuple,
							   conn.is_client_only() || conn.is_client_and_server(),
							   conn.is_server_only() || conn.is_client_and_server());

	m_connection_count += 1;

	// Remove localhost noise, we don't account for it in our
	// metrics
	if (secure_helper::is_localhost(tuple))
	{
		return false;
	}

	// Validation to remove invalid tuples and commands
	if (!secure_helper::is_valid_tuple(tuple) ||
		!validate_container(conn) ||
		!validate_comm(conn, &k8s_comm))
	{
		m_communication_invalid += 1;
		return false;
	}

	if (k8s_comm.is_server() && !k8s_comm.is_client() &&
		m_k8s_cluster_communication.has_communication_resolved_ingress(tuple))
	{
		return false;
	}
	if (k8s_comm.is_client() && !k8s_comm.is_server() &&
		m_k8s_cluster_communication.has_communication_resolved_egress(tuple))
	{
		return false;
	}

	if (k8s_comm.is_client() && k8s_comm.is_server() &&
		m_k8s_cluster_communication.has_communication_resolved_egress(tuple) &&
		m_k8s_cluster_communication.has_communication_resolved_ingress(tuple))
	{
		return false;
	}

	// If the k8s cidrs are not configured, we always skip the
	// validation and try to enrich. Otherwise, filter out
	// non-intra cluster communications
	if (m_k8s_cidrs_configured)
	{
		if (!this->is_tuple_in_k8s_cidr(tuple))
		{
			m_communication_cidr_out += 1;
			return false;
		}
		else
		{
			m_communication_cidr_in += 1;
		}
	}

	// Enrichment of process command information and pod owner
	enrich_connection(&k8s_comm);
	return insert_or_update_communication(tuple, k8s_comm);
}

// Adding a congroup to the secure_netsec in-memory state
// (k8s_cluster_communication)
bool secure_netsec::add_cg(std::shared_ptr<draiosproto::container_group> cg)
{
	bool is_new_entry = false;

	const auto& uid = cg->uid().id();
	const auto& kind = cg->uid().kind();

	if (kind == "k8s_endpoints")
	{
		k8s_endpoint e;
		congroup_to_endpoint(cg, &e);

		is_new_entry = m_k8s_cluster_communication.add_endpoint(uid, e);
	}
	else if (kind == "k8s_namespace")
	{
		k8s_namespace n;
		congroup_to_namespace(cg, &n);

		is_new_entry = m_k8s_cluster_communication.add_namespace(uid, n);
	}
	else if (kind == "k8s_service")
	{
		k8s_service s;
		congroup_to_service(cg, &s);

		is_new_entry = m_k8s_cluster_communication.add_service(uid, s);
	}
	else if (kind == "k8s_cronjob")
	{
		k8s_cronjob cj;
		congroup_to_cronjob(cg, &cj);

		is_new_entry = m_k8s_cluster_communication.add_cronjob(uid, cj);
	}
	else if(kind == "container")
	{
		if (m_netsec_v2 != nullptr)
		{
			m_netsec_v2->on_container(cg);
		}
	}
	else if (kind == "k8s_networkpolicy")
	{
		secure::K8SNetworkPolicy knp;
		congroup_to_networkpolicy(cg, &knp);
		is_new_entry = m_k8s_cluster_communication.add_knp(uid, knp);
	}

	// TODO as a future optimization, a new entry could already be
	// emitted into the protobuf

	return is_new_entry;
}

// Fills out uid and namespace from cg to a k8s_metadata
void secure_netsec::congroup_to_metadata(
	std::shared_ptr<draiosproto::container_group> cg,
	k8s_metadata* meta)
{
	meta->set_uid(cg->uid().id());

	// Namespace: we may have congroups with empty namespace. This
	// is may be due to purging done during
	// `infrastructure_state::connect_to_namespace'.
	if (cg->namespace_().empty())
	{
		string namespace_;
		m_infrastructure_state->find_tag(make_pair(cg->uid().kind(),
							   cg->uid().id()),
						 "kubernetes.namespace.name",
						 namespace_);

		meta->set_namespace_(namespace_);
	}
	else
	{
		meta->set_namespace_(cg->namespace_());
	}
}

void secure_netsec::congroup_to_endpoint(std::shared_ptr<draiosproto::container_group> cg,
										 k8s_endpoint* k8s_endpoint)
{
	auto tag = cg->tags().find("kubernetes.endpoints.name");

	if (tag != cg->tags().end())
	{
		auto meta = k8s_endpoint->mutable_metadata();
		congroup_to_metadata(cg, meta);
		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_endpoints");

		auto subset = k8s_endpoint->add_subsets();

		for (const auto& cg_ip_address : cg->ip_addresses())
		{
			struct sockaddr_in sa;
			inet_pton(AF_INET, cg_ip_address.c_str(), &(sa.sin_addr));
			subset->add_addresses(ntohl(sa.sin_addr.s_addr));
		}
		for (const auto& cg_port : cg->ports())
		{
			subset->add_ports(cg_port.port());
		}
	}
}

void secure_netsec::congroup_to_networkpolicy(std::shared_ptr<draiosproto::container_group> cg,
											  secure::K8SNetworkPolicy *k8s_networkpolicy)
{
	const auto& name_iter = cg->tags().find("kubernetes.networkpolicy.name");

	if (name_iter != cg->tags().end())
	{
		auto meta = k8s_networkpolicy->mutable_metadata();
		congroup_to_metadata(cg, meta);
		meta->set_name(name_iter->second);
		meta->set_kind("k8s_networkpolicy");

		const auto& spec_iter = cg->internal_tags().find("kubernetes.networkpolicy.spec");
		if (spec_iter != cg->internal_tags().end()) {
			k8s_networkpolicy->set_spec(spec_iter->second);
		}

		const auto& ver_iter = cg->tags().find("kubernetes.networkpolicy.version");
		if (ver_iter != cg->tags().end()) {
			k8s_networkpolicy->set_version(ver_iter->second);
		}
	}
}

void secure_netsec::congroup_to_namespace(std::shared_ptr<draiosproto::container_group> cg,
					  k8s_namespace* k8s_namespace)
{
	auto tag = cg->tags().find("kubernetes.namespace.name");

	if (tag != cg->tags().end())
	{
		auto meta = k8s_namespace->mutable_metadata();
		congroup_to_metadata(cg, meta);

		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_namespace");

		std::string k8s_namespace_tag = "kubernetes.namespace.label";

		for (auto t : cg->tags())
		{
			if (t.first.compare(0, k8s_namespace_tag.size(), k8s_namespace_tag) == 0)
			{
				auto& match_labels = *(k8s_namespace->mutable_label_selector()->mutable_match_labels());

				// kubecollect provides label
				// infromation in the follwing form
				// `kubernetes.namespace.label.<KEY> : <VALUE>'
				//
				// We need to trim away the prefix and
				// leave just the <KEY>.
				match_labels[t.first.substr(k8s_namespace_tag.size() + 1)] = t.second;
			}
		}
	}
}

void secure_netsec::congroup_to_service(
	std::shared_ptr<draiosproto::container_group> cg,
	k8s_service* k8s_service)
{
	auto tag = cg->tags().find("kubernetes.service.name");
	auto service_type = cg->internal_tags().find("kubernetes.service.type");

	if (tag != cg->tags().end())
	{
		auto meta = k8s_service->mutable_metadata();
		congroup_to_metadata(cg, meta);
		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_service");

		for (const auto& cg_ip_address : cg->ip_addresses())
		{
			struct sockaddr_in sa;
			inet_pton(AF_INET, cg_ip_address.c_str(), &(sa.sin_addr));
			k8s_service->mutable_cluster_ip_details()->set_cluster_ip(ntohl(sa.sin_addr.s_addr));
			// only should be only one virtual service IP
			break;
		}

		for (const auto& cg_ports : cg->ports())
		{
			auto port = k8s_service->add_ports();
			port->set_port(cg_ports.port());
			port->set_protocol(cg_ports.protocol());
			if (cg_ports.target_port())
			{
				port->set_target_port(cg_ports.target_port());
			}
		}

		if (service_type != cg->internal_tags().end())
		{
			k8s_service->set_type(service_type->second.c_str());
		}
	}
}

void secure_netsec::congroup_to_cronjob(
	std::shared_ptr<draiosproto::container_group> cg,
	k8s_cronjob* k8s_cronjob)
{
	auto tag = cg->tags().find("kubernetes.cronJob.name");

	if (tag != cg->tags().end())
	{
		auto meta = k8s_cronjob->mutable_metadata();
		congroup_to_metadata(cg, meta);
		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_cronjob");

		for (const auto &it : cg->pod_template_labels())
		{
			(*k8s_cronjob->mutable_template_labels())[it.first] = it.second;
		}
	}
}

// Insert the communication in the appropriate set(s), and update the
// counters. A communication can be ingress only (server), egress only
// (client) or both (in case both client and server endpoints are
// collocated on the same host).
// Return true if any insertion has been performed.
bool secure_netsec::insert_or_update_communication(ipv4tuple tuple,
						   const k8s_communication& k8s_comm)
{
	bool ingress = false, egress = false;

	if (k8s_comm.is_server() &&
	    m_k8s_cluster_communication.insert_or_update_communication_ingress(tuple, k8s_comm))
	{
		m_communication_ingress_count += 1;
		ingress = true;
	}

	if (k8s_comm.is_client() &&
	    m_k8s_cluster_communication.insert_or_update_communication_egress(tuple, k8s_comm))
	{
		m_communication_egress_count += 1;
		egress = true;
	}

	return ingress || egress;
}

secure::K8SClusterCommunication* secure_netsec::serialize_cluster_information()
{
	auto cluster = m_k8s_communication_summary->add_clusters();

	cluster->set_cluster_id(m_cluster_id);

	auto cluster_meta = cluster->mutable_cluster_metadata();

	cluster_meta->set_cluster_name(m_cluster_name);

	if (is_k8s_cidr_configured())
	{
		if (m_cluster_cidr_netip && m_cluster_cidr_netmask)
		{
			auto cluster_cidr = cluster_meta->mutable_cluster_cidr();
			cluster_cidr->set_ip(m_cluster_cidr_netip);
			cluster_cidr->set_netmask(m_cluster_cidr_netmask);
		}

		if (m_service_cidr_netip && m_service_cidr_netmask)
		{
			auto service_cidr = cluster_meta->mutable_service_cidr();
			service_cidr->set_ip(m_service_cidr_netip);
			service_cidr->set_netmask(m_service_cidr_netmask);
		}
	} // If no CIDR has been configured or discovered, leave the
	  // fields blank

	return cluster;
}

void secure_netsec::serialize_protobuf()
{
	if (!feature_manager::instance().get_enabled(NETWORK_TOPOLOGY))
	{
		return;
	}

	auto ts = sinsp_utils::get_current_time_ns();
	m_k8s_communication_summary->set_timestamp_ns(ts);
	m_k8s_communication_summary->set_window_start_ns(ts - c_secure_netsec_report_interval.get_value());
	m_k8s_communication_summary->set_window_end_ns(ts);
	m_k8s_communication_summary->set_hostname(sinsp_gethostname());

	auto cluster = serialize_cluster_information();

	if (m_netsec_v2 != nullptr)
	{
		m_netsec_v2->serialize(cluster);
		m_k8s_cluster_communication.serialize_protobuf_v2(cluster);
		if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
		{
			LOG_DEBUG("\n\ncluster v1=%s\n", cluster->ShortDebugString().c_str());
		}
	}
	else
	{
		m_k8s_cluster_communication.serialize_protobuf(cluster);
		if (LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
		{
			LOG_DEBUG("\n\ncluster v1=%s\n", cluster->ShortDebugString().c_str());
		}
	}
}

void secure_netsec::reset_counters()
{
	m_connection_count = 0;
	m_connection_dropped_count = 0;
	m_communication_invalid = 0;
	m_communication_cidr_out = 0;
	m_communication_cidr_in = 0;
	m_communication_ingress_count = 0;
	m_communication_egress_count = 0;
	m_resolved_client = 0;
	m_resolved_server = 0;
	m_resolved_owner = 0;
}


const secure::K8SCommunicationSummary* secure_netsec::get_netsec_summary(uint64_t timestamp)
{
	if (!feature_manager::instance().get_enabled(NETWORK_TOPOLOGY))
	{
		return nullptr;
	}

    if (m_k8s_communication_summary->clusters_size() > 0 &&
        (m_k8s_communication_summary->clusters(0).egresses_size() > 0 ||
         m_k8s_communication_summary->clusters(0).ingresses_size() > 0))
    {
        return m_k8s_communication_summary;
    }

	if (!m_k8s_cluster_communication.has_data())
	{
		LOG_DEBUG("secure_netsec: no secure netsec messages generated");
		return nullptr;
	}
	return m_k8s_communication_summary;
}
