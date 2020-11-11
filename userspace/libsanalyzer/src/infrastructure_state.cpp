#define __STDC_FORMAT_MACROS

#include "user_event_logger.h"

#include <algorithm>
#include <cinttypes>
#ifndef CYGWING_AGENT
#include "analyzer.h"
#include "common_logger.h"
#include "configuration_manager.h"
#include "infrastructure_state.h"
#include "legacy_k8s_protobuf.h"
#include "user_event.h"
#include "utils.h"

#include "Poco/File.h"
#include "Poco/Path.h"

COMMON_LOGGER();

using namespace std;

#define DEFAULT_CONNECT_INTERVAL (60 * ONE_SECOND_IN_NS)

type_config<uint32_t> infrastructure_state::c_orchestrator_queue_len(
    10000,
    "set the number of events to queue in cointerface before we drop",
    "orch_queue_len");
type_config<int32_t> infrastructure_state::c_orchestrator_gc(10,
                                                             "GC percentage for cointerface",
                                                             "orch_gc");
type_config<uint32_t> infrastructure_state::c_orchestrator_informer_wait_time_s(
    5,
    "orchestrator informer wait time [sec]",
    "orch_inf_wait_time_s");
type_config<uint32_t> infrastructure_state::c_orchestrator_tick_interval_ms(
    100,
    "orchestrator tick interval (ms)",
    "orch_tick_interval_ms");
type_config<uint32_t> infrastructure_state::c_orchestrator_low_ticks_needed(
    10,
    "orchestrator events low ticks needed",
    "orch_low_ticks_needed");
type_config<uint32_t> infrastructure_state::c_orchestrator_low_event_threshold(
    50,
    "orchestrator events low threshold",
    "orch_low_evt_threshold");
type_config<bool> infrastructure_state::c_orchestrator_filter_empty(
    true,
    "orchestrator events filter empty resources",
    "orch_filter_empty");
type_config<uint32_t> infrastructure_state::c_orchestrator_batch_messages_queue_length(
    100,
    "size of batch queue before sending messages through the grpc pipe",
    "orch_batch_msgs_queue_len");
type_config<uint32_t> infrastructure_state::c_orchestrator_batch_messages_tick_interval_ms(
    100,
    "set interval before sending messages through grpc pipe",
    "orch_batch_msgs_tick_interval_ms");
type_config<bool> infrastructure_state::c_k8s_ssl_verify_certificate(
    false,
    "K8S certificate verification enabled",
    "k8s_ssl_verify_certificate");
type_config<std::string> infrastructure_state::c_k8s_bt_auth_token(
    "",
    "path to K8S bearer token authorization",
    "k8s_bt_auth_token");
type_config<std::vector<std::string>> infrastructure_state::c_k8s_include_types(
    {},
    "list of extra k8s types to resquest beyond the default",
    "k8s_extra_resources",
    "include");
type_config<std::vector<std::string>> infrastructure_state::c_k8s_pod_status_wl(
    {"Evicted", "DeadlineExceeded", "Error", "ContainerCreating", "CrashLoopBackOff", "Pending"},
    "list of aggregate pod status that can be sent to BE",
    "k8s_pod_status_reason_strings");
type_config<bool> infrastructure_state::c_k8s_terminated_pods_enabled(
    false,
    "Enable terminated pods handling",
    "k8s_terminated_pod_enabled");
type_config<uint32_t>
    infrastructure_state::c_k8s_event_counts_log_time(0, "", "k8s_event_counts_log_time");
type_config<std::string> infrastructure_state::c_k8s_url("", "URL of k8s api server", "k8s_uri");
type_config<std::string> infrastructure_state::c_k8s_ca_certificate("",
                                                                    "K8S CA certificate",
                                                                    "k8s_ca_certificate");
type_config<std::string> infrastructure_state::c_k8s_ssl_certificate("",
                                                                     "K8S certificate",
                                                                     "k8s_ssl_cert");
type_config<std::string> infrastructure_state::c_k8s_ssl_key("", "K8S SLL key", "k8s_ssl_key");
type_config<uint64_t> infrastructure_state::c_k8s_timeout_s(60,
                                                            "K8S reconnection interval [sec]",
                                                            "k8s_timeout_s");
type_config<std::string>::ptr infrastructure_state::c_k8s_ssl_key_password =
    type_config_builder<std::string>("", "K8S SSL key password", "k8s_ssl_key_password")
        .hidden()
        .build();
type_config<std::string> infrastructure_state::c_k8s_ssl_certificate_type("PEM",
                                                                          "K8S certificate type",
                                                                          "k8s_ssl_cert_type");
type_config<bool> infrastructure_state::c_k8s_autodetect(true,
                                                         "K8S autodetect enabled",
                                                         "k8s_autodetect");
type_config<uint64_t> infrastructure_state::c_k8s_refresh_interval(
    ONE_SECOND_IN_NS / 500,
    "cointerface queue processing interval (in ns)",
    "infra_state",
    "cointerface_refresh_interval");
type_config<uint32_t>::ptr infrastructure_state::c_k8s_max_rnd_conn_delay =
    type_config_builder<uint32_t>(
        0,
        "maximum random delay (in seconds) before connecting to K8s API server",
        "k8s_max_rnd_conn_delay")
        .min(0)
        .max(900)
        .build();
type_config<bool>::ptr infrastructure_state::c_thin_cointerface_enabled =
	type_config_builder<bool>(
		false,
		"Enable the Thin Cointerface feature (i.e. retryWatchers)",
		"thin_cointerface_enabled"
		).hidden()
	         .build();
type_config<uint64_t> infrastructure_state::c_congroup_ttl_s(60,
							     "Congroup TTL [sec]",
							     "congroup_ttl_s");

type_config<std::vector<std::string>> infrastructure_state::c_pod_prefix_for_cidr_retrieval(
    {"kube-apiserver", "kube-controller-manager"},
    "List of pod prefixes used to retrieve k8s cidr information",
    "network_topology",
    "pod_prefix_for_cidr_retrieval");


// We have seen clusters where object's ownerReferences were not standard k8s objects
// (e.g. Kafka to mention one). We must ensure that we are handling only types with any Watchers in cointerface.
// The risk is to fatten some internal structures with elements that won't be removed
type_config<std::vector<std::string>>::ptr infrastructure_state::c_k8s_allow_list_kinds =
	type_config_builder<std::vector<std::string>>(
		{"k8s_cronjob",
		 "k8s_daemonset",
		 "k8s_deployment",
		 "k8s_hpa",
		 "k8s_ingress",
		 "k8s_job",
		 "k8s_namespace",
		 "k8s_node",
		 "k8s_persistentvolume",
		 "k8s_persistentvolumeclaim",
		 "k8s_pod",
		 "k8s_replicaset",
		 "k8s_replicationcontroller",
		 "k8s_resourcequota",
		 "k8s_service",
		 "k8s_statefulset",
		 "container"},
		"List of k8s types that the agent will handle",
		"k8s_allow_list_kinds"
		).hidden()
	         .build();


namespace
{
const std::unordered_map<std::string, std::string> host_children{
    {"k8s_node", "kubernetes.node.name"}
    // other orchestrators nodes
};
}

std::string infrastructure_state::normalize_path(const std::string& path) const
{
	if (path.size() != 0 && path[0] != '/')
	{
		return Poco::Path(path).makeAbsolute(m_root_dir).toString();
	}

	return path;
}

void infrastructure_state::configure_k8s_environment()
{
	static const string k8s_ca_crt = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
	static const string k8s_bearer_token_file_name =
	    "/var/run/secrets/kubernetes.io/serviceaccount/token";
	if (m_k8s_url.empty())
	{
		// K8s API server not set by user, try to auto-discover.
		// This will work only when agent runs in a K8s pod.
		char* sh = getenv("KUBERNETES_SERVICE_HOST");
		if (sh && strlen(sh))
		{
			char* sp = getenv("KUBERNETES_SERVICE_PORT_HTTPS");
			if (sp && strlen(sp))  // secure
			{
				m_k8s_url = "https://";
				m_k8s_url.append(sh).append(1, ':').append(sp);
				if (m_k8s_bt_auth_token.empty())
				{
					if (Poco::File(k8s_bearer_token_file_name).exists())
					{
						m_k8s_bt_auth_token = k8s_bearer_token_file_name;
					}
					else
					{
						LOG_WARNING(
						    "Bearer token not found at default location (%s), authentication may "
						    "not work. If needed, please specify the location using "
						    "k8s_bt_auth_token config entry.",
						    k8s_bearer_token_file_name.c_str());
					}
				}
				if (c_k8s_ssl_verify_certificate.get_value() && m_k8s_ca_certificate.empty())
				{
					if (Poco::File(k8s_ca_crt).exists())
					{
						m_k8s_ca_certificate = k8s_ca_crt;
					}
					else
					{
						LOG_WARNING(
						    "CA certificate verification configured, but CA certificate not "
						    "specified nor found at default location (%s), server authentication "
						    "will not work. If server authentication is desired, please specify "
						    "the CA certificate file location using k8s_ca_certificate config "
						    "entry.",
						    k8s_ca_crt.c_str());
					}
				}
			}
			else
			{
				sp = getenv("KUBERNETES_SERVICE_PORT");
				if (sp && strlen(sp))
				{
					m_k8s_url = "http://";
					m_k8s_url.append(sh).append(1, ':').append(sp);
				}
			}
		}
	}
}

bool infrastructure_state::get_cached_result(const std::string& entity_id, size_t h, bool* res)
{
	auto cached_results = m_policy_cache.find(entity_id);
	if (cached_results != m_policy_cache.end())
	{
		auto cached_result = cached_results->second.find(h);
		if (cached_result != cached_results->second.end())
		{
			*res = cached_result->second;
			return true;
		}
	}

	return false;
}

void infrastructure_state::insert_cached_result(const std::string& entity_id, size_t h, bool res)
{
	if (m_policy_cache.find(entity_id) == m_policy_cache.end())
	{
		m_policy_cache.emplace(entity_id, std::unordered_map<size_t, bool>());
	}

	m_policy_cache[entity_id].emplace(h, res);
}

void infrastructure_state::clear_cached_result(const std::string& entity_id)
{
	m_policy_cache.erase(entity_id);
}

bool evaluate_on(draiosproto::container_group* congroup, scope_predicates& preds)
{
	auto evaluate = [](const draiosproto::scope_predicate& p, const std::string& value) {
		// KISS for now
		LOG_DEBUG(
		    "infra_state: Evaluating %s %s %s%s with value %s",
		    p.key().c_str(),
		    draiosproto::scope_operator_Name(p.op()).c_str(),
		    p.values(0).c_str(),
		    ((p.op() == draiosproto::IN_SET || p.op() == draiosproto::NOT_IN_SET) ? "..." : ""),
		    value.c_str());
		bool ret;
		switch (p.op())
		{
		case draiosproto::EQ:
			ret = p.values(0) == value;
			break;
		case draiosproto::NOT_EQ:
			ret = p.values(0) != value;
			break;
		case draiosproto::CONTAINS:
			ret = value.find(p.values(0)) != std::string::npos;
			break;
		case draiosproto::NOT_CONTAINS:
			ret = value.find(p.values(0)) == std::string::npos;
			break;
		case draiosproto::STARTS_WITH:
			ret = value.substr(0, p.values(0).size()) == p.values(0);
			break;
		case draiosproto::IN_SET:
			ret = false;
			for (auto v : p.values())
			{
				if (v == value)
				{
					ret = true;
					break;
				}
			}
			break;
		case draiosproto::NOT_IN_SET:
			ret = true;
			for (auto v : p.values())
			{
				if (v == value)
				{
					ret = false;
					break;
				}
			}
			break;
		default:
			LOG_WARNING("infra_state: Cannot evaluate scope_predicate %s",
			            p.DebugString().c_str());
			ret = true;
		}

		return ret;
	};

	for (auto i = preds.begin(); i != preds.end();)
	{
		if (congroup->tags().find(i->key()) != congroup->tags().end())
		{
			if (!evaluate(*i, congroup->tags().at(i->key())))
			{
				preds.erase(i);
				return false;
			}
			else
			{
				i = preds.erase(i);
			}
		}
		else if (congroup->internal_tags().find(i->key()) != congroup->internal_tags().end())
		{
			if (!evaluate(*i, congroup->internal_tags().at(i->key())))
			{
				preds.erase(i);
				return false;
			}
			else
			{
				i = preds.erase(i);
			}
		}
		else
		{
			++i;
		}
	}

	return true;
}

infrastructure_state::infrastructure_state(sinsp_analyzer& analyzer,
                                           sinsp* inspector,
                                           const std::string& rootdir,
                                           const k8s_limits::sptr_t& the_k8s_limits,
                                           bool force_k8s_subscribed):
      m_k8s_store_manager(std::move(k8s_store_manager_builder<k8s_pod_store, k8s_hpa_store>(c_thin_cointerface_enabled->get_value()).build())),
      m_analyzer(analyzer),
      m_inspector(inspector),
      m_ts(0),
      m_k8s_subscribed(force_k8s_subscribed),
      m_k8s_connected(false),
      m_k8s_limits(the_k8s_limits),
      m_k8s_refresh_interval(c_k8s_refresh_interval.get_value()),
      m_k8s_connect_interval(DEFAULT_CONNECT_INTERVAL),
      m_delayed_removal_interval(c_congroup_ttl_s.get_value() * ONE_SECOND_IN_NS),
      m_k8s_prev_connect_state(-1),
      m_k8s_node_actual(false),
      m_root_dir(rootdir),
      m_k8s_url(c_k8s_url.get_value()),
      m_k8s_bt_auth_token(normalize_path(c_k8s_bt_auth_token.get_value())),
      m_k8s_ca_certificate(normalize_path(c_k8s_ca_certificate.get_value())),
      m_k8s_ssl_certificate(normalize_path(c_k8s_ssl_certificate.get_value())),
      m_k8s_ssl_key(normalize_path(c_k8s_ssl_key.get_value())),
      m_k8s_cluster_name(std::string())
{
	if (c_k8s_autodetect.get_value())
	{
		configure_k8s_environment();
	}

	m_k8s_callback = [this](bool successful, google::protobuf::Message* response_msg) {
		k8s_generate_user_event(successful);

		if (successful)
		{
			auto evtq = dynamic_cast<sdc_internal::array_congroup_update_event*>(response_msg);

			for (int i = 0; i < evtq->events_size(); i++)
			{
				draiosproto::congroup_update_event* evt = evtq->mutable_events(i);
				handle_event(evt);
			}
		}
		else
		{
			//
			// Error from cointerface, destroy the whole state and subscribe again
			//
			LOG_WARNING(
			    "infra_state: Error while receiving k8s orchestrator events. Reset and retry.");
			m_k8s_connected = false;
			reset();
		}
	};
	m_inspector->m_container_manager.subscribe_on_new_container(
	    [this](const sinsp_container_info& container_info, sinsp_threadinfo* tinfo) {
		    on_new_container(container_info, tinfo);
	    });
	m_inspector->m_container_manager.subscribe_on_remove_container(
	    [this](const sinsp_container_info& container_info) {
		    on_remove_container(container_info);
	    });

	if(c_thin_cointerface_enabled->get_value() == true)
	{
		m_handle_update_event = [this](const draiosproto::congroup_update_event* evt)
				      {
					      handle_update_event_thin_cointerface(evt);
				      };
	}
	else
	{
		m_handle_update_event = [this](const draiosproto::congroup_update_event* evt)
				      {
					      handle_update_event_no_thin_cointerface(evt);
				      };
	}

	for(const auto& kind : c_k8s_allow_list_kinds->get_value())
	{
		m_allow_list_kinds.insert(kind);
	}
}

infrastructure_state::~infrastructure_state() {}

void infrastructure_state::init(const std::string& machine_id, const std::string& host_tags)
{
	m_machine_id = machine_id;

	// Add information about this agent by creating an
	// orchestrator_events message and pushing it onto the queue.
	draiosproto::orchestrator_events evts;
	draiosproto::congroup_update_event* evt = evts.add_events();
	draiosproto::container_group* obj = evt->mutable_object();
	draiosproto::congroup_uid* uid = obj->mutable_uid();

	evt->set_type(draiosproto::ADDED);
	uid->set_kind("host");
	uid->set_id(machine_id);

	(*obj->mutable_tags())[string("host.hostName")] = sinsp_gethostname();
	(*obj->mutable_tags())[string("host.mac")] = machine_id;

	const string &k8s_cluster_name = get_k8s_cluster_name();
	if (!k8s_cluster_name.empty())
	{
		(*obj->mutable_tags())[string("kubernetes.cluster.name")] = k8s_cluster_name;
	}

	std::vector<std::string> tags = sinsp_split(host_tags, ',');

	std::string tag_prefix = "agent.tag.";

	for (auto& pair : tags)
	{
		std::vector<std::string> parts = sinsp_split(pair, ':');

		if (parts.size() == 2)
		{
			(*obj->mutable_tags())[tag_prefix + parts[0]] = parts[1];
		}
		else
		{
			LOG_ERROR("infra_state: Could not split agent tag %s into key/value", pair.c_str());
		}
	}

	LOG_DEBUG("Adding local host information: %s", evts.DebugString().c_str());

	receive_hosts_metadata(evts.events());
}

bool infrastructure_state::inited()
{
	return m_inspector != nullptr;
}

std::string infrastructure_state::as_string(const scope_predicates& predicates)
{
	std::string preds_str;
	for (int i = 0; i < predicates.size(); i++)
	{
		if (i > 0)
		{
			preds_str += " ";
		}
		preds_str += predicates[i].ShortDebugString();
	}

	return preds_str;
}

void infrastructure_state::subscribe_to_k8s()
{
	ASSERT(!m_k8s_connected);

	LOG_INFO(
	    "infra_state: Subscribe to k8s orchestrator events, api server: %s, reconnect interval: "
	    "%ld sec",
	    m_k8s_url.c_str(),
	    c_k8s_timeout_s.get_value());
	m_k8s_connect_interval.interval(c_k8s_timeout_s.get_value() * ONE_SECOND_IN_NS);

	connect_to_k8s();
}

void infrastructure_state::connect_to_k8s(uint64_t ts)
{
	// Make sure we only have one RPC active
	if (m_k8s_connected)
	{
		LOG_DEBUG("infra_state: Ignoring k8s connection attempt because an RPC is already active");
		return;
	}

	m_k8s_connect_interval.run(
	    [this]() {
		    LOG_INFO("infra_state: Connect to k8s orchestrator events.");
		    sdc_internal::orchestrator_events_stream_command cmd;
		    cmd.set_url(m_k8s_url);
		    cmd.set_ca_cert(m_k8s_ca_certificate);
		    cmd.set_client_cert(m_k8s_ssl_certificate);
		    cmd.set_client_key(m_k8s_ssl_key);
		    cmd.set_queue_len(c_orchestrator_queue_len.get_value());
		    cmd.set_startup_gc(c_orchestrator_gc.get_value());
		    cmd.set_startup_inf_wait_time_s(c_orchestrator_informer_wait_time_s.get_value());
		    cmd.set_startup_tick_interval_ms(c_orchestrator_tick_interval_ms.get_value());
		    cmd.set_startup_low_ticks_needed(c_orchestrator_low_ticks_needed.get_value());
		    cmd.set_startup_low_evt_threshold(c_orchestrator_low_event_threshold.get_value());
		    cmd.set_filter_empty(c_orchestrator_filter_empty.get_value());
		    cmd.set_batch_msgs_queue_len(c_orchestrator_batch_messages_queue_length.get_value());
		    cmd.set_batch_msgs_tick_interval_ms(
		        c_orchestrator_batch_messages_tick_interval_ms.get_value());
		    cmd.set_ssl_verify_certificate(c_k8s_ssl_verify_certificate.get_value());
		    cmd.set_auth_token(m_k8s_bt_auth_token);
		    for (const auto& annot : m_annotation_filter)
		    {
			    cmd.add_annotation_filter(annot);
		    }

		    *cmd.mutable_include_types() = {c_k8s_include_types.get_value().begin(),
		                                    c_k8s_include_types.get_value().end()};
		    cmd.set_event_counts_log_time(c_k8s_event_counts_log_time.get_value());
		    cmd.set_max_rnd_conn_delay(c_k8s_max_rnd_conn_delay->get_value());
		    *cmd.mutable_pod_status_allowlist() = {c_k8s_pod_status_wl.get_value().begin(),
		                                           c_k8s_pod_status_wl.get_value().end()};
		    cmd.set_terminated_pods_enabled(c_k8s_terminated_pods_enabled.get_value());
		    cmd.set_thin_cointerface(c_thin_cointerface_enabled->get_value());

		    for (const auto& prefix : c_pod_prefix_for_cidr_retrieval.get_value())
		    {
			    cmd.add_pod_prefix_for_cidr_retrieval(prefix);
		    }

		    m_k8s_subscribed = true;
		    m_k8s_connected = true;
		    m_k8s_coclient.reset(new coclient(m_root_dir));
		    m_k8s_coclient->get_orchestrator_events(cmd, m_k8s_callback);
	    },
	    ts);
}

// Currently there's just the one event, k8s server connectivity state
void infrastructure_state::k8s_generate_user_event(const bool success)
{
	if (m_k8s_prev_connect_state == -1)
	{
		// Connect state is uninitialized
		m_k8s_prev_connect_state = success;
	}
	else if (m_k8s_prev_connect_state != success)
	{
		m_k8s_prev_connect_state = success;
	}
	else
	{
		// Connection state hasn't changed, so don't do anything
		return;
	}

	time_t now = sinsp_utils::get_current_time_ns() / ONE_SECOND_IN_NS;

	sinsp_user_event::tag_map_t event_tags;
	// The source tag used here is the same as that for k8s events.
	event_tags["source"] = "kubernetes";
	if (!m_k8s_url.empty())
	{
		event_tags["url"] = m_k8s_url;
	}

	// Gather config info to be included in the event description.
	string config_info;
	if (!m_k8s_ca_certificate.empty())
	{
		config_info += ", k8s_ca_cert: " + m_k8s_ca_certificate;
	}
	if (!m_k8s_ssl_certificate.empty())
	{
		config_info += ", k8s_client_cert: " + m_k8s_ssl_certificate;
	}
	if (!m_k8s_ssl_key.empty())
	{
		config_info += ", k8s_client_key: " + m_k8s_ssl_key;
	}

	event_scope scope;
	string host;
	if (inited())
	{
		if (!m_k8s_node.empty())
		{
			scope.add("kubernetes.node.name", m_k8s_node);
		}
		else
		{
			host = m_inspector->get_machine_info()->hostname;
			if (!host.empty())
			{
				scope.add("kubernetes.node.name", host);
			}
			else if (!m_machine_id.empty())
			{
				host = m_machine_id;
				scope.add("host.mac", host);
			}
		}

		string k8s_cluster_name = get_k8s_cluster_name();
		if (!k8s_cluster_name.empty())
		{
			scope.add("kubernetes.cluster.name", k8s_cluster_name);
		}

		string k8s_cluster_id = get_k8s_cluster_id();
		if (!k8s_cluster_id.empty())
		{
			scope.add("kubernetes.cluster.id", k8s_cluster_id);
		}
	}

	string event_name = "Infra Connectivity", event_desc;
	user_event_logger::severity event_sev;
	if (success)
	{
		event_sev = user_event_logger::SEV_EVT_INFORMATION;
		event_desc = "Status: OK";
	}
	else
	{
		// Most k8s events are INFO, so leaving this at NOTICE for now.
		event_sev = user_event_logger::SEV_EVT_NOTICE;
		event_desc = "Status: Error, check agent logs";
		if (!host.empty())
		{
			event_desc += " for host '" + host + "'";
		}
		uint64_t conn_intv = m_k8s_connect_interval.interval() / ONE_SECOND_IN_NS;
		config_info += ", reconnect interval: " + to_string(conn_intv) + "s";
	}
	if (!config_info.empty())
	{
		event_desc += " (" + config_info + ")";
	}

	auto evt = sinsp_user_event(now,
	                            std::move(event_name),
	                            std::move(event_desc),
	                            std::move(scope.get_ref()),
	                            std::move(event_tags),
	                            event_sev);

	LOG_DEBUG("Logging user event: " + evt.to_string());
	user_event_logger::log(evt, event_sev);
}

bool infrastructure_state::subscribed()
{
	return m_k8s_subscribed;  // || m_mesos_subscribed || ...
}

void infrastructure_state::refresh(uint64_t ts)
{
	m_ts = ts;
	if (m_k8s_connected)
	{
		ASSERT(m_k8s_subscribed);
		m_k8s_refresh_interval.run([this]() { m_k8s_coclient->process_queue(); }, ts);
	}
	else if (m_k8s_subscribed)
	{
		connect_to_k8s(ts);
	}

	// if (m_mesos_subscribed) { ... }

	// Check if it's time to handle delayed removals
	m_delayed_removal_interval.run(
	    [this]() {
		    if (!m_cg_ttl.empty())
		    {
			    for (auto i = m_cg_ttl.begin(); i != m_cg_ttl.end();)
			    {
				    uid_t key = i->first;
				    uint64_t ttl = i->second;
				    if (m_ts > ttl)
				    {
					    LOG_DEBUG("infra_state: Delayed removal of container_group <%s,%s>",
					              key.first.c_str(),
					              key.second.c_str());
					    remove(key);
					    i = m_cg_ttl.erase(i);
				    }
				    else
				    {
					    LOG_DEBUG(
					        "infra_state: Delayed removal of container_group <%s,%s> will happen "
					        "in %.3f secs",
					        key.first.c_str(),
					        key.second.c_str(),
					        (float)(ttl - m_ts) / ONE_SECOND_IN_NS);
					    ++i;
				    }
			    }
		    }
	    },
	    ts);

	//
	// Calling empty before locking to avoid useless overhead
	//
	if (!m_host_events_queue.empty() && m_host_events_queue_mutex.try_lock())
	{
		LOG_DEBUG(
		    "infra_state: Hosts metadata available and lock aquired. Start refresh operation of "
		    "%ld hosts.",
		    m_host_events_queue.size());
		refresh_hosts_metadata();
		m_host_events_queue_mutex.unlock();
		LOG_DEBUG("infra_state: Refresh of hosts metadata completed and lock unlocked.");
	}
}

void infrastructure_state::reset()
{
	LOG_DEBUG("infra_state (%p): reset()", this);

	std::unique_lock<std::mutex> scoped_lock(m_host_events_queue_mutex, std::try_to_lock);

	if (scoped_lock.owns_lock())
	{
		LOG_DEBUG("infra_state: Hosts metadata available and lock aquired. Start reset operation.");

		m_policy_cache.clear();
		m_orphans.clear();
		m_cg_ttl.clear();
		m_cg_by_addr.clear();
		m_state.clear();
		m_k8s_namespace_store.clear();
		m_k8s_store_manager.clear();
		m_k8s_cached_cluster_id.clear();
		m_k8s_node.clear();
		m_k8s_node_uid.clear();
		m_k8s_node_actual = false;
		m_registered_scopes.clear();
		m_rate_metric_state.clear();

		if (m_k8s_subscribed)
		{
			connect_to_k8s();
		}

		LOG_DEBUG("infra_state: Reset of hosts metadata completed and lock unlocked.");
	}
	else
	{
		LOG_ERROR("infra_state: Could not acquire lock, skipping reset");
	}
}

void infrastructure_state::load_single_event(const draiosproto::congroup_update_event& evt,
                                             bool overwrite)
{
	handle_event(&evt, overwrite);
}

unsigned int infrastructure_state::size()
{
	return m_state.size();
}

bool infrastructure_state::has(uid_t uid) const
{
	return m_state.find(uid) != m_state.end();
}

std::unique_ptr<draiosproto::container_group> infrastructure_state::get(uid_t uid)
{
	if (!has(uid))
	{
		return nullptr;
	}

	auto res = make_unique<draiosproto::container_group>();
	res->CopyFrom(*m_state[uid]);

	return res;
}

bool infrastructure_state::add(uid_t key)
{
	if (has(key))
		return false;

	m_state[key] = make_unique<draiosproto::container_group>();
	m_state[key]->mutable_uid()->set_kind(key.first);
	m_state[key]->mutable_uid()->set_id(key.second);

	return true;
}

bool infrastructure_state::find_tag(const uid_t& uid,
                                    const string& tag,
                                    string& value,
                                    std::unordered_set<uid_t>& visited) const
{
	if (!has(uid) || (visited.find(uid) != visited.end()))
	{
		return false;
	}
	visited.emplace(uid);

	auto* cg = m_state.find(uid)->second.get();

	if (!cg)
	{  // Shouldn't happen
		return false;
	}
	if (cg->tags().find(tag) != cg->tags().end())
	{
		value = cg->tags().at(tag);
		return true;
	}
	if (cg->internal_tags().find(tag) != cg->internal_tags().end())
	{
		value = cg->internal_tags().at(tag);
		return true;
	}

	for (const auto& p_uid : cg->parents())
	{
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		if (find_tag(pkey, tag, value, visited))
		{
			return true;
		}
	}

	return false;
}

int infrastructure_state::get_tags(uid_t uid, std::unordered_map<string, string>& tags_map) const
{
	int ret = 0;

	if (!has(uid))
	{
		return ret;
	}

	auto* cg = m_state.find(uid)->second.get();

	if (!cg)
	{  // Shouldn't happen
		return ret;
	}

	// Look for object name tags and add them to tags_map
	for (const auto& tag : cg->tags())
	{
		tags_map[tag.first] = tag.second;
		ret++;
	}

	return ret;
}

int infrastructure_state::find_tag_list(uid_t uid,
                                        std::unordered_set<string>& tags_set,
                                        std::unordered_map<string, string>& labels,
                                        std::unordered_set<uid_t>& visited) const
{
	int ret = 0;

	if (!has(uid) || (visited.find(uid) != visited.end()))
	{
		return ret;
	}
	visited.emplace(uid);

	auto* cg = m_state.find(uid)->second.get();

	if (!cg)
	{  // Shouldn't happen
		return ret;
	}
	// Look for object name tags and add them to the scope
	for (const auto& tag : cg->tags())
	{
		if (tags_set.find(tag.first) != tags_set.end())  // match_name(tag.first))
		{
			labels[tag.first] = tag.second;
			ret++;
		}
	}

	for (const auto& p_uid : cg->parents())
	{
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		ret += find_tag_list(pkey, tags_set, labels, visited);
	}

	return ret;
}

bool infrastructure_state::is_mesos_label(const std::string& lbl)
{
	static const std::string mesos = "mesos";
	static const std::string marathon = "marathon";

	return !lbl.compare(0, mesos.size(), mesos) || !lbl.compare(0, marathon.size(), marathon);
}

void infrastructure_state::get_orch_labels(
    const uid_t uid,
    google::protobuf::RepeatedPtrField<draiosproto::container_label>* labels,
    std::unordered_set<uid_t>* visited)
{
	if (!visited)
	{
		std::unordered_set<uid_t> newvis;
		get_orch_labels(uid, labels, &newvis);
		return;
	}
	if (!has(uid) || (visited->find(uid) != visited->end()))
	{
		return;
	}
	visited->emplace(uid);

	auto* cg = m_state[uid].get();

	if (!cg)
	{  // Shouldn't happen
		return;
	}
	for (const auto& tag : cg->internal_tags())
	{
		if (is_mesos_label(tag.first))
		{
			auto lbl = labels->Add();
			lbl->set_key(tag.first);
			lbl->set_value(tag.second);
		}
	}
}

static std::string pathtotaskname(const std::string path)
{
	std::string ret;

	size_t last = 0, i = 0;
	while ((i = path.find('/', last)) != string::npos)
	{
		if ((i - last) > 0)
		{
			ret = path.substr(last, i - last) + (ret.empty() ? "" : ("." + ret));
		}
		last = i + 1;
	}
	if (last < path.size())
	{
		ret = path.substr(last, path.size() - last) + (ret.empty() ? "" : ("." + ret));
	}

	return ret;
}

void infrastructure_state::scrape_mesos_env(const sinsp_container_info& container,
                                            sinsp_threadinfo* tinfo)
{
	static const std::string mesos_framework_name = "SYSDIG_MESOS_FRAMEWORK_NAME";
	static const std::string mar_app_id = "MARATHON_APP_ID";
	static const std::string mar_app_labels = "MARATHON_APP_LABELS";
	static const std::string mar_app_label = "MARATHON_APP_LABEL_";
	static const vector<std::string> mes_task_ids = {"MESOS_TASK_ID",
	                                                 "mesos_task_id",
	                                                 "MESOS_EXECUTOR_ID"};

	if (!tinfo || container.m_id.empty())
	{
		LOG_DEBUG("scrape_mesos: Missing thread or container id");
		return;
	}

	// Try container environment first (currently only available for docker)
	const vector<string>& env =
	    container.get_env().empty() ? tinfo->get_env() : container.get_env();

	// For now only scrape if we find "MARATHON_APP_ID" in env
	string app_id;
	if (!sinsp_utils::find_env(app_id, env, mar_app_id) || app_id.empty())
	{
		LOG_DEBUG("scrape_mesos: Container %s: no MARATHON_APP_ID found", container.m_id.c_str());
		return;
	}

	string mesostaskname = pathtotaskname(app_id);

	auto idx = app_id.find_last_of("/");
	string appname =
	    ((idx != string::npos) && (idx < app_id.size() - 1)) ? app_id.substr(idx + 1) : app_id;
	string groupname = (idx == string::npos) ? "/" : app_id.substr(0, idx ? idx : idx + 1);

	uid_t ckey = make_pair("container", container.m_id);
	add(ckey);

	string fwork_name;
	if (!sinsp_utils::find_env(fwork_name, env, mesos_framework_name) || fwork_name.empty())
	{
		fwork_name = "marathon";
	}

	(*m_state[ckey]->mutable_internal_tags())["mesos.framework.name"] = fwork_name;
	if (!groupname.empty())
		(*m_state[ckey]->mutable_internal_tags())["marathon.group.name"] = groupname;
	if (!appname.empty())
		(*m_state[ckey]->mutable_internal_tags())["marathon.app.name"] = appname;
	if (!mesostaskname.empty())
		(*m_state[ckey]->mutable_internal_tags())["mesos.task.name"] = mesostaskname;

	string taskid;
	if (sinsp_utils::find_first_env(taskid, env, mes_task_ids) && !taskid.empty())
	{
		(*m_state[ckey]->mutable_internal_tags())["mesos.task.id"] = taskid;
	}

	LOG_DEBUG("scrape_mesos: Container %s: found app_id %s:%s, mesos taskname: %s, taskid: %s",
	          container.m_id.c_str(),
	          groupname.c_str(),
	          appname.c_str(),
	          mesostaskname.c_str(),
	          taskid.c_str());

	// Adding labels as tags
	for (const string& enstr : env)
	{
		size_t eq;
		if ((enstr.size() > mar_app_label.size()) &&
		    !enstr.compare(0, mar_app_label.size(), mar_app_label) &&
		    ((eq = enstr.find('=', mar_app_label.size())) != string::npos) &&
		    (eq > mar_app_label.size()))
		{
			string label = enstr.substr(mar_app_label.size(), eq - mar_app_label.size());
			std::transform(label.begin(), label.end(), label.begin(), ::tolower);
			string marlabel = "marathon.app.label." + label;
			string meslabel = "mesos.task.label." + label;
			string value = enstr.substr(eq + 1);
			if (!label.empty() && !value.empty())
			{
				auto* tagmap = m_state[ckey]->mutable_internal_tags();
				(*tagmap)[marlabel] = value;
				(*tagmap)[meslabel] = value;
			}
		}
	}
}

void infrastructure_state::handle_cluster_cidr(const draiosproto::container_group& cg)
{
	// Check for Cluster/Service CIDR. Cointerface tries to fetch
	// the values from the command of the kube-apiserver and
	// kube-controller-manager (actual prefix container names can
	// be configured, as they may vary across distribution), and
	// if a value is found, it is stored it in the internal tags
	// of a container group of type k8s_cluster_cidr.
	if (!is_k8s_cidr_discovered())
	{
		auto con_inttags = cg.internal_tags();

		auto inttag_iter = con_inttags.find("kubernetes.cluster_cidr");
		if (inttag_iter != con_inttags.end())
		{
			m_command_k8s_cluster_cidr = inttag_iter->second;
			LOG_DEBUG("infra_state: discovered cluster_cidr (%s)",
				  m_command_k8s_cluster_cidr.c_str());
		}
		inttag_iter = con_inttags.find("kubernetes.service_cidr");
		if (inttag_iter != con_inttags.end())
		{
			m_command_k8s_service_cidr = inttag_iter->second;
			LOG_DEBUG("infra_state: discovered service_cidr (%s)",
				  m_command_k8s_service_cidr.c_str());
		}
	}
}

void infrastructure_state::handle_event(const draiosproto::congroup_update_event* evt,
                                        bool overwrite)
{
	std::string kind = evt->object().uid().kind();
	std::string id = evt->object().uid().id();

	LOG_DEBUG("infra_state: Handling %s event with uid <%s,%s>",
	          draiosproto::congroup_event_type_Name(evt->type()).c_str(),
	          kind.c_str(),
	          id.c_str());
	auto key = make_pair(kind, id);

	if (evt->object().uid().kind() == "k8s_cluster_cidr")
	{
		handle_cluster_cidr(evt->object());
		return;
	}

	m_k8s_namespace_store.handle_event(*evt);

	if (!has(key))
	{
		switch (evt->type())
		{
		case draiosproto::ADDED:
			add(key, evt->object());

			// Connect group with its namespace
			connect_to_namespace(key);
			m_k8s_store_manager.handle_add(key, m_state);

			if(kind == k8s_namespace_store::KIND_NAMESPACE)
			{
				connect_orphans();
			}

			connect(key);
			print_obj(key);
			break;
		case draiosproto::REMOVED:
			// allow double delete (example: remove a container for an already terminated k8s_job)
			LOG_DEBUG(
			    "infra_state: Ignoring request to delete non-existent container group <%s,%s>",
			    kind.c_str(),
			    id.c_str());
			break;
		case draiosproto::UPDATED:
			LOG_WARNING(
			    "infra_state: Ignoring request to update container_group <%s,%s> because it does "
			    "not exists.",
			    kind.c_str(),
			    id.c_str());
			break;
		}
	}
	else
	{
		switch (evt->type())
		{
		case draiosproto::ADDED:
			if (!overwrite)
			{
				if (kind != "container")
				{
					LOG_WARNING(
					    "infra_state: Cannot add container_group <%s,%s> because it's already "
					    "present.",
					    kind.c_str(),
					    id.c_str());
				}
				break;
			}
			LOG_DEBUG("infra_state: Overwrite container group <%s,%s>", kind.c_str(), id.c_str());

			add(key, evt->object());
			print_obj(key);
			break;
		case draiosproto::REMOVED:
			print_obj(key);
			m_k8s_store_manager.handle_delete(key, m_state);

			m_cg_ttl[key] = m_ts + (c_congroup_ttl_s.get_value() * ONE_SECOND_IN_NS);
			LOG_DEBUG("infra_state: container_group <%s,%s> marked for removal.", kind.c_str(), id.c_str());

			// Key removal is done only after the TTL has expired.
			break;
		case draiosproto::UPDATED:
			m_handle_update_event(evt);
			print_obj(key);
			break;
		}
	}

	LOG_DEBUG("infra_state: %s event with uid <%s,%s> handled. Current state size: %ld",
	          draiosproto::congroup_event_type_Name(evt->type()).c_str(),
	          kind.c_str(),
	          id.c_str(),
	          m_state.size());
	print_state();
}

bool infrastructure_state::has_link(
    const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& links,
    const uid_t& uid)
{
	for (const auto& l : links)
	{
		if (l.kind() == uid.first && l.id() == uid.second)
		{
			return true;
		}
	}

	return false;
}

// We're adding two things to m_parents[current_object]:
// - the parent we're looking at
// - its m_parents
// We're recursing parent->child in here, so m_parents contains all the parents
// recursively to the top of the hierarchy. For example, say we have a deployment owned by a
// namespace:
//
// m_parents[deployment].clear()
// m_parents[deployment] += namespace
// m_parents[deployment] += m_parents[namespace] (i.e. empty)
// recurse to children of the deployment (i.e. a replicaset)
// m_parents[replicaset].clear()
// m_parents[replicaset] += deployment
// m_parents[replicaset] += m_parents[deployment] (i.e. namespace)
// recurse to children of the replicaset (i.e. a bunch of pods) and for each pod:
// m_parents[pod].clear()
// m_parents[pod] += replicaset
// m_parents[pod] += m_parents[replicaset] (i.e. deployment + namespace)
//
// so in the end:
// m_parents[namespace] = {}
// m_parents[deployment] = {namespace}
// m_parents[replicaset] = {namespace, deployment}
// m_parents[pod] = {namespace, deployment, replicaset}
void infrastructure_state::update_parent_child_links(const uid_t& uid)
{
	const auto congroup_iter = m_state.find(uid);
	if (congroup_iter == m_state.end())
	{
		return;
	}

	auto& parents = m_parents[uid];
	parents.clear();
	const auto& congroup = congroup_iter->second;
	for (const auto& parent : congroup->parents())
	{
		auto pos = parents.emplace(parent.kind(), parent.id());
		parents.insert(m_parents[*pos.first].begin(), m_parents[*pos.first].end());
	}

	for (const auto& child : congroup->children())
	{
		update_parent_child_links(std::make_pair(child.kind(), child.id()));
	}
}

void infrastructure_state::connect_to_namespace(const infrastructure_state::uid_t& key)
{
	ASSERT(m_state[key] != nullptr);

	draiosproto::container_group& cg = *m_state[key].get();
	if (k8s_namespace_store::object_kind_is_namespaced(key.first))
	{
		LOG_DEBUG("Entered connect_to_namespace <%s,%s>", key.first.c_str(), key.second.c_str());

		auto ns_name = cg.namespace_();

		// If we already have a complete namespace, connect this object to it.
		// Otherwise we had already added this object as orphan to the incomplete namespace, and
		// then nothing has to be done here.
		if (!ns_name.empty() && m_k8s_namespace_store.seen_namespace_object(ns_name))
		{
			m_k8s_namespace_store.add_child_to_namespace(ns_name, key.second);
			// Get the namespace name
			std::string ns_uid = m_k8s_namespace_store.lookup_ns_by_object_uid(key.second);
			ASSERT(!ns_uid.empty());
			LOG_DEBUG("infra_state connecting <%s,%s> to namespace %s",
			          key.first.c_str(),
			          key.second.c_str(),
			          ns_name.c_str());
			draiosproto::congroup_uid* parent_uid = m_state[key]->mutable_parents()->Add();
			parent_uid->set_kind("k8s_namespace");
			parent_uid->set_id(ns_uid);
			// The reverse link will be done later in connect
		}
	}
}

void infrastructure_state::connect_orphans()
{
	// look for namespaces with orphans ready for linking(e.g. namespace ADD event arrived)
	for (const auto& el : m_k8s_namespace_store.get_all_orphans_of_complete_namespaces())
	{
		const std::string& ns_name = el.first.first;
		const std::string& ns_uid = el.first.second;
		const std::vector<uid_t>& orphan_vec = el.second;

		auto father_pos = m_state.find(std::make_pair("k8s_namespace", ns_uid));
		ASSERT(father_pos != m_state.end());
		draiosproto::container_group& father = *father_pos->second.get();

		for (const auto& orphan_id : orphan_vec)
		{
			ASSERT(has(orphan_id));
			draiosproto::congroup_uid* parent = m_state[orphan_id]->mutable_parents()->Add();
			parent->set_kind("k8s_namespace");
			parent->set_id(ns_uid);
			LOG_DEBUG("infra_state add parent namespace %s to <%s,%s>",
			          ns_name.c_str(),
			          orphan_id.first.c_str(),
			          orphan_id.second.c_str());

			draiosproto::congroup_uid* child = father.mutable_children()->Add();
			child->set_kind(orphan_id.first);
			child->set_id(orphan_id.second);
			                LOG_DEBUG("infra_state add child <%s,%s> to <k8s_namespace,%s>",
			                child->kind().c_str(),
			                child->id().c_str(),
			                ns_name.c_str());
			m_k8s_namespace_store.add_child_to_namespace(ns_name, orphan_id.second);
		}
		m_k8s_namespace_store.clear_namespace_orphans(ns_name);
	}
}

void infrastructure_state::add_ip_mappings(std::shared_ptr<draiosproto::container_group> cg)
{
	if (feature_manager::instance().get_enabled(NETWORK_TOPOLOGY))
	{
		if (cg->uid().kind() == "k8s_endpoints" ||
		    cg->uid().kind() == "k8s_namespace" ||
		    cg->uid().kind() == "k8s_service")
		{
			m_analyzer.add_cg_to_network_topology(cg);
		}
	}

	// Only handle ip mappings for nodes, pods, services and
	// endpoints
	if (cg->uid().kind() == "k8s_pod" ||
	    cg->uid().kind() == "k8s_service" ||
	    cg->uid().kind() == "k8s_endpoints" ||
	    cg->uid().kind() == "k8s_node" ||
	    cg->uid().kind() == "node")
	{
		for (auto i = cg->ip_addresses().begin(), i_end = cg->ip_addresses().end(); i != i_end; ++i)
		{
			if (cg->uid().kind() != "host" && cg->uid().kind() != "k8s_node")
			{
				// check if one of the cgs removed by the orchestrator was the previous owner of this address
				for (auto &r_cg_info : m_cg_ttl)
				{
					uid_t key = r_cg_info.first;
					bool removed = false;
					for (auto j = m_state[key]->ip_addresses().begin(), j_end = m_state[key]->ip_addresses().end(); j != j_end; ++j) {
						if (*i == *j) {
							LOG_DEBUG("infra_state: Remove container_group <%s,%s> before TTL expiration since one of its IP addresses (%s) have been reassigned",
								  key.first.c_str(), key.second.c_str(), i->c_str());
							remove(key);
							m_cg_ttl.erase(key);
							removed = true;
							break;
						}
					}
					if (removed)
					{
						break;
					}
				}
			}

			if (m_cg_by_addr.find(*i) == m_cg_by_addr.end())
				m_cg_by_addr[*i] = std::unordered_set<std::shared_ptr<draiosproto::container_group>>();
			m_cg_by_addr[*i].emplace(cg);
		}
	}
}

void infrastructure_state::remove_ip_mappings(std::shared_ptr<draiosproto::container_group> cg)
{
	// Only handle ip mappings for nodes, pods, services and
	// endpoints
	if (cg->uid().kind() != "node" &&
	    cg->uid().kind() != "k8s_node" &&
	    cg->uid().kind() != "k8s_pod" &&
	    cg->uid().kind() != "k8s_service" &&
	    cg->uid().kind() != "k8s_endpoints")
	{
		return;
	}

	for (auto i = cg->ip_addresses().begin(), i_end = cg->ip_addresses().end(); i != i_end; ++i)
	{
		if (m_cg_by_addr.find(*i) == m_cg_by_addr.end())
		{
			continue;
		}
	        auto j = m_cg_by_addr[*i].find(cg);
		if (j != m_cg_by_addr[*i].end())
		{
			m_cg_by_addr[*i].erase(j);
		}
	}
}

void infrastructure_state::add(uid_t &key, const draiosproto::container_group &cg)
{
	if(!has(key))
	{
		m_state[key] = make_unique<draiosproto::container_group>();
	}
	purge_tags_and_copy(key, cg);

	add_ip_mappings(m_state[key]);
}

void infrastructure_state::connect(const infrastructure_state::uid_t& key)
{
	//
	// Connect the new group to his parents
	//
	for (const auto& x : m_state[key]->parents())
	{
		auto pkey = make_pair(x.kind(), x.id());

		// If the parent is not in the allowed list just skip all
		if(!kind_is_allowed(pkey.first))
		{
			LOG_DEBUG("Skipping connection <%s,%s> with <%s,%s> because its kind is not in the allowed list",
				  key.first.c_str(),
				  key.second.c_str(),
				  pkey.first.c_str(),
				  pkey.second.c_str());
			continue;
		}

		if (!has(pkey))
		{
			// keep track of the missing parent. We will fix the children links when this event
			// arrives
			LOG_DEBUG("infra_state: adding orphan for <%s,%s> : <%s,%s>",
			                key.first.c_str(),
			                key.second.c_str(),
			                x.kind().c_str(),
			                x.id().c_str());
			m_orphans[pkey].emplace_back(key.first, key.second);
		}
		else if (!has_link(m_state[pkey]->children(), key))
		{
			draiosproto::congroup_uid* child = m_state[pkey]->mutable_children()->Add();
			child->set_kind(key.first);
			child->set_id(key.second);
			LOG_DEBUG("infra_state: child <%s,%s> added to <%s,%s>",
			          key.first.c_str(),
			          key.second.c_str(),
			          pkey.first.c_str(),
			          pkey.second.c_str());
		}
		else
		{
			LOG_DEBUG("infra_state: <%s,%s> already connected to child <%s,%s>",
			          pkey.first.c_str(),
			          pkey.second.c_str(),
			          key.first.c_str(),
			          key.second.c_str());
		}
	}

	//
	// and connect his children to him
	//
	for (const auto& x : m_state[key]->children())
	{
		auto ckey = make_pair(x.kind(), x.id());

		// If the child is not in the allowed list kind just skip all
		if(!kind_is_allowed(ckey.first))
		{
			LOG_DEBUG("Skipping connection <%s,%s> with child <%s,%s> because its kind is not in the allowed list",
				  key.first.c_str(),
				  key.second.c_str(),
				  ckey.first.c_str(),
				  ckey.second.c_str());
			continue;
		}

		if (!has(ckey))
		{
			// the connection will be created when the child arrives
			continue;
		}
		else if (!has_link(m_state[ckey]->parents(), key))
		{
			draiosproto::congroup_uid* parent = m_state[ckey]->mutable_parents()->Add();
			parent->set_kind(key.first);
			parent->set_id(key.second);
			LOG_DEBUG("infra_state: parent <%s,%s> added to <%s,%s>",
			          key.first.c_str(),
			          key.second.c_str(),
			          ckey.first.c_str(),
			          ckey.second.c_str());
		}
		else
		{
			LOG_DEBUG("infra_state: <%s,%s> already connected to parent <%s,%s>",
			          ckey.first.c_str(),
			          ckey.second.c_str(),
			          key.first.c_str(),
			          key.second.c_str());
		}
	}

	// Fix any broken link involving this container group
	// do this after checking the children otherwise this node will be added as parent twice
	if (m_orphans.find(key) != m_orphans.end())
	{
		for (const auto& orphan_uid : m_orphans[key])
		{
			if (!has_link(m_state[key]->children(), orphan_uid))
			{
				draiosproto::congroup_uid* child = m_state[key]->mutable_children()->Add();
				child->set_kind(orphan_uid.first);
				child->set_id(orphan_uid.second);
				LOG_DEBUG("infra_state: (deferred) child <%s,%s> added to <%s,%s>",
				          orphan_uid.first.c_str(),
				          orphan_uid.second.c_str(),
				          key.first.c_str(),
				          key.second.c_str());
			}
			else
			{
				LOG_DEBUG("infra_state: (deferred) <%s,%s> already connected to <%s,%s>",
				          key.first.c_str(),
				          key.second.c_str(),
				          orphan_uid.first.c_str(),
				          orphan_uid.second.c_str());
			}
		}
		m_orphans.erase(key);
	}

	update_parent_child_links(key);
}

void infrastructure_state::remove(infrastructure_state::uid_t& key, bool update)
{
	//
	// Remove all children references to this group
	//
	LOG_DEBUG("infra_state: Remove container group <%s,%s>", key.first.c_str(), key.second.c_str());

	LOG_DEBUG("infra_state: Container group <%s,%s> has %d parents",
	          key.first.c_str(),
	          key.second.c_str(),
	          m_state[key]->parents().size());
	for (const auto& x : m_state[key]->parents())
	{
		auto pkey = make_pair(x.kind(), x.id());

		if (!has(pkey))
		{
			// parent has already been deleted
			LOG_DEBUG("infra_state: Container group <%s,%s> has been already deleted",
				  pkey.first.c_str(),
				  pkey.second.c_str());
			continue;
		}

		bool erased = false;
		LOG_DEBUG("infra_state: Searching children links inside container group <%s,%s>",
			  pkey.first.c_str(),
			  pkey.second.c_str());

		for (auto pos = m_state[pkey]->children().begin(); pos != m_state[pkey]->children().end();)
		{
			if (pos->kind() == key.first && pos->id() == key.second)
			{
				LOG_DEBUG("infra_state: Erase child link from <%s,%s>",
					  pkey.first.c_str(),
					  pkey.second.c_str());
				m_state[pkey]->mutable_children()->erase(pos);
				LOG_DEBUG("infra_state: Child link erased.");
				erased = true;
				break;
			}

			++pos;

		}

		if (!erased)
		{
			LOG_DEBUG(
				"infra_state: Container groups inconsistency detected. <%s,%s> should be a child "
				"of <%s,%s>.",
				m_state[key]->uid().kind().c_str(),
				m_state[key]->uid().id().c_str(),
				m_state[pkey]->uid().kind().c_str(),
				m_state[pkey]->uid().id().c_str());
		}
	}

	if (m_state[key]->uid().kind() == "container")
	{
		//
		// Delete all cached results for this container
		//
		m_policy_cache.erase(m_state[key]->uid().id());
	}

	// Delete IP mappings for this group
	remove_ip_mappings(m_state[key]);

	// If this is not an updated
	// discend into the status graph and remove this parent
	// Notice that recursion is needed for m_parents structure
	if(update == false)
	{
		remove_parent_recursively(key, key);
	}

	// Remove the group itself
	m_state.erase(key);

	// Remove the objects from m_parents. This is
	// the only place where elements are taken off from this structure.
	m_parents.erase(key);

	// Keep rate metric history if this object is just getting updated
	if (!update)
	{
		delete_rate_metrics(key);
	}

	LOG_DEBUG("infra_state: Container group <%s,%s> removed.",
	          key.first.c_str(),
	          key.second.c_str());
}

void infrastructure_state::remove_parent_recursively(const uid_t& what_uid, const uid_t& father_uid)
{
	if(!has(father_uid))
	{
		return;
	}

	for(const auto& child : m_state[father_uid]->children())
	{
		auto child_id = std::make_pair(child.kind(), child.id());
		LOG_DEBUG("Looking for parent <%s,%s> in child <%s,%s>",
			  what_uid.first.c_str(),
			  what_uid.second.c_str(),
			  child_id.first.c_str(),
			  child_id.second.c_str());
		if(has(child_id))
		{
			remove_parent_recursively(what_uid, child_id);

			// Erase root_uid from the actual node
			for(auto it = m_state[child_id]->mutable_parents()->begin(); it != m_state[child_id]->mutable_parents()->end(); )
			{
				if(std::make_pair(it->kind(), it->id()) == what_uid)
				{
					LOG_DEBUG("Removing parent <%s,%s> from <%s,%s>",
						  it->kind().c_str(),
						  it->id().c_str(),
						  child.kind().c_str(),
						  child.id().c_str());
					it = m_state[child_id]->mutable_parents()->erase(it);
					break;
				}
				it++;
			}
			m_parents[child_id].erase(what_uid);
		}
	}
}

bool infrastructure_state::walk_and_match(draiosproto::container_group* congroup,
                                          scope_predicates& preds,
                                          std::unordered_set<uid_t>& visited_groups)
{
	uid_t uid = make_pair(congroup->uid().kind(), congroup->uid().id());

	if (visited_groups.find(uid) != visited_groups.end())
	{
		// Group already visited, continue the evaluation
		return true;
	}

	//
	// Evaluate current group's fields
	// Remove the successfully evaluated ones
	//
	if (!evaluate_on(congroup, preds))
	{
		// A predicate is false
		return false;
	}

	//
	// All predicates evalutated successfully,
	// nothing else to do
	//
	if (preds.empty())
		return true;

	// Remember we've visited this group
	visited_groups.emplace(uid);

	//
	// Evaluate parents' tags
	//
	for (const auto& p_uid : congroup->parents())
	{
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		if (!has(pkey))
		{
			// We don't have this parent (yet...)
			LOG_WARNING(
			    "infra_state: Cannot fully evaluate policy scope because the infrastructure state "
			    "is incomplete.");
			return false;
		}

		if (!walk_and_match(m_state[pkey].get(), preds, visited_groups))
		{
			// A predicate in the upper levels returned false
			// The final result is false
			return false;
		}
		if (preds.empty())
			break;
	}

	return true;
}

bool infrastructure_state::match_scope(const uid_t& uid, const scope_predicates& predicates)
{
	bool result = true;

	std::string preds_str = as_string(predicates);
	size_t preds_hash = m_str_hash_f(preds_str);

	if (predicates.empty())
	{
		// no predicates, we can safely return true immediately
		result = true;
	}
	else
	{
		if (get_cached_result(uid.second, preds_hash, &result))
		{
			return result;
		}

		auto pos = m_state.find(uid);
		if (pos == m_state.end())
			return false;

		scope_predicates preds(predicates);

		if (uid.first == "host")
		{
			result = evaluate_on(pos->second.get(), preds);
		}
		else
		{
			std::unordered_set<uid_t, std::hash<uid_t>> visited;
			result = walk_and_match(pos->second.get(), preds, visited);
		}

		if (result && !preds.empty())
		{
			LOG_DEBUG("infra_state: Predicates list not empty, check operators...");
			auto i = preds.begin();
			for (; i != preds.end(); ++i)
			{
				if (i->op() != draiosproto::NOT_EQ && i->op() != draiosproto::NOT_IN_SET &&
				    i->op() != draiosproto::NOT_CONTAINS)
				{
					break;
				}
			}
			if (i == preds.end())
			{
				LOG_DEBUG(
				    "infra_state: The unmatched predicates are only !=, not in, not contains. "
				    "Assume the metrics are not set in the current sub-infrastructure and return "
				    "true");
				result = true;
			}
			else
			{
				result = false;
			}
		}

		LOG_DEBUG(
		    "infra_state: Matching scope with hash %lu, composed by %d predicates, against "
		    "<%s,%s> ----> %s",
		    preds_hash,
		    predicates.size(),
		    uid.first.c_str(),
		    uid.second.c_str(),
		    (result ? "true" : "false"));
	}

	insert_cached_result(uid.second, preds_hash, result);

	return result;
}

std::shared_ptr<draiosproto::container_group> infrastructure_state::get_pod_owner(
	std::shared_ptr<draiosproto::container_group> const& cg)
{
	for (const auto& parent : cg->parents())
	{
		auto ckey = make_pair(parent.kind(), parent.id());
		auto kind = parent.kind();

		if (kind == "k8s_replicaset")
		{
			// let's always skip replicaset, and try to
			// fetch the replicaset's owner
			const auto& rs = m_state[ckey];
			if (rs)
			{
				return get_pod_owner(rs);
			}
		} else if (kind == "k8s_deployment" ||
			   kind == "k8s_daemonset" ||
			   kind == "k8s_statefulset" ||
			   kind == "k8s_job")
		{
			auto owner = m_state[ckey];
			if (owner)
			{
				return owner;
			}
		}
	}

	return nullptr;
}


// Given an address, if a matching pod owner is found returns true and
// set the pod owner in the entity, false otherwise.
std::shared_ptr<draiosproto::container_group> infrastructure_state::match_from_addr(
	const std::string &addr, bool *found)
{
	*found = false;
	if (m_cg_by_addr.find(addr) == m_cg_by_addr.end())
	{
		LOG_DEBUG("infra_state: Cannot find IP address %s",
			  addr.c_str());
		return nullptr;
	}

	auto cgs = m_cg_by_addr[addr];
	std::shared_ptr<draiosproto::container_group> owner = nullptr;

	for (const auto& cg : cgs)
	{
		// skip all host activity, this will also exclude all
		// pods configured using hostNetwork
		if (cg->uid().kind() == "node" ||
		    cg->uid().kind() == "k8s_node")
		{
			*found = true;
			owner = cg;
			break;
		}
		else if (cg->uid().kind() == "k8s_pod")
		{
			*found = true;
			owner = get_pod_owner(cg);
			// don't break, as if we find later on
			// the loop a node cg, we need to
			// invalidate the search, and return
			// false
		}
	}

	return owner;
}

bool infrastructure_state::register_scope(reg_id_t& reg,
                                          bool host_scope,
                                          bool container_scope,
                                          const scope_predicates& predicates)
{
	auto it = m_registered_scopes.lower_bound(reg);

	if (it != m_registered_scopes.end() && it->first == reg)
	{
		// Some entry already exists with this reg.
		return false;
	}

	// Now see if the scope matches the set of running containers.
	bool scope_match = false;

	if (predicates.empty())
	{
		scope_match = true;
	}
	else
	{
		if (host_scope)
		{
			infrastructure_state::uid_t uid = make_pair("host", m_machine_id);

			scope_match = match_scope(uid, predicates);
		}
		if (!scope_match && container_scope)
		{
			scope_match = match_scope_all_containers(predicates);
		}
	}

	LOG_DEBUG("infra_state: Registering scope %s host=%d container=%d (%s)",
	          reg.c_str(),
	          host_scope,
	          container_scope,
	          as_string(predicates).c_str());

	reg_scope_t rscope = {host_scope, container_scope, predicates, scope_match};
	m_registered_scopes.emplace_hint(it, std::make_pair(reg, rscope));

	return true;
}

bool infrastructure_state::check_registered_scope(reg_id_t& reg) const
{
	auto it = m_registered_scopes.find(reg);
	if (it == m_registered_scopes.end())
	{
		LOG_ERROR("infra_state: No registered scope matching %s", reg.c_str());
		return false;
	}

	LOG_DEBUG("infra_state: Checking registered scope %s match=%d",
	          reg.c_str(),
	          it->second.m_scope_match);

	return it->second.m_scope_match;
}

std::string infrastructure_state::get_machine_id() const
{
	return m_machine_id;
}

sinsp_container_info::ptr_t infrastructure_state::get_container_info(const std::string& container_id)
{
	return m_inspector->m_container_manager.get_container(container_id);
}

// This function tests if a given congroup is valid for export
// Rules:
// 1.) ONLY Export: k8s_* objects
// 2.) ALWAYS Export : k8s_namespace, k8s_node, k8s_persistentvolume
// 3.) NEVER Export  : host , container
// 4.) Conditional Export : (a). All other congroups ONLY if they have
//                               k8s_namespace parent
//                          (b). A k8s_pod should be exported ONLY
//                               if it has both k8s_namespace and k8s_node
//                               parents.
bool infrastructure_state::is_valid_for_export(const draiosproto::container_group* grp) const
{
	// Never return host and container.
	if (grp->uid().kind() == "host" || grp->uid().kind() == "container")
	{
		return false;
	}

	if (m_cg_ttl.find(make_pair(grp->uid().kind(), grp->uid().id())) != m_cg_ttl.end())
	{
		return false;
	}

	// Make sure we are dealing with a k8s_* object
	// If we are not. Always export and return early.
	// This preserves previous behaviour for such congroups
	if ((grp->uid().kind()).substr(0, 4) != "k8s_")
	{
		return true;
	}

	// Always return node and namespace
	if (grp->uid().kind() == "k8s_namespace" || grp->uid().kind() == "k8s_node" ||
	    grp->uid().kind() == "k8s_persistentvolume")
	{
		return true;
	}

	// Now check for parents conditions based on rules above
	bool has_k8s_namespace(false), has_k8s_node(false);

	for (const auto& p_uid : grp->parents())
	{
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		if (p_uid.kind() == "k8s_namespace")
		{
			has_k8s_namespace = has(pkey);
		}
		else if (grp->uid().kind() == "k8s_pod" && p_uid.kind() == "k8s_node")
		{
			has_k8s_node = has(pkey);
		}
	}

	auto is_unschedulable = [](const draiosproto::container_group& cg) {
		for (const auto& l : cg.tags())
		{
			if (std::make_pair(l.first, l.second) ==
			    std::make_pair(UNSCHEDULABLE_TAG, std::string("true")))
			{
				return true;
			}
		}
		return false;
	};

	if (grp->uid().kind() == "k8s_pod")
	{
		return (has_k8s_node && has_k8s_namespace) || is_unschedulable(*grp);
	}

	return has_k8s_namespace;
}

void infrastructure_state::state_of(const draiosproto::container_group* grp,
                                    draiosproto::k8s_state* state,
                                    std::unordered_set<uid_t>& visited,
                                    const uint64_t ts)
{
	uid_t uid = make_pair(grp->uid().kind(), grp->uid().id());

	if (visited.find(uid) != visited.end())
	{
		// Group already visited, skip it
		return;
	}
	visited.emplace(uid);

	for (const auto& p_uid : grp->parents())
	{
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		if (!has(pkey))
		{
			// We don't have this parent (yet...)
			continue;
		}

		//
		// Build parent state
		//
		state_of(m_state[pkey].get(), state, visited, ts);
	}

	//
	// Export a congroup only if it obeys the rules
	// of the valid for export method above
	if (is_valid_for_export(grp))
	{
		emit(grp, state, ts);
	}
}

void infrastructure_state::state_of(const draiosproto::container_group* grp,
                                    container_groups* state,
                                    std::unordered_set<uid_t>& visited,
                                    const uint64_t ts)
{
	uid_t uid = make_pair(grp->uid().kind(), grp->uid().id());

	if (visited.find(uid) != visited.end())
	{
		// Group already visited, skip it
		return;
	}
	visited.emplace(uid);

	for (const auto& p_uid : grp->parents())
	{
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		if (!has(pkey))
		{
			// We don't have this parent (yet...)
			continue;
		}

		//
		// Build parent state
		//
		state_of(m_state[pkey].get(), state, visited, ts);
	}

	//
	// Export a congroup only if it obeys the rules
	// of the valid for export method above
	if (is_valid_for_export(grp))
	{
		auto x = state->Add();
		x->CopyFrom(*grp);
		// Clean children links, backend will reconstruct them from parent ones
		if (grp->uid().kind() != "k8s_pod")
		{
			x->mutable_children()->Clear();
		}
		// Internal_tags are meant for use inside agent only
		x->mutable_internal_tags()->clear();

		calculate_rate_metrics(x, ts);
	}
}

void infrastructure_state::state_of(const std::vector<std::string>& container_ids,
                                    draiosproto::k8s_state* state,
                                    uint64_t ts)
{
	std::unordered_set<uid_t, std::hash<uid_t>> visited;

	//
	// Retrieve the state of every container
	//
	for (const auto& c_id : container_ids)
	{
		auto pos = m_state.find(make_pair("container", c_id));
		if (pos == m_state.end())
		{
			//
			// This container is not in the orchestrator state
			//
			continue;
		}

		state_of(pos->second.get(), state, visited, ts);
	}

	//
	// Add everything running on this node that hasn't been added yet
	// (like pods without containers)
	//
	if (!m_k8s_node_uid.empty())
	{
		auto node_key = make_pair("k8s_node", m_k8s_node_uid);
		if (has(node_key))
		{
			const auto* node = m_state[node_key].get();

			for (const auto& c_uid : node->children())
			{
				LOG_DEBUG("infra_state: node %s has %s:%s",
				          m_k8s_node_uid.c_str(),
				          c_uid.kind().c_str(),
				          c_uid.id().c_str());
				auto ckey = make_pair(c_uid.kind(), c_uid.id());

				if (!has(ckey))
				{
					// We don't have this child (yet...)
					continue;
				}

				if (visited.find(ckey) == visited.end())
				{
					// state_of() looks at visited too
					// We just want to do it here for logging purposes
					LOG_DEBUG("infra_state: adding state for (container-less) %s:%s",
					          c_uid.kind().c_str(),
					          c_uid.id().c_str());
					state_of(m_state[ckey].get(), state, visited, ts);
				}
			}
		}
	}

	resolve_names(state);
}

void infrastructure_state::state_of(const std::vector<std::string>& container_ids,
                                    container_groups* state,
                                    uint64_t ts)
{
	std::unordered_set<uid_t, std::hash<uid_t>> visited;

	//
	// Retrieve the state of every container
	//
	for (const auto& c_id : container_ids)
	{
		auto pos = m_state.find(make_pair("container", c_id));
		if (pos == m_state.end())
		{
			//
			// This container is not in the orchestrator state
			//
			continue;
		}

		state_of(pos->second.get(), state, visited, ts);
	}

	//
	// Add everything running on this node that hasn't been added yet
	// (like pods without containers)
	//
	if (!m_k8s_node_uid.empty())
	{
		auto node_key = make_pair("k8s_node", m_k8s_node_uid);
		if (has(node_key))
		{
			const auto* node = m_state[node_key].get();

			for (const auto& c_uid : node->children())
			{
				LOG_DEBUG("infra_state: node %s has %s:%s",
				          m_k8s_node_uid.c_str(),
				          c_uid.kind().c_str(),
				          c_uid.id().c_str());
				auto ckey = make_pair(c_uid.kind(), c_uid.id());

				if (!has(ckey))
				{
					// We don't have this child (yet...)
					continue;
				}

				if (visited.find(ckey) == visited.end())
				{
					// state_of() looks at visited too
					// We just want to do it here for logging purposes
					LOG_DEBUG("infra_state: adding state for (container-less) %s:%s",
					          c_uid.kind().c_str(),
					          c_uid.id().c_str());
					state_of(m_state[ckey].get(), state, visited, ts);
				}
			}
		}
	}

	//
	// Clean up the broken links
	// (except for container links, that are used to identify the containers)
	//
	for (auto state_cgroup = state->begin(), state_end = state->end(); state_cgroup != state_end;
	     ++state_cgroup)
	{
		for (auto i = state_cgroup->mutable_children()->begin();
		     i != state_cgroup->mutable_children()->end();)
		{
			if (i->kind() != "container" &&
			    visited.find(make_pair(i->kind(), i->id())) == visited.end())
			{
				i = state_cgroup->mutable_children()->erase(i);
			}
			else
			{
				++i;
			}
		}
		// clean up the host link
		if (host_children.find(state_cgroup->uid().kind()) != host_children.end())
		{
			for (auto i = state_cgroup->mutable_parents()->begin(),
			          i_end = state_cgroup->mutable_parents()->end();
			     i != i_end;
			     ++i)
			{
				if (i->kind() == "host")
				{
					state_cgroup->mutable_parents()->erase(i);
					break;
				}
			}
		}
	}
}

double infrastructure_state::calculate_rate(rate_metric_state_t& prev, double value, uint64_t ts)
{
	// Set rate to 0 if we don't have a previous value yet
	double rate = 0.0;
	if (prev.ts != 0)
	{
		uint64_t timediff = ts - prev.ts;
		if (timediff < (ONE_SECOND_IN_NS / 2))
		{
			// If we're called again during the same cycle, timediff should be 0
			// We'll just repeat the rate value from last calculation
			if (timediff)
			{
				// This shouldn't happen. We're either called more than
				// twice per second or with a different time source.
				static ratelimit r(1, 1 * NSECS_PER_SEC);
				r.run([&] {
					LOG_WARNING("Time difference too small for rate calculation: %" PRIu64
							  " ns, time now: %" PRIu64 ", last: %" PRIu64,
						  timediff,
						  ts,
						  prev.ts);
				});
			}
			return prev.last_rate;
		}
		rate = (value - prev.val) * (double)ONE_SECOND_IN_NS / (double)timediff;
	}

	prev.last_rate = rate;
	prev.ts = ts;
	prev.val = value;

	return rate;
}

void infrastructure_state::calculate_rate_metrics(draiosproto::container_group* cg,
                                                  const uint64_t ts)
{
	auto cgkey = make_pair(cg->uid().kind(), cg->uid().id());
	for (auto it = cg->mutable_metrics()->begin(); it != cg->mutable_metrics()->end(); it++)
	{
		if (it->type() != draiosproto::app_metric_type::APP_METRIC_TYPE_RATE)
			continue;

		double rate = calculate_rate(m_rate_metric_state[cgkey][it->name()], it->value(), ts);
		it->set_value(rate);
	}
}

void infrastructure_state::delete_rate_metrics(const uid_t& key)
{
	m_rate_metric_state.erase(key);
	if (key.first == "k8s_pod")
	{
		m_pod_restart_rate.erase(key.second);
	}
}

void infrastructure_state::get_congroups_by_kind(std::vector<std::shared_ptr<draiosproto::container_group>> *cgs, const string &kind) const
{
	// Skip ahead to kind then walk them sequentially
	uid_t lb_key(kind, "");
	for (auto it = m_state.lower_bound(lb_key); it != m_state.end(); ++it)
	{
		if (it->first.first != kind)
		{
			break;
		}
		cgs->push_back(it->second);
	}
}

void infrastructure_state::get_state(container_groups* state, const uint64_t ts)
{
	for (auto i = m_state.begin(); i != m_state.end(); ++i)
	{
		auto cg = i->second.get();
		if (is_valid_for_export(cg))
		{
			auto x = state->Add();
			x->CopyFrom(*cg);
			// clean up host links
			if (host_children.find(cg->uid().kind()) != host_children.end())
			{
				for (auto j = x->mutable_parents()->begin(), j_end = x->mutable_parents()->end();
				     j != j_end;
				     ++j)
				{
					if (j->kind() == "host")
					{
						x->mutable_parents()->erase(j);
						break;
					}
				}
			}
		}
	}
	m_k8s_store_manager.print_store_status();
}

void infrastructure_state::resolve_names(draiosproto::k8s_state* state)
{
	// uid -> name
	std::unordered_map<std::string, std::string> job_names;
	std::unordered_map<std::string, std::string> node_names;
	std::unordered_map<std::string, std::string> ns_names;
	std::unordered_map<std::string, draiosproto::k8s_namespace*> namespaces;

	state->set_namespace_count(state->namespaces_size());

	for (auto& ns : *(state->mutable_namespaces()))
	{
		ns_names[ns.common().uid()] = ns.common().name();
		ns.set_deployment_count(0);
		ns.set_service_count(0);
		ns.set_replicaset_count(0);
		ns.set_job_count(0);
		ns.set_statefulset_count(0);
		ns.set_resourcequota_count(0);
		ns.set_persistentvolumeclaim_count(0);
		ns.set_hpa_count(0);
		ns.set_pod_desired_count(0);
		ns.set_pod_available_count(0);
		ns.set_pod_running_count(0);
		namespaces[ns.common().uid()] = &ns;
	}

	for (auto& job : *(state->mutable_jobs()))
	{
		job_names[job.common().uid()] = job.common().name();
		auto ns = namespaces.find(job.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_job_count(ns->second->job_count() + 1);
		}
		legacy_k8s::set_namespace(job.mutable_common(), ns_names);
	}

	for (const auto& node : state->nodes())
	{
		node_names[node.common().uid()] = node.common().name();
	}

	for (auto& pod : *(state->mutable_pods()))
	{
		const auto& job_name = job_names.find(pod.job_name());
		if (job_name != job_names.end())
		{
			pod.set_job_name(job_name->second);
		}

		const auto& node_name = node_names.find(pod.node_name());
		if (node_name != node_names.end())
		{
			pod.set_node_name(node_name->second);
		}

		if (pod.status_phase() == "Running")
		{
			auto ns = namespaces.find(pod.common().namespace_());
			if (ns != namespaces.end())
			{
				ns->second->set_pod_running_count(ns->second->pod_running_count() + 1);
			}
		}

		legacy_k8s::set_namespace(pod.mutable_common(), ns_names);
	}

	for (auto& obj : *(state->mutable_controllers()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_pod_desired_count(ns->second->pod_desired_count() +
			                                  obj.replicas_desired());
			ns->second->set_pod_available_count(ns->second->pod_available_count() +
			                                    obj.replicas_available());
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}

	for (auto& obj : *(state->mutable_services()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_service_count(ns->second->service_count() + 1);
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_replica_sets()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_replicaset_count(ns->second->replicaset_count() + 1);
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_deployments()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_deployment_count(ns->second->deployment_count() + 1);
			ns->second->set_pod_desired_count(ns->second->pod_desired_count() +
			                                  obj.replicas_desired());
			ns->second->set_pod_available_count(ns->second->pod_available_count() +
			                                    obj.replicas_available());
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_daemonsets()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_pod_desired_count(ns->second->pod_desired_count() +
			                                  obj.desired_scheduled());
			ns->second->set_pod_available_count(ns->second->pod_available_count() +
			                                    obj.current_scheduled());
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_statefulsets()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_statefulset_count(ns->second->statefulset_count() + 1);
			ns->second->set_pod_desired_count(ns->second->pod_desired_count() + obj.replicas());
			ns->second->set_pod_available_count(ns->second->pod_available_count() +
			                                    obj.status_replicas_current());
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_resourcequotas()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_resourcequota_count(ns->second->resourcequota_count() + 1);
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_persistentvolumes()))  // XXX they aren't namespaced
	{
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_persistentvolumeclaims()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_persistentvolumeclaim_count(ns->second->persistentvolumeclaim_count() +
			                                            1);
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}
	for (auto& obj : *(state->mutable_hpas()))
	{
		auto ns = namespaces.find(obj.common().namespace_());
		if (ns != namespaces.end())
		{
			ns->second->set_hpa_count(ns->second->hpa_count() + 1);
			ns->second->set_pod_desired_count(ns->second->pod_desired_count() +
			                                  obj.replicas_desired());
			ns->second->set_pod_available_count(ns->second->pod_available_count() +
			                                    obj.replicas_current());
		}
		legacy_k8s::set_namespace(obj.mutable_common(), ns_names);
	}

	for (auto& obj : m_pod_status)
	{
		auto ns = namespaces.find(obj.first);
		if (ns != namespaces.end())
		{
			for (auto& pod_status : obj.second)
			{
				ns->second->add_pod_status_count()->CopyFrom(pod_status);
			}
		}
	}
}

void infrastructure_state::emit(const draiosproto::container_group* cg,
                                draiosproto::k8s_state* state,
                                uint64_t ts)
{
	if (!is_valid_for_export(cg))
	{
		return;
	}

	auto key = std::make_pair(cg->uid().kind(), cg->uid().id());
	const std::string& kind = cg->uid().kind();

	if (kind == "k8s_job")
	{
		auto job = state->add_jobs();
		legacy_k8s::export_k8s_object(m_parents[key], cg, job);
	}
	else if (kind == "k8s_cronjob")
	{
		// no protobuf for these
		return;
	}
	else if (kind == "k8s_daemonset")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_daemonsets());
	}
	else if (kind == "k8s_deployment")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_deployments());
	}
	else if (kind == "k8s_hpa")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_hpas());
	}
	else if (kind == "k8s_ingress")
	{
		// no protobuf for these
		return;
	}
	else if (kind == "k8s_endpoints")
	{
		// no protobuf for these (used only for secure_netsec)
		return;
	}
	else if (kind == "k8s_namespace")
	{
		auto ns = state->add_namespaces();
		legacy_k8s::fill_common(m_parents[key], cg, ns->mutable_common(), "kubernetes.namespace.");
	}
	else if (kind == "k8s_node")
	{
		auto node = state->add_nodes();
		legacy_k8s::export_k8s_object(m_parents[key], cg, node);
		node->mutable_host_ips()->CopyFrom(cg->ip_addresses());
	}
	else if (kind == "k8s_persistentvolumeclaim")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_persistentvolumeclaims());
	}
	else if (kind == "k8s_persistentvolume")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_persistentvolumes());
	}
	else if (kind == "k8s_pod")
	{
		auto pod = state->add_pods();
		legacy_k8s::export_k8s_object(m_parents[key], cg, pod);
		for (const auto& parent : cg->parents())
		{
			if (parent.kind() == "k8s_node")
			{
				// will be overwritten in the second pass
				pod->set_node_name(parent.id());
				break;
			}
		}

		for (const auto& ip : cg->ip_addresses())
		{
			// a pod cannot have more than one IP, right?
			pod->set_internal_ip(ip);
			break;
		}

		for (const auto& child : cg->children())
		{
			if (child.kind() == "container")
			{
				pod->add_container_ids("internal://" + child.id());
			}
		}

		// Set explicitly the status phase here because it is stored in a map.
		// We than will spare to do a linear search later in resolve names
		// where we would iterate over the labels
		auto status_phase = cg->tags().find(infrastructure_state::POD_STATUS_PHASE_LABEL);
		if (status_phase != std::end(cg->tags()))
		{
			pod->set_status_phase(status_phase->second);
		}

		// TODO I don't think cointerface exposes this
		// optional string host_ip = 4;

		double rate = calculate_rate(m_pod_restart_rate[cg->uid().id()], pod->restart_rate(), ts);
		pod->set_restart_rate(rate);
	}
	else if (kind == "k8s_replicaset")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_replica_sets());
	}
	else if (kind == "k8s_replicationcontroller")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_controllers());
	}
	else if (kind == "k8s_resourcequota")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_resourcequotas());
	}
	else if (kind == "k8s_service")
	{
		auto service = state->add_services();
		legacy_k8s::fill_common(m_parents[key],
		                        cg,
		                        service->mutable_common(),
		                        "kubernetes.service.");

		for (const auto& cg_port : cg->ports())
		{
			auto port = service->add_ports();
			port->set_port(cg_port.port());
			port->set_target_port(cg_port.target_port());
			port->set_protocol(cg_port.protocol());
			port->set_node_port(cg_port.node_port());
			// TODO what about published_port?
		}

		for (const auto& ip : cg->ip_addresses())
		{
			// a service cannot have more than one IP, right?
			service->set_cluster_ip(ip);
			break;
		}
	}
	else if (kind == "k8s_statefulset")
	{
		legacy_k8s::export_k8s_object(m_parents[key], cg, state->add_statefulsets());
	}
	else if (kind == "podstatuscounter")
	{
		draiosproto::pod_status_count pod_status;

		// look for the parent namespace
		std::string ns;
		for (auto& parent : cg->parents())
		{
			if (parent.kind() == "k8s_namespace")
			{
				ns = parent.id();
				break;
			}
		}

		if (!ns.empty())
		{
			legacy_k8s::export_k8s_object<draiosproto::pod_status_count>(m_parents[key],
			                                                             cg,
			                                                             &pod_status);
			auto pos = m_pod_status[ns].find(pod_status);
			if (pos != m_pod_status[ns].end())
			{
				m_pod_status[ns].erase(pos);
			}
			m_pod_status[ns].insert(std::move(pod_status));
		}
	}
	else
	{
		LOG_NOTICE("Unsupported k8s resource type %s", kind.c_str());
		return;
	}
}

void infrastructure_state::get_state(draiosproto::k8s_state* state, uint64_t ts)
{
	for (const auto& it : m_state)
	{
		emit(it.second.get(), state, ts);
	}
	resolve_names(state);
	dump_memory_info();
}

void infrastructure_state::on_new_container(const sinsp_container_info& container_info,
                                            sinsp_threadinfo* tinfo)
{
	if (container_info.is_pod_sandbox())
	{
		// filter out k8s internal container/s
		return;
	}

	// Remove any cached result related to this container
	// id. (This can occur for containers where an initial stub
	// container with complete information is added first, with a
	// complete container being added later).
	//
	// It's necessary as match_scope always checks the cache
	// first, and if the cache is based on the incomplete
	// container, it won't ever relocate it based on the complete
	// container information.
	clear_cached_result(container_info.m_id);

	LOG_DEBUG("infra_state: Receiving new container event (id: %s) from container_manager",
	          container_info.m_id.c_str());
	draiosproto::congroup_update_event evt;
	evt.set_type(draiosproto::ADDED);
	auto cg = evt.mutable_object();
	cg->mutable_uid()->set_kind("container");
	cg->mutable_uid()->set_id(container_info.m_id);

	if(container_info.m_container_ip != 0) {
		uint32_t addr = htonl(container_info.m_container_ip);
		char buf[INET_ADDRSTRLEN];
		if(inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN) != NULL) {
			cg->add_ip_addresses(string(buf));
		}
	}

	(*cg->mutable_tags())["container.id"] = container_info.m_id;
	(*cg->mutable_tags())["container.name"] = container_info.m_name;
	(*cg->mutable_tags())["container.image"] = container_info.m_image;
	(*cg->mutable_tags())["container.image.id"] = container_info.m_imageid.substr(0, 12);
	(*cg->mutable_tags())["container.image.repo"] = container_info.m_imagerepo;
	(*cg->mutable_tags())["container.image.tag"] = container_info.m_imagetag;
	(*cg->mutable_tags())["container.image.digest"] = container_info.m_imagedigest;
	// only needed for baseline MVP grouping key
	size_t apos = container_info.m_image.find("@");
	(*cg->mutable_internal_tags())["container.image.name_no_digest"] =
	    apos != string::npos ? container_info.m_image.substr(0, apos) : container_info.m_image;
	std::string com_docker_swarm = "com.docker.swarm";
	std::string com_docker = "com.docker.";
	for (const auto& t : container_info.m_labels)
	{
		(*cg->mutable_tags())["container.label." + t.first] = t.second;
		if (m_k8s_subscribed && std::string(t.first) == "io.kubernetes.pod.uid")
		{
			auto p = cg->mutable_parents()->Add();
			p->set_kind("k8s_pod");
			p->set_id(t.second);
			LOG_DEBUG("infra_state: Adding parent <k8s_pod,%s> to container %s",
			          t.second.c_str(),
			          container_info.m_id.c_str());
		}

		// Convert labels starting with "com.docker.swarm"
		// into tags, dropping the "com.docker"
		std::string label = std::string(t.first);
		if (label.compare(0, com_docker_swarm.size(), com_docker_swarm) == 0)
		{
			label.erase(0, com_docker.size());
			(*cg->mutable_tags())[label] = t.second;
			LOG_DEBUG("infra_state: Adding docker swarm label %s -> %s",
			          label.c_str(),
			          t.second.c_str());
		}
	}
	uid_t h_pkey = make_pair("host", m_machine_id);
	if (has(h_pkey))
	{
		auto p = cg->mutable_parents()->Add();
		p->set_kind(h_pkey.first);
		p->set_id(h_pkey.second);
		LOG_DEBUG("infra_state: Adding parent <host,%s> to container %s",
		          m_machine_id.c_str(),
		          container_info.m_id.c_str());
	}

	uid_t c_key = make_pair("container", container_info.m_id);
	// If the container already exists; remove it first
	if (has(c_key))
	{
		// expedite removal, don't wait for TTL
		m_k8s_store_manager.handle_delete(c_key, m_state);
		remove(c_key);
	}
	// Handle the container event (ADDED type)
	handle_event(&evt, true);

	scrape_mesos_env(container_info, tinfo);

	// Now check all registered scopes that do *not* match, and
	// see if they match this new container.
	for (auto& sit : m_registered_scopes)
	{
		bool old_scope_match = sit.second.m_scope_match;

		// Only need to reevaluate if the scope does *not*
		// currently match and if the scope is a container-level scope.
		if (!sit.second.m_scope_match && sit.second.m_container_scope)
		{
			infrastructure_state::uid_t uid = make_pair("container", container_info.m_id);

			if (match_scope(uid, sit.second.m_predicates))
			{
				sit.second.m_scope_match = true;
			}
		}

		LOG_DEBUG("infra_state: on_new_container registered scope %s old match=%d match=%d",
		          sit.first.c_str(),
		          old_scope_match,
		          sit.second.m_scope_match);
	}
}

void infrastructure_state::on_remove_container(const sinsp_container_info& container_info)
{
	if (container_info.is_pod_sandbox())
	{
		// filter out k8s internal container/s
		return;
	}

	LOG_DEBUG("infra_state: Receiving remove container event (id: %s) from container_manager",
	          container_info.m_id.c_str());
	draiosproto::congroup_update_event evt;
	evt.set_type(draiosproto::REMOVED);
	auto cg = evt.mutable_object();
	cg->mutable_uid()->set_kind("container");
	cg->mutable_uid()->set_id(container_info.m_id);

	handle_event(&evt);

	// We're not tracking the specific container that matched the
	// registered scopes, so we need to reevaluate each scope
	// against the set of containers.
	for (auto& sit : m_registered_scopes)
	{
		bool old_scope_match = sit.second.m_scope_match;

		// Only need to reevaluate if the scope does
		// currently match and if the scope is a container-level scope.
		if (sit.second.m_scope_match && sit.second.m_container_scope)
		{
			sit.second.m_scope_match = match_scope_all_containers(sit.second.m_predicates);
		}

		LOG_DEBUG("infra_state: on_remove_container registered scope %s old match=%d match=%d",
		          sit.first.c_str(),
		          old_scope_match,
		          sit.second.m_scope_match);
	}
}

void infrastructure_state::receive_hosts_metadata(
    const google::protobuf::RepeatedPtrField<draiosproto::congroup_update_event>& host_events)
{
	m_host_events_queue_mutex.lock();
	LOG_DEBUG("infra_state: Lock and receive hosts metadata");
	for (auto hevt : host_events)
	{
		m_host_events_queue.emplace(std::move(hevt));
	}
	LOG_DEBUG("infra_state: %ld hosts metadata received. Unlock.", m_host_events_queue.size());
	m_host_events_queue_mutex.unlock();
}

void infrastructure_state::clear_scope_cache()
{
	LOG_DEBUG("infra_state: Clear container/host scope cache because policies will be reloaded...");
	m_policy_cache.clear();
}

void infrastructure_state::refresh_hosts_metadata()
{
	// Ensure we have m_inspector and m_machine_id
	if (!inited())
		return;
	//
	// Remove current hosts
	//
	for (auto i = m_state.begin(); i != m_state.end();)
	{
		auto cg = i->second;
		auto congroup = i->second.get();
		// remove all the links to host nodes
		if (host_children.find(congroup->uid().kind()) != host_children.end() ||
		    congroup->uid().kind() == "container")
		{
			for (auto j = congroup->mutable_parents()->begin(),
			          j_end = congroup->mutable_parents()->end();
			     j != j_end;
			     ++j)
			{
				if (j->kind() == "host")
				{
					congroup->mutable_parents()->erase(j);
					break;
				}
			}
		}

		if (congroup->uid().kind() == "host")
		{
			remove_ip_mappings(cg);
			i = m_state.erase(i);
		}
		else
		{
			++i;
		}
	}

	//
	// Delete all cached results for policy scopes
	//
	clear_scope_cache();

	LOG_INFO("infra_state: Adding %ld hosts to infrastructure state", m_host_events_queue.size());

	//
	// Connect the refreshed data to the state
	//
	while (!m_host_events_queue.empty())
	{
		auto& hevt = m_host_events_queue.front();
		auto host = hevt.mutable_object();

		LOG_DEBUG("infra_state: Add host %s to infrastructure state", host->uid().id().c_str());

		if (m_k8s_subscribed)
		{
			uid_t child_uid;
			bool has_child = true;
			std::vector<uid_t> nodes;

			for (auto i = m_state.begin(), e = m_state.end(); i != e; ++i)
			{
				auto congroup = i->second.get();
				if (host_children.find(congroup->uid().kind()) != host_children.end())
				{
					// don't try to match with removed container groups
					if(m_cg_ttl.find(make_pair(congroup->uid().kind(), congroup->uid().id())) != m_cg_ttl.end()) {
						continue;
					}

					bool found = false;
					for (auto j = congroup->ip_addresses().begin(),
					          j_end = congroup->ip_addresses().end();
					     j != j_end;
					     ++j)
					{
						for (auto k = host->ip_addresses().begin(),
						          k_end = host->ip_addresses().end();
						     k != k_end;
						     ++k)
						{
							if (*j == *k)
							{
								LOG_DEBUG(
								    "infra_state: Host %s match with congroup <%s,%s> for IP %s",
								    host->uid().id().c_str(),
								    congroup->uid().kind().c_str(),
								    congroup->uid().id().c_str(),
								    (*j).c_str());
								nodes.emplace_back(congroup->uid().kind(), congroup->uid().id());
								found = true;
								break;
							}
						}
						if (found)
						{
							break;
						}
					}
				}
			}

			if (nodes.empty())
			{
				// this could also happen if the node has been removed but the backend didn't
				// realized it yet
				LOG_INFO("infra_state: Cannot match host %s, no suitable orchestrator nodes found.",
				         host->uid().id().c_str());
				has_child = false;
			}
			else if (nodes.size() == 1)
			{
				child_uid = *nodes.begin();
			}
			else
			{
				LOG_WARNING(
				    "infra_state: Multiple matches while inserting metadata of host %s inside "
				    "the infrastructure state",
				    host->uid().id().c_str());

				//
				// Tiebreak based on hostName
				//
				bool found = false;
				if (host->tags().find("host.hostName") != host->tags().end())
				{
					for (const auto c_uid : nodes)
					{
						const std::string& key = host_children.find(c_uid.first)->second + ".name";
						if (m_state[c_uid]->tags().find(key) != m_state[c_uid]->tags().end())
						{
							std::string h_hn = m_state[c_uid]->tags().at(key);
							std::string n_hn = host->tags().at("host.hostName");
							std::transform(h_hn.begin(), h_hn.end(), h_hn.begin(), ::tolower);
							std::transform(n_hn.begin(), n_hn.end(), n_hn.begin(), ::tolower);
							if (h_hn == n_hn)
							{
								LOG_DEBUG("infra_state: hostName tiebreak found <%s,%s>",
								          c_uid.first.c_str(),
								          c_uid.second.c_str());
								found = true;
								child_uid = c_uid;
								break;
							}
						}
					}
				}

				if (!found)
				{
					LOG_WARNING(
					    "infra_state: Matching host %s when multiple agents matched based on IP "
					    "but none matched on hostname",
					    host->uid().id().c_str());
					child_uid = *nodes.begin();
				}
			}

			if (has_child)
			{
				//
				// Add the children link, handle_event will take care of connecting the host to the
				// state
				//
				LOG_DEBUG("infra_state: Host %s is parent of <%s,%s>",
				          host->uid().id().c_str(),
				          child_uid.first.c_str(),
				          child_uid.second.c_str());
				draiosproto::congroup_uid* c = host->mutable_children()->Add();
				c->set_kind(child_uid.first);
				c->set_id(child_uid.second);
			}
		}

		if (host->uid().id() == m_machine_id)
		{
			//
			// connect the local host to all the local containers
			//
			const auto containers_info = m_inspector->m_container_manager.get_containers();
			for (auto it = containers_info->begin(), it_end = containers_info->end(); it != it_end;
			     ++it)
			{
				draiosproto::congroup_uid* c = host->mutable_children()->Add();
				c->set_kind("container");
				c->set_id(it->first);
			}
		}

		handle_event(&hevt);

		m_host_events_queue.pop();
	}

	// Now take any registered scopes that have a host component
	// and see if they now match or not.
	for (auto& sit : m_registered_scopes)
	{
		bool old_scope_match = sit.second.m_scope_match;

		// Only need to reevaluate if the scope is a host-level scope.
		if (sit.second.m_host_scope)
		{
			infrastructure_state::uid_t uid = make_pair("host", m_machine_id);

			if (match_scope(uid, sit.second.m_predicates))
			{
				sit.second.m_scope_match = true;
			}
		}

		LOG_INFO("infra_state: refresh_hosts_metadata registered scope %s old match=%d match=%d",
		         sit.first.c_str(),
		         old_scope_match,
		         sit.second.m_scope_match);
	}
}

void infrastructure_state::print_state() const
{
	if (!LOG_WILL_EMIT(Poco::Message::Priority::PRIO_TRACE))
	{
		return;
	}

	LOG_TRACE("infra_state: INFRASTRUCTURE STATE (size: %ld)", m_state.size());

	for (auto it = m_state.begin(), e = m_state.end(); it != e; ++it)
	{
		draiosproto::container_group* cong = it->second.get();
		LOG_TRACE("infra_state:  Container group <%s,%s>%s",
		      cong->uid().kind().c_str(),
		      cong->uid().id().c_str(),
		      m_cg_ttl.find(make_pair(cong->uid().kind(), cong->uid().id())) != m_cg_ttl.end() ? " [REMOVAL REQUESTED]" : "");
		LOG_TRACE("infra_state:   Tags:");
		for (auto t : cong->tags())
			LOG_TRACE("infra_state:    %s:%s", t.first.c_str(), t.second.c_str());
		LOG_TRACE("infra_state:   Int-Tags:");
		for (auto t : cong->internal_tags())
			LOG_TRACE("infra_state:    %s:%s", t.first.c_str(), t.second.c_str());
		LOG_TRACE("infra_state:   IP Addresses:");
		for (auto i : cong->ip_addresses())
			LOG_TRACE("infra_state:    %s", i.c_str());
		LOG_TRACE("infra_state:   Ports:");
		for (auto p : cong->ports())
			LOG_TRACE("infra_state:    %d:%s (target:%d, node:%d, published:%d)",
			          p.port(),
			          p.protocol().c_str(),
			          p.target_port(),
			          p.node_port(),
			          p.published_port());
		LOG_TRACE("infra_state:   Metrics:");
		for (auto m : cong->metrics())
			LOG_TRACE("infra_state:    %s:%g", m.name().c_str(), m.value());
		LOG_TRACE("infra_state:   Parents:");
		for (auto m : cong->parents())
			LOG_TRACE("infra_state:    <%s,%s>", m.kind().c_str(), m.id().c_str());
		LOG_TRACE("infra_state:   Children:");
		for (auto m : cong->children())
			LOG_TRACE("infra_state:    <%s,%s>", m.kind().c_str(), m.id().c_str());
	}
}

void infrastructure_state::print_obj(const uid_t& key) const
{
	if (!LOG_WILL_EMIT(Poco::Message::Priority::PRIO_DEBUG))
	{
		return;
	}

	decltype(m_state)::const_iterator iter = m_state.find(key);
	if (iter == m_state.cend())
	{
		LOG_DEBUG("infra_state: Couldn't find <%s,%s>", key.first.c_str(), key.second.c_str());
	}
	else
	{
		LOG_DEBUG("infra_state: %s", iter->second->DebugString().c_str());
	}
}

// Main method to extract the value of $NAME in "cluster:$NAME"
// IFF a tag called "cluster:" exists in the agent tags.
std::string infrastructure_state::get_cluster_name_from_agent_tags() const
{
	std::string cluster_tag("");
	std::string tags = configuration_manager::instance().get_config<std::string>("tags")->get_value();

	// Matches for pattern:
	// cluster:$NAME    OR
	// ,  cluster:$NAME OR
	// ,cluster:$NAME   OR
	//,cluster :$NAME
	// This is needed to prevent false positive matches
	// for tags like:    foocluster:barvalue
	// The reg_exp captures the value of $NAME
	Poco::RegularExpression reg_exp("(^|,)\\s*cluster:\\s*([A-Za-z0-9]+)");
	std::vector<std::string> match_strings;

	reg_exp.split(tags, match_strings);

	if (match_strings.size() > 0)
	{
		// We have a match ! Match is last entry in
		// the vector of strings.
		cluster_tag = match_strings[match_strings.size() - 1];
	}

	return cluster_tag;
}

// Get the cluster name from 1 of 3 sources.
// Priority order:
// 1.) Get k8s_cluster_name from the config map; if it exists.
// 2.) Get cluster name from "cluster:$NAME" agent tag; if it exists.
// 3.) if above 2 don't exist, get name from GKE cluster or
//     other cluster name source. for now, this is always "default"
std::string infrastructure_state::get_k8s_cluster_name()
{
	// Check local cache first. if not empty return it.
	if (!m_k8s_cluster_name.empty())
	{
		return m_k8s_cluster_name;
	}

	// Priority 1 : get cluster name from k8s_cluster_name config
	if (!m_analyzer.m_configuration->get_k8s_cluster_name().empty())
	{
		m_k8s_cluster_name = m_analyzer.m_configuration->get_k8s_cluster_name();
	}  // Priority 2: get it from agent tag "cluster:*"
	else if (!get_cluster_name_from_agent_tags().empty())
	{
		m_k8s_cluster_name = get_cluster_name_from_agent_tags();
	}  // Priority 3: Get from infra state
	else
	{
		// For now this is always "default".
		// In future this could be obtained from GKE for example.
		m_k8s_cluster_name = "default";
	}

	return m_k8s_cluster_name;
}

// The UID of the default namespace is used as the cluster id
std::string infrastructure_state::get_k8s_cluster_id() const
{
	if (!m_k8s_cached_cluster_id.empty())
	{
		return m_k8s_cached_cluster_id;
	}

	// Skip ahead to namespaces then walk them sequentially
	uid_t lb_key("k8s_namespace", "");
	for (auto it = m_state.lower_bound(lb_key); it != m_state.end(); ++it)
	{
		// it.first is a uid_t
		// it.second is a container_group
		if (it->first.first != "k8s_namespace")
		{
			LOG_DEBUG("infra_state: Unable to find default namespace for cluster id");
			break;
		}
		auto con_tags = it->second->tags();
		auto tag_iter = con_tags.find("kubernetes.namespace.name");
		// This "default" is the namespace name,
		// not to be confused with final return statement below
		if (tag_iter != con_tags.end() && tag_iter->second == "default")
		{
			m_k8s_cached_cluster_id = it->first.second;
			return m_k8s_cached_cluster_id;
		}
	}

	return "";
}

void infrastructure_state::purge_tags_and_copy(uid_t key, const draiosproto::container_group& cg)
{
	ASSERT(m_state.find(key) != std::end(m_state));
	m_state[key]->CopyFrom(cg);

	if (m_k8s_limits)
	{
		m_k8s_limits->purge_tags(*m_state[key].get());
	}
}

bool infrastructure_state::match_scope_all_containers(const scope_predicates& predicates)
{
	uid_t lb_key("container", "");
	for (auto it = m_state.lower_bound(lb_key); it != m_state.end(); ++it)
	{
		// Stop at the first non-container value.
		if (it->first.first != "container")
		{
			break;
		}
		if (match_scope(it->first, predicates))
		{
			return true;
		}
	}

	return false;
}

void infrastructure_state::handle_update_event_thin_cointerface(const draiosproto::congroup_update_event *evt)
{
	auto key = std::make_pair(evt->object().uid().kind(), evt->object().uid().id());

	remove(key, true);

	m_state[key] = make_unique<draiosproto::container_group>();
	purge_tags_and_copy(key, evt->object());

	m_k8s_store_manager.handle_update(key, m_state);
	add_ip_mappings(m_state[key]);
	connect_to_namespace(key);
	connect(key);
}

void infrastructure_state::handle_update_event_no_thin_cointerface(const draiosproto::congroup_update_event *evt)
{
	auto key = std::make_pair(evt->object().uid().kind(), evt->object().uid().id());

	if (evt->object().parents().size() > 0 || evt->object().children().size() > 0 ||
	    evt->object().ports().size() > 0)
	{
		LOG_DEBUG(
			"infra_state: UPDATED event will change relationships, remove the container "
			"group then connect it again");
		remove(key, true);

		m_state[key] = make_unique<draiosproto::container_group>();
		purge_tags_and_copy(key, evt->object());

		add_ip_mappings(m_state[key]);
		connect_to_namespace(key);
		connect(key);
	}
	else
	{
		remove_ip_mappings(m_state[key]);

		LOG_DEBUG(
			"infra_state: UPDATED event will not change relationships, just update the "
			"metadata");
		*m_state[key]->mutable_tags() = evt->object().tags();
		if (m_k8s_limits)
		{
			m_k8s_limits->purge_tags(*m_state[key].get());
		}
		*m_state[key]->mutable_internal_tags() = evt->object().internal_tags();
		m_state[key]->mutable_ip_addresses()->CopyFrom(evt->object().ip_addresses());
		m_state[key]->mutable_metrics()->CopyFrom(evt->object().metrics());

		add_ip_mappings(m_state[key]);
	}
}

bool infrastructure_state::kind_is_allowed(const std::string& kind) const
{
	return m_allow_list_kinds.find(kind) != m_allow_list_kinds.end();
}

void infrastructure_state::add_annotation_filter(const string& ann)
{
	m_annotation_filter.emplace(ann);
}

int infrastructure_state::iterate_tree(bool scan_up,
                                       const uid_t& uid,
                                       cg_cb_t cg_cb,
                                       bool& stop,
                                       std::unordered_set<uid_t>& visited) const
{
	if (visited.find(uid) != visited.end())
	{
		return 0;
	}
	visited.emplace(uid);

	auto it = m_state.find(uid);
	if (it == m_state.end())
	{
		return 0;
	}
	const draiosproto::container_group* cg = it->second.get();

	if (!cg)
	{  // Shouldn't happen
		return 0;
	}

	int sum = 0;
	sum = cg_cb(cg, stop);

	for (const auto& p_uid : (scan_up ? cg->parents() : cg->children()))
	{
		if (stop)
		{
			return sum;
		}
		auto pkey = make_pair(p_uid.kind(), p_uid.id());

		sum += iterate_tree(scan_up, pkey, cg_cb, stop, visited);
	}
	return sum;
}

int infrastructure_state::iterate_parent_tags(const uid_t& uid, tag_cb_t tag_cb) const
{
	// Lambda to iterate over tags within a container group
	infrastructure_state::cg_cb_t cg_cb = [&tag_cb](const draiosproto::container_group* cg,
	                                                bool& stop) -> int {
		int sum = 0;
		for (const auto& tag : cg->tags())
		{
			sum += tag_cb(tag, stop);
			if (stop)
			{
				return sum;
			}
		}
		return sum;
	};

	return iterate_parents(uid, cg_cb);
}

bool infrastructure_state::match_name(const std::string& name, std::string* shortname) const
{
	auto it = m_name_map.find(name);
	if (it == m_name_map.end())
		return false;
	if (shortname != nullptr)
	{
		*shortname = it->second;
	}
	return true;
}

int infrastructure_state::get_scope_names(const uid_t& uid, event_scope* scope) const
{
	// Lambda to iterate over all parent tags
	infrastructure_state::tag_cb_t tag_cb =
	    [this, &scope, &uid](const std::pair<std::string, std::string>& tag, bool& stop) -> int {
		// Look for object name tags and add them to the scope
		if (match_name(tag.first))
		{
			LOG_DEBUG("scope_name: %s:%s tag %s added to scope",
			          uid.first.c_str(),
			          uid.second.c_str(),
			          tag.first.c_str());
			scope->add(tag.first, tag.second);
			return 1;
		}
		return 0;
	};

	return iterate_parent_tags(uid, tag_cb);
}

bool infrastructure_state::find_parent_kind(const uid_t& uid,
                                            const string& kind,
                                            uid_t& found_id) const
{
	// Lambda to iterate over all parent container groups
	infrastructure_state::cg_cb_t cg_cb = [&kind, &found_id](const draiosproto::container_group* cg,
	                                                         bool& stop) -> int {
		if (cg->uid().kind() != kind)
			return 0;
		found_id = make_pair(cg->uid().kind(), cg->uid().id());
		stop = true;
		return 1;
	};

	return iterate_parents(uid, cg_cb) > 0;
}

void infrastructure_state::find_our_k8s_node(const std::vector<string>* container_ids)
{
	if (m_k8s_node_actual)
		return;  // Already found authoritative answer

	uid_t node_uid;
	bool found_node = false;
	bool found_node_through_container = false;
	string source_name;

	sinsp_threadinfo* tinfo = m_inspector->m_thread_manager->get_threads()->get(getpid());
	if (tinfo)
	{
		const auto container = get_container_info(tinfo->m_container_id);
		if (container && !container->m_id.empty())
		{
			uid_t c_uid = make_pair("container", container->m_id);
			if (find_parent_kind(c_uid, "k8s_node", node_uid))
			{
				source_name = "agent container";
				found_node = true;
				found_node_through_container = true;
			}
		}
	}

	if (!found_node && container_ids && !container_ids->empty())
	{
		// Didn't find node through agent container, try one random local container
		// That way we don't waste too much cycles looking for a container connecting
		// to our node, but will at least find it eventually (if there is one)
		uid_t c_uid = make_pair("container", (*container_ids)[random() % container_ids->size()]);
		if (find_parent_kind(c_uid, "k8s_node", node_uid))
		{
			source_name = "container " + c_uid.second;
			found_node = true;
			found_node_through_container = true;
		}
	}

#ifdef FIND_NODE_THROUGH_IP
	// Try and find the node through IP address
	if (!found_node)
	{
		std::set<std::string> ip_addrs;
		if (m_inspector && m_inspector->get_ifaddr_list())
		{
			for (const auto& iface : *m_inspector->get_ifaddr_list()->get_ipv4_list())
			{
				ip_addrs.emplace(iface.address());
			}
		}
		if (ip_addrs.empty())
		{
			LOG_WARNING("infra_state: No IP addresses found");
		}
		else
		{
			for (const auto& i : m_state)
			{
				if (i.first.first != "k8s_node")
					continue;

				std::string name;
				auto cg = i.second.get();

				for (auto ip : cg->ip_addresses())
				{
					if (ip_addrs.find(ip) != ip_addrs.end())
					{
						node_uid = make_pair(cg->uid().kind(), cg->uid().id());
						found_node = true;
						found_node_through_container = false;
						source_name = "IP address: " + ip;
						break;
					}
				}
			}
		}
	}
#endif

	if (found_node && has(node_uid))
	{
		auto* cg = m_state.find(node_uid)->second.get();
		auto tag = cg->tags().find("kubernetes.node.name");

		m_k8s_node_uid = node_uid.second;
		if (tag != cg->tags().end())
		{
			m_k8s_node = tag->second;

			if (found_node_through_container)
			{
				// Only stop trying to find our node if we found it through a container
				// and we have the node name
				m_k8s_node_actual = true;
			}
		}
		else
		{
			LOG_INFO("infra_state: No node name found for UUID %s", node_uid.second.c_str());
			// Use UUID instead
			m_k8s_node = node_uid.second;
		}

		LOG_DEBUG("infra_state: Found our node %s %s through %s",
		          m_k8s_node.c_str(),
		          m_k8s_node_actual ? "definitively" : "temporarily",
		          source_name.c_str());
	}
	else
	{
		LOG_DEBUG("infra_state: Couldn't find our node");
	}
}

const std::string& infrastructure_state::get_k8s_url()
{
	return m_k8s_url;
}

const std::string& infrastructure_state::get_k8s_ca_certificate()
{
	return m_k8s_ca_certificate;
}

const std::string& infrastructure_state::get_k8s_bt_auth_token()
{
	return m_k8s_bt_auth_token;
}

const std::string& infrastructure_state::get_k8s_ssl_certificate()
{
	return m_k8s_ssl_certificate;
}

const std::string& infrastructure_state::get_k8s_ssl_key()
{
	return m_k8s_ssl_key;
}

std::unordered_set<std::string> infrastructure_state::test_only_get_container_ids() const
{
	std::unordered_set<std::string> container_ids;
	for (const auto& obj : m_state)
	{
		auto uid = obj.first;
		if (uid.first == "container")
		{
			container_ids.emplace(uid.second);
		}
	}

	return container_ids;
}

// Look for sysdig agent by pod name, container name or image, or daemonset
// name or label
bool new_k8s_delegator::has_agent(infrastructure_state* state,
                                  const infrastructure_state::uid_t uid,
                                  std::unordered_set<infrastructure_state::uid_t>* visited)
{
	const std::string agentname("sysdig-agent");
	const std::string agentimage("sysdig/agent");

	if (!visited)
	{
		std::unordered_set<infrastructure_state::uid_t> newvis;
		return has_agent(state, uid, &newvis);
	}
	if (!state->has(uid) || (visited->find(uid) != visited->end()))
	{
		return false;
	}
	visited->emplace(uid);

	auto* cg = state->m_state.find(uid)->second.get();

	if (!cg)
	{  // Shouldn't happen
		return false;
	}

	if (uid.first == "k8s_pod")
	{
		// Don't bother looking further under a non-running pod
		// If we can't find phase, assume it's running
		auto phaseit = cg->tags().find("kubernetes.pod.label.status.phase");
		if ((phaseit != cg->tags().end()) && (phaseit->second != "Running"))
		{
			LOG_DEBUG("k8s_deleg: Skipping agent check for non-running pod %s", uid.second.c_str());
			return false;
		}

		auto tag = cg->tags().find("kubernetes.pod.label.name");
		if ((tag != cg->tags().end()) && (tag->second == agentname))
		{
			LOG_DEBUG("k8s_deleg: Found sysdig-agent pod %s", uid.second.c_str());
			return true;
		}

		// Look for parent daemonset with sysdig tags
		for (const auto& parent : cg->parents())
		{
			if (parent.kind() != "k8s_daemonset")
				continue;
			auto pkey = make_pair(parent.kind(), parent.id());
			if (!state->has(pkey))
				break;
			auto* pcg = state->m_state.find(pkey)->second.get();
			if (!pcg)  // Shouldn't happen
				break;
			auto ptag = pcg->tags().find("kubernetes.daemonSet.name");
			auto ptag2 = pcg->tags().find("kubernetes.daemonSet.label.app");
			if (((ptag != pcg->tags().end()) && ptag->second == agentname) ||
			    ((ptag2 != pcg->tags().end()) && ptag2->second == agentname))
			{
				LOG_DEBUG("k8s_deleg: Found sysdig-agent pod %s from daemonset",
				          uid.second.c_str());
				return true;
			}
		}
	}
	else if (uid.first == "container")
	{
		auto tag = cg->tags().find("container.name");
		if ((tag != cg->tags().end()) && (tag->second == agentname))
		{
			LOG_DEBUG("k8s_deleg: Found sysdig-agent container %s", uid.second.c_str());
			return true;
		}
		tag = cg->tags().find("container.label.io.kubernetes.container.name");
		if ((tag != cg->tags().end()) && (tag->second == agentname))
		{
			LOG_DEBUG("k8s_deleg: Found sysdig-agent container label in %s", uid.second.c_str());
			return true;
		}
		tag = cg->tags().find("container.image");
		if ((tag != cg->tags().end()) && !tag->second.compare(0, agentimage.size(), agentimage))
		{
			LOG_DEBUG("k8s_deleg: Found sysdig/agent container image in %s", uid.second.c_str());
			return true;
		}
	}

	for (const auto& c_uid : cg->children())
	{
		auto ckey = make_pair(c_uid.kind(), c_uid.id());

		if (has_agent(state, ckey, visited))
		{
			return true;
		}
	}

	return false;
}

// Find out if our node is one of the delegated ones.
// The first <n> nodes, sorted by uuid, that are running an agent are
// considered delegated.
// If we don't find any other nodes running agents, we're assuming they're all running agents.
bool new_k8s_delegator::is_delegated_now(infrastructure_state* state, int num_delegated)
{
	if (num_delegated < 0)
	{
		LOG_INFO("k8s_deleg: delegation forced by config override");
		return true;
	}
	else if (num_delegated == 0)
	{
		LOG_INFO("k8s_deleg: delegation disabled by config override");
		return false;
	}

	class NodeData
	{
	public:
		NodeData(const std::string& id, const std::string& ips) : m_uuid(id), m_ips(ips) {}
		std::string m_uuid;
		std::string m_ips;
	};
	std::map<std::string, NodeData> nodes;
	std::map<std::string, NodeData> allnodes;

	if (!state->m_inspector || !state->m_inspector->get_ifaddr_list())
	{
		LOG_WARNING("k8s_deleg: No IP addresses found");
		return false;
	}

	for (const auto& i : state->m_state)
	{
		if (i.first.first != "k8s_node")
			continue;

		std::ostringstream os;
		bool found_our_node =
		    (!state->m_k8s_node_uid.empty() && (i.first.second == state->m_k8s_node_uid));

		std::string name;
		auto cg = i.second.get();
		auto tag = cg->tags().find("kubernetes.node.name");
		if (tag != cg->tags().end())
		{
			name = tag->second;
		}
		else
		{
			LOG_INFO("k8s_deleg: No node name found for UUID %s", i.first.second.c_str());
			// Use UUID instead
			name = i.first.second;
		}

		for (auto ip : cg->ip_addresses())
		{
			os << (os.str().empty() ? "" : " ") << ip;
		}

		if (found_our_node)
		{
			LOG_INFO("k8s_deleg: found our node: %s", name.c_str());
		}
		if (found_our_node || has_agent(state, i.first))
		{
			nodes.emplace(name, NodeData(i.first.second, os.str()));
		}
		allnodes.emplace(std::move(name), NodeData(i.first.second, os.str()));
	}

	std::map<std::string, NodeData>* searchnodes = &nodes;
	if (nodes.size() <= 1)
	{
		LOG_DEBUG(
		    "k8s_deleg: Didn't find other agent nodes, assuming all %ld nodes are running agents.",
		    allnodes.size());
		searchnodes = &allnodes;
	}
	bool delegated = false;
	int cnt = 0;
	for (auto it = searchnodes->begin(); (cnt < num_delegated) && it != searchnodes->end();
	     it++, cnt++)
	{
		if (it->second.m_uuid == state->m_k8s_node_uid)
			delegated = true;
		LOG_INFO("k8s_deleg: delegated node %s ips: %s id: %s%s",
		         it->first.c_str(),
		         it->second.m_ips.c_str(),
		         it->second.m_uuid.c_str(),
		         (it->second.m_uuid == state->m_k8s_node_uid) ? " (this node)" : "");
	}

	return delegated;
}

// Cached version of is_delegated_now()
bool new_k8s_delegator::is_delegated(infrastructure_state* state, int num_delegated, uint64_t now)
{
	m_delegation_interval.run(
	    [this, &state, &num_delegated]() {
		    bool deleg = is_delegated_now(state, num_delegated);
		    // Only report as delegated if we're found to be delegated twice in a row.
		    LOG_INFO("k8s_deleg: This node %s delegated",
		             (deleg ? (m_prev_deleg ? "is" : "is not yet") : "is not"));

		    m_cached_deleg = m_prev_deleg && deleg;
		    m_prev_deleg = deleg;
	    },
	    now);
	return m_cached_deleg;
}

std::string infrastructure_state::get_k8s_pod_uid(const std::string& namespace_name,
                                                  const std::string& pod_name) const
{
	// Skip ahead to pods then walk them sequentially
	uid_t lb_key("k8s_pod", "");
	for (auto it = m_state.lower_bound(lb_key); it != m_state.end(); ++it)
	{
		if (it->first.first != "k8s_pod")
		{
			break;
		}
		auto con_tags = it->second->tags();
		auto tag_iter = con_tags.find("kubernetes.pod.name");
		if (tag_iter != con_tags.end() && tag_iter->second == pod_name)
		{
			// check namespace name too, just in case there's collision
			// on the pod name in the cluster (should happen very rarely though)
			std::string ns_name;
			if (find_tag(it->first, "kubernetes.namespace.name", ns_name) &&
			    ns_name == namespace_name)
			{
				return it->first.second;
			}
		}
	}

	return "";
}

std::string infrastructure_state::get_container_id_from_k8s_pod_and_k8s_pod_name(
    const uid_t& p_uid,
    const std::string& pod_container_name) const
{
	if (!has(p_uid))
	{
		return "";
	}

	auto* p_cg = m_state.find(p_uid)->second.get();
	for (const auto& c_uid : p_cg->children())
	{
		auto ckey = make_pair(c_uid.kind(), c_uid.id());

		auto* c_cg = m_state.find(ckey)->second.get();
		if (!c_cg)
		{
			continue;
		}

		auto label = c_cg->tags().find("container.label.io.kubernetes.container.name");
		if ((label != c_cg->tags().end()) && (label->second == pod_container_name))
		{
			return c_uid.id();
		}
		label = c_cg->tags().find("container.name");
		if ((label != c_cg->tags().end()) && (label->second == pod_container_name))
		{
			return c_uid.id();
		}
	}

	return "";
}

std::string infrastructure_state::get_parent_ip_address(const uid_t& uid) const
{
	std::string parent_ip;
	// Lambda to iterate over all parent container groups
	infrastructure_state::cg_cb_t cg_cb = [&parent_ip](const draiosproto::container_group* cg,
	                                                   bool& stop) -> int {
		if ((cg->uid().kind() != "k8s_pod") && (cg->uid().kind() != "k8s_service"))
			return 0;
		if (cg->ip_addresses().empty())
			return 0;
		parent_ip = cg->ip_addresses()[0];
		// Found an ip, stop searching
		stop = true;
		return 1;
	};

	iterate_parents(uid, cg_cb);
	return parent_ip;
}

bool infrastructure_state::find_local_ip(const std::string &src_ip, uid_t *uid) const
{
	if (m_k8s_node_uid.empty())
	{
		LOG_DEBUG("Don't have node. Can't determine if IP is local");
		return false;
	}
	auto node_key = make_pair("k8s_node", m_k8s_node_uid);
	bool found = false;
	uid_t ip_uid;

	// Lambda to iterate over all node children
	infrastructure_state::cg_cb_t cg_cb = [&found, &ip_uid, &src_ip](const draiosproto::container_group* cg,
	                                                   bool& stop) -> int {
		if ((cg->uid().kind() != "k8s_pod") && (cg->uid().kind() != "k8s_node"))
			return 0;
		for (const auto &ip : cg->ip_addresses())
		{
			if (!ip.compare(src_ip))
			{
				found = true;
				ip_uid = make_pair(cg->uid().kind(), cg->uid().id());
				stop = true;
				return 1;
			}
		}
		return 0;
	};

	iterate_children(node_key, cg_cb);
	if (found)
	{
		if (uid)
		{
			*uid = ip_uid;
		}
		LOG_DEBUG("Found ip %s in %s:%s", src_ip.c_str(), ip_uid.first.c_str(),
			ip_uid.second.c_str());
	}
	else
	{
		LOG_DEBUG("Didn't find ip %s in node %s", src_ip.c_str(), m_k8s_node_uid.c_str());
	}
	return found;
}

std::map<infrastructure_state::uid_t, uint32_t> infrastructure_state::get_duplicated_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& links) const
{
	std::map<uid_t, uint32_t> duplicated;
	for(const auto& el : links)
	{
		duplicated[std::make_pair(el.kind(), el.id())]++;
	}

	for(auto pos = duplicated.begin(); pos!=duplicated.end();)
	{
		if(pos->second == 1)
		{
			pos = duplicated.erase(pos);
		}
		else
		{
			pos->second -=1;
			pos ++;
		}
	}
	return duplicated;
}

void infrastructure_state::dump_memory_info() const
{
	auto dump_log = [this]() {
		std::string prefix("MEM DUMP");
		LOG_DEBUG("%s m_orphans size: %ld", prefix.c_str(), m_orphans.size());
		LOG_DEBUG("%s m_parents size: %ld", prefix.c_str(), m_parents.size());
		LOG_DEBUG("%s m_state size: %ld", prefix.c_str(), m_state.size());
		m_k8s_store_manager.print_store_status();

		for (const auto& el : m_state)
		{
			draiosproto::container_group& cg = *el.second.get();

			auto duplicated_parents = get_duplicated_link(cg.parents());
			auto duplicated_children = get_duplicated_link(cg.children());

			for (const auto& dup : duplicated_parents)
			{
				LOG_DEBUG("%s container_group <%s,%s> has parent <%s,%s> duplicated %d times",
				          prefix.c_str(),
				          el.first.first.c_str(),
				          el.first.second.c_str(),
				          dup.first.first.c_str(),
				          dup.first.second.c_str(),
				          dup.second);
				LOG_DEBUG("%s", cg.DebugString().c_str());
			}

			for (const auto& dup : duplicated_children)
			{
				LOG_DEBUG("%s container_group <%s,%s> has child <%s,%s> duplicated %d times",
				          prefix.c_str(),
				          el.first.first.c_str(),
				          el.first.second.c_str(),
				          dup.first.first.c_str(),
				          dup.first.second.c_str(),
				          dup.second);
			}
		}
	};

	static ratelimit r(1, 30*NSECS_PER_SEC);
	r.run(dump_log);
}

const std::string infrastructure_state::POD_STATUS_PHASE_LABEL = "kubernetes.pod.label.status.phase";
const std::string infrastructure_state::UNSCHEDULABLE_TAG = "kubernetes.pod.label.status.unschedulable";
const std::string infrastructure_state::CONTAINER_WAITING_METRIC_NAME = "kubernetes.pod.container.waiting";
const std::string infrastructure_state::CONTAINER_TERMINATED_METRIC_NAME = "kubernetes.pod.container.terminated";
const std::string infrastructure_state::CONTAINER_ID_TAG = "containerId";
const std::string infrastructure_state::CONTAINER_STATUS_REASON_TAG = "reason";
#endif  // CYGWING_AGENT
