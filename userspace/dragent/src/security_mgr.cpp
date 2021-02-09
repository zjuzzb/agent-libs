#ifndef CYGWING_AGENT

#include <sstream>
#include <string>

#include <google/protobuf/text_format.h>

#include "sinsp_worker.h"
#include "infrastructure_state.h"
#include "common_logger.h"
#include "configuration_manager.h"

#include "security_config.h"
#include "security_mgr.h"

// we get nlohmann jsons from falco k8s audit, while dragent dragent
// generally uses the `jsoncpp' library
#include <nlohmann/json.hpp>

using namespace std;
using nlohmann::json;
using namespace libsanalyzer;

namespace
{
COMMON_LOGGER();
}

type_config<bool> security_mgr::c_event_labels_enabled(
        true,
        "Policy Events Labels enabled",
        "event_labels", "enabled");

type_config<int> security_mgr::c_event_labels_max_agent_tags(
		30,
		"Event Labels - Max agent tags to be considered",
		"event_labels", "max_agent_tags"
		);

type_config<std::vector<std::string>> security_mgr::c_event_labels_include(
		{},
		"Event Labels included",
		"event_labels", "include"
		);

type_config<std::vector<std::string>> security_mgr::c_event_labels_exclude(
		{},
		"Event Labels excluded",
		"event_labels", "exclude"
);

std::string security_mgr::m_empty_container_id = "";

// XXX/mstemm TODO
// - Is there a good way to immediately check the status of a sysdig capture that I can put in the action result?
// - The currently event handling doesn't actually work with on
// - default, where no policy matches. I think I need to have special
// - case for when the hash table doesn't match anything.

// Refactor TODO
// - Double check for proper use of std:: namespace
// - Double check for proper includes in all files
// - Add unit tests
// - Make sure all objects will gracefully fail if init() is not called

security_mgr::security_mgr(const string& install_root,
			   security_result_handler& result_handler)
	: m_initialized(false),
	  m_inspector(NULL),
	  m_result_handler(result_handler),
	  m_infra_state(NULL),
	  m_k8s_audit_evt_sink(NULL),
	  m_capture_job_queue_handler(NULL),
	  m_configuration(NULL),
	  m_install_root(install_root),
	  m_cointerface_sock_path("unix:" + install_root + "/run/cointerface.sock"),
	  m_last_pid(0),
	  m_last_security_rules_group(m_null_security_rules),
	  m_k8s_audit_server_started(false)
{
	m_security_evt_metrics = {make_shared<security_evt_metrics>(m_process_metrics), make_shared<security_evt_metrics>(m_container_metrics),
				  make_shared<security_evt_metrics>(m_readonly_fs_metrics),
				  make_shared<security_evt_metrics>(m_readwrite_fs_metrics),
				  make_shared<security_evt_metrics>(m_nofd_readwrite_fs_metrics),
				  make_shared<security_evt_metrics>(m_net_inbound_metrics), make_shared<security_evt_metrics>(m_net_outbound_metrics),
				  make_shared<security_evt_metrics>(m_tcp_listenport_metrics), make_shared<security_evt_metrics>(m_udp_listenport_metrics),
				  make_shared<security_evt_metrics>(m_syscall_metrics), make_shared<security_evt_metrics>(m_falco_metrics)};
	scope_predicates preds;
	security_rules_group dummy(preds, m_inspector, m_configuration);
	dummy.init_metrics(m_security_evt_metrics);
	configure_event_labels_set();

	m_parse_evts_falco_engine = make_shared<falco_engine>(true, m_configuration->c_root_dir.get_value() + "/share/lua/");
}

security_mgr::~security_mgr()
{
	if (security_config::instance().get_k8s_audit_server_enabled())
	{
	    stop_k8s_audit_server();
	}
}

void security_mgr::init(sinsp *inspector,
			const std::string &agent_container_id,
			infrastructure_state_iface *infra_state,
			secure_k8s_audit_event_sink_iface *k8s_audit_evt_sink,
			capture_job_queue_handler *capture_job_queue_handler,
			dragent_configuration *configuration,
			const internal_metrics::sptr_t& metrics)

{
	m_inspector = inspector;
	m_infra_state = infra_state;
	m_k8s_audit_evt_sink = k8s_audit_evt_sink;
	m_capture_job_queue_handler = capture_job_queue_handler;
	m_configuration = configuration;

	m_inspector->m_container_manager.subscribe_on_new_container([this](const sinsp_container_info &container_info, sinsp_threadinfo *tinfo) {
		on_new_container(container_info, tinfo);
	});
	m_inspector->m_container_manager.subscribe_on_remove_container([this](const sinsp_container_info &container_info) {
		on_remove_container(container_info);
	});

	m_report_events_interval = make_unique<run_on_interval>(security_config::instance().get_report_interval_ns());
	m_report_throttled_events_interval = make_unique<run_on_interval>(security_config::instance().get_throttled_report_interval_ns());

	m_actions_poll_interval = make_unique<run_on_interval>(security_config::instance().get_actions_poll_interval_ns());

	// Only check the above every second
	m_check_periodic_tasks_interval = make_unique<run_on_interval>(1000000000);

	m_check_k8s_audit_start_interval = make_unique<run_on_interval>(security_config::instance().get_k8s_audit_server_refresh_interval());

	m_coclient = make_shared<coclient>(m_install_root);

	m_actions.init(this,
		       agent_container_id,
		       m_coclient,
		       m_infra_state);

	if (metrics != nullptr)
	{
		for(auto &metric : m_security_evt_metrics)
		{
			metric->reset();
			metrics->add_ext_source(metric.get());
		}
		m_metrics.reset();
		metrics->add_ext_source(&m_metrics);
	}

	m_k8s_audit_events_queue = make_shared<tbb::concurrent_queue<sdc_internal::k8s_audit_event>>();

	m_grpc_channel = libsinsp::grpc_channel_registry::get_channel(m_cointerface_sock_path);

	if (security_config::instance().get_k8s_audit_server_enabled())
	{
		start_k8s_audit_server();
	}

	m_initialized = true;
}

bool security_mgr::request_load_policies_v2_file(const char *filename, std::string &errstr)
{
	draiosproto::policies_v2 policies_v2;

	int fd = open(filename, O_RDONLY);
	google::protobuf::io::FileInputStream fstream(fd);
	if (!google::protobuf::TextFormat::Parse(&fstream, &policies_v2)) {
		errstr = string("Failed to parse policies file ")
			+ filename;
		close(fd);
		return false;
	}
	close(fd);

	request_load_policies_v2(policies_v2);

	return true;
}

security_mgr::loaded_v2_policies::loaded_v2_policies(sinsp *inspector,
						     dragent_configuration *configuration,
						     std::shared_ptr<draiosproto::policies_v2> policies_v2_msg,
						     metrics &security_mgr_metrics,
						     std::list<std::shared_ptr<security_evt_metrics>> &security_evt_metrics)
	: m_inspector(inspector),
	  m_configuration(configuration),
	  m_policies_v2_msg(policies_v2_msg),
	  m_metrics(security_mgr_metrics),
	  m_security_evt_metrics(security_evt_metrics)
{
	m_fastengine_rules_library = make_shared<security_rule_library>();

	m_evttypes.assign(PPM_EVENT_MAX+1, false);
}

security_mgr::loaded_v2_policies::~loaded_v2_policies()
{
}

void security_mgr::loaded_v2_policies::load_syscall_policy_v2(infrastructure_state_iface *infra_state,
							      std::shared_ptr<security_policy_v2> spolicy_v2,
							      std::list<std::string> &ids)
{
	LOG_DEBUG("Loading syscall v2 policy " + spolicy_v2->DebugString() +
		     ", testing against set of " + to_string(ids.size()) +
		     " container ids");

	for (const auto &id : ids)
	{
		if(spolicy_v2->match_syscall_scope(id, infra_state))
		{
			LOG_DEBUG("Policy " + spolicy_v2->name() + " matched scope for container " + id);

			// get/create the policies group and add the policy
			std::shared_ptr<security_rules_group> grp;

			grp = get_rules_group_of(spolicy_v2->scope_predicates());
			grp->add_policy(spolicy_v2);
			m_scoped_security_rules[id].emplace(grp);
		}
		else
		{
			LOG_DEBUG("Policy " + spolicy_v2->name() + " did not match scope for container " + id);
		}
	}
}

void security_mgr::loaded_v2_policies::load_k8s_audit_policy_v2(std::shared_ptr<security_policy_v2> spolicy_v2)
{
	LOG_DEBUG("Loading v2 policy " + spolicy_v2->DebugString() +
		     ", adding to k8s rules group");

	// Also, always add to the k8s rules group without checking
	// scopes. We'll check the scopes as the events arrive.
	std::shared_ptr<security_rules_group> grp = make_shared<security_rules_group>(
		spolicy_v2->scope_predicates(), m_inspector, m_configuration);
	grp->init(m_falco_engine, m_fastengine_rules_library, m_security_evt_metrics);

	grp->add_policy(spolicy_v2);

	LOG_DEBUG("Creating K8s Audit Rules Group: " + grp->to_string());
	m_k8s_audit_security_rules.emplace_back(grp);
}

bool security_mgr::loaded_v2_policies::load_falco_rules_files(const draiosproto::falco_rules_files &files, std::string &errstr)
{
	bool verbose = false;
	bool all_events = false;

	for(auto &file : files.files())
	{
		// Find the variant that has the highest required
		// engine version that is compatible with our engine
		// version.
		int best_variant = -1;
		uint32_t best_engine_version = 0;

		for(int i=0; i < file.variants_size(); i++)
		{
			auto &variant = file.variants(i);

			if(variant.required_engine_version() <= m_falco_engine->engine_version() &&
			   ((variant.required_engine_version() > best_engine_version) ||
			    (best_variant == -1)))
			{
				best_variant = i;
				best_engine_version=variant.required_engine_version();
			}
		}

		if(best_variant == -1)
		{
			LOG_INFO("Could not find any compatible variant for falco rules file " + file.filename() + ", skipping");
		}
		else
		{
			try {
				LOG_INFO("Loading falco rules content tag=" + files.tag() +
				         " filename=" + file.filename() +
					 " required_engine_version=" + to_string(best_engine_version));
				m_falco_engine->load_rules(file.variants(best_variant).content(),
							   verbose, all_events);
			}
			catch (falco_exception &e)
			{
				errstr = e.what();
				return false;
			}
		}
	}

	return true;
}

void security_mgr::loaded_v2_policies::match_policy_scopes(infrastructure_state_iface *infra_state,
							   std::list<std::string> &container_ids)
{
	if(infra_state)
	{
		infra_state->clear_scope_cache();
	}

	uint64_t num_enabled = 0;

	for(auto &policy : m_policies_v2_msg->policy_list())
	{
		std::shared_ptr<security_policy_v2> spolicy = std::make_shared<security_policy_v2>(policy);
		m_policies_v2.insert(make_pair(policy.id(), spolicy));

		if(policy.enabled())
		{
			if (policy.policy_type() == "" ||
			    policy.policy_type() == "falco")
			{
				// Policy type falco really means policies that work
				// on syscalls, whether they use falco rules or fast
				// engine rules. Blank is for backwards compatibility,
				// where policies did not have a policy_type.

				load_syscall_policy_v2(infra_state, spolicy, container_ids);
				num_enabled++;
			}
			else if (policy.policy_type() == "k8s_audit")
			{
				load_k8s_audit_policy_v2(spolicy);
				num_enabled++;
			}
			else
			{
				LOG_DEBUG("Unknown policy type \"%s\", skipping", policy.policy_type().c_str());
			}
		}
	}

	for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
	{
		for(const auto &group: m_rules_groups)
		{
			m_evttypes[evttype] = m_evttypes[evttype] | group->m_evttypes[evttype];
		}
	}

	log_rules_group_info();

	m_metrics.set_policies_count(m_policies_v2_msg->policy_list().size(), num_enabled);
}

bool security_mgr::loaded_v2_policies::load(std::string &errstr)
{
	LOG_DEBUG("Loading policies_v2 message: " + m_policies_v2_msg->DebugString());

	m_fastengine_rules_library->reset();

	m_falco_engine = make_shared<falco_engine>(true, m_configuration->c_root_dir.get_value() + "/share/lua/");
	m_falco_engine->set_inspector(m_inspector);
	m_falco_engine->set_sampling_multiplier(m_configuration->m_falco_engine_sampling_multiplier);

	// Load all falco rules files into the engine. We'll selectively
	// enable them based on the contents of the policies.

	if(m_policies_v2_msg->has_falco_group())
	{
		if(m_policies_v2_msg->falco_group().has_default_files())
		{
			if(!load_falco_rules_files(m_policies_v2_msg->falco_group().default_files(), errstr))
			{
				return false;
			}
		}

		if(m_policies_v2_msg->falco_group().has_custom_files())
		{
			if (!load_falco_rules_files(m_policies_v2_msg->falco_group().custom_files(), errstr))
			{
				return false;
			}
		}
	}

	if(m_policies_v2_msg->has_fastengine_files())
	{
		for(auto &rules_file : m_policies_v2_msg->fastengine_files().files())
		{
			if(rules_file.has_json_content())
			{
				m_fastengine_rules_library->parse(rules_file.json_content());
			}
		}
	}

	return true;
}

void security_mgr::loaded_v2_policies::log_rules_group_info()
{
	if(!m_rules_groups.empty())
	{
		LOG_INFO(to_string(m_rules_groups.size()) + " rules groups loaded");
		if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG)
		{
			for (const auto &group : m_rules_groups)
			{
				LOG_DEBUG(group->to_string());
			}
			LOG_DEBUG("splitted between " + to_string(m_scoped_security_rules.size()) + " entities as follows:");
			for (const auto &it : m_scoped_security_rules)
			{
				string str = "  " + (it.first.empty() ? "host" : it.first) + ": { ";
				for(const auto &group: it.second)
				{
					str += group->to_string() + ", ";
				}
				str = str.substr(0, str.size() - 2) + " }";
				LOG_DEBUG(str);
			}
		}
	}
}

security_mgr::security_rules_group_set &security_mgr::loaded_v2_policies::get_rules_group_for_container(std::string &container_id)
{
	return m_scoped_security_rules[container_id];
}

std::list<std::shared_ptr<security_mgr::security_rules_group>> security_mgr::loaded_v2_policies::get_k8s_audit_security_rules()
{
	return m_k8s_audit_security_rules;
}

bool security_mgr::loaded_v2_policies::match_evttype(int etype)
{
	return m_evttypes[etype];
}

// This is expected to be called from a different thread than the one
// calling security_mgr::process_event().
void security_mgr::request_load_policies_v2(const draiosproto::policies_v2 &policies_v2)
{
	m_policies_v2_msg.reset(new draiosproto::policies_v2(policies_v2));

	load_policies_v2_async();
}

void security_mgr::request_reload_policies_v2()
{
	load_policies_v2_async();
}

bool security_mgr::wait_load_policies_v2(uint32_t secs)
{
	return (m_loaded_v2_policies_future.valid() &&
		m_loaded_v2_policies_future.wait_for(std::chrono::seconds(secs)) == std::future_status::ready);
}

void security_mgr::load_policies_v2_async()
{
	// If a load is already in progress, no need to do anything
	if(m_loaded_v2_policies_future.valid())
	{
		LOG_DEBUG("Policies v2 load already in progress, not doing anything");
		return;
	}

	auto loader = [this](std::shared_ptr<draiosproto::policies_v2> policies_v2_msg)
        {
		load_policies_result ret;

		ret.loaded_policies = std::make_shared<loaded_v2_policies>(m_inspector,
									   m_configuration,
									   policies_v2_msg,
									   m_metrics,
									   m_security_evt_metrics);

		std::string errstr;
		if (!ret.loaded_policies->load(errstr))
		{
			LOG_ERROR("Could not load policies_v2 message: " + errstr);
			ret.successful = false;
		} else {
			ret.successful = true;
			m_received_policies = true;
		}

		return ret;
	};

	m_loaded_v2_policies_future = std::async(std::launch::async, loader, m_policies_v2_msg);
}

bool security_mgr::event_qualifies(sinsp_evt *evt)
{
	// if this event is from a docker container and the process name starts with
	// runc, filter it out since behaviors from those processes cannot really
	// be considered neither host nor container events.

	// The checks are intentionally ordered from the fastest to the slowest,
	// so we first check if the process is runc and if we have a container event,
	// and only if that's true we check if it's a docker container event.

	// CONTAINER_JSON events are always ok as the rules that use
	// container events focus on container properties.
	if(evt->get_type() == PPME_CONTAINER_JSON_E)
	{
		return true;
	}

	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(tinfo == NULL)
	{
		return true;
	}

	if(tinfo->m_container_id.empty() || strncmp(tinfo->get_comm().c_str(), "runc:[", 6) != 0)
	{
		return true;
	}

	const auto container_info = m_inspector->m_container_manager.get_container(tinfo->m_container_id);
	if(!container_info)
	{
		return true;
	}

	if(is_docker_compatible(container_info->m_type))
	{
		return false;
	}

	// ...

	return true;
}

bool security_mgr::event_qualifies(json_event *evt)
{

	return true;
}

void security_mgr::perform_periodic_tasks(uint64_t ts_ns)
{
	m_check_periodic_tasks_interval->run([this, ts_ns]()
        {
		// Possibly report the current set of events.
		m_report_events_interval->run([this, ts_ns]()
                {
			report_events(ts_ns);
		}, ts_ns);

		// Possibly report counts of the number of throttled policy events.
		m_report_throttled_events_interval->run([this, ts_ns]()
		{
			report_throttled_events(ts_ns);
		}, ts_ns);

		// Drive the coclient loop to pick up any async grpc responses
		m_actions_poll_interval->run([this, ts_ns]()
                {
			m_coclient->process_queue();
			m_actions.periodic_cleanup(ts_ns);
		}, ts_ns);

		if (security_config::instance().get_k8s_audit_server_enabled())
		{
			m_check_k8s_audit_start_interval->run([this, ts_ns]()
                        {
				if(!m_k8s_audit_server_started)
				{
					start_k8s_audit_server();
				}
			}, ts_ns);

			check_pending_k8s_audit_events();
		}
	}, ts_ns);
}

bool security_mgr::should_evaluate_event(gen_event *evt,
					 uint64_t ts_ns,
					 std::string* &container_id_ptr,
					 sinsp_threadinfo **tinfo)
{
	bool evaluate_event = false;
	sinsp_evt *sevt;

	switch (evt->get_source())
	{
	case ESRC_SINSP:
		// Consider putting this in check_periodic_tasks above.
		m_actions.check_outstanding_actions(ts_ns);

		sevt = static_cast<sinsp_evt *>(evt);

		*tinfo = sevt->get_thread_info();

		if(!m_loaded_policies->match_evttype(sevt->get_type()))
		{
			m_metrics.incr(metrics::MET_MISS_EVTTYPE);
		}
		else if(!event_qualifies(sevt))
		{
			m_metrics.incr(metrics::MET_MISS_QUAL);
		}
		else if(!*tinfo)
		{
			m_metrics.incr(metrics::MET_MISS_TINFO);
		}
		else
		{
			container_id_ptr = &((*tinfo)->m_container_id);
			evaluate_event = true;

		}
		break;
	case ESRC_K8S_AUDIT:
		evaluate_event = true;
		break;
	default:
		LOG_ERROR("Invalid event source" + std::to_string(evt->get_source()));
		break;
	}

	return evaluate_event;

}

void security_mgr::process_event(gen_event *evt)
{
	uint64_t ts_ns = evt->get_ts();
	perform_periodic_tasks(ts_ns);

	return process_event_v2(evt);
}

void security_mgr::process_event_v2(gen_event *evt)
{
	if(m_loaded_v2_policies_future.valid() &&
	   m_loaded_v2_policies_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
	{
		load_policies_result ret = m_loaded_v2_policies_future.get();

		if (ret.successful)
		{
			m_loaded_policies = ret.loaded_policies;

			// The rules/policies have been loaded in the
			// background. In this thread, we need to
			// iterate over all existing containers and
			// identify which containers match the scope
			// of each policy. That can't be done in the
			// background as infra_state/get_containers()
			// aren't thread safe.
			std::list<std::string> ids{
				"" // tinfo.m_container_id is empty for host events
			};
			const auto &containers = *m_inspector->m_container_manager.get_containers();
			for (const auto &c : containers)
			{
				ids.push_back(c.first);
			}

			m_loaded_policies->match_policy_scopes(m_infra_state, ids);
			m_last_pid = 0;
		}
	}

	if (!m_loaded_policies)
	{
		return;
	}

	uint64_t ts_ns = evt->get_ts();

	std::string *container_id_ptr = &m_empty_container_id;
	sinsp_threadinfo *tinfo = NULL;

	if (should_evaluate_event(evt, ts_ns, container_id_ptr, &tinfo))
	{
		std::list<security_rules::match_result> *results = NULL;

		if(evt->get_source() == ESRC_SINSP)
		{
			if(tinfo->m_pid != m_last_pid)
			{
				m_last_security_rules_group =
					m_loaded_policies->get_rules_group_for_container(*container_id_ptr);
			}
			m_last_pid = tinfo->m_pid;

			for (const auto &group : m_last_security_rules_group.get())
			{
				std::list<security_rules::match_result> *gresults;

				gresults = group->match_event(evt);

				if(gresults)
				{
					if(!results)
					{
						results = gresults;
					}
					else
					{
						results->splice(results->end(), *gresults);
						delete gresults;
					}
				}
			}
		}
		else if (evt->get_source() == ESRC_K8S_AUDIT)
		{
			json_event *j_evt = static_cast<json_event *>(evt);

			for (const auto &group : m_loaded_policies->get_k8s_audit_security_rules())
			{
				// The scope must match the event
				if(m_k8s_audit_infra_state.match_scope(j_evt, m_infra_state->get_k8s_cluster_name(), group->m_scope_predicates))
				{
					std::list<security_rules::match_result> *gresults;

					gresults = group->match_event(evt);

					if(gresults)
					{
						if(!results)
						{
							results = gresults;
						}
						else
						{
							results->splice(results->end(), *gresults);
							delete gresults;
						}
					}
				}
			}
		}
		else
		{
			LOG_DEBUG("Found unexpected event type " + to_string(evt->get_source()) + ", not matching against any security rules groups");
		}

		if(!results)
		{
			return;
		}

		// Take all actions for all results
		for(auto &result : *results)
		{
			LOG_DEBUG("Taking action via policy: " + result.m_policy->name() + ". detail=" + result.m_detail.DebugString());

			if(throttle_policy_event(ts_ns, (*container_id_ptr), result.m_policy->id(), result.m_policy->name()))
			{
				uint64_t policy_version = 2;

				add_policy_event_metrics(result);

				draiosproto::policy_event *event = create_policy_event(evt,
										       (*container_id_ptr),
										       tinfo,
										       result.m_policy->id(),
										       result.m_detail,
										       policy_version);

				// Not throttled--perform the actions associated
				// with the policy. The actions will add their action
				// results to the policy event as they complete.
				m_actions.perform_actions(ts_ns,
							  tinfo,
							  result.m_policy->name(),
							  result.m_policy->policy_type(),
							  result.m_policy->actions(),
							  result.m_policy->v2actions(),
							  event);
			}
		}

		delete results;
	}
}

bool security_mgr::start_capture(uint64_t ts_ns,
				 const string &policy,
				 const string &token, const string &filter,
				 uint64_t before_event_ns, uint64_t after_event_ns,
				 bool apply_scope, std::string &container_id,
				 uint64_t pid,
				 std::string &errstr)
{
	std::shared_ptr<capture_job_queue_handler::dump_job_request> job_request =
		std::make_shared<capture_job_queue_handler::dump_job_request>();

	job_request->m_start_details = make_unique<capture_job_queue_handler::start_job_details>();

	job_request->m_request_type = capture_job_queue_handler::dump_job_request::JOB_START;
	job_request->m_token = token;

	job_request->m_start_details->m_filter = filter;

	if(apply_scope && container_id != "")
	{
		// Limit the capture to the container where the event occurred.
		if(!job_request->m_start_details->m_filter.empty())
		{
			job_request->m_start_details->m_filter += " and ";
		}

		job_request->m_start_details->m_filter += "container.id=" + container_id;
	}

	job_request->m_start_details->m_duration_ns = after_event_ns;
	job_request->m_start_details->m_past_duration_ns = before_event_ns;
	job_request->m_start_details->m_start_ns = ts_ns;
	job_request->m_start_details->m_notification_desc = policy;
	job_request->m_start_details->m_notification_pid = pid;
	job_request->m_start_details->m_defer_send = true;

	// Note: Not enforcing any maximum size.
	return m_capture_job_queue_handler->queue_job_request(m_inspector, job_request, errstr);
}

void security_mgr::start_sending_capture(const string &token)
{
	string errstr;

	std::shared_ptr<capture_job_queue_handler::dump_job_request> job_request =
		std::make_shared<capture_job_queue_handler::dump_job_request>();

	job_request->m_request_type = capture_job_queue_handler::dump_job_request::JOB_SEND_START;
	job_request->m_token = token;

	if (!m_capture_job_queue_handler->queue_job_request(m_inspector, job_request, errstr))
	{
		LOG_ERROR("security_mgr::start_sending_capture could not start sending capture token=" + token + "(" + errstr + "). Trying to stop capture.");
		stop_capture(token);
	}
}

void security_mgr::stop_capture(const string &token)
{
	string errstr;

	std::shared_ptr<capture_job_queue_handler::dump_job_request> stop_request =
		std::make_shared<capture_job_queue_handler::dump_job_request>();

	stop_request->m_stop_details = make_unique<capture_job_queue_handler::stop_job_details>();

	stop_request->m_request_type = capture_job_queue_handler::dump_job_request::JOB_STOP;
	stop_request->m_token = token;

	// Any call to security_mgr::stop_capture is for an aborted
	// capture, in which case the capture should not be sent at all.
	stop_request->m_stop_details->m_remove_unsent_job = true;

	if (!m_capture_job_queue_handler->queue_job_request(m_inspector, stop_request, errstr))
	{
		LOG_CRITICAL("security_mgr::start_sending_capture could not stop capture token=" + token + "(" + errstr + ")");

		// This will result in a capture that runs to
		// completion but is never sent, and a file on
		// disk that is never cleaned up.
	}
}

void security_mgr::send_policy_event(uint64_t ts_ns, shared_ptr<draiosproto::policy_event> &event, bool send_now)
{
	// Not throttled, queue the policy event or send
	// immediately.
	if(send_now)
	{
		draiosproto::policy_events events;
		events.set_machine_id(m_configuration->machine_id());
		events.set_customer_id(m_configuration->m_customer_id);
		draiosproto::policy_event *new_event = events.add_events();
		new_event->MergeFrom(*event);
		report_events_now(ts_ns, events);
	}
	else
	{
		draiosproto::policy_event *new_event = m_events.add_events();
		new_event->MergeFrom(*event);
	}
}

bool security_mgr::throttle_policy_event(uint64_t ts_ns,
					 std::string &container_id,
					 uint64_t policy_id,
					 const std::string &policy_name)
{
	bool accepted = true;

	// Find the matching token bucket, creating it if necessary
	rate_limit_scope_t scope(container_id, policy_id);

	auto it = m_policy_rates.lower_bound(rate_limit_scope_t(scope));

	if (it == m_policy_rates.end() ||
	    it->first != scope)
	{
		it = m_policy_rates.emplace_hint(it, make_pair(scope, token_bucket()));
		it->second.init(security_config::instance().get_policy_events_rate(),
		                security_config::instance().get_policy_events_max_burst(),
		                ts_ns);

		LOG_DEBUG("security_mgr::accept_policy_event creating new token bucket for policy=" + policy_name
			     + ", container=" + container_id);
	}

	if(it->second.claim(1, ts_ns))
	{
		LOG_DEBUG("security_mgr::accept_policy_event allowing policy=" + policy_name
			     + ", container=" + container_id
			     + ", tokens=" + NumberFormatter::format(it->second.get_tokens()));
	}
	else
	{
		accepted = false;

		// Throttled. Increment the throttled count.

		auto it2 = m_policy_throttled_counts.lower_bound(rate_limit_scope_t(scope));

		if (it2 == m_policy_throttled_counts.end() ||
		    it2->first != scope)
		{
			it2 = m_policy_throttled_counts.emplace_hint(it2, make_pair(scope, 0));
		}

		it2->second = it2->second + 1;

		LOG_DEBUG("security_mgr::accept_policy_event throttling policy=" + policy_name
			     + ", container=" + container_id
			     + ", tcount=" + NumberFormatter::format(it2->second));
	}

	return accepted;
}

void security_mgr::add_policy_event_metrics(const security_rules::match_result &res)
{
	m_metrics.incr(metrics::MET_POLICY_EVTS);
	switch(res.m_rule_type)
	{
	case draiosproto::PTYPE_PROCESS:
		m_metrics.incr(metrics::MET_POLICY_EVTS_PROCESS);
		break;
	case draiosproto::PTYPE_CONTAINER:
		m_metrics.incr(metrics::MET_POLICY_EVTS_CONTAINER);
		break;
	case draiosproto::PTYPE_FILESYSTEM:
		m_metrics.incr(metrics::MET_POLICY_EVTS_FILESYSTEM);
		break;
	case draiosproto::PTYPE_NETWORK:
		m_metrics.incr(metrics::MET_POLICY_EVTS_NETWORK);
		break;
	case draiosproto::PTYPE_SYSCALL:
		m_metrics.incr(metrics::MET_POLICY_EVTS_SYSCALL);
		break;
	case draiosproto::PTYPE_FALCO:
		m_metrics.incr(metrics::MET_POLICY_EVTS_FALCO);
		break;
	default:
		LOG_ERROR("Unknown policy type " + to_string(res.m_rule_type));
		break;
	}

	// If the policy has a severity field, map the severity as
	// number to one of the values low, medium, high and increment
	if(res.m_policy->has_severity())
	{
		if(res.m_policy->severity() <= 3)
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_HIGH);
		}
		else if (res.m_policy->severity() <= 5)
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_MEDIUM);
		}
		else
		{
			m_metrics.incr(metrics::MET_POLICY_EVTS_SEV_LOW);
		}
	}

	m_metrics.incr_policy(res.m_policy->name());
}

draiosproto::policy_event * security_mgr::create_policy_event(gen_event *evt,
							      std::string &container_id,
							      sinsp_threadinfo *tinfo,
							      uint64_t policy_id,
							      draiosproto::event_detail *details,
							      uint64_t policy_version)
{
	draiosproto::policy_event *event = new draiosproto::policy_event();

	int64_t ts_ns = evt->get_ts();
	uint16_t event_source = evt->get_source();

	event->set_timestamp_ns(ts_ns);
	event->set_policy_id(policy_id);
	event->set_policy_version(policy_version);
	if(!container_id.empty())
	{
		event->set_container_id(container_id);
	}

	event->set_allocated_event_details(details);

	// If the policy event comes from falco, copy the information
	// to the falco_details section of the policy event. This is
	// for backwards compatibility with older backend versions.
	if(details->has_output_details() && details->output_details().output_type() == draiosproto::PTYPE_FALCO)
	{
		draiosproto::falco_event_detail *fdet = event->mutable_falco_details();
		fdet->set_rule(details->output_details().output_fields().at("falco.rule"));
		fdet->set_output(details->output_details().output());
	}

	if (c_event_labels_enabled.get_value())
	{
		if (event_source == ESRC_K8S_AUDIT)
		{
			json_event *j_evt = static_cast<json_event *>(evt);
			set_event_labels_k8s_audit(details, event, j_evt);
		}
		else
		{
			set_event_labels(container_id, tinfo, event);
		}
	}
	return event;
}

draiosproto::policy_event * security_mgr::create_policy_event(gen_event *evt,
							      std::string &container_id,
							      sinsp_threadinfo *tinfo,
							      uint64_t policy_id,
							      draiosproto::event_detail &details,
							      uint64_t policy_version)
{
	draiosproto::policy_event *event = new draiosproto::policy_event();

	int64_t ts_ns = evt->get_ts();
	uint16_t event_source = evt->get_source();

	event->set_timestamp_ns(ts_ns);
	event->set_policy_id(policy_id);
	event->set_policy_version(policy_version);
	if(!container_id.empty())
	{
		event->set_container_id(container_id);
	}

	draiosproto::event_detail* mdetails = event->mutable_event_details();
	*mdetails = details;

	// If the policy event comes from falco, copy the information
	// to the falco_details section of the policy event. This is
	// for backwards compatibility with older backend versions.
	if(details.has_output_details() && details.output_details().output_type() == draiosproto::PTYPE_FALCO)
	{
		draiosproto::falco_event_detail *fdet = event->mutable_falco_details();
		fdet->set_rule(details.output_details().output_fields().at("falco.rule"));
		fdet->set_output(details.output_details().output());
	}

	if (c_event_labels_enabled.get_value())
	{
		if (event_source == ESRC_K8S_AUDIT)
		{
			json_event *j_evt = static_cast<json_event *>(evt);
			set_event_labels_k8s_audit(mdetails, event, j_evt);
		}
		else
		{
			set_event_labels(container_id, tinfo, event);
		}
	}
	return event;
}

void security_mgr::set_event_labels(std::string &container_id,
									sinsp_threadinfo *tinfo,
									draiosproto::policy_event *event)
{
	// Process Name
	if (m_event_labels.find("process.name") != m_event_labels.end())
	{
		if (tinfo != nullptr && tinfo->m_tid > 0)
		{
			std::string cmdline;
			sinsp_threadinfo::populate_cmdline(cmdline, tinfo);
			if (!cmdline.empty()) {
				(*event->mutable_event_labels())["process.name"] = std::move(cmdline);
			}
		}
	}

	// Host Name
	if (m_event_labels.find("host.hostName") != m_event_labels.end())
	{
		string host_name = sinsp_gethostname();
		if (!host_name.empty()) {
			(*event->mutable_event_labels())["host.hostName"] = std::move(host_name);
		}
	}

	if (m_configuration != nullptr)
	{
        // AWS Instance ID
        if (m_event_labels.find("aws.instance_id") != m_event_labels.end())
        {
            string aws_instance_id = m_configuration->get_aws_instance_id();
            if (!aws_instance_id.empty()) {
                (*event->mutable_event_labels())["aws.instance_id"] = std::move(aws_instance_id);
            }
        }

        // AWS Account ID
        if (m_event_labels.find("aws.account_id") != m_event_labels.end())
        {
            string aws_account_id = m_configuration->get_aws_account_id();
            if (!aws_account_id.empty()) {
                (*event->mutable_event_labels())["aws.account_id"] = std::move(aws_account_id);
            }
        }

        // AWS Region
        if (m_event_labels.find("aws.account_region") != m_event_labels.end())
        {
            string aws_region = m_configuration->get_aws_region();
            if (!aws_region.empty()) {
                (*event->mutable_event_labels())["aws.region"] = std::move(aws_region);
            }
        }
	}

	// Agent Tags
	if (m_event_labels.find("agent.tag") != m_event_labels.end()) {
		std::vector<std::string> tags = sinsp_split(configuration_manager::instance().get_config<std::string>("tags")->get_value(), ',');

		std::string tag_prefix = "agent.tag.";

		int count_tags = 0;
		for (auto &pair : tags) {
			if (count_tags >= c_event_labels_max_agent_tags.get_value())
			{
				break;
			}
			// tags are available in pair in the format key:value
			// in case of multiple ":" are found the first one will be considered the separator
			// between key and value
			auto found = pair.find(":");

			if (found != std::string::npos){
				auto tag_key = pair.substr(0, found);
				// Do not include hardcoded "sysdig_secure.enabled" tag
				if (tag_key != "sysdig_secure.enabled") {
					auto tag_value = pair.substr(found + 1, std::string::npos);
					(*event->mutable_event_labels())[tag_prefix + tag_key] = tag_value;
					count_tags++;
				}
			}
		}
	}

	// Infrastructure Lookup for Kubernetes Labels
	infrastructure_state::uid_t uid;
	uid = std::make_pair("container", container_id);

	std::unordered_map<std::string, std::string>event_labels;
	if (m_infra_state != nullptr)
	{
		m_infra_state->find_tag_list(uid, m_event_labels, event_labels);

		for (auto& it: event_labels)
		{
			(*event->mutable_event_labels())[it.first] = std::move(it.second);
		}

		// Kubernetes Cluster Name
		if (m_event_labels.find("kubernetes.cluster.name") != m_event_labels.end())
		{
			// kubernetes.cluster.name should be pushed only if the event is related to k8s
			// Use Pod Name label to check it
			if (event_labels.find("kubernetes.pod.name") != event_labels.end())
			{
				if (!m_infra_state->get_k8s_cluster_name().empty())
				{
					(*event->mutable_event_labels())["kubernetes.cluster.name"] = m_infra_state->get_k8s_cluster_name();
				}
			}
		}
	}
}

void security_mgr::set_event_labels_k8s_audit(draiosproto::event_detail *details, draiosproto::policy_event *event, json_event *j_evt)
{
	if (!m_infra_state->get_k8s_cluster_name().empty())
	{
		(*event->mutable_event_labels())["kubernetes.cluster.name"] = m_infra_state->get_k8s_cluster_name();
	}

	const nlohmann::json& j = j_evt->jevt();

	try
	{
		nlohmann::json::json_pointer r_jptr("/objectRef/resource");
		if (m_infra_state != nullptr && j.at(r_jptr) == "pods")
		{
			// if the object of this audit event is a pod,
			// get its container.id and host.hostName
			// from infrastructure state
			nlohmann::json::json_pointer ns_jptr("/objectRef/namespace"),
				n_jptr("/objectRef/name");
			std::string pod_uid = m_infra_state->get_k8s_pod_uid(j.at(ns_jptr), j.at(n_jptr));
			if (!pod_uid.empty())
			{
				infrastructure_state::uid_t uid = make_pair("k8s_pod", pod_uid);

				// labels retrieval
				std::unordered_map<std::string, std::string> event_labels;
				m_infra_state->find_tag_list(uid, m_event_labels, event_labels);

				for (auto &it: event_labels)
				{
					(*event->mutable_event_labels())[it.first] = std::move(it.second);
				}

				if (m_event_labels.find("agent.tag") != m_event_labels.end()) {
					// lookup host.mac
					std::string host_mac;
					m_infra_state->find_tag(uid, "host.mac", host_mac);

					// lookup agent tags from host
					uid = make_pair("host", host_mac);
					std::unordered_map<std::string, std::string> host_tags;
					m_infra_state->get_tags(uid, host_tags);

					int count_tags = 0;
					for (auto &it: host_tags)
					{
						if (count_tags >= c_event_labels_max_agent_tags.get_value())
						{
							break;
						}

						// filter out tags that are not agent.tag
						size_t found = it.first.find("agent.tag");
						if (found != string::npos)
						{
							(*event->mutable_event_labels())[it.first] = std::move(it.second);
							count_tags++;
						}
					}
				}
			}
		}

	}
	catch (nlohmann::json::out_of_range&)
	{
		LOG_DEBUG("security_mgr::set_event_labels_k8s_audit: catch exception");
	}
	return;
}

void security_mgr::report_events(uint64_t ts_ns)
{
	if(m_events.events_size() == 0)
	{
		LOG_DEBUG("security_mgr::report_events: no events");
		return;
	}

	report_events_now(ts_ns, m_events);
	m_events.Clear();
}

void security_mgr::report_events_now(uint64_t ts_ns, draiosproto::policy_events &events)
{
	if(events.events_size() == 0)
	{
		LOG_ERROR("security_mgr::report_events_now: empty set of events ?");
		return;
	} else {
		LOG_INFO("security_mgr::report_events_now: " + to_string(events.events_size()) + " events");
	}

	events.set_machine_id(m_configuration->machine_id());
	events.set_customer_id(m_configuration->m_customer_id);
	m_result_handler.security_mgr_policy_events_ready(ts_ns, &events);
}

void security_mgr::report_throttled_events(uint64_t ts_ns)
{
	uint32_t total_throttled_count = 0;

	if(m_policy_throttled_counts.size() > 0)
	{
		draiosproto::throttled_policy_events tevents;
		tevents.set_machine_id(m_configuration->machine_id());
		tevents.set_customer_id(m_configuration->m_customer_id);

		for(auto &it : m_policy_throttled_counts)
		{
			draiosproto::throttled_policy_event *new_tevent = tevents.add_events();
			new_tevent->set_timestamp_ns(ts_ns);
			new_tevent->set_container_id(it.first.first);
			new_tevent->set_policy_id(it.first.second);
			new_tevent->set_count(it.second);
			total_throttled_count += it.second;
		}

		m_result_handler.security_mgr_throttled_events_ready(ts_ns, &tevents, total_throttled_count);
	}

	// Also remove any token buckets that haven't been seen in
	// (1/rate * max burst) seconds. These token buckets have
	// definitely reclaimed all their tokens, even if fully consumed.
	auto bucket = m_policy_rates.begin();
	while(bucket != m_policy_rates.end())
	{
		if((ts_ns - bucket->second.get_last_seen()) >
		   (1000000000UL *
			(1 / security_config::instance().get_policy_events_rate()) * security_config::instance().get_policy_events_max_burst()))
		{
			LOG_DEBUG("Removing token bucket for container=" + bucket->first.first
				     + ", policy_id=" + to_string(bucket->first.second));
			m_policy_rates.erase(bucket++);
		}
		else
		{
			bucket++;
		}
	}


	m_policy_throttled_counts.clear();
}

void security_mgr::on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo)
{
	if (m_loaded_policies)
	{
		std::list<std::string> ids{container_info.m_id};
		m_loaded_policies->match_policy_scopes(m_infra_state, ids);
	}
}

void security_mgr::on_remove_container(const sinsp_container_info& container_info)
{
	// TODO if needed
	// since we are resetting everything every time we load the policies
}

std::shared_ptr<security_mgr::security_rules_group> security_mgr::loaded_v2_policies::get_rules_group_of(const scope_predicates &preds)
{
	for(const auto &group : m_rules_groups)
	{
		if(group->m_scope_predicates.size() != preds.size())
		{
			continue;
		}

		bool match_predicates = true;

		for(int i=0; i < group->m_scope_predicates.size(); i++)
		{
			if(group->m_scope_predicates[i].SerializeAsString() != preds[i].SerializeAsString())
			{
				match_predicates = false;
				break;
			}
		}

		if(match_predicates)
		{
			return group;
		}
	}

	std::shared_ptr<security_rules_group> grp = make_shared<security_rules_group>(preds, m_inspector, m_configuration);
	grp->init(m_falco_engine, m_fastengine_rules_library, m_security_evt_metrics);

	LOG_DEBUG("Creating Syscall Rules Group: " + grp->to_string());
	m_rules_groups.emplace_back(grp);

	return grp;
};

void security_mgr::start_k8s_audit_server()
{
	auto work =
		[](std::shared_ptr<grpc::Channel> chan,
		   shared_k8s_audit_event_queue queue,
		   sdc_internal::k8s_audit_server_start start)
	{
		grpc::ClientContext context;
		std::unique_ptr<sdc_internal::K8sAudit::Stub> stub = sdc_internal::K8sAudit::NewStub(chan);
		std::unique_ptr<grpc::ClientReader<sdc_internal::k8s_audit_event>> reader(stub->Start(&context, start));

		sdc_internal::k8s_audit_event ev;

		while(reader->Read(&ev))
		{
			queue->push(ev);
		}

		grpc::Status status = reader->Finish();

		return status;
	};

	sdc_internal::k8s_audit_server_start start;
	start.set_tls_enabled(security_config::instance().get_k8s_audit_server_tls_enabled());
	start.set_url(security_config::instance().get_k8s_audit_server_url());
	start.set_port(security_config::instance().get_k8s_audit_server_port());

	for(auto path : security_config::instance().get_k8s_audit_server_path_uris())
	{
		// If path doesn't start with a /, add one.
		if(path.size() > 0 && path.at(0) != '/')
		{
			path = "/" + path;
		}
		start.add_path_uris(path);
	}

	if (security_config::instance().get_k8s_audit_server_tls_enabled())
	{
		sdc_internal::k8s_audit_server_X509 *x509 = start.add_x509();
		x509->set_x509_cert_file(security_config::instance().get_k8s_audit_server_x509_cert_file());
		x509->set_x509_key_file(security_config::instance().get_k8s_audit_server_x509_key_file());
	}

	LOG_DEBUG(string("Sending start message to K8s Audit Server: ") + start.DebugString());
	m_k8s_audit_server_start_future = std::async(std::launch::async, work, m_grpc_channel, m_k8s_audit_events_queue, start);
	m_k8s_audit_server_started = true;
}

void security_mgr::check_pending_k8s_audit_events()
{
	if(m_k8s_audit_server_start_future.valid() &&
	   m_k8s_audit_server_start_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
	{
		grpc::Status res = m_k8s_audit_server_start_future.get();

		if(!res.ok())
		{
			std::ostringstream os;
			os << "Could not start k8s audit server ("
			   << res.error_message()
			   << "), trying again in "
			   << NumberFormatter::format(security_config::instance().get_k8s_audit_server_refresh_interval() / 1000000000)
			   << "seconds";

			LOG_ERROR(os.str());
		}
		else
		{
			LOG_DEBUG("K8s Audit Server GRPC completed");
		}

		m_k8s_audit_server_started = false;
	}

	// Now try to read any pending k8s audit events from the queue
	sdc_internal::k8s_audit_event jevt;

	while(m_k8s_audit_events_queue->try_pop(jevt))
	{
		std::list<json_event> jevts;
		nlohmann::json j;

		LOG_DEBUG("Response from K8s Audit Server start: jevt=" +
			     jevt.DebugString());
		try {
			j = json::parse( jevt.evt_json() );
		} catch  (json::parse_error& e) {
			LOG_ERROR(string("Could not parse data: ") + e.what());
			continue;
		}
		if(!m_parse_evts_falco_engine->parse_k8s_audit_json(j, jevts))
		{
			LOG_ERROR(string("Data not recognized as a K8s Audit Event"));
			continue;
		}
		for(auto jev : jevts)
		{
			m_k8s_audit_evt_sink->receive_k8s_audit_event(jev.jevt(),
								      m_configuration->m_secure_audit_k8s_active_filters,
								      m_configuration->m_secure_audit_k8s_filters);

			// instead of calling directly process_event, it might be worth enqueue into a list and have a worker thread processing the list
			process_event_v2(&jev);

			m_metrics.incr(metrics::MET_NUM_K8S_AUDIT_EVTS);
		}
	}
}

void security_mgr::stop_k8s_audit_server()
{
	auto work =
		[](std::shared_ptr<grpc::Channel> chan)
                {
			sdc_internal::k8s_audit_server_stop stop;

			std::unique_ptr<sdc_internal::K8sAudit::Stub> stub = sdc_internal::K8sAudit::NewStub(chan);
			grpc::ClientContext context;
			grpc::Status status;
			sdc_internal::k8s_audit_server_stop_result res;

			status = stub->Stop(&context, stop, &res);
			if(!status.ok())
			{
				res.set_successful(false);
				res.set_errstr(status.error_message());
			}

			return res;
		};

	std::future<sdc_internal::k8s_audit_server_stop_result> stop_future = std::async(std::launch::async, work, m_grpc_channel);

	// Wait up to 10 seconds for the stop to complete.
	if(stop_future.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
	{
		LOG_ERROR("Did not receive response to K8s Audit Server Stop() call within 10 seconds");
		return;
	}
	else
	{
		sdc_internal::k8s_audit_server_stop_result res = stop_future.get();
		if(!res.successful())
		{
			LOG_ERROR(string("K8s Audit Server Stop() call returned error ") +
				     res.errstr());
		}
	}
}

// Given two vectors of strings 'include' and 'exclude'
// if a key is present in both include and exclude ignore it
// otherwise create a set of 'include' strings
void security_mgr::configure_event_labels_set(){
	for (const auto& s : c_event_labels_include.get_value()){
		m_event_labels.insert(s);
	}
	for (const auto& s : c_event_labels_exclude.get_value()){
		m_event_labels.erase(s);
	}
}

bool security_mgr::has_received_policies()
{
	return m_received_policies;
}
#endif // CYGWING_AGENT
