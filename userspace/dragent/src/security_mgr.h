#ifndef CYGWING_AGENT
#pragma once
// The security manager class is responsible for receiving the list of
// policies from the backend, creating necessary objects to implement
// the policies, and sending the stream of detected events to the
// backend.

#include <memory>
#include <future>
#include <map>
#include <vector>
#include <algorithm>
#include <functional>

#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include <Poco/RWLock.h>
#include <tbb/concurrent_queue.h>

#include <sinsp.h>
#include <token_bucket.h>

#include <draios.pb.h>
#include <falco_engine.h>

#include "capture_job_handler.h"
#include "configuration.h"
#include "event_source.h"
#include "infrastructure_state.h"
#include "security_result_handler.h"
#include "security_rule.h"
#include "security_policy_v2_loader.h"
#include "security_action.h"
#include "security_metrics.h"
#include "internal_metrics.h"

class SINSP_PUBLIC security_mgr : public event_listener,
                                  public dragent::security_policy_v2_loader
{
public:
	security_mgr(const std::string& install_root,
		     security_result_handler& result_handler);
	virtual ~security_mgr();

	void init(sinsp *inspector,
		  infrastructure_state_iface *infra_state,
		  secure_k8s_audit_event_sink_iface *k8s_audit_evt_sink,
		  capture_job_queue_handler *capture_job_queue_handler,
		  dragent_configuration *configuration,
		  const internal_metrics::sptr_t& metrics);

	//
	// All of the below request_load_* and request_reload_* methods
	// can be called from a separate thread than the event
	// processing thread.
	//

	// Request that the security_mgr load the provided policies_v2
	// file on the next call to process_event.
	bool request_load_policies_v2_file(const char *filename, std::string &errstr);
	void request_load_policies_v2(const draiosproto::policies_v2 &policies_v2) override;

	// Reload the most recently provided policies_v2 message by
	// calling request_load_policies_v2_file.
	void request_reload_policies_v2();

	// Only used in tests--wait a configurable time for rules to
	// be loaded in the background. Returns true if rules were
	// loaded, false if the elapsed time passed
	bool wait_load_policies_v2(uint32_t secs);

	// Attempt to match the event agains the set of policies. If
	// the event matches one or more policies, will perform the
	// necessary actions and send agent events.
	//
	// This also calls perform_periodic_tasks, which may do things
	// like flushing policy events, polling for new k8s audit
	// events, etc. The (protected) method process_event_only()
	// only does the rule matching.
	void process_event(gen_event *evt);

	// this only required because c++ can't figure out that agent_event is a gen_event,
	// and therefore the above function should work
	void process_event(agent_event* evt) override
	{
		gen_event* evt_cast = evt;
		process_event(evt_cast);
	}

	// Send the provided policy event, either adding the event to
	// the pending events list or reporting it immediately,
	// depending on send_now).
	//
	void send_policy_event(uint64_t ts_ns, std::shared_ptr<draiosproto::policy_event> &event, bool send_now);

	// Start a sysdig capture. Returns true on success, false (and
	// fills in errstr) if the capture couldn't be started.
	bool start_capture(uint64_t ts_ns,
			   const std::string &policy,
			   const std::string &token, const std::string &filter,
			   uint64_t before_event_ns, uint64_t after_event_ns,
			   bool apply_scope,
			   std::string &container_id,
			   uint64_t pid,
			   std::string &errstr);

	void start_sending_capture(const std::string &token);

	void stop_capture(const std::string &token);

	void start_k8s_audit_server();
	void stop_k8s_audit_server();
	void check_pending_k8s_audit_events();

	// configs
	static type_config<bool> c_event_labels_enabled;
	static type_config<int> c_event_labels_max_agent_tags;
	static type_config<std::vector<std::string>> c_event_labels_include;
	static type_config<std::vector<std::string>> c_event_labels_exclude;

	std::unordered_set<std::string> m_event_labels = std::unordered_set<std::string>({
		"process.name",
		"host.hostName",
		"aws.instance_id",
		"aws.account_id",
		"aws.region",
		"agent.tag",
		"container.name",
		"kubernetes.cluster.name",
		"kubernetes.namespace.name",
		"kubernetes.deployment.name",
		"kubernetes.pod.name",
		"kubernetes.node.name"});

	void configure_event_labels_set();

	static std::string m_empty_container_id;

private:

	// Helper used by
	// request_load_policies_v2/request_reload_policies_v2
	void load_policies_v2_async();

	class metrics : public internal_metrics::ext_source
        {
	public:
		enum reason
		{
			MET_MISS_EVTTYPE = 0,
			MET_MISS_TINFO,
			MET_MISS_QUAL,
			MET_POLICIES,
			MET_POLICIES_ENABLED,
			MET_POLICY_EVTS,
			MET_POLICY_EVTS_SEV_LOW,
			MET_POLICY_EVTS_SEV_MEDIUM,
			MET_POLICY_EVTS_SEV_HIGH,
			MET_POLICY_EVTS_PROCESS,
			MET_POLICY_EVTS_CONTAINER,
			MET_POLICY_EVTS_FILESYSTEM,
			MET_POLICY_EVTS_NETWORK,
			MET_POLICY_EVTS_SYSCALL,
			MET_POLICY_EVTS_FALCO,
			MET_NUM_K8S_AUDIT_EVTS,
			MET_MAX
		};

		metrics()
		{
			memset(m_metrics, 0, sizeof(m_metrics));
		}

		virtual ~metrics()
		{
		}

		void set_policies_count(uint64_t num_policies, uint64_t num_enabled)
		{
			m_num_policies = num_policies;
			m_num_policies_enabled = num_enabled;
		}

		void incr(reason res, uint64_t delta=1)
		{
			m_metrics[res] += delta;
		}

		void incr_policy(const std::string &policy_name, uint64_t delta=1)
		{
			auto it = m_policy_evts_by_name.find(policy_name);
			if(it == m_policy_evts_by_name.end())
			{
				m_policy_evts_by_name.insert(make_pair(policy_name, delta));
			}
			else
			{
				it->second += delta;
			}
		}

		void reset()
		{
			std::fill_n(m_metrics, MET_MAX, 0);
			m_policy_evts_by_name.clear();

			// Add back the policy counts. These aren't
			// related to any event, so they're only
			// changed when the set of policies change.
			incr(MET_POLICIES, m_num_policies);
			incr(MET_POLICIES_ENABLED, m_num_policies_enabled);
		}

		std::string to_string()
		{
			std::string str;

			for(uint32_t i = 0; i < MET_MAX; i++)
			{
				str += " " + m_metric_names[i] + "=" + std::to_string(m_metrics[i]);
			}

			for(auto &pair : m_policy_evts_by_name)
			{
				str += " policy:" + pair.first + "=" + std::to_string(pair.second);
			}

			return str;
		}

		virtual void send_all(draiosproto::statsd_info* statsd_info)
		{
			// Not we only send some of the metrics here
			for(uint32_t i=0; i<MET_POLICIES; i++)
			{
				internal_metrics::write_metric(statsd_info,
							       m_metric_names[i],
							       draiosproto::STATSD_COUNT,
							       m_metrics[i]);
			}

			send_some(statsd_info);

			reset();
		}

		virtual void send_some(draiosproto::statsd_info* statsd_info)
		{

			for(uint32_t i=MET_POLICIES; i<MET_MAX; i++)
			{
				internal_metrics::write_metric(statsd_info,
							       m_metric_names[i],
							       draiosproto::STATSD_COUNT,
							       m_metrics[i]);
			}

			// Also do counts by policy name, sorted by count decreasing, capped at 10.
			std::vector<std::string> top_policies;
			for(auto &pair : m_policy_evts_by_name)
			{
				top_policies.push_back(pair.first);
			}

			uint32_t len = (top_policies.size() < 10 ? top_policies.size() : 10);
			if(top_policies.size() > 0)
			{
				partial_sort(top_policies.begin(),
					     top_policies.begin() + len,
					     top_policies.end(),
					     [this](const std::string &a, const std::string &b) {
						     return (m_policy_evts_by_name[a] > m_policy_evts_by_name[b]);
					     });
			}

			for(uint32_t i=0; i < len; i++)
			{
				std::map<std::string,std::string> tags = {{std::string("name"), top_policies[i]}};
				internal_metrics::write_metric(statsd_info,
							       "security_policy_evts.by_name",
							       tags,
							       draiosproto::STATSD_COUNT,
							       m_policy_evts_by_name[top_policies[i]]);
			}

			reset();
		}

	private:
		uint64_t m_num_policies;
		uint64_t m_num_policies_enabled;
		uint64_t m_metrics[MET_MAX];
		std::string m_metric_names[MET_MAX]{
				"security.miss.evttype",
				"security.miss.tinfo",
				"security.miss.qual",
				"security.policies.total",
				"security.policies.enabled",
				"security.policy_evts.total",
				"security.policy_evts.low",
				"security.policy_evts.medium",
				"security.policy_evts.high",
				"security.policy_evts.process",
				"security.policy_evts.container",
				"security.policy_evts.filesystem",
				"security.policy_evts.network",
				"security.policy_evts.syscall",
				"security.policy_evts.falco",
				"security.evts.k8s_audit",
				};

		// Counts by policy name
		std::map<std::string,uint64_t> m_policy_evts_by_name;
	};

	// Potentially throttle the provided policy event. This method
	// enforces any rate limits that apply for the given (policy,
	// container) tuple.
	//
	// Returns true if the policy event was *not* throttled.
	// Returns false if the policy event was throttled,
	// meaning that it will be added to the periodic throttled
	// events message. In this case, the event should be discarded.
        bool throttle_policy_event(uint64_t ts_ns,
				   std::string &container_id,
				   uint64_t policy_id, const std::string &policy_name);

	void add_policy_event_metrics(const security_rules::match_result &res);

	draiosproto::policy_event * create_policy_event(gen_event *evt,
							std::string &container_id,
							sinsp_threadinfo *tinfo,
							uint64_t policy_id,
							draiosproto::event_detail *details,
							uint64_t policy_version);

	draiosproto::policy_event * create_policy_event(gen_event *evt,
							std::string &container_id,
							sinsp_threadinfo *tinfo,
							uint64_t policy_id,
							draiosproto::event_detail &details,
							uint64_t policy_version);

	bool event_qualifies(sinsp_evt *evt);
	bool event_qualifies(json_event *evt);

	void check_periodic_tasks(uint64_t ts_ns);

	bool should_evaluate_event(gen_event *evt,
				   uint64_t ts_ns,
				   std::string* &container_id_ptr,
				   sinsp_threadinfo **tinfo);

	void process_event_v2(gen_event *evt);

	// Send the latest events to the backend
	void report_events(uint64_t ts_ns);

	void perform_periodic_tasks(uint64_t ts_ns);

	// Send a set of events to the backend immediately without
	// waiting for the next policy event flush.
	void report_events_now(uint64_t ts_ns, draiosproto::policy_events &events);

	void set_event_labels(std::string &container_id, sinsp_threadinfo *tinfo, draiosproto::policy_event *event);
	void set_event_labels_k8s_audit(draiosproto::event_detail *details, draiosproto::policy_event *event, json_event *j_evt);

	// Send counts of throttled policy events to the backend
	void report_throttled_events(uint64_t ts_ns);

	void on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo);
	void on_remove_container(const sinsp_container_info& container_info);

	// The last policies_v2 message passed to
	// request_load_policies. Used for reload.
	std::shared_ptr<draiosproto::policies_v2> m_policies_v2_msg;

	// Holds the token buckets that enforce rate limiting for
	// policy events for a given policy + container.
	typedef std::pair<std::string,uint64_t> rate_limit_scope_t;
	std::map<rate_limit_scope_t,token_bucket> m_policy_rates;

	// Holds counts of the number of throttled policy events. This
	// is reported in a separate message in flush().
	std::map<rate_limit_scope_t,uint32_t> m_policy_throttled_counts;

	std::unique_ptr<run_on_interval> m_report_events_interval;
	std::unique_ptr<run_on_interval> m_report_throttled_events_interval;
	std::unique_ptr<run_on_interval> m_check_periodic_tasks_interval;
	std::unique_ptr<run_on_interval> m_check_k8s_audit_start_interval;

	bool m_initialized;
	sinsp* m_inspector;
	security_result_handler& m_result_handler;
	infrastructure_state_iface *m_infra_state;
	secure_k8s_audit_event_sink_iface *m_k8s_audit_evt_sink;
	capture_job_queue_handler *m_capture_job_queue_handler;
	dragent_configuration *m_configuration;
	std::string m_install_root;
	std::string m_cointerface_sock_path;

	security_actions m_actions;

	// A security rules group holds a
	// set of *security_rules objects
	// that share the same scope.
	class security_rules_group
	{
	public:
		security_rules_group(const scope_predicates &preds, sinsp *inspector, dragent_configuration *configuration)
			: m_scope_predicates(preds),
			  m_inspector(inspector),
			  m_configuration(configuration)
		{
			m_possible_security_rules = {&m_process_rules, &m_container_rules,
						     &m_readonly_fs_rules, &m_readwrite_fs_rules, &m_nofd_readwrite_fs_rules,
						     &m_net_inbound_rules, &m_net_outbound_rules,
						     &m_tcp_listenport_rules, &m_udp_listenport_rules,
						     &m_syscall_rules, &m_falco_rules};
			m_evttypes.assign(PPM_EVENT_MAX+1, false);
		};
		virtual ~security_rules_group() {};

		void init(std::shared_ptr<falco_engine> falco_engine,
			  std::shared_ptr<security_rule_library> library,
			  std::list<std::shared_ptr<security_evt_metrics>> &metrics)
		{
			m_falco_rules.set_engine(falco_engine);

			auto s_it = m_possible_security_rules.begin();
			auto m_it = metrics.begin();
			for (; s_it != m_possible_security_rules.end(), m_it != metrics.end(); s_it++, m_it++)
			{
				security_rules *srule = *s_it;
				srule->init(m_configuration, m_inspector, library, *m_it);
				srule->reset();
			}
		}

		void init_metrics(std::list<std::shared_ptr<security_evt_metrics>> &metrics)
		{
			auto s_it = m_possible_security_rules.begin();
			auto m_it = metrics.begin();
			for (; s_it != m_possible_security_rules.end(), m_it != metrics.end(); s_it++, m_it++)
			{
				security_rules *srule = *s_it;
				(*m_it)->init(srule->name(), (srule->name() == "falco"));
			}
		}

		void add_policy(std::shared_ptr<security_policy_v2> policy)
		{
			if(m_loaded_policies.find(policy->id()) != m_loaded_policies.end())
			{
				return;
			}

			m_loaded_policies.insert(policy->id());

			for (auto &srule : m_possible_security_rules)
			{
				srule->add_policy(policy);

				if(srule->num_loaded_rules() > 0)
				{
					m_group_security_rules.insert(srule);
				}

				for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
				{
					m_evttypes[evttype] = m_evttypes[evttype] | srule->m_evttypes[evttype];
				}
			}
		}

		std::list<security_rules::match_result> *match_event(gen_event *evt)
		{
			std::list<security_rules::match_result> *results = NULL;

			if(m_evttypes[evt->get_type()])
			{
				for (const auto &srule : m_group_security_rules)
				{
					std::list<security_rules::match_result> *rules_results;

					rules_results = srule->match_event(evt);

					if(rules_results)
					{
						if(!results)
						{
							results = rules_results;
						}
						else
						{
							results->splice(results->end(), *rules_results);
							delete rules_results;
						}
					}
				}
			}

			return results;
		}

		std::string to_string()
		{
			std::string str;

			for (auto &pred : m_scope_predicates)
			{
				if(!str.empty())
				{
					str += " ";
				}

				str += pred.DebugString();
			}

			for (auto &srule : m_possible_security_rules)
			{
				str += " " + srule->name() + "=" + std::to_string(srule->num_loaded_rules());
			}

			return str;
		}

		// The union of event types handled by rules in this group
		std::vector<bool> m_evttypes;
		scope_predicates m_scope_predicates;
	private:
		// The list of security_rules objects that may be used for this group.
		std::list<security_rules *> m_possible_security_rules;

		// The list of security_rules objects that are
		// actually used for this group. Items are added to
		// this set in add_policy if num_loaded_rules is > 0.
		std::set<security_rules *> m_group_security_rules;

		std::set<uint64_t> m_loaded_policies;

		falco_security_rules m_falco_rules;
		readonly_fs_rules m_readonly_fs_rules;
		readwrite_fs_rules m_readwrite_fs_rules;
		nofd_readwrite_fs_rules m_nofd_readwrite_fs_rules;
		net_inbound_rules m_net_inbound_rules;
		net_outbound_rules m_net_outbound_rules;
		tcp_listenport_rules m_tcp_listenport_rules;
		udp_listenport_rules m_udp_listenport_rules;
		syscall_rules m_syscall_rules;
		container_rules m_container_rules;
		process_rules m_process_rules;

		sinsp* m_inspector;
		dragent_configuration *m_configuration;
	};

	typedef std::set<std::shared_ptr<security_rules_group>> security_rules_group_set;

	// Holds a policies_v2 message and anything required to match
	// against events and scopes.
	class loaded_v2_policies {
	public:
		loaded_v2_policies(sinsp *inspector,
				   dragent_configuration *configuration,
				   std::shared_ptr<draiosproto::policies_v2> policies_v2_msg,
				   metrics &security_mgr_metrics,
				   std::list<std::shared_ptr<security_evt_metrics>> &security_evt_metrics);

		virtual ~loaded_v2_policies();

		// This happens in the async thread that loads rules
		bool load(std::string &errstr);

		// This *must* be called after the async thread has
		// loaded rules, in the inspector thread.
		void match_policy_scopes(infrastructure_state_iface *infra_state,
					 std::list<std::string> &container_ids);

		security_rules_group_set &get_rules_group_for_container(std::string &container_id);

		std::shared_ptr<security_rules_group> get_k8s_audit_security_rules();

		bool match_evttype(int etype);

	private:
		void log_rules_group_info();

		void load_policy_v2(infrastructure_state_iface *infra_state,
				    std::shared_ptr<security_policy_v2> spolicy_v2,
				    std::list<std::string> &ids);

		bool load_falco_rules_files(const draiosproto::falco_rules_files &files, std::string &errstr);

		sinsp *m_inspector;
		dragent_configuration *m_configuration;

		std::shared_ptr<draiosproto::policies_v2> m_policies_v2_msg;

		std::unordered_map<std::string, security_rules_group_set> m_scoped_security_rules;
		std::list<std::shared_ptr<security_rules_group>> m_rules_groups;

		// Maintained as a separate set as they don't honor scopes.
		std::shared_ptr<security_rules_group> m_k8s_audit_security_rules;

		std::shared_ptr<security_rules_group> get_rules_group_of(const scope_predicates &preds);

		std::map<uint64_t,std::shared_ptr<security_policy_v2>> m_policies_v2;

		// The event types that are relevant. It's the union
		// of all event types for all policies.
		std::vector<bool> m_evttypes;

		metrics &m_metrics;
		std::list<std::shared_ptr<security_evt_metrics>> &m_security_evt_metrics;

		std::shared_ptr<security_rule_library> m_fastengine_rules_library;

		std::shared_ptr<falco_engine> m_falco_engine;
	};

	// Contains the actually loaded policies + rules from m_policies_v2_msg;
	std::shared_ptr<loaded_v2_policies> m_loaded_policies;

	// When a new loaded_v2_policies object is available, is is
	// available in this future.
	struct load_policies_result {
		bool successful;
		std::shared_ptr<loaded_v2_policies> loaded_policies;
	};

	std::future<load_policies_result> m_loaded_v2_policies_future;

	// The "empty" set of security rules (ones related to pid 0, which never exists).
	security_rules_group_set m_null_security_rules;

	// To avoid the overhead of hashing, save the last threadinfo
	// pid and the security rules group it hashed to.
	int64_t m_last_pid;
	std::reference_wrapper<security_rules_group_set> m_last_security_rules_group;

	// Only used to call parse_k8s_audit_json()
	std::shared_ptr<falco_engine> m_parse_evts_falco_engine;

	std::shared_ptr<coclient> m_coclient;

	std::unique_ptr<run_on_interval> m_actions_poll_interval;

	std::unique_ptr<run_on_interval> m_metrics_report_interval;

	double m_policy_events_rate;
	uint32_t m_policy_events_max_burst;

	// The current set of events that have occurred. Periodically,
	// it calls flush() to send these events to the collector.
	draiosproto::policy_events m_events;

	// must be initialized in the same order of m_possible_security_rules
	std::list<std::shared_ptr<security_evt_metrics>> m_security_evt_metrics;

	security_evt_metrics m_falco_metrics;
	security_evt_metrics m_readonly_fs_metrics;
	security_evt_metrics m_readwrite_fs_metrics;
	security_evt_metrics m_nofd_readwrite_fs_metrics;
	security_evt_metrics m_net_inbound_metrics;
	security_evt_metrics m_net_outbound_metrics;
	security_evt_metrics m_tcp_listenport_metrics;
	security_evt_metrics m_udp_listenport_metrics;
	security_evt_metrics m_syscall_metrics;
	security_evt_metrics m_container_metrics;
	security_evt_metrics m_process_metrics;

	metrics m_metrics;

	std::shared_ptr<grpc::Channel> m_grpc_channel;
	std::future<grpc::Status> m_k8s_audit_server_start_future;
	std::future<sdc_internal::k8s_audit_server_stop_result> m_k8s_audit_server_stop_future;

	typedef std::shared_ptr<tbb::concurrent_queue<sdc_internal::k8s_audit_event>> shared_k8s_audit_event_queue;
	shared_k8s_audit_event_queue m_k8s_audit_events_queue;
	bool m_k8s_audit_server_started;
};
#endif // CYGWING_AGENT
