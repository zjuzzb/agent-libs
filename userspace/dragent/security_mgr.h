#ifndef CYGWING_AGENT
#pragma once
// The security manager class is responsible for receiving the list of
// policies from the backend, creating necessary objects to implement
// the policies, and sending the stream of detected events to the
// backend.

#include <memory>
#include <map>
#include <vector>

#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include <Poco/RWLock.h>

#include <sinsp.h>
#include <token_bucket.h>

#include <draios.pb.h>
#include <falco_engine.h>

#include "coclient.h"

#include "capture_job_handler.h"
#include "configuration.h"
#include "analyzer.h"
#include "sinsp_data_handler.h"
#include "security_policy.h"
#include "security_action.h"
#include "baseline_mgr.h"
#include "internal_metrics.h"

class SINSP_PUBLIC security_mgr
{
public:
	security_mgr();
	virtual ~security_mgr();

	void init(sinsp *inspector,
		  sinsp_data_handler *sinsp_handler,
		  sinsp_analyzer *analyzer,
		  capture_job_handler *capture_job_handler,
		  dragent_configuration *configuration,
		  internal_metrics::sptr_t &metrics);

	bool load_policies_file(const char *filename, std::string &errstr);

	bool load_baselines_file(const char *filename, std::string &errstr);

	// Returns true if loaded successfully, false otherwise. Sets
	// errstr when returning false.
	bool load_policies(const draiosproto::policies &policies, std::string &errstr);

	// Load the baselines and update the policies accordingly. Sets
	// errstr when returning false.
	bool load_baselines(const draiosproto::baselines &baselines, std::string &errstr);

	// Attempt to match the event agains the set of policies. If
	// the event matches one or more policies, will perform the
	// necessary actions and send agent events.
	void process_event(sinsp_evt *evt);

	// Send the provided policy event, either adding the event to
	// the pending events list or reporting it immediately,
	// depending on send_now).
	//
	void send_policy_event(uint64_t ts_ns, shared_ptr<draiosproto::policy_event> &event, bool send_now);

	// Start a sysdig capture. Returns true on success, false (and
	// fills in errstr) if the capture couldn't be started.
	bool start_capture(uint64_t ts_ns,
			   const string &policy,
			   const string &token, const string &filter,
			   uint64_t before_event_ns, uint64_t after_event_ns,
			   bool apply_scope,
			   std::string &container_id,
			   uint64_t pid,
			   std::string &errstr);

	void start_sending_capture(const string &token);

	void stop_capture(const string &token);

	sinsp_analyzer *analyzer();

	baseline_mgr &baseline_manager();
private:

	class metrics : public internal_metrics::ext_source
        {
	public:
		enum reason
		{
			MET_MISS_EVTTYPE = 0,
			MET_MISS_TINFO,
			MET_MISS_QUAL,
			MET_MAX
		};

		metrics()
		{
			memset(m_metrics, 0, sizeof(m_metrics));
		}

		virtual ~metrics()
		{
		}

		void incr(reason res)
		{
			m_metrics[res]++;
		}

		void reset()
		{
			std::fill_n(m_metrics, MET_MAX, 0);
		}

		std::string to_string()
		{
			std::string str;

			for(uint32_t i = 0; i < MET_MAX; i++)
			{
				str += " " + m_metric_names[i] + "=" + std::to_string(m_metrics[i]);
			}

			return str;
		}

		virtual void send_all(draiosproto::statsd_info* statsd_info)
		{
			for(uint32_t i=0; i<MET_MAX; i++)
			{
				internal_metrics::write_metric(statsd_info,
							       m_metric_names[i],
							       draiosproto::STATSD_COUNT,
							       m_metrics[i]);
				m_metrics[i] = 0;
			}
		}
	private:
		std::string prefix;
		uint64_t m_metrics[MET_MAX];
		std::string m_metric_names[MET_MAX]{
				"security.miss.evttype",
				"security.miss.tinfo",
				"security.miss.qual",
				};
	};

	// Potentially throttle the provided policy event. This method
	// enforces any rate limits that apply for the given (policy,
	// container) tuple.
	//
	// Returns true if the policy event was *not* throttled.
	// Returns false if the policy event was throttled,
	// meaning that it will be added to the periodic throttled
	// events message. In this case, the event should be discarded.
        bool throttle_policy_event(uint64_t ts_ns, std::string &container_id, uint64_t policy_id);

	draiosproto::policy_event * create_policy_event(int64_t ts_ns,
							std::string &container_id,
							uint64_t policy_id,
							draiosproto::event_detail *details);

	void load_policy(const security_policy &spolicy, std::list<std::string> &ids);

	bool load(const draiosproto::policies &policies, const draiosproto::baselines &baselines, std::string &errstr);

	bool event_qualifies(sinsp_evt *evt);

	void check_periodic_tasks(uint64_t ts_ns);

	// Send the latest events to the backend
	void report_events(uint64_t ts_ns);

	// Send a set of events to the backend immediately without
	// waiting for the next policy event flush.
	void report_events_now(uint64_t ts_ns, draiosproto::policy_events &events);

	// Send counts of throttled policy events to the backend
	void report_throttled_events(uint64_t ts_ns);

	void on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo);
	void on_remove_container(const sinsp_container_info& container_info);

	// The last policies/baselines we loaded
	draiosproto::policies m_policies_msg;
	draiosproto::baselines m_baselines_msg;

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

	bool m_initialized;
	sinsp* m_inspector;
	sinsp_data_handler *m_sinsp_handler;
	sinsp_analyzer *m_analyzer;
	capture_job_handler *m_capture_job_handler;
	dragent_configuration *m_configuration;

	Poco::RWLock m_policies_lock;

	baseline_mgr m_baseline_mgr;

	security_actions m_actions;

	std::shared_ptr<falco_engine> m_falco_engine;

	struct scope_info
	{
	public:
		scope_predicates preds;
		bool container_scope;
		bool host_scope;

		bool operator==(scope_info &sinfo)
		{
			if (container_scope != sinfo.container_scope ||
			    host_scope != sinfo.host_scope ||
			    preds.size() != sinfo.preds.size())
			{
				return false;
			}
			for(int i=0; i < preds.size(); i++)
			{
				if(preds[i].SerializeAsString() != sinfo.preds[i].SerializeAsString())
				{
					return false;
				}
			}
			return true;
		}

		std::string to_string()
		{
			std::string str = "";
			if(preds.size())
			{
				for(const auto &p : preds)
				{
					str += p.key() + " " +
					       draiosproto::scope_operator_Name(p.op()) + " " +
					       p.values(0) + string((p.op() == draiosproto::IN_SET || p.op() == draiosproto::NOT_IN_SET)?"...":"") +
					       " and ";
				}
				str = str.substr(0, str.size() - 5);
			}
			else
			{
				str = "Entire infrastructure";
			}

			return string(host_scope && container_scope?"h&c":(host_scope?"hosts":"containers")) + " matching \"" + str + "\"";
		}
	};

	// A security policies group holds a
	// set of *security_policies objects
	// that share the same scope.
	class security_policies_group
	{
	public:
		security_policies_group(scope_info sinfo, sinsp *inspector, dragent_configuration *configuration)
			: m_scope_info(sinfo),
			  m_inspector(inspector),
			  m_configuration(configuration)
		{
			m_security_policies = {&m_process_policies, &m_container_policies,
					       &m_readonly_fs_policies, &m_readwrite_fs_policies, &m_nofd_readwrite_fs_policies,
					       &m_net_inbound_policies, &m_net_outbound_policies,
					       &m_tcp_listenport_policies, &m_udp_listenport_policies,
					       &m_syscall_policies, &m_falco_policies};
			m_evttypes.assign(PPM_EVENT_MAX+1, false);
		};
		virtual ~security_policies_group() {};

		void init(std::shared_ptr<falco_engine> falco_engine, std::list<std::shared_ptr<security_evt_metrics>> &metrics)
		{
			m_falco_policies.set_engine(falco_engine);

			auto s_it = m_security_policies.begin();
			auto m_it = metrics.begin();
			for (; s_it != m_security_policies.end(), m_it != metrics.end(); s_it++, m_it++)
			{
				security_policies *spol = *s_it;
				spol->init(m_configuration, m_inspector, *m_it);
				spol->reset();
			}
		}

		void init_metrics(std::list<std::shared_ptr<security_evt_metrics>> &metrics)
		{
			auto s_it = m_security_policies.begin();
			auto m_it = metrics.begin();
			for (; s_it != m_security_policies.end(), m_it != metrics.end(); s_it++, m_it++)
			{
				security_policies *spol = *s_it;
				(*m_it)->init(spol->name(), (spol->name() == "falco"));
			}
		}

		void add_policy(const security_policy &spolicy, std::shared_ptr<security_baseline> baseline = {})
		{
			for (auto &spol : m_security_policies)
			{
				spol->add_policy(spolicy, baseline);

				for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
				{
					m_evttypes[evttype] = m_evttypes[evttype] | spol->m_evttypes[evttype];
				}
			}
		}

		security_policies::match_result *match_event(sinsp_evt *evt)
		{
			security_policies::match_result *match;
			for (const auto &spol : m_security_policies)
			{
				if(spol->m_evttypes[evt->get_type()] && (match = spol->match_event(evt)) != NULL)
				{
					return match;
				}
			}

			return NULL;
		}

		std::string to_string()
		{
			std::string str;
			for (auto &spol : m_security_policies)
			{
				str += " " + spol->name() + "=" + std::to_string(spol->num_loaded_policies());
			}

			return m_scope_info.to_string() + " :" + str;
		}

		std::vector<bool> m_evttypes;
		scope_info m_scope_info;
	private:
		std::list<security_policies *> m_security_policies;

		falco_security_policies m_falco_policies;
		readonly_fs_policies m_readonly_fs_policies;
		readwrite_fs_policies m_readwrite_fs_policies;
		nofd_readwrite_fs_policies m_nofd_readwrite_fs_policies;
		net_inbound_policies m_net_inbound_policies;
		net_outbound_policies m_net_outbound_policies;
		tcp_listenport_policies m_tcp_listenport_policies;
		udp_listenport_policies m_udp_listenport_policies;
		syscall_policies m_syscall_policies;
		container_policies m_container_policies;
		process_policies m_process_policies;

		sinsp* m_inspector;
		dragent_configuration *m_configuration;
	};

	// container id -> list(security_policies_group) for every scope matched
	// "" is used as host key
	std::unordered_map<std::string, std::set<std::shared_ptr<security_policies_group>>> m_security_policies;
	std::list<std::shared_ptr<security_policies_group>> m_policies_groups;

	std::shared_ptr<security_policies_group> get_policies_group_of(scope_info &sinfo);

	std::map<uint64_t,std::shared_ptr<security_policy>> m_policies;

	std::shared_ptr<coclient> m_coclient;

	unique_ptr<run_on_interval> m_actions_poll_interval;

	unique_ptr<run_on_interval> m_metrics_report_interval;

	double m_policy_events_rate;
	uint32_t m_policy_events_max_burst;

	// The current set of events that have occurred. Periodically,
	// it calls flush() to send these events to the collector.
	draiosproto::policy_events m_events;

	// The event types that are relevant. It's the union of all
	// event types for all policies.
	std::vector<bool> m_evttypes;

	// must be initialized in the same order of security_policies_group::m_security_policies
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
};
#endif // CYGWING_AGENT
