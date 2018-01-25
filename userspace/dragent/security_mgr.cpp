#include <google/protobuf/text_format.h>

#include "sinsp_worker.h"
#include "logger.h"

#include "security_mgr.h"

using namespace std;

// XXX/mstemm TODO
// - Is there a good way to immediately check the status of a sysdig capture that I can put in the action result?

security_mgr::security_mgr()
	: m_initialized(false),
	  m_inspector(NULL),
	  m_sinsp_handler(NULL),
	  m_analyzer(NULL),
	  m_capture_job_handler(NULL),
	  m_configuration(NULL)
{
	m_print.SetSingleLineMode(true);
}

security_mgr::~security_mgr()
{
}

void security_mgr::init(sinsp *inspector,
			sinsp_data_handler *sinsp_handler,
			sinsp_analyzer *analyzer,
			capture_job_handler *capture_job_handler,
			dragent_configuration *configuration)

{
	m_inspector = inspector;
	m_sinsp_handler = sinsp_handler;
	m_analyzer = analyzer;
	m_capture_job_handler = capture_job_handler;
	m_configuration = configuration;

	m_evttypes.assign(PPM_EVENT_MAX+1, false);

	m_report_events_interval = make_unique<run_on_interval>(m_configuration->m_security_report_interval_ns);
	m_report_throttled_events_interval = make_unique<run_on_interval>(m_configuration->m_security_throttled_report_interval_ns);

	m_actions_poll_interval = make_unique<run_on_interval>(m_configuration->m_actions_poll_interval_ns);

	m_metrics_report_interval = make_unique<run_on_interval>(m_configuration->m_metrics_report_interval_ns);

	// Only check the above every second
	m_check_periodic_tasks_interval = make_unique<run_on_interval>(1000000000);

	m_coclient = make_shared<coclient>();
	m_initialized = true;
}

bool security_mgr::load(const draiosproto::policies &policies, std::string &errstr)
{
	Poco::ScopedWriteRWLock lck(m_policies_lock);

	string tmp;

	m_falco_engine = NULL;

	m_falco_policies.clear();
	m_policy_names.clear();
	m_evttypes.assign(PPM_EVENT_MAX+1, false);
	m_analyzer->infra_state()->clear_scope_cache();

	m_print.PrintToString(policies, &tmp);

	g_log->debug("Loading policies message: " + tmp);

	// Load all falco rules files into the engine. We'll selectively
	// enable them based on the contents of the policy.
	if(policies.has_falco_rules())
	{
		bool verbose = false;
		bool all_events = false;

		m_falco_engine = make_shared<falco_engine>();
		m_falco_engine->set_inspector(m_inspector);
		m_falco_engine->set_sampling_multiplier(m_configuration->m_falco_engine_sampling_multiplier);

		for(auto &content : policies.falco_rules().contents())
		{
			try {
				g_log->debug("Loading Falco Rules Content: " + content);
				m_falco_engine->load_rules(content, verbose, all_events);
			}
			catch (falco_exception &e)
			{
				errstr = e.what();
				return false;
			}
		}
	}

	for(auto &policy : policies.policy_list())
	{
		m_policy_names.insert(make_pair(policy.id(),policy.name()));
		if(policy.type() == draiosproto::POLICY_FALCO)
		{
			m_falco_policies.push_back(make_unique<falco_security_policy>(this,
										      m_configuration,
										      policy,
										      m_inspector,
										      m_falco_engine,
										      m_coclient));

			g_log->debug("Loaded Falco Policy: "
				     + m_falco_policies.back()->to_string());

			for(uint32_t evttype = 0; evttype < PPM_EVENT_MAX; evttype++)
			{
				m_evttypes[evttype] = m_evttypes[evttype] | m_falco_policies.back()->m_evttypes[evttype];
			}
		}

	}

	// There must be falco rules content if there are any falco policies
	if(m_falco_policies.size() > 0 && !policies.has_falco_rules())
	{
		errstr = "One or more falco policies, but no falco ruleset";
		return false;
	}

	return true;
}

void security_mgr::process_event(sinsp_evt *evt)
{
	// Write lock acquired in load()
	if(!m_initialized || !m_policies_lock.tryReadLock())
	{
		return;
	}

	uint64_t ts_ns = evt->get_ts();

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
		m_actions_poll_interval->run([this]()
                {
			m_coclient->process_queue();
		}, ts_ns);

		m_metrics_report_interval->run([this]()
		{
			for(auto &policy : m_falco_policies)
			{
				policy->log_metrics();
				policy->reset_metrics();
			}
			g_log->information("Events skipped at security_mgr level: " + to_string(m_skipped_evts));
		}, ts_ns);
	}, ts_ns);

	// If no policy cares about this event type, return
	// immediately.
	if(m_evttypes[evt->get_type()])
	{
		for(auto &fpolicy : m_falco_policies)
		{
			if(fpolicy->process_event(evt))
			{
				g_log->debug("match_event() returned true, not testing later policies");
				break;
			}
		}
	}
	else
	{
		m_skipped_evts++;
	}

	m_policies_lock.unlock();
}

bool security_mgr::start_capture(uint64_t ts_ns,
				 const string &policy,
				 const string &token, const string &filter,
				 uint64_t before_event_ns, uint64_t after_event_ns,
				 bool apply_scope, std::string &container_id,
				 uint64_t pid,
				 std::string &errstr)
{
	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		std::make_shared<capture_job_handler::dump_job_request>();

	job_request->m_start_details = make_unique<capture_job_handler::start_job_details>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_START;
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
	return m_capture_job_handler->queue_job_request(m_inspector, job_request, errstr);
}

void security_mgr::start_sending_capture(const string &token)
{
	string errstr;

	std::shared_ptr<capture_job_handler::dump_job_request> job_request =
		std::make_shared<capture_job_handler::dump_job_request>();

	job_request->m_request_type = capture_job_handler::dump_job_request::JOB_SEND_START;
	job_request->m_token = token;

	if (!m_capture_job_handler->queue_job_request(m_inspector, job_request, errstr))
	{
		g_log->error("security_mgr::start_sending_capture could not start sending capture token=" + token + "(" + errstr + "). Trying to stop capture.");
		stop_capture(token);
	}
}

void security_mgr::stop_capture(const string &token)
{
	string errstr;

	std::shared_ptr<capture_job_handler::dump_job_request> stop_request =
		std::make_shared<capture_job_handler::dump_job_request>();

	stop_request->m_request_type = capture_job_handler::dump_job_request::JOB_STOP;
	stop_request->m_token = token;

	if (!m_capture_job_handler->queue_job_request(m_inspector, stop_request, errstr))
	{
		g_log->critical("security_mgr::start_sending_capture could not stop capture token=" + token + "(" + errstr + ")");

		// This will result in a capture that runs to
		// completion but is never sent, and a file on
		// disk that is never cleaned up.
	}
}

sinsp_analyzer *security_mgr::analyzer()
{
	return m_analyzer;
}

bool security_mgr::accept_policy_event(uint64_t ts_ns, shared_ptr<draiosproto::policy_event> &event, bool send_now)
{
	bool accepted = true;

	// Find the matching token bucket, creating it if necessary

	rate_limit_scope_t scope(event->container_id(), event->policy_id());

	string policy_name = "N/A";
	auto it2 = m_policy_names.find(event->policy_id());
	if(it2 != m_policy_names.end())
	{
		policy_name = it2->second;
	}

	auto it = m_policy_rates.lower_bound(rate_limit_scope_t(scope));

	if (it == m_policy_rates.end() ||
	    it->first != scope)
	{
		it = m_policy_rates.emplace_hint(it, make_pair(scope, token_bucket()));
		it->second.init(m_configuration->m_policy_events_rate, m_configuration->m_policy_events_max_burst, ts_ns);

		g_log->debug("security_mgr::accept_policy_event creating new token bucket for policy=" + policy_name
			     + ", container=" + event->container_id());
	}

	if(it->second.claim(1, ts_ns))
	{
		// Not throttled, queue the policy event or send
		// immediately.
		if(send_now)
		{
			draiosproto::policy_events events;
			events.set_machine_id(m_configuration->m_machine_id);
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

		g_log->debug("security_mgr::accept_policy_event allowing policy=" + policy_name
			     + ", container=" + event->container_id()
			     + ", tokens=" + NumberFormatter::format(it->second.get_tokens()));
	}
	else
	{
		accepted = false;

		string policy_name = "N/A";
		auto it = m_policy_names.find(event->policy_id());
		if(it != m_policy_names.end())
		{
			policy_name = it->second;
		}

		// Throttled. Increment the throttled count.

		auto it2 = m_policy_throttled_counts.lower_bound(rate_limit_scope_t(scope));

		if (it2 == m_policy_throttled_counts.end() ||
		    it2->first != scope)
		{
			it2 = m_policy_throttled_counts.emplace_hint(it2, make_pair(scope, 0));
		}

		it2->second = it2->second + 1;

		g_log->debug("security_mgr::accept_policy_event throttling policy=" + policy_name
			     + ", container=" + event->container_id()
			     + ", tcount=" + NumberFormatter::format(it2->second));
	}

	return accepted;
}


void security_mgr::report_events(uint64_t ts_ns)
{
	if(m_events.events_size() == 0)
	{
		g_log->debug("security_mgr::report_events: no events");
		return;
	}

	report_events_now(ts_ns, m_events);
	m_events.Clear();
}

void security_mgr::report_events_now(uint64_t ts_ns, draiosproto::policy_events &events)
{
	if(events.events_size() == 0)
	{
		g_log->error("security_mgr::report_events_now: empty set of events ?");
		return;
	} else {
		g_log->information("security_mgr::report_events_now: " + to_string(events.events_size()) + " events");
	}

	events.set_machine_id(m_configuration->m_machine_id);
	events.set_customer_id(m_configuration->m_customer_id);
	m_sinsp_handler->security_mgr_policy_events_ready(ts_ns, &events);
}

void security_mgr::report_throttled_events(uint64_t ts_ns)
{
	uint32_t total_throttled_count = 0;

	if(m_policy_throttled_counts.size() > 0)
	{
		draiosproto::throttled_policy_events tevents;
		tevents.set_machine_id(m_configuration->m_machine_id);
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

		m_sinsp_handler->security_mgr_throttled_events_ready(ts_ns, &tevents, total_throttled_count);
	}

	// Also remove any token buckets that haven't been seen in
	// (1/rate * max burst) seconds. These token buckets have
	// definitely reclaimed all their tokens, even if fully consumed.
	auto bucket = m_policy_rates.begin();
	while(bucket != m_policy_rates.end())
	{
		if((ts_ns - bucket->second.get_last_seen()) > (1000000000UL * (1/m_configuration->m_policy_events_rate) * m_configuration->m_policy_events_max_burst))
		{
			g_log->debug("Removing token bucket for container=" + bucket->first.first
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
