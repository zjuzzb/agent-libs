#pragma once

// The security manager class is responsible for receiving the list of
// policies from the backend, creating necessary objects to implement
// the policies, and sending the stream of detected events to the
// backend.

#include <memory>
#include <map>

#include <google/protobuf/text_format.h>

#include <Poco/RWLock.h>

#include <sinsp.h>
#include <token_bucket.h>

#include <draios.pb.h>
#include <falco_engine.h>
#include <falco_events.h>

#include "coclient.h"

#include "capture_job_handler.h"
#include "configuration.h"
#include "sinsp_data_handler.h"
#include "security_policy.h"

class SINSP_PUBLIC security_mgr
{
public:
	security_mgr();
	virtual ~security_mgr();

	void init(sinsp *inspector,
		  sinsp_data_handler *sinsp_handler,
		  sinsp_analyzer *analyzer,
		  capture_job_handler *capture_job_handler,
		  dragent_configuration *configuration);

	// Returns true if loaded successfully, false otherwise. Sets
	// errstr when returning false.
	bool load(const draiosproto::policies &policies, std::string &errstr);

	// Attempt to match the event agains the set of policies. If
	// the event matches one or more policies, will perform the
	// necessary actions and send agent events.
	void process_event(sinsp_evt *evt);

	// Accept the provided policy event. This method enforces any
	// rate limits that apply for the given (policy, container)
	// tuple and adds the event to the pending events list (or
	// reports it immediately, depending on send_now)
	void accept_policy_event(uint64_t ts_ns, shared_ptr<draiosproto::policy_event> &event, bool send_now);

	// Start a sysdig capture. Returns true on success, false (and
	// fills in errstr) if the capture couldn't be started.
	bool start_capture(uint64_t ts_ns,
			   const string &token, const string &filter,
			   uint64_t before_event_ns, uint64_t after_event_ns,
			   bool apply_scope,
			   std::string &container_id,
			   std::string &errstr);

	sinsp_analyzer *analyzer();

private:

	// Send the latest events to the backend
	void report_events(uint64_t ts_ns);

	// Send a set of events to the backend immediately without
	// waiting for the next policy event flush.
	void report_events_now(uint64_t ts_ns, draiosproto::policy_events &events);

	// Send counts of throttled policy events to the backend
	void report_throttled_events(uint64_t ts_ns);

	// Holds the token buckets that enforce rate limiting for
	// policy events for a given policy + container.
	typedef std::pair<std::string,uint64_t> rate_limit_scope_t;
	std::map<rate_limit_scope_t,token_bucket> m_policy_rates;

	// Holds counts of the number of throttled policy events. This
	// is reported in a separate message in flush().
	std::map<rate_limit_scope_t,uint32_t> m_policy_throttled_counts;

	std::unique_ptr<run_on_interval> m_report_events_interval;
	std::unique_ptr<run_on_interval> m_report_throttled_events_interval;

	google::protobuf::TextFormat::Printer m_print;
	bool m_initialized;
	sinsp* m_inspector;
	sinsp_data_handler *m_sinsp_handler;
	sinsp_analyzer *m_analyzer;
	capture_job_handler *m_capture_job_handler;
	dragent_configuration *m_configuration;

	Poco::RWLock m_policies_lock;

	shared_ptr<falco_engine> m_falco_engine;
	shared_ptr<falco_events> m_falco_events;

	std::list<falco_security_policy> m_falco_policies;

	std::map<uint64_t,std::string> m_policy_names;

	std::shared_ptr<coclient> m_coclient;

	unique_ptr<run_on_interval> m_actions_poll_interval;

	double m_policy_events_rate;
	uint32_t m_policy_events_max_burst;

	// The current set of events that have occurred. Periodically,
	// it calls flush() to send these events to the collector.
	draiosproto::policy_events m_events;
};
