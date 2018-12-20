#pragma once

#include <atomic>
#include <memory>
#include <token_bucket.h>
#include "capture_job_handler.h"
#include "configuration.h"
#include "internal_metrics.h"
#include "main.h"
#include "security_mgr.h"
#include "sinsp_data_handler.h"
#include "subprocesses_logger.h"
#include "watchdog_runnable.h"


class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};

class sinsp_worker : public dragent::watchdog_runnable
{
public:
	sinsp_worker(dragent_configuration* configuration,
		     internal_metrics::sptr_t im,
		     protocol_queue* queue,
		     atomic<bool> *enable_autodrop,
		     capture_job_handler *handler);
	~sinsp_worker();

	void init();

	// This is a way to schedule capture jobs from threads other
	// than the sinsp_worker thread. It actually passes the
	// request along to the capture_job_handler thread, but does
	// some necessary prep work such as creating sinsp_dumper
	// objects, etc.
	void queue_job_request(std::shared_ptr<capture_job_handler::dump_job_request> job_request);

	const sinsp* get_inspector() const
	{
		return m_inspector;
	}

	const sinsp_data_handler* get_sinsp_data_handler() const
	{
		return &m_sinsp_handler;
	}

	void set_statsite_pipes(shared_ptr<pipe_manager> pipes)
	{
		m_statsite_pipes = pipes;
	}

	void set_statsd_capture_localhost(bool value)
	{
		if(value)
		{
			g_log->information("Enable statsd localhost capture");
		}
		m_statsd_capture_localhost = value;
		if(m_analyzer)
		{
			m_analyzer->set_statsd_capture_localhost(value);
		}
	}

	void set_app_checks_enabled(bool value)
	{
		m_app_checks_enabled = value;
	}

	void set_user_event_queue(user_event_queue::ptr_t user_event_queue)
	{
		m_user_event_queue = user_event_queue;
	}

#ifndef CYGWING_AGENT
	bool load_policies(draiosproto::policies &policies, std::string &errstr);
	bool set_compliance_calendar(draiosproto::comp_calendar &calendar, std::string &errstr);
	void receive_hosts_metadata(draiosproto::orchestrator_events &evts);
#endif
	bool load_baselines(draiosproto::baselines &baselines, std::string &errstr);

	const sinsp_analyzer &analyzer()
	{
		return *m_analyzer;
	}

	/**
	 * The old event tracker decides when too many events have been
	 * received that are too old.
	 */
	class old_event_tracker
	{
	public:
		old_event_tracker(uint64_t timeout_s);

		// ctor for unit test allows control of time
		typedef const std::function<uint64_t(void)> current_ns_delegate;
		typedef const std::function<uint64_t(void)> uptime_ms_delegate;
		old_event_tracker(uint64_t timeout_s,
				  current_ns_delegate& current,
				  uptime_ms_delegate& uptime);

		/**
		 * @return whether the event time is valid
		 */
		bool validate(uint64_t event_ns);

	private:
		const uint64_t m_timeout_s = 0;
		current_ns_delegate current_time_ns;
		uptime_ms_delegate uptime_ms;
		uint64_t m_first_wall_time_ns = 0;
		uint64_t m_first_uptime_ms = 0;
	};

private:
	void do_run() override;
	void process_job_requests();
	void check_autodrop(uint64_t ts_ns);

	void get_internal_metrics();

	static const string m_name;

	run_on_interval m_job_requests_interval;

	bool m_initialized;
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	atomic<bool> *m_enable_autodrop;
	bool m_autodrop_currently_enabled;
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
#ifndef CYGWING_AGENT
	security_mgr *m_security_mgr;
#endif
	capture_job_handler *m_capture_job_handler;
	sinsp_data_handler m_sinsp_handler;
	blocking_queue<std::shared_ptr<capture_job_handler::dump_job_request>> m_dump_job_requests;
	std::atomic<uint64_t> m_last_loop_ns;
	std::atomic<pthread_t> m_pthread_id;
	shared_ptr<pipe_manager> m_statsite_pipes;
	bool m_statsd_capture_localhost;
	bool m_app_checks_enabled;
	uint64_t m_last_mode_switch_time;

	static const uint64_t IFLIST_REFRESH_FIRST_TIMEOUT_NS = 30*ONE_SECOND_IN_NS;
	static const uint64_t IFLIST_REFRESH_TIMEOUT_NS = 10*60*ONE_SECOND_IN_NS;
	uint64_t m_next_iflist_refresh_ns;
	aws_metadata_refresher m_aws_metadata_refresher;

	user_event_queue::ptr_t m_user_event_queue;
	internal_metrics::sptr_t m_internal_metrics;
	old_event_tracker m_old_event_tracker;

	// friends for unit testing
	friend class memdump_test;
	friend class security_policies_test;
};
