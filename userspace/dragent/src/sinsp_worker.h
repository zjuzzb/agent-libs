#pragma once

#include <atomic>
#include <memory>

#include <token_bucket.h>

#include "main.h"
#include "dump_job_request_queue.h"
#include "configuration.h"
#include "security_baselines_loader.h"
#include "security_compliance_calender_receiver.h"
#include "security_compliance_task_runner.h"
#include "security_host_metadata_receiver.h"
#include "security_policy_loader.h"
#include "security_policy_v2_loader.h"
#include "sinsp_data_handler.h"
#include "subprocesses_logger.h"
#include "internal_metrics.h"

#include "capture_job_handler.h"
#include "security_mgr.h"
#include "compliance_mgr.h"

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

class sinsp_worker : public Poco::Runnable,
                     public dragent::dump_job_request_queue,
                     public dragent::security_baselines_loader,
                     public dragent::security_compliance_calender_receiver,
                     public dragent::security_compliance_task_runner,
                     public dragent::security_host_metadata_receiver,
                     public dragent::security_policy_loader,
                     public dragent::security_policy_v2_loader
{
public:
	sinsp_worker(dragent_configuration* configuration,
		     const internal_metrics::sptr_t& im,
		     protocol_queue* queue,
		     std::atomic<bool> *enable_autodrop,
		     capture_job_handler *handler);
	~sinsp_worker();

	void run() override;

	// This is a way to schedule capture jobs from threads other
	// than the sinsp_worker thread. It actually passes the
	// request along to the capture_job_handler thread, but does
	// some necessary prep work such as creating sinsp_dumper
	// objects, etc.
	void queue_job_request(std::shared_ptr<capture_job_handler::dump_job_request> job_request) override;

	uint64_t get_last_loop_ns() const
	{
		return m_last_loop_ns;
	}

	/**
	 * Returns whether the sinsp_worker is running in a mode where
	 *         the caller should verify that get_last_loop_ns has
	 *         fallen behind the current wall time.
	 */
	bool is_stall_fatal() const;

	pthread_t get_pthread_id()
	{
		return m_pthread_id;
	}

	const sinsp* get_inspector() const
	{
		return m_inspector.get();
	}

	const sinsp_data_handler* get_sinsp_data_handler() const
	{
		return &m_sinsp_handler;
	}

	void set_statsite_pipes(std::shared_ptr<pipe_manager> pipes)
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
	bool load_policies(const draiosproto::policies &policies,
	                   std::string &errstr) override;
	bool load_policies_v2(const draiosproto::policies_v2 &policies_v2,
	                      std::string &errstr) override;
	bool set_compliance_calendar(const draiosproto::comp_calendar &calendar,
				     bool send_results,
				     bool send_events,
				     std::string &errstr) override;
	bool run_compliance_tasks(const draiosproto::comp_run &run,
	                          std::string &errstr) override;
	void receive_hosts_metadata(const draiosproto::orchestrator_events &evts) override;
#endif
	bool load_baselines(const draiosproto::baselines &baselines,
	                    std::string &errstr) override;

private:
	void init();
	void do_grpc_tracing();
	void process_job_requests(bool should_dump);
	void check_autodrop(uint64_t ts_ns);
	bool handle_signal_dump();

	void get_internal_metrics();

	bool get_statsd_limit() const;

	static const std::string m_name;

	run_on_interval m_job_requests_interval;

	bool m_initialized;
	dragent_configuration *m_configuration;
	protocol_queue* m_queue;
	std::atomic<bool> *m_enable_autodrop;
	bool m_autodrop_currently_enabled;
	sinsp::ptr m_inspector;
	sinsp_analyzer* m_analyzer;
#ifndef CYGWING_AGENT
	security_mgr *m_security_mgr;
	compliance_mgr *m_compliance_mgr;
#endif
	capture_job_handler *m_capture_job_handler;
	sinsp_data_handler m_sinsp_handler;
	blocking_queue<std::shared_ptr<capture_job_handler::dump_job_request>> m_dump_job_requests;
	std::atomic<uint64_t> m_last_loop_ns;
	std::atomic<pthread_t> m_pthread_id;
	std::shared_ptr<pipe_manager> m_statsite_pipes;
	bool m_statsd_capture_localhost;
	bool m_app_checks_enabled;
	bool m_grpc_trace_enabled;
	uint64_t m_last_mode_switch_time;

	static const uint64_t IFLIST_REFRESH_FIRST_TIMEOUT_NS = 30*ONE_SECOND_IN_NS;
	static const uint64_t IFLIST_REFRESH_TIMEOUT_NS = 10*60*ONE_SECOND_IN_NS;
	uint64_t m_next_iflist_refresh_ns;
	aws_metadata_refresher m_aws_metadata_refresher;

	user_event_queue::ptr_t m_user_event_queue;
	internal_metrics::sptr_t m_internal_metrics;

	friend class dragent_app;
	friend class memdump_test;
	friend class security_policies_test;
};
