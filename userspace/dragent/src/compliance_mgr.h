#ifndef CYGWING_AGENT
#pragma once

#include "compliance_statsd_destination.h"
#include "configuration.h"
#include "security_compliance_calendar_receiver.h"
#include "security_compliance_task_runner.h"
#include "security_result_handler.h"

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include <draios.pb.h>
#include <future>
#include <map>
#include <memory>
#include <tbb/concurrent_queue.h>

class SINSP_PUBLIC compliance_mgr : public dragent::security_compliance_task_runner,
                                    public dragent::security_compliance_calendar_receiver
{
public:
	compliance_mgr(const std::string& run_root, security_result_handler& result_handler);
	virtual ~compliance_mgr();

	void init(sinsp_analyzer* analyzer,
	          dragent_configuration* configuration,
	          dragent::compliance_statsd_destination* statsd_dest,
	          bool save_errors = false);

	void process_event(sinsp_evt* evt);

	// Check the status of new configuration and in-progress rpc calls.
	void check_tasks();

	void request_refresh_compliance_tasks();
	void set_compliance_run(const draiosproto::comp_run& run);

	void stop_compliance_tasks();

	// These are only used for testing
	std::map<std::string, std::vector<std::string>> m_task_errors;
	uint64_t m_num_grpc_errs;
	bool get_future_runs(sdc_internal::comp_get_future_runs& req,
	                     sdc_internal::comp_future_runs& res,
	                     std::string& errstr);

public:  // security_complaince_calendar_receiver
	bool set_compliance_calendar(const draiosproto::comp_calendar& calendar,
	                             bool send_results,
	                             bool send_events) override;

public:  // security_compliance_task_runner
	bool run_compliance_tasks(const draiosproto::comp_run& run) override;

private:
	void refresh_compliance_tasks();
	void start_compliance_tasks(sdc_internal::comp_start& start);
	void check_pending_task_results();
	void check_run_tasks_status();

	draiosproto::comp_calendar m_compliance_calendar;
	bool m_send_compliance_results;
	bool m_send_compliance_events;
	draiosproto::comp_run m_compliance_run;
	std::set<uint64_t> m_cur_compliance_tasks;
	bool m_should_refresh_compliance_tasks;

	std::unique_ptr<run_on_interval> m_check_periodic_tasks_interval;
	bool m_initialized;
	security_result_handler& m_result_handler;
	sinsp_analyzer* m_analyzer;
	dragent::compliance_statsd_destination* m_statsd_dest;
	dragent_configuration* m_configuration;
	bool m_save_errors;
	std::string m_cointerface_sock_path;

	std::shared_ptr<grpc::Channel> m_grpc_channel;

	std::future<sdc_internal::comp_run_result> m_run_tasks_future;
	std::future<grpc::Status> m_start_tasks_future;

	typedef std::shared_ptr<tbb::concurrent_queue<sdc_internal::comp_task_event>>
	    shared_comp_event_queue;
	shared_comp_event_queue m_comp_events_queue;
};
#endif  // CYGWING_AGENT
