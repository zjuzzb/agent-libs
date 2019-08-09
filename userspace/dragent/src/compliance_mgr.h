#ifndef CYGWING_AGENT
#pragma once

#include <memory>
#include <future>
#include <map>

#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include <tbb/concurrent_queue.h>

#include <draios.pb.h>

#include "sinsp_data_handler.h"
#include "configuration.h"

class SINSP_PUBLIC compliance_mgr
{
public:
	compliance_mgr(const std::string& run_root);
	virtual ~compliance_mgr();

	void init(sinsp_data_handler *sinsp_handler,
		  sinsp_analyzer *analyzer,
		  dragent_configuration *configuration,
		  bool save_errors=false);

	void process_event(sinsp_evt *evt);

	// Check the status of new configuration and in-progress rpc calls.
	void check_tasks();

	void set_compliance_calendar(const draiosproto::comp_calendar &calendar, bool send_results, bool send_events);
	void request_refresh_compliance_tasks();
	void set_compliance_run(const draiosproto::comp_run &run);

	void stop_compliance_tasks();

	// These are only used for testing
	std::map<std::string, std::vector<std::string>> m_task_errors;
	uint64_t m_num_grpc_errs;
	bool get_future_runs(sdc_internal::comp_get_future_runs &req, sdc_internal::comp_future_runs &res, std::string &errstr);

private:

	void refresh_compliance_tasks();
	void run_compliance_tasks(draiosproto::comp_run &run);
	void start_compliance_tasks(sdc_internal::comp_start &start);
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
	sinsp_data_handler *m_sinsp_handler;
	sinsp_analyzer *m_analyzer;
	dragent_configuration *m_configuration;
	bool m_save_errors;
	std::string m_cointerface_sock_path;

	std::shared_ptr<grpc::Channel> m_grpc_channel;

	std::future<sdc_internal::comp_run_result> m_run_tasks_future;
	std::future<grpc::Status> m_start_tasks_future;

	typedef std::shared_ptr<tbb::concurrent_queue<sdc_internal::comp_task_event>> shared_comp_event_queue;
	shared_comp_event_queue m_comp_events_queue;
};
#endif // CYGWING_AGENT
