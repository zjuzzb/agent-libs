#ifndef CYGWING_AGENT
#include <google/protobuf/text_format.h>

#include "compliance_mgr.h"

using namespace std;

compliance_mgr::compliance_mgr(const string &run_root)
	: m_num_grpc_errs(0),
	  m_send_compliance_results(false),
	  m_send_compliance_events(false),
	  m_should_refresh_compliance_tasks(false),
	  m_initialized(false),
	  m_sinsp_handler(NULL),
	  m_analyzer(NULL),
	  m_cointerface_sock_path("unix:" + run_root + "/cointerface.sock")
{
}

compliance_mgr::~compliance_mgr()
{
	stop_compliance_tasks();
}

void compliance_mgr::init(sinsp_data_handler *sinsp_handler,
			  sinsp_analyzer *analyzer,
			  dragent_configuration *configuration,
			  bool save_errors)
{
	m_sinsp_handler = sinsp_handler;
	m_analyzer = analyzer;
	m_configuration = configuration;
	m_save_errors = save_errors;

	m_check_periodic_tasks_interval = make_unique<run_on_interval>(1000000000);

	m_comp_events_queue = make_shared<tbb::concurrent_queue<sdc_internal::comp_task_event>>();

	m_grpc_channel = grpc::CreateChannel(m_cointerface_sock_path, grpc::InsecureChannelCredentials());

	m_initialized = true;
}

void compliance_mgr::process_event(sinsp_evt *evt)
{
	if(!m_initialized)
	{
		return;
	}

	uint64_t ts_ns = evt->get_ts();

	m_check_periodic_tasks_interval->run([this, ts_ns]()
        {
		check_tasks();
	});

}

void compliance_mgr::check_tasks()
{
	check_pending_task_results();

	check_run_tasks_status();

	if(m_should_refresh_compliance_tasks)
	{
		refresh_compliance_tasks();
		m_should_refresh_compliance_tasks = false;
	}
}

void compliance_mgr::set_compliance_calendar(draiosproto::comp_calendar &calendar, bool send_results, bool send_events)
{
	m_compliance_calendar = calendar;
	m_send_compliance_results = send_results;
	m_send_compliance_events = send_events;
	request_refresh_compliance_tasks();
}

void compliance_mgr::request_refresh_compliance_tasks()
{
	m_should_refresh_compliance_tasks = true;
}

void compliance_mgr::set_compliance_run(draiosproto::comp_run &run)
{
	m_compliance_run = run;
}

void compliance_mgr::refresh_compliance_tasks()
{
	g_log->debug("Checking for new compliance tasks from calendar: " + m_compliance_calendar.DebugString());

	std::set<uint64_t> new_tasks;

	// The calendar might refer to tasks that are not enabled or
	// tasks that don't match the scope of this agent or the
	// containers it runs. So we create a separate calendar just
	// for the tasks that should actually run.
	sdc_internal::comp_start start;

	start.set_machine_id(m_configuration->machine_id());
	start.set_customer_id(m_configuration->m_customer_id);
	start.set_include_desc(m_configuration->m_security_include_desc_in_compliance_results);
	start.set_send_failed_results(m_configuration->m_security_compliance_send_failed_results);
	start.set_save_temp_files(m_configuration->m_security_compliance_save_temp_files);

	for(auto &task : m_compliance_calendar.tasks())
	{
		if(!task.enabled())
		{
			continue;
		}

		// Check the scope of the task. Unlike other
		// policies, where we have an event with an associated
		// container id, we need to register this scope with the
		// infrastructure_state object so it can reevaluate the scope
		// as containers come and go.
		infrastructure_state::reg_id_t reg = "compliance_tasks:" + task.name();

		if(m_analyzer)
		{
			m_analyzer->infra_state()->register_scope(reg,
								  true,
								  true,
								  task.scope_predicates());

			// For now, do a single check of the registered scope and only
			// start the compliance modules if the scope matches. Later,
			// we'll want to periodically check and start/stop modules.
			if(!m_analyzer->infra_state()->check_registered_scope(reg))
			{
				g_log->information("Not starting compliance task (scope doesn't match)");
				continue;
			}
		}

		draiosproto::comp_task *run_task = start.mutable_calendar()->add_tasks();

		*run_task = task;

		// If the task is a kube-bench task and if the agent
		// is configured to run a specific variant, pass the
		// variant as a param.
		if(m_configuration->m_security_compliance_kube_bench_variant != "")
		{
			draiosproto::comp_task_param *param = run_task->add_task_params();
			param->set_key("variant");
			param->set_val(m_configuration->m_security_compliance_kube_bench_variant);
		}

		new_tasks.insert(task.id());
	}

	if(new_tasks == m_cur_compliance_tasks)
	{
		g_log->information("Compliance tasks unchanged, not doing anything");
		return;
	}

	m_cur_compliance_tasks = new_tasks;

	start_compliance_tasks(start);
}

void compliance_mgr::start_compliance_tasks(sdc_internal::comp_start &start)
{
	g_log->debug("Starting compliance tasks: " + start.DebugString());

	// Stop any existing tasks.
	stop_compliance_tasks();

	// Start a thread that does the RPC and writes to the queue
	auto work = [](std::shared_ptr<grpc::Channel> chan,
		       shared_comp_event_queue queue,
		       sdc_internal::comp_start start)
        {
		grpc::ClientContext context;
		std::unique_ptr<sdc_internal::ComplianceModuleMgr::Stub> stub = sdc_internal::ComplianceModuleMgr::NewStub(chan);
		std::unique_ptr<grpc::ClientReader<sdc_internal::comp_task_event>> reader(stub->Start(&context, start));

		sdc_internal::comp_task_event ev;

		while(reader->Read(&ev))
		{
			queue->push(ev);
		}

		grpc::Status status = reader->Finish();

		return status;
	};

	m_start_tasks_future = std::async(std::launch::async, work, m_grpc_channel, m_comp_events_queue, start);
}

void compliance_mgr::run_compliance_tasks(draiosproto::comp_run &run)
{
	g_log->debug("Running compliance tasks: " + run.DebugString());

	auto work =
		[](std::shared_ptr<grpc::Channel> chan,
		   draiosproto::comp_run run)
                {
			std::unique_ptr<sdc_internal::ComplianceModuleMgr::Stub> stub = sdc_internal::ComplianceModuleMgr::NewStub(chan);
			grpc::ClientContext context;
			grpc::Status status;
			sdc_internal::comp_run_result res;

			status = stub->RunTasks(&context, run, &res);
			if(!status.ok())
			{
				res.set_successful(false);
				res.set_errstr(status.error_message());
			}

			return res;
		};

	m_run_tasks_future = std::async(std::launch::async, work, m_grpc_channel, run);
}

void compliance_mgr::stop_compliance_tasks()
{
	if(!m_start_tasks_future.valid())
	{
		return;
	}

	auto work =
		[](std::shared_ptr<grpc::Channel> chan)
                {
			sdc_internal::comp_stop stop;

			std::unique_ptr<sdc_internal::ComplianceModuleMgr::Stub> stub = sdc_internal::ComplianceModuleMgr::NewStub(chan);
			grpc::ClientContext context;
			grpc::Status status;
			sdc_internal::comp_stop_result res;

			status = stub->Stop(&context, stop, &res);
			if(!status.ok())
			{
				res.set_successful(false);
				res.set_errstr(status.error_message());
			}

			return res;
		};

	std::future<sdc_internal::comp_stop_result> stop_future = std::async(std::launch::async, work, m_grpc_channel);

	// Wait up to 10 seconds for the stop to complete.
	if(stop_future.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
	{
		g_log->error("Did not receive response to Compliance Stop() call within 10 seconds");
		return;
	}
	else
	{
		sdc_internal::comp_stop_result res = stop_future.get();
		if(!res.successful())
		{
			g_log->debug("Compliance Stop() call returned error " + res.errstr());
		}
	}
}

bool compliance_mgr::get_future_runs(sdc_internal::comp_get_future_runs &req, sdc_internal::comp_future_runs &res, std::string &errstr)
{
	// This does a blocking RPC without a separate thread or
	// future. But it's only used for testing.

	std::unique_ptr<sdc_internal::ComplianceModuleMgr::Stub> stub = sdc_internal::ComplianceModuleMgr::NewStub(m_grpc_channel);

	grpc::ClientContext context;
	grpc::Status status;

	status = stub->GetFutureRuns(&context, req, &res);

	if(!status.ok())
	{
		errstr = status.error_message();
		return false;
	}

	return true;
}

void compliance_mgr::check_pending_task_results()
{
	// First check the status of the future. This is returned when
	// the start completes (either due to an error or due to being
	// stopped)
	if(m_start_tasks_future.valid() &&
	   m_start_tasks_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
	{
		grpc::Status res = m_start_tasks_future.get();

		if(!res.ok())
		{
			g_log->error("Could not start compliance tasks (" +
				     res.error_message() +
				     "), trying again in " +
				     NumberFormatter::format(m_configuration->m_security_compliance_refresh_interval / 1000000000) +
				     " seconds");
		}
		else
		{
			g_log->debug("Compliance Start GRPC completed");
		}
	}

	// Now try to read any pending compliance messages from the queue
	sdc_internal::comp_task_event cevent;

	while(m_comp_events_queue->try_pop(cevent))
	{
		g_log->debug("Response from compliance start: cevent=" +
			     cevent.DebugString());

		if(!cevent.init_successful())
		{
			g_log->error("Could not initialize compliance task " +
				     cevent.task_name() +
				     " (" +
				     cevent.errstr() +
				     "), trying again in " +
				     NumberFormatter::format(m_configuration->m_security_compliance_refresh_interval / 1000000000) +
				     " seconds");

			m_num_grpc_errs++;

			if(m_save_errors)
			{
				m_task_errors[cevent.task_name()].push_back(cevent.errstr());
			}
		}


		if(m_send_compliance_events)
		{
			for(int i=0; i<cevent.events().events_size(); i++)
			{
				// XXX/mstemm need to fill this in once we've decided on a message format.
			}
		}

		if(m_send_compliance_results)
		{
			if(cevent.results().results_size() > 0)
			{
				m_sinsp_handler->security_mgr_comp_results_ready(cevent.results().results(0).timestamp_ns(),
										 &(cevent.results()));
			}
		}
	}
}

void compliance_mgr::check_run_tasks_status()
{
	if(m_run_tasks_future.valid() &&
	   m_run_tasks_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
	{
		sdc_internal::comp_run_result res = m_run_tasks_future.get();

		if(!res.successful())
		{
			g_log->error(string("Could not run compliance tasks (") + res.errstr() + ")");
		}
	}

	if(!m_compliance_run.task_ids().empty())
	{
		run_compliance_tasks(m_compliance_run);

		// Reset to empty message
		m_compliance_run = draiosproto::comp_run();
	}
}

#endif // CYGWING_AGENT
