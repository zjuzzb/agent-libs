#include "sinsp_worker.h"
#include "common_logger.h"
#include "container_config.h"
#include "config_update.h"
#include "error_handler.h"
#include "infrastructure_state.h"
#include "memdumper.h"
#include "run_once_after.h"
#include "security_config.h"
#include "sinsp_factory.h"
#include "utils.h"
#include "user_event_logger.h"
#include "type_config.h"
#include "statsite_config.h"
#include <grpc/grpc.h>
#include <grpc/support/log.h>
#include <Poco/DateTimeFormatter.h>
#include "protocol_handler.h"

using namespace std;
using namespace dragent;

namespace security_config = libsanalyzer::security_config;

namespace
{

COMMON_LOGGER();

type_config<uint16_t> config_increased_snaplen_port_range_start(
		0,
		"Starting port in the range of ports to enable a larger snaplen on",
		"increased_snaplen_port_range_start");
type_config<uint16_t> config_increased_snaplen_port_range_end(
		0,
		"Ending port in the range of ports to enable a larger snaplen on",
		"increased_snaplen_port_range_end");

type_config<uint16_t>::ptr c_inspector_start_delay_s =
    type_config_builder<uint16_t>(1,
                                  "Amount of time to wait before starting the"
                                  " system call inspector.  It can be useful to"
                                  " delay the inspector if the agent terminates"
                                  " soon after starting because it gets behind"
                                  " in processing system calls",
                                  "inspector_start_delay_s")
        .min(1)
        .build();

} // namespace

class sinsp_worker::compliance_calendar_backup
{
public:
	compliance_calendar_backup(const draiosproto::comp_calendar& calendar,
				   const bool send_results,
				   const bool send_events):
		m_calendar(calendar),
		m_send_results(send_results),
		m_send_events(send_events)
	{ }

	const draiosproto::comp_calendar& get_calendar() const
	{
		return m_calendar;
	}

	void set_calendar(const draiosproto::comp_calendar& calendar)
	{
		m_calendar = calendar;
	}

	bool get_send_results() const
	{
		return m_send_results;
	}

	void set_send_results(const bool send_results)
	{
		m_send_results = send_results;
	}

	bool get_send_events() const
	{
		return m_send_events;
	}

	void set_send_events(const bool send_events)
	{
		m_send_events = send_events;
	}

private:
	draiosproto::comp_calendar m_calendar;
	bool m_send_results;
	bool m_send_events;
};

const string sinsp_worker::m_name = "sinsp_worker";

sinsp_worker::sinsp_worker(dragent_configuration* configuration,
			   const internal_metrics::sptr_t& im,
			   protocol_handler& handler,
			   capture_job_handler *capture_job_handler):
	m_job_requests_interval(1000000000),
	m_initialized(false),
	m_configuration(configuration),
	m_protocol_handler(handler),
	m_analyzer(NULL),
#ifndef CYGWING_AGENT
	m_security_initialized(false),
	m_security_mgr(NULL),
	m_compliance_mgr(NULL),
	m_hosts_metadata_uptodate(true),
#endif
	m_capture_job_handler(capture_job_handler),
	m_dump_job_requests(10),
	m_last_loop_ns(0),
	m_statsd_capture_localhost(false),
	m_grpc_trace_enabled(false),
	m_last_mode_switch_time(0),
	m_next_iflist_refresh_ns(0),
	m_aws_metadata_refresher(*configuration),
	m_internal_metrics(im),
	m_capture_paused(false)
{ }

sinsp_worker::~sinsp_worker()
{
	if(m_inspector)
	{
		m_inspector->set_log_callback(0);
		// Manually delete the inspector so that it is destroyed
		// before the other objects
		m_inspector.reset();
	}

	delete m_analyzer;
#ifndef CYGWING_AGENT
	delete m_security_mgr;
	delete m_compliance_mgr;
#endif
}

void sinsp_worker::init_security()
{
#ifndef CYGWING_AGENT
	ASSERT(!m_security_initialized);

	// If auto config is enabled, then we defer security initialization
	// until after receiving the CONFIG_DATA message from the backend to
	// avoid performing the initialization twice, once before the
	// CONFIG_DATA and once after receiving that message (and the
	// subsequent agent restart).
	if(m_configuration->m_auto_config)
	{
		if(!config_update::received() && !config_update::timed_out())
		{
			return;
		}

		// The CONFIG_DATA message resulted in a config update, so the agent
		// will restart soon.  Skip initialization.
		if(config_update::updated())
		{
			return;
		}

		LOG_INFO("Proceeding with security initialization");
	}

	std::lock_guard<std::mutex> lock(m_security_mgr_creation_mutex);

	if(security_config::is_enabled())
	{
		if(!m_configuration->m_cointerface_enabled)
		{
			LOGGED_THROW(sinsp_exception,
				     "Security capabilities depend on cointerface, "
				     "but cointerface is disabled.");
		}

		m_security_mgr = new security_mgr(m_configuration->c_root_dir.get_value(),
						  m_protocol_handler);
		m_security_mgr->init(m_inspector.get(),
				     m_analyzer,
				     m_capture_job_handler,
				     m_configuration,
				     m_internal_metrics);

		if(security_config::get_policies_v2_file() != "")
		{
			std::string errstr;

			if(!m_security_mgr->load_policies_v2_file(
						security_config::get_policies_v2_file().c_str(),
						errstr))
			{
				LOGGED_THROW(sinsp_exception,
					     "Could not load policies_v2 from file: %s",
					     errstr.c_str());
			}
		}
		else if(security_config::get_policies_file() != "")
		{
			std::string errstr;

			if(!m_security_mgr->load_policies_file(
						security_config::get_policies_file().c_str(),
						errstr))
			{
				LOGGED_THROW(sinsp_exception,
					     "Could not load policies from file: %s",
					     errstr.c_str());
			}
		}

		if(security_config::get_baselines_file() != "")
		{
			std::string errstr;

			if(!m_security_mgr->load_baselines_file(
						security_config::get_baselines_file().c_str(),
						errstr))
			{
				LOGGED_THROW(sinsp_exception,
					     "Could not load baselines from file: %s",
					     errstr.c_str());
			}
		}
	}

	if(m_configuration->m_cointerface_enabled)
	{
		const std::string run_dir =
			m_configuration->c_root_dir.get_value() + "/run";

		m_compliance_mgr = new compliance_mgr(run_dir, m_protocol_handler);
		m_compliance_mgr->init(m_analyzer,
				       m_configuration);

		if(security_config::get_default_compliance_schedule() != "")
		{
			std::string errstr;
			draiosproto::comp_calendar cal;

			draiosproto::comp_task* const k8s_task = cal.add_tasks();
			k8s_task->set_id(1);
			k8s_task->set_name("Check K8s Environment");
			k8s_task->set_mod_name("kube-bench");
			k8s_task->set_enabled(true);
			k8s_task->set_schedule(security_config::get_default_compliance_schedule());

			draiosproto::comp_task* const docker_task = cal.add_tasks();
			docker_task->set_id(2);
			docker_task->set_name("Check Docker Environment");
			docker_task->set_mod_name("docker-bench-security");
			docker_task->set_enabled(true);
			docker_task->set_schedule(security_config::get_default_compliance_schedule());

			// When using a default calendar, never send results or events
			const bool send_results = false;
			const bool send_events = false;
			if(!set_compliance_calendar_internal(cal,
			                                     send_results,
			                                     send_events,
			                                     errstr))
			{
				LOGGED_THROW(sinsp_exception,
					     "Could not set default compliance calendar: %s",
					     errstr.c_str());
			}
		}
	}

	//
	// If the agent received any policies/policies_v2/comp_calendar from
	// the backend while it was waiting for CONFIG_DATA, then load that
	// backup version now.
	//

	if(m_security_mgr && m_security_policies_backup)
	{
		std::string errstr;

		LOG_INFO("Loading backup security policies");
		if(!m_security_mgr->load_policies(*m_security_policies_backup, errstr))
		{
			LOG_ERROR("Failed to load backup policies, err: %s",
				  errstr.c_str());
		}

		m_security_policies_backup.reset();
	}

	if(m_security_mgr && m_security_policies_v2_backup)
	{
		std::string errstr;

		LOG_INFO("Loading backup security policies_v2");
		if(!m_security_mgr->load_policies_v2(*m_security_policies_v2_backup, errstr))
		{
			LOG_ERROR("Failed to load backup policies_v2, err: %s",
				  errstr.c_str());
		}

		m_security_policies_v2_backup.reset();
	}

	if(m_compliance_mgr && m_security_compliance_calendar_backup)
	{
		LOG_INFO("Loading backup security compliance calendar");
		m_compliance_mgr->set_compliance_calendar(
				m_security_compliance_calendar_backup->get_calendar(),
				m_security_compliance_calendar_backup->get_send_results(),
				m_security_compliance_calendar_backup->get_send_events());

		m_security_compliance_calendar_backup.reset();
	}

	m_security_initialized = true;
#endif // CYGWING_AGENT
}

void sinsp_worker::init(sinsp::ptr& inspector, sinsp_analyzer* analyzer)
{
	if(m_initialized)
	{
		return;
	}

	m_initialized = true;

	m_inspector = inspector;
	m_analyzer = analyzer;

	stress_tool_matcher::set_comm_list(m_configuration->m_stress_tools);

	for(const auto &comm : m_configuration->m_suppressed_comms)
	{
		m_inspector->suppress_events_comm(comm);
	}

	m_inspector->set_query_docker_image_info(m_configuration->m_query_docker_image_info);
	m_inspector->set_cri_socket_path(c_cri_socket_path->get_value());
	m_inspector->set_cri_timeout(c_cri_timeout_ms.get_value());
	m_inspector->set_cri_extra_queries(c_cri_extra_queries.get_value());
	m_inspector->set_cri_async(c_cri_async.get_value());
	m_inspector->set_cri_delay(c_cri_delay_ms.get_value());

	if(c_cri_socket_path->get_value().empty())
	{
		LOG_INFO("CRI support disabled.");
	}
	else
	{
		LOG_INFO("CRI support enabled, socket: %s", c_cri_socket_path->get_value().c_str());
	}

	//
	// Start the capture with sinsp
	//
	g_log->information("Opening the capture source");
	if(!m_configuration->m_input_filename.empty())
	{
		m_inspector->open(m_configuration->m_input_filename);
	}
	else if(m_configuration->m_mode == dragent_mode_t::NODRIVER)
	{
		m_inspector->open_nodriver();
		// Change these values so the inactive thread pruning
		// runs more often
		m_inspector->m_thread_timeout_ns = 0;
		m_inspector->m_inactive_thread_scan_time_ns = NODRIVER_PROCLIST_REFRESH_INTERVAL_NS;
	}
	else if (m_configuration->m_mode == dragent_mode_t::SIMPLEDRIVER)
	{
		m_analyzer->get_configuration()->set_detect_stress_tools(m_configuration->m_detect_stress_tools);
		m_inspector->open("");
		pause_capture();
		m_inspector->set_simpledriver_mode();
		m_analyzer->set_simpledriver_mode();
	}
	else
	{
		m_analyzer->get_configuration()->set_detect_stress_tools(m_configuration->m_detect_stress_tools);

		m_inspector->open("");
		pause_capture();

		if(m_configuration->m_snaplen != 0)
		{
			m_inspector->set_snaplen(m_configuration->m_snaplen);
		}

		uint16_t range_start = config_increased_snaplen_port_range_start.get_value();
		uint16_t range_end = config_increased_snaplen_port_range_end.get_value();

		if(range_start > 0 && range_end > 0)
		{
			try
			{
				m_inspector->set_fullcapture_port_range(range_start, range_end);
			}
			catch(const sinsp_exception& e)
			{
				// If (for some reason) sysdig doesn't have the corresponding changes
				// then it will throw a sinsp_exception when setting the fullcapture
				// range. Just log an error and continue.
				g_log->error("Could not set increased snaplen size (are you running with updated sysdig?): " + string(e.what()));
			}
		}

		const uint16_t statsd_port = libsanalyzer::statsite_config::get_udp_port();

		if(statsd_port != libsanalyzer::statsite_config::DEFAULT_STATSD_PORT)
		{
			try
			{
				m_inspector->set_statsd_port(statsd_port);
			}
			catch(const sinsp_exception& e)
			{
				// The version of sysdig we're working with doesn't
				// support this operation.
				g_log->error("Could not set statsd port in driver (are "
					     "you running with updated sysdig?): " +
					     string(e.what()));
			}
		}
	}

#ifndef CYGWING_AGENT
	for(const auto type : m_configuration->m_suppressed_types)
	{
		const std::string type_str = to_string(type);

		try
		{
			LOG_DEBUG("Setting eventmask for ignored type: %s",
			          type_str.c_str());
			m_inspector->unset_eventmask(type);
		}
		catch (const sinsp_exception& ex)
		{
			LOG_ERROR("Setting eventmask for type '%s' failed, err: %s",
			          type_str.c_str(),
			          ex.what());
		}
	}
#endif // CYGWING_AGENT

	if(m_configuration->m_procfs_scan_thread)
	{
		LOG_INFO("Procfs scan thread enabled, ignoring switch events");
		try
		{
			m_inspector->unset_eventmask(PPME_SCHEDSWITCH_1_E);
			m_inspector->unset_eventmask(PPME_SCHEDSWITCH_6_E);
		}
		catch (const sinsp_exception& ex)
		{
			LOG_ERROR("Failed to ignore switch events, err: %s",
			          ex.what());
		}
	}

	if(m_configuration->m_aws_metadata.m_public_ipv4)
	{
		sinsp_ipv4_ifinfo aws_interface(m_configuration->m_aws_metadata.m_public_ipv4,
			m_configuration->m_aws_metadata.m_public_ipv4, m_configuration->m_aws_metadata.m_public_ipv4, "aws");
		m_inspector->import_ipv4_interface(aws_interface);
	}

	m_analyzer->set_protocols_enabled(m_configuration->m_protocols_enabled);
	m_analyzer->set_statsd_capture_localhost(m_statsd_capture_localhost);

	m_analyzer->set_containers_limit(m_configuration->m_containers_limit);
	m_analyzer->set_container_patterns(m_configuration->m_container_patterns);
	m_analyzer->set_containers_labels_max_len(m_configuration->m_containers_labels_max_len);
	m_next_iflist_refresh_ns = sinsp_utils::get_current_time_ns()+IFLIST_REFRESH_FIRST_TIMEOUT_NS;

	m_analyzer->set_user_event_queue(m_user_event_queue);

	m_analyzer->set_emit_tracers(m_configuration->m_emit_tracers);
	m_analyzer->set_flush_log_time(m_configuration->m_flush_log_time);
	m_analyzer->set_flush_log_time_duration(m_configuration->m_flush_log_time_duration);
	m_analyzer->set_flush_log_time_cooldown(m_configuration->m_flush_log_time_cooldown);

#ifndef CYGWING_AGENT
	m_analyzer->set_coclient_max_loop_evts(m_configuration->m_coclient_max_loop_evts);
#endif
	m_analyzer->set_max_n_external_clients(m_configuration->m_max_n_external_clients);
	m_analyzer->set_top_connections_in_sample(m_configuration->m_top_connections_in_sample);
	m_analyzer->set_top_processes_in_sample(m_configuration->m_top_processes_in_sample);
	m_analyzer->set_top_processes_per_container(m_configuration->m_top_processes_per_container);
	m_analyzer->set_report_source_port(m_configuration->m_report_source_port);

        if (m_configuration->m_url_groups_enabled)
        {
            m_analyzer->set_url_groups(m_configuration->m_url_groups);
        }
	m_analyzer->set_track_connection_status(m_configuration->m_track_connection_status);
	m_analyzer->set_connection_truncate_report_interval(m_configuration->m_connection_truncate_report_interval);
	m_analyzer->set_connection_truncate_log_interval(m_configuration->m_connection_truncate_log_interval);

	m_analyzer->set_username_lookups(m_configuration->m_username_lookups);

	m_analyzer->set_top_files(
		m_configuration->m_top_files_per_prog,
		m_configuration->m_top_files_per_container,
		m_configuration->m_top_files_per_host);

	m_analyzer->set_top_devices(
		m_configuration->m_top_file_devices_per_prog,
		m_configuration->m_top_file_devices_per_container,
		m_configuration->m_top_file_devices_per_host);

	metric_forwarding_configuration::print();
}

void sinsp_worker::run()
{
	userspace_shared::run_once_after inspector_delayed_start(
			c_inspector_start_delay_s->get_value() * ONE_SECOND_IN_NS,
			sinsp_utils::get_current_time_ns);

	uint64_t nevts = 0;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;

	m_pthread_id = pthread_self();

	g_log->information("sinsp_worker: Starting");

	if(!m_initialized)
	{
		throw sinsp_exception("Starting uninitialized worker");
	}

	if (m_configuration->m_config_test)
	{
		dragent_configuration::m_terminate = true;
		m_analyzer->dump_config_test();
	}

	m_last_loop_ns = sinsp_utils::get_current_time_ns();

	while(!dragent_configuration::m_terminate)
	{
		// This will happen only the first time after receiving the
		// CONFIG_DATA message from the backend (or a timeout)
		if(!m_security_initialized)
		{
			init_security();
		}

		if(m_configuration->m_evtcnt != 0 && nevts == m_configuration->m_evtcnt)
		{
			dragent_configuration::m_terminate = true;
			break;
		}

		if (m_capture_paused)
		{
			// Run once c_inspector_start_delay_s seconds after
			// the sinsp_worker thread starts
			inspector_delayed_start.run(
				[this]()
				{
					LOG_INFO("Resuming capture");
					m_capture_paused = false;
					m_inspector->start_capture();
					m_inspector->refresh_proc_list();
				});
		}

		res = m_inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			m_last_loop_ns = sinsp_utils::get_current_time_ns();
			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			cerr << "res = " << res << endl;
			LOGGED_THROW(sinsp_exception, "%s", m_inspector->getlasterr().c_str());
		}

		if(m_analyzer->get_mode_switch_state() >= sinsp_analyzer::MSR_REQUEST_NODRIVER)
		{
			if(m_analyzer->get_mode_switch_state() == sinsp_analyzer::MSR_REQUEST_NODRIVER)
			{
				auto evt = sinsp_user_event(
					ev->get_ts() / ONE_SECOND_IN_NS,
					"Agent switch to nodriver",
					"Agent switched to nodriver mode due to high overhead",
					std::move(event_scope("host.mac", m_configuration->machine_id()).get_ref()),
					{ {"source", "agent"} },
					user_event_logger::SEV_EVT_WARNING);
				user_event_logger::log(evt, user_event_logger::SEV_EVT_WARNING);

				m_last_mode_switch_time = ev->get_ts();

				m_inspector->close();
				m_analyzer->set_mode_switch_state(sinsp_analyzer::MSR_SWITCHED_TO_NODRIVER);
				m_analyzer->ack_sampling_ratio(1);

				m_inspector->open_nodriver();
				// Change these values so the inactive thread pruning
				// runs more often
				m_inspector->m_thread_timeout_ns = 0;
				m_inspector->m_inactive_thread_scan_time_ns = NODRIVER_PROCLIST_REFRESH_INTERVAL_NS;

				continue;
			}
			else
			{
				static bool full_mode_event_sent = false;
				if(ev->get_ts() - m_last_mode_switch_time > MIN_NODRIVER_SWITCH_TIME)
				{
					// TODO: investigate if we can void agent restart and just reopen the inspector
					LOGGED_THROW(sinsp_exception, "restarting agent to restore normal operation mode");
				}
				else if(!full_mode_event_sent && ev->get_ts() - m_last_mode_switch_time > MIN_NODRIVER_SWITCH_TIME - 2*ONE_SECOND_IN_NS)
				{
					// Since we restart the agent to apply the switch back, we have to send the event
					// few seconds before doing it otherwise there can be chances that it's not sent at all
					full_mode_event_sent = true;
					auto evt = sinsp_user_event(
						ev->get_ts() / ONE_SECOND_IN_NS,
						"Agent restore full mode",
						"Agent restarting to restore full operation mode",
						std::move(event_scope("host.mac", m_configuration->machine_id()).get_ref()),
						{ {"source", "agent"} },
						user_event_logger::SEV_EVT_WARNING);

					user_event_logger::log(evt, user_event_logger::SEV_EVT_WARNING);
				}
			}
		}

		const bool should_dump = handle_signal_dump();

		//
		// Update the time
		//
		ts = ev->get_ts();
		m_last_loop_ns = ts;

		m_job_requests_interval.run([this, should_dump]()
		{
			process_job_requests(should_dump);
		}, ts);

		if(!m_inspector->is_capture() && (ts > m_next_iflist_refresh_ns) && !m_aws_metadata_refresher.is_running())
		{
			ThreadPool::defaultPool().start(m_aws_metadata_refresher, "aws_metadata_refresher");
			m_next_iflist_refresh_ns = sinsp_utils::get_current_time_ns() + IFLIST_REFRESH_TIMEOUT_NS;
		}
		if(m_aws_metadata_refresher.done())
		{
			g_log->information("Refresh network interfaces list");
			m_inspector->refresh_ifaddr_list();
			if(m_configuration->m_aws_metadata.m_public_ipv4)
			{
				sinsp_ipv4_ifinfo aws_interface(m_configuration->m_aws_metadata.m_public_ipv4,
												m_configuration->m_aws_metadata.m_public_ipv4,
												m_configuration->m_aws_metadata.m_public_ipv4, "aws");
				m_inspector->import_ipv4_interface(aws_interface);
			}
			m_aws_metadata_refresher.reset();
		}

#ifndef CYGWING_AGENT
		bool update_hosts_metadata = !m_hosts_metadata_uptodate.test_and_set();

		// Possibly pass the event to the security manager
		if(m_security_mgr)
		{
			std::string errstr;
			if(update_hosts_metadata && !m_security_mgr->reload_policies(errstr))
			{
				LOG_ERROR("Could not reload policies after receiving "
					  "new hosts metadata: %s", errstr.c_str());
			}
			m_security_mgr->process_event(ev);
		}

		if(m_compliance_mgr)
		{
			if(update_hosts_metadata)
			{
				m_compliance_mgr->request_refresh_compliance_tasks();
			}
			m_compliance_mgr->process_event(ev);
		}
#endif

		m_capture_job_handler->process_event(ev);

		//
		// Update the event count
		//
		++nevts;
	}

	g_log->information("sinsp_worker: Terminating");
}

bool sinsp_worker::handle_signal_dump()
{
	if(!dragent_configuration::m_signal_dump)
	{
		return false;
	}

	dragent_configuration::m_signal_dump = false;

	m_analyzer->dump_infrastructure_state_on_next_flush();

	return true;
}

void sinsp_worker::queue_job_request(std::shared_ptr<capture_job_handler::dump_job_request> job_request)
{
	g_log->information(m_name + ": scheduling job request type=" +
			   capture_job_handler::dump_job_request::request_type_str(job_request->m_request_type) +
			    ", token= " + job_request->m_token);

	if(!m_dump_job_requests.put(job_request))
	{
		// Note that although the queue is for communication
		// between some other thread and the sinsp_worker
		// thread, the error response is sent via the capture
		// job handler, as it has the queue of messages that
		// go back to the connection manager.

		m_capture_job_handler->send_error(job_request->m_token, "Maximum number of requests reached");
	}
}

#ifndef CYGWING_AGENT
bool sinsp_worker::load_policies(const draiosproto::policies &policies,
                                 std::string &errstr)
{
	std::lock_guard<std::mutex> lock(m_security_mgr_creation_mutex);

	if(m_security_mgr)
	{
		return m_security_mgr->load_policies(policies, errstr);
	}

	LOG_INFO("Saving policies");
	if(m_security_policies_backup)
	{
		*m_security_policies_backup = policies;
	}
	else
	{
		m_security_policies_backup = make_unique<draiosproto::policies>(policies);
	}

	errstr = "No Security Manager object created";
	return false;
}

bool sinsp_worker::load_policies_v2(const draiosproto::policies_v2 &policies_v2,
                                    std::string &errstr)
{
	std::lock_guard<std::mutex> lock(m_security_mgr_creation_mutex);

	if(m_security_mgr)
	{
		return m_security_mgr->load_policies_v2(policies_v2, errstr);
	}

	LOG_INFO("Saving policies_v2");
	if(m_security_policies_v2_backup)
	{
		*m_security_policies_v2_backup = policies_v2;
	}
	else
	{
		m_security_policies_v2_backup = make_unique<draiosproto::policies_v2>(policies_v2);
	}

	errstr = "No Security Manager object created";
	return false;
}

bool sinsp_worker::is_stall_fatal() const
{
	// If the input filename is not empty then we are reading an scap file
	// that has old timestamps so tell the caller to not check for stalls
	return m_configuration->m_input_filename.empty();
}

bool sinsp_worker::set_compliance_calendar(
		const draiosproto::comp_calendar& calendar,
		const bool send_results,
		const bool send_events,
		std::string& errstr)
{
	std::lock_guard<std::mutex> lock(m_security_mgr_creation_mutex);

	return set_compliance_calendar_internal(calendar,
	                                        send_results,
	                                        send_events,
	                                        errstr);
}

bool sinsp_worker::set_compliance_calendar_internal(
		const draiosproto::comp_calendar& calendar,
		const bool send_results,
		const bool send_events,
		std::string& errstr)
{
	if(m_compliance_mgr)
	{
		m_compliance_mgr->set_compliance_calendar(calendar,
							  send_results,
							  send_events);
		return true;
	}

	LOG_INFO("Saving compliance calendar");
	if(m_security_compliance_calendar_backup)
	{
		m_security_compliance_calendar_backup->set_calendar(calendar);
		m_security_compliance_calendar_backup->set_send_results(send_results);
		m_security_compliance_calendar_backup->set_send_events(send_events);
	}
	else
	{
		m_security_compliance_calendar_backup =
			make_unique<compliance_calendar_backup>(calendar,
			                                        send_results,
			                                        send_events);
	}

	errstr = "No Compliance Manager object created";
	return false;
}

bool sinsp_worker::run_compliance_tasks(const draiosproto::comp_run &run,
                                        std::string &errstr)
{
	if(m_compliance_mgr)
	{
		m_compliance_mgr->set_compliance_run(run);
		return true;
	}
	else
	{
		errstr = "No Compliance Manager object created";
		return false;
	}
}

void sinsp_worker::receive_hosts_metadata(const draiosproto::orchestrator_events &evts)
{
	m_analyzer->infra_state()->receive_hosts_metadata(evts.events());
	m_hosts_metadata_uptodate.clear();
}
#endif

void sinsp_worker::do_grpc_tracing()
{
	if(m_grpc_trace_enabled)
	{
		m_grpc_trace_enabled = false;
		m_configuration->m_dirty_shutdown_report_log_size_b = m_configuration->m_dirty_shutdown_default_report_log_size_b;
		g_log->information("Received SIGSTKFLT, disabling gRPC tracing");
		grpc_tracer_set_enabled("all", 0);
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_ERROR);
	}
	else
	{
		m_grpc_trace_enabled = true;
		m_configuration->m_dirty_shutdown_report_log_size_b = m_configuration->m_dirty_shutdown_trace_report_log_size_b;
		g_log->information("Received SIGSTKFLT, enabling gRPC tracing");
		grpc_tracer_set_enabled("all", 1);
		gpr_set_log_verbosity(GPR_LOG_SEVERITY_DEBUG);
	}
}

// Receive job requests and pass them along to the capture job
// handler, adding a sinsp_dumper object associated with our
// inspector.

void sinsp_worker::process_job_requests(bool should_dump)
{
	string errstr;

	if(should_dump)
	{
		g_log->information("Received SIGUSR1, starting dump");

		std::shared_ptr<capture_job_handler::dump_job_request> job_request
			= make_shared<capture_job_handler::dump_job_request>();

		job_request->m_start_details = make_unique<capture_job_handler::start_job_details>();

		job_request->m_request_type = capture_job_handler::dump_job_request::JOB_START;
		job_request->m_token = string("dump").append(NumberFormatter::format(time(NULL)));
		job_request->m_start_details->m_duration_ns = 20000000000LL;
		job_request->m_start_details->m_delete_file_when_done = false;
		job_request->m_start_details->m_send_file = false;

		if(!m_capture_job_handler->queue_job_request(m_inspector.get(), job_request, errstr))
		{
			g_log->error("sinsp_worker: could not start capture: " + errstr);
		}
	}

	if(dragent_configuration::m_enable_trace)
	{
		dragent_configuration::m_enable_trace = false;

		if (m_configuration->m_enable_grpc_tracing) {
			do_grpc_tracing();
		}
	}

	std::shared_ptr<capture_job_handler::dump_job_request> request;
	while(m_dump_job_requests.get(&request, 0))
	{
		string errstr;

		g_log->debug("sinsp_worker: dequeued dump request token=" + request->m_token);

		if(!m_capture_job_handler->queue_job_request(m_inspector.get(), request, errstr))
		{
			// It's assumed these requests were ones from
			// the backend, so send an error to the
			// backend.
			m_capture_job_handler->send_error(request->m_token, errstr);
		}
	}
}

void sinsp_worker::pause_capture()
{
	LOG_INFO("Pausing capture");
	m_inspector->stop_capture();
	m_capture_paused = true;
}
