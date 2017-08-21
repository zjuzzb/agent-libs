#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include "sinsp_worker.h"

#include "logger.h"
#include "error_handler.h"
#include "utils.h"
#include "memdumper.h"
#include "Poco/DateTimeFormatter.h"

const string sinsp_worker::m_name = "sinsp_worker";

sinsp_worker::sinsp_worker(dragent_configuration* configuration,
			   internal_metrics::sptr_t im,
			   protocol_queue* queue,
			   atomic<bool> *enable_autodrop,
			   synchronized_policy_events *policy_events,
			   capture_job_handler *capture_job_handler):
	m_job_requests_interval(1000000000),
	m_initialized(false),
	m_configuration(configuration),
	m_queue(queue),
	m_enable_autodrop(enable_autodrop),
	m_autodrop_currently_enabled(true),
	m_inspector(NULL),
	m_analyzer(NULL),
	m_security_mgr(NULL),
	m_capture_job_handler(capture_job_handler),
	m_sinsp_handler(configuration, queue, policy_events),
	m_dump_job_requests(10),
	m_last_loop_ns(0),
	m_statsd_capture_localhost(false),
	m_app_checks_enabled(false),
	m_next_iflist_refresh_ns(0),
	m_aws_metadata_refresher(configuration),
	m_internal_metrics(im)
{
	m_last_mode_switch_time = 0;
}

sinsp_worker::~sinsp_worker()
{
	if(m_inspector != NULL)
	{
		m_inspector->set_log_callback(0);
		delete m_inspector;
	}

	delete m_analyzer;
	delete m_security_mgr;
}

void sinsp_worker::init()
{
	if(m_initialized)
	{
		return;
	}

	m_initialized = true;

	m_inspector = new sinsp();
	m_analyzer = new sinsp_analyzer(m_inspector);

	// custom metrics filters (!!!do not move - needed by jmx, statsd and appchecks, so it must be
	// set before checks are created!!!)
	m_analyzer->get_configuration()->set_metrics_filter(m_configuration->m_metrics_filter);
	m_analyzer->get_configuration()->set_mounts_filter(m_configuration->m_mounts_filter);
	m_analyzer->get_configuration()->set_mounts_limit_size(m_configuration->m_mounts_limit_size);
	m_analyzer->get_configuration()->set_excess_metrics_log(m_configuration->m_excess_metric_log);
	m_analyzer->get_configuration()->set_metrics_cache(m_configuration->m_metrics_cache);
	m_analyzer->set_internal_metrics(m_internal_metrics);

	if(m_configuration->java_present() && m_configuration->m_sdjagent_enabled)
	{
		m_analyzer->enable_jmx(m_configuration->m_print_protobuf, m_configuration->m_jmx_sampling, m_configuration->m_jmx_limit);
	}

	if(m_statsite_pipes)
	{
		m_analyzer->set_statsd_iofds(m_statsite_pipes->get_io_fds(), m_configuration->m_mode == dragent_mode_t::NODRIVER);
	}

	m_inspector->m_analyzer = m_analyzer;

	m_inspector->set_debug_mode(true);
	m_inspector->set_hostname_and_port_resolution_mode(false);

	//
	// Attach our transmit callback to the analyzer
	//
	m_analyzer->set_sample_callback(&m_sinsp_handler);

	//
	// Plug the sinsp logger into our one
	//
	m_inspector->set_log_callback(dragent_logger::sinsp_logger_callback);
	if(m_configuration->m_min_console_priority > m_configuration->m_min_file_priority)
	{
		m_inspector->set_min_log_severity(static_cast<sinsp_logger::severity>(m_configuration->m_min_console_priority));
	}
	else
	{
		m_inspector->set_min_log_severity(static_cast<sinsp_logger::severity>(m_configuration->m_min_file_priority));
	}

	if(!m_configuration->m_metrics_dir.empty())
	{
		//
		// Create the metrics directory if it doesn't exist
		//
		File md(m_configuration->m_metrics_dir);
		md.createDirectories();
		m_analyzer->get_configuration()->set_emit_metrics_to_file(true);
		m_analyzer->get_configuration()->set_metrics_directory(m_configuration->m_metrics_dir);
	}
	else
	{
		g_log->information("metricsfile.location not specified, metrics won't be saved to disk.");
	}

	//
	// The machine id is the MAC address of the first physical adapter
	//
	m_analyzer->get_configuration()->set_machine_id(m_configuration->m_machine_id_prefix + m_configuration->m_machine_id);

	m_analyzer->get_configuration()->set_customer_id(m_configuration->m_customer_id);

	//
	// kubernetes
	//
	if(!m_configuration->m_k8s_api_server.empty())
	{
		m_analyzer->get_configuration()->set_k8s_api_server(m_configuration->m_k8s_api_server);
	}

	m_analyzer->get_configuration()->set_k8s_autodetect_enabled(m_configuration->m_k8s_autodetect);

	if(!m_configuration->m_k8s_ssl_cert_type.empty())
	{
		m_analyzer->get_configuration()->set_k8s_ssl_cert_type(m_configuration->m_k8s_ssl_cert_type);
	}

	if(!m_configuration->m_k8s_ssl_cert.empty())
	{
		m_analyzer->get_configuration()->set_k8s_ssl_cert(m_configuration->m_k8s_ssl_cert);
	}

	if(!m_configuration->m_k8s_ssl_key.empty())
	{
		m_analyzer->get_configuration()->set_k8s_ssl_key(m_configuration->m_k8s_ssl_key);
	}

	if(!m_configuration->m_k8s_ssl_key_password.empty())
	{
		m_analyzer->get_configuration()->set_k8s_ssl_key_password(m_configuration->m_k8s_ssl_key_password);
	}

	if(!m_configuration->m_k8s_ssl_ca_certificate.empty())
	{
		m_analyzer->get_configuration()->set_k8s_ssl_ca_certificate(m_configuration->m_k8s_ssl_ca_certificate);
	}

	if(!m_configuration->m_k8s_bt_auth_token.empty())
	{
		m_analyzer->get_configuration()->set_k8s_bt_auth_token(m_configuration->m_k8s_bt_auth_token);
	}

	m_analyzer->get_configuration()->set_k8s_ssl_verify_certificate(m_configuration->m_k8s_ssl_verify_certificate);

	m_analyzer->get_configuration()->set_k8s_timeout_ms(m_configuration->m_k8s_timeout_ms);

	m_analyzer->get_configuration()->set_k8s_simulate_delegation(m_configuration->m_k8s_simulate_delegation);
	m_analyzer->get_configuration()->set_k8s_delegated_nodes(m_configuration->m_k8s_delegated_nodes);

	if(m_configuration->m_k8s_extensions.size())
	{
		m_analyzer->get_configuration()->set_k8s_extensions(m_configuration->m_k8s_extensions);
	}

	//
	// mesos
	//
	m_analyzer->get_configuration()->set_mesos_credentials(m_configuration->m_mesos_credentials);
	if(!m_configuration->m_mesos_state_uri.empty())
	{
		m_analyzer->get_configuration()->set_mesos_state_uri(m_configuration->m_mesos_state_uri);
		m_analyzer->get_configuration()->set_mesos_state_original_uri(m_configuration->m_mesos_state_uri);
	}
	m_analyzer->get_configuration()->set_mesos_autodetect_enabled(m_configuration->m_mesos_autodetect);
	m_analyzer->get_configuration()->set_mesos_follow_leader(m_configuration->m_mesos_follow_leader);
	m_analyzer->get_configuration()->set_mesos_timeout_ms(m_configuration->m_mesos_timeout_ms);

	// marathon
	m_analyzer->get_configuration()->set_marathon_credentials(m_configuration->m_marathon_credentials);
	if(!m_configuration->m_marathon_uris.empty())
	{
		m_analyzer->get_configuration()->set_marathon_uris(m_configuration->m_marathon_uris);
	}
	m_analyzer->get_configuration()->set_marathon_follow_leader(m_configuration->m_marathon_follow_leader);
	m_analyzer->get_configuration()->set_dcos_enterprise_credentials(m_configuration->m_dcos_enterprise_credentials);

	if(m_configuration->m_marathon_skip_labels.size())
	{
		m_analyzer->get_configuration()->set_marathon_skip_labels(m_configuration->m_marathon_skip_labels);
	}

	// curl
	m_analyzer->get_configuration()->set_curl_debug(m_configuration->m_curl_debug);

	// user-configured events
	m_analyzer->get_configuration()->set_k8s_event_filter(m_configuration->m_k8s_event_filter);
	m_analyzer->get_configuration()->set_docker_event_filter(m_configuration->m_docker_event_filter);

	// percentiles
	m_analyzer->get_configuration()->set_percentiles(m_configuration->m_percentiles);
	m_analyzer->set_percentiles();

	//
	// Configure compression in the protocol
	//
	m_analyzer->get_configuration()->set_compress_metrics(m_configuration->m_compression_enabled);

	//
	// Configure connection aggregation
	//
	m_analyzer->get_configuration()->set_aggregate_connections_in_proto(!m_configuration->m_emit_full_connections);

	if(m_configuration->m_drop_upper_threshold != 0)
	{
		g_log->information("Drop upper threshold=" + NumberFormatter::format(m_configuration->m_drop_upper_threshold));
		m_analyzer->get_configuration()->set_drop_upper_threshold(m_configuration->m_drop_upper_threshold);
	}

	if(m_configuration->m_drop_lower_threshold != 0)
	{
		g_log->information("Drop lower threshold=" + NumberFormatter::format(m_configuration->m_drop_lower_threshold));
		m_analyzer->get_configuration()->set_drop_lower_threshold(m_configuration->m_drop_lower_threshold);
	}

	if(m_configuration->m_host_custom_name != "")
	{
		g_log->information("Setting custom name=" + m_configuration->m_host_custom_name);
		m_analyzer->get_configuration()->set_host_custom_name(m_configuration->m_host_custom_name);
	}

	if(m_configuration->m_host_tags != "")
	{
		g_log->information("Setting tags=" + m_configuration->m_host_tags);
		m_analyzer->get_configuration()->set_host_tags(m_configuration->m_host_tags);
	}

	if(m_configuration->m_host_custom_map != "")
	{
		g_log->information("Setting custom map=" + m_configuration->m_host_custom_map);
		m_analyzer->get_configuration()->set_host_custom_map(m_configuration->m_host_custom_map);
	}

	if(m_configuration->m_hidden_processes != "")
	{
		g_log->information("Setting hidden processes=" + m_configuration->m_hidden_processes);
		m_analyzer->get_configuration()->set_hidden_processes(m_configuration->m_hidden_processes);
	}

	if(m_configuration->m_host_hidden)
	{
		g_log->information("Setting host hidden");
		m_analyzer->get_configuration()->set_host_hidden(m_configuration->m_host_hidden);
	}

	m_autodrop_currently_enabled = m_configuration->m_autodrop_enabled;

	if(m_configuration->m_autodrop_enabled)
	{
		g_log->information("Setting autodrop");
		m_analyzer->get_configuration()->set_autodrop_enabled(true);
	}

	if(m_configuration->m_falco_baselining_enabled)
	{
		g_log->information("Setting falco baselining");
		m_analyzer->get_configuration()->set_falco_baselining_enabled(
			m_configuration->m_falco_baselining_enabled);
	}

	if(m_configuration->m_command_lines_capture_enabled)
	{
		g_log->information("Setting command lines capture");
		m_analyzer->get_configuration()->set_command_lines_capture_enabled(
			m_configuration->m_command_lines_capture_enabled);
		m_analyzer->get_configuration()->set_command_lines_capture_mode(
			m_configuration->m_command_lines_capture_mode);
		m_analyzer->get_configuration()->set_command_lines_valid_ancestors(
			m_configuration->m_command_lines_valid_ancestors);
	}

	if(m_configuration->m_capture_dragent_events)
	{
		g_log->information("Setting capture dragent events");
		m_analyzer->get_configuration()->set_capture_dragent_events(
			m_configuration->m_capture_dragent_events);
	}

	m_analyzer->get_configuration()->set_version(AGENT_VERSION);
	m_analyzer->get_configuration()->set_instance_id(m_configuration->m_aws_metadata.m_instance_id);
	m_analyzer->get_configuration()->set_known_ports(m_configuration->m_known_server_ports);
	m_analyzer->get_configuration()->set_blacklisted_ports(m_configuration->m_blacklisted_ports);
	m_analyzer->get_configuration()->set_statsd_limit(m_configuration->m_statsd_limit);
	m_analyzer->get_configuration()->set_app_checks_limit(m_configuration->m_app_checks_limit);
	m_analyzer->get_configuration()->set_protocols_truncation_size(m_configuration->m_protocols_truncation_size);
	m_analyzer->set_fs_usage_from_external_proc(m_configuration->m_system_supports_containers);

	m_analyzer->get_configuration()->set_cointerface_enabled(m_configuration->m_cointerface_enabled);
	m_analyzer->get_configuration()->set_swarm_enabled(m_configuration->m_swarm_enabled);

	//
	// Load the chisels
	//
	for(auto chinfo : m_configuration->m_chisel_details)
	{
		g_log->information("Loading chisel " + chinfo.m_name);
		m_analyzer->add_chisel(&chinfo);
	}

	m_analyzer->initialize_chisels();

	if(m_configuration->m_security_enabled)
	{
		if(!m_configuration->m_cointerface_enabled)
		{
			throw sinsp_exception("Security capabilities depend on cointerface, but cointerface is disabled.");
		}

		m_security_mgr = new security_mgr();
		m_security_mgr->init(m_inspector,
				     &m_sinsp_handler,
				     m_capture_job_handler,
				     m_configuration,
				     m_analyzer);

		if(m_configuration->m_security_policies_file != "")
		{
			string errstr;
			draiosproto::policies policies;

			int fd = open(m_configuration->m_security_policies_file.c_str(), O_RDONLY);
			google::protobuf::io::FileInputStream fstream(fd);
			if (!google::protobuf::TextFormat::Parse(&fstream, &policies)) {
				throw sinsp_exception("Failed to parse policies file "
						      + m_configuration->m_security_policies_file);
			}
			close(fd);

			if(!m_security_mgr->load(policies, errstr))
			{
				throw sinsp_exception("Could not load policies: " + errstr);
			}
		}
	}

	//
	// Start the capture with sinsp
	//
	g_log->information("Opening the capture source");
	if(m_configuration->m_input_filename != "")
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
	else
	{
		m_analyzer->get_configuration()->set_detect_stress_tools(m_configuration->m_detect_stress_tools);

		m_inspector->open("");
	}

	if(m_configuration->m_subsampling_ratio != 1)
	{
		g_log->information("Enabling dropping mode, ratio=" + NumberFormatter::format(m_configuration->m_subsampling_ratio));
		m_analyzer->start_dropping_mode(m_configuration->m_subsampling_ratio);
	}

	if(m_configuration->m_aws_metadata.m_public_ipv4)
	{
		sinsp_ipv4_ifinfo aws_interface(m_configuration->m_aws_metadata.m_public_ipv4,
			m_configuration->m_aws_metadata.m_public_ipv4, m_configuration->m_aws_metadata.m_public_ipv4, "aws");
		m_inspector->import_ipv4_interface(aws_interface);
	}

	m_analyzer->set_protocols_enabled(m_configuration->m_protocols_enabled);
	m_analyzer->set_remotefs_enabled(m_configuration->m_remotefs_enabled);
	m_analyzer->set_statsd_capture_localhost(m_statsd_capture_localhost);
	if(m_app_checks_enabled)
	{
		m_analyzer->set_app_checks(m_configuration->m_app_checks);
	}
	m_analyzer->set_containers_limit(m_configuration->m_containers_limit);
	m_analyzer->set_container_patterns(m_configuration->m_container_patterns);
	m_next_iflist_refresh_ns = sinsp_utils::get_current_time_ns()+IFLIST_REFRESH_FIRST_TIMEOUT_NS;

	m_analyzer->set_user_event_queue(m_user_event_queue);

	m_analyzer->set_emit_tracers(m_configuration->m_emit_tracers);

	init_falco();
}

void sinsp_worker::run()
{
	uint64_t nevts = 0;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;

	m_pthread_id = pthread_self();

	g_log->information("sinsp_worker: Starting");

	init();

	m_last_loop_ns = sinsp_utils::get_current_time_ns();

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration->m_evtcnt != 0 && nevts == m_configuration->m_evtcnt)
		{
			dragent_configuration::m_terminate = true;
			break;
		}

		if(m_configuration->m_reset_falco_engine)
		{
			init_falco();
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
			throw sinsp_exception(m_inspector->getlasterr().c_str());
		}

		if(m_analyzer->m_mode_switch_state >= sinsp_analyzer::MSR_REQUEST_NODRIVER)
		{
			if(m_analyzer->m_mode_switch_state == sinsp_analyzer::MSR_REQUEST_NODRIVER)
			{
				m_last_mode_switch_time = ev->get_ts();

				m_inspector->close();
				m_analyzer->m_mode_switch_state = sinsp_analyzer::MSR_SWITCHED_TO_NODRIVER;
				m_analyzer->set_sampling_ratio(1);

				m_inspector->open_nodriver();
				// Change these values so the inactive thread pruning
				// runs more often
				m_inspector->m_thread_timeout_ns = 0;
				m_inspector->m_inactive_thread_scan_time_ns = NODRIVER_PROCLIST_REFRESH_INTERVAL_NS;

				continue;
			}
			else
			{
				if(ev->get_ts() - m_last_mode_switch_time > MIN_NODRIVER_SWITCH_TIME)
				{
					throw sinsp_exception("restarting agent to restore normal operation mode");
				}
			}
		}

		//
		// Update the time
		//
		ts = ev->get_ts();
		m_last_loop_ns = ts;

		m_job_requests_interval.run([this]()
                {
			process_job_requests();
		}, ts);

		check_autodrop(ts);

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

		// Possibly pass the event to the security manager
		if(m_security_mgr)
		{
			m_security_mgr->process_event(ev);
		}

		m_capture_job_handler->process_event(ev);

		//
		// Update the event count
		//
		++nevts;
	}

	g_log->information("sinsp_worker: Terminating");
}

void sinsp_worker::queue_job_request(std::shared_ptr<capture_job_handler::dump_job_request> job_request)
{
	g_log->information(m_name + ": scheduling job request type=" +
			   (job_request->m_request_type == capture_job_handler::dump_job_request::JOB_START ? "start" : "stop") +
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

bool sinsp_worker::load_policies(draiosproto::policies &policies, std::string &errstr)
{
	if(m_security_mgr)
	{
		return m_security_mgr->load(policies, errstr);
	}
	else
	{
		errstr = "No Security Manager object created";
		return false;
	}
}

void sinsp_worker::init_falco()
{
	if(m_configuration->m_enable_falco_engine)
	{
		m_analyzer->disable_falco();
		m_analyzer->enable_falco(m_configuration->m_falco_default_rules_filename,
					 m_configuration->m_falco_auto_rules_filename,
					 m_configuration->m_falco_rules_filename,
					 m_configuration->m_falco_engine_disabled_rule_patterns,
					 m_configuration->m_falco_engine_sampling_multiplier);
	}

	m_configuration->m_reset_falco_engine = false;
}

// Receive job requests and pass them along to the capture job
// handler, adding a sinsp_dumper object associated with our
// inspector.

void sinsp_worker::process_job_requests()
{
	string errstr;

	if(dragent_configuration::m_signal_dump)
	{
		dragent_configuration::m_signal_dump = false;
		g_log->information("Received SIGUSR1, starting dump");

		std::shared_ptr<capture_job_handler::dump_job_request> job_request
			= make_shared<capture_job_handler::dump_job_request>();

		job_request->m_request_type = capture_job_handler::dump_job_request::JOB_START;
		job_request->m_token = string("dump").append(NumberFormatter::format(time(NULL)));
		job_request->m_duration_ns = 20000000000LL;
		job_request->m_delete_file_when_done = false;
		job_request->m_send_file = false;

		if(!m_capture_job_handler->queue_job_request(m_inspector, job_request, errstr))
		{
			g_log->error("sinsp_worker: could not start capture: " + errstr);
		}
	}

	std::shared_ptr<capture_job_handler::dump_job_request> request;
	while(m_dump_job_requests.get(&request, 0))
	{
		string errstr;

		g_log->debug("sinsp_worker: dequeued dump request token=" + request->m_token);

		if(!m_capture_job_handler->queue_job_request(m_inspector, request, errstr))
		{
			// It's assumed these requests were ones from
			// the backend, so send an error to the
			// backend.
			m_capture_job_handler->send_error(request->m_token, errstr);
		}
	}
}

void sinsp_worker::check_autodrop(uint64_t ts_ns)
{
	if(!m_configuration->m_autodrop_enabled)
	{
		return;
	}
	if(*m_enable_autodrop)
	{
		if (!m_autodrop_currently_enabled)
		{
			g_log->information("Restoring dropping mode state");

			if(m_configuration->m_autodrop_enabled)
			{
				m_analyzer->start_dropping_mode(1);
				m_analyzer->set_capture_in_progress(false);
			}

			m_autodrop_currently_enabled = true;
		}
	}
	else
	{
		if (m_autodrop_currently_enabled)
		{
			g_log->information("Disabling dropping mode by setting sampling ratio to 1");
			m_analyzer->start_dropping_mode(1);
			m_analyzer->set_capture_in_progress(true);
			m_autodrop_currently_enabled = false;
		}
	}
}
