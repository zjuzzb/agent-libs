#include "sinsp_worker.h"

#include "logger.h"
#include "error_handler.h"
#include "utils.h"
#include "memdumper.h"
#include "Poco/DateTimeFormatter.h"

const string sinsp_worker::m_name = "sinsp_worker";

sinsp_worker::sinsp_worker(dragent_configuration* configuration,
			   protocol_queue* queue):
	m_configuration(configuration),
	m_queue(queue),
	m_inspector(NULL),
	m_analyzer(NULL),
	m_sinsp_handler(configuration, queue),
	m_dump_job_requests(10),
	m_driver_stopped_dropping_ns(0),
	m_last_loop_ns(0),
	m_statsd_capture_localhost(false),
	m_app_checks_enabled(false),
	m_max_chunk_size(default_max_chunk_size),
	m_next_iflist_refresh_ns(0),
	m_aws_metadata_refresher(configuration)
{
}

sinsp_worker::~sinsp_worker()
{
	if(m_inspector != NULL)
	{
		m_inspector->set_log_callback(0);
		delete m_inspector;
	}

	delete m_analyzer;
}

void sinsp_worker::init()
{
	m_inspector = new sinsp();
	m_analyzer = new sinsp_analyzer(m_inspector);

	// custom metrics filters (!!!do not move - needed by jmx, statsd and appchecks, so it must be
	// set before checks are created!!!)
	m_analyzer->get_configuration()->set_metrics_filter(m_configuration->m_metrics_filter);
	m_analyzer->get_configuration()->set_excess_metrics_log(m_configuration->m_excess_metric_log);
	m_analyzer->get_configuration()->set_metrics_cache(m_configuration->m_metrics_cache);
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
		m_analyzer->get_configuration()->set_command_lines_capture_all_commands(
			m_configuration->m_command_lines_capture_all_commands);
	}

	if(m_configuration->m_capture_dragent_events)
	{
		g_log->information("Setting capture dragent events");
		m_analyzer->get_configuration()->set_capture_dragent_events(
			m_configuration->m_capture_dragent_events);
	}

	if(m_configuration->m_memdump_enabled)
	{
		g_log->information("Setting memdump, size=" + to_string(m_configuration->m_memdump_size));
		m_analyzer->get_configuration()->set_memdump_size(
			m_configuration->m_memdump_size);
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

	//
	// Start the capture with sinsp
	//
	g_log->information("Opening the capture source");
	if(m_configuration->m_input_filename != "")
	{
		m_inspector->open(m_configuration->m_input_filename);
	}
	else if (m_configuration->m_mode == dragent_mode_t::NODRIVER)
	{
		m_inspector->open_nodriver();
		// Change these values so the inactive thread pruning
		// runs more often
		m_inspector->m_thread_timeout_ns = 0;
		m_inspector->m_inactive_thread_scan_time_ns = NODRIVER_PROCLIST_REFRESH_INTERVAL_NS;
	}
	else
	{
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

	m_last_job_check_ns = 0;
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

		//
		// Update the time
		//
		ts = ev->get_ts();
		m_last_loop_ns = ts;

		if(ts - m_last_job_check_ns > 1000000000)
		{
			m_last_job_check_ns = ts;

			process_job_requests(ts);

			//
			// Also, just every second, cleanup the old ones
			// Why every second? Because the sending queue might be
			// full and we still send each one every second
			//
			flush_jobs(ts, &m_running_standard_dump_jobs, true);
			flush_jobs(ts, &m_running_memdump_jobs, false);
		}

		run_standard_jobs(ev);
		check_memdump_jobs(ev);

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
		//
		// Update the event count
		//
		++nevts;
	}

	g_log->information("sinsp_worker: Terminating");
}

void sinsp_worker::queue_job_request(SharedPtr<dump_job_request> job_request)
{
	g_log->information("Scheduling job request " + job_request->m_token);

	if(!m_dump_job_requests.put(job_request))
	{
		send_error(job_request->m_token, "Maximum number of requests reached");
	}
}

void sinsp_worker::prepare_response(const string& token, draiosproto::dump_response* response)
{
	response->set_timestamp_ns(sinsp_utils::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->m_machine_id_prefix + m_configuration->m_machine_id);
	response->set_token(token);
}

bool sinsp_worker::queue_response(const draiosproto::dump_response& response, protocol_queue::item_priority priority)
{
	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		draiosproto::message_type::DUMP_RESPONSE,
		response,
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return true;
	}

	while(!m_queue->put(buffer, priority))
	{
		g_log->information("Queue full");
		return false;
	}

	return true;
}

void sinsp_worker::run_standard_jobs(sinsp_evt* ev)
{
	if(m_running_standard_dump_jobs.empty())
	{
		return;
	}

	if(m_driver_stopped_dropping_ns)
	{
		if(!m_analyzer->driver_stopped_dropping())
		{
			//
			// Wait maximum 5 seconds after disabling dropping prior to running the job
			//
			if(ev->get_ts() - m_driver_stopped_dropping_ns < 5 * 1000000000LL)
			{
				return;
			}

			g_log->error("Timeout waiting for drop ack event, proceeding anyway");
		}
		else
		{
			g_log->information("Received drop ack event, proceeding");
		}

		m_driver_stopped_dropping_ns = 0;
	}

	for(vector<SharedPtr<dump_job_state>>::iterator it = m_running_standard_dump_jobs.begin();
		it != m_running_standard_dump_jobs.end(); ++it)
	{
		SharedPtr<dump_job_state> job = *it;

		if(job->m_terminated)
		{
			continue;
		}

		//
		// We don't want dragent to show up in captures
		//
		sinsp_threadinfo* tinfo = ev->get_thread_info();
		uint16_t etype = ev->get_type();

		if(!m_configuration->m_capture_dragent_events &&
			tinfo &&
			tinfo->m_pid == m_inspector->m_sysdig_pid &&
			etype != PPME_SCHEDSWITCH_1_E &&
			etype != PPME_SCHEDSWITCH_6_E)
		{
			continue;
		}

		if(job->m_max_size &&
			job->m_file_size > job->m_max_size)
		{
			stop_standard_job(job);
			continue;
		}

		if(job->m_duration_ns &&
			ev->get_ts() - job->m_start_ns > job->m_duration_ns)
		{
			stop_standard_job(job);
			continue;
		}

		if(job->m_filter)
		{
			if(!job->m_filter->run(ev))
			{
				continue;
			}
		}

		job->m_dumper->dump(ev);
		++job->m_n_events;
	}
}

void sinsp_worker::stop_standard_job(dump_job_state* job)
{
	ASSERT(!job->m_terminated);
	job->m_terminated = true;

	g_log->information("Job " + job->m_token + " stopped, captured events: "
		+ NumberFormatter::format(job->m_n_events));

	//
	// Stop the job, but don't delete it yet, there might be
	// a bunch of pending chunks
	//
	delete job->m_dumper;
	job->m_dumper = NULL;
}

void sinsp_worker::check_memdump_jobs(sinsp_evt* ev)
{
	if(m_running_memdump_jobs.empty())
	{
		return;
	}

	for(vector<SharedPtr<dump_job_state>>::iterator it = m_running_memdump_jobs.begin();
		it != m_running_memdump_jobs.end(); ++it)
	{
		SharedPtr<dump_job_state> job = *it;

		if(job->m_terminated)
		{
			continue;
		}

		if(job->m_memdumper_job->is_done())
		{
			stop_memdump_job(job);
			continue;
		}
	}
}

void sinsp_worker::stop_memdump_job(dump_job_state* job)
{
	ASSERT(!job->m_terminated);
	job->m_terminated = true;

	g_log->information("memdump Job " + job->m_token + " stopped");

	//
	// Stop the job, but don't delete it yet, there might be
	// a bunch of pending chunks
	//
	sinsp_memory_dumper* memdumper = m_analyzer->get_memory_dumper();
	if(memdumper == NULL)
	{
		send_error(job->m_token, "memory dump corrupted in the agent. Cannot perform back in time capture.");
		ASSERT(false);
		return;
	}

	job->m_memdumper_job->stop();
	memdumper->remove_job(job->m_memdumper_job);
}

void sinsp_worker::send_error(const string& token, const string& error)
{
	g_log->error(error);
	draiosproto::dump_response response;
	prepare_response(token, &response);
	response.set_error(error);
	queue_response(response, protocol_queue::BQ_PRIORITY_HIGH);
}

void sinsp_worker::send_dump_chunks(dump_job_state* job)
{
	ASSERT(job->m_last_chunk_offset <= job->m_file_size);
	while(job->m_last_chunk_offset < job->m_file_size &&
		(job->m_terminated ||
		job->m_file_size - job->m_last_chunk_offset > m_max_chunk_size))
	{
		if(job->m_last_chunk.empty())
		{
			read_chunk(job);
		}

		uint32_t progress = 0;
		ASSERT(job->m_file_size > 0);
		if(job->m_file_size > 0)
		{
			progress = (job->m_last_chunk_offset * 100) / job->m_file_size;
		}

		g_log->information(m_name + ": " + job->m_file + ": Sending chunk "
			+ NumberFormatter::format(job->m_last_chunk_idx) + " of size "
			+ NumberFormatter::format(job->m_last_chunk.size())
			+ ", progress " + NumberFormatter::format(progress) + "%%");

		draiosproto::dump_response response;
		prepare_response(job->m_token, &response);
		response.set_content(job->m_last_chunk);
		response.set_chunk_no(job->m_last_chunk_idx);

		ASSERT(job->m_last_chunk_offset + job->m_last_chunk.size() <= job->m_file_size);
		if(job->m_last_chunk_offset + job->m_last_chunk.size() >= job->m_file_size)
		{
			response.set_final_chunk(true);
		}

		if(job->m_terminated)
		{
			response.set_final_size_bytes(job->m_file_size);
		}

		if(!queue_response(response, protocol_queue::BQ_PRIORITY_LOW))
		{
			g_log->information(m_name + ": " + job->m_file + ": Queue full while sending chunk "
				+ NumberFormatter::format(job->m_last_chunk_idx) + ", will retry in 1 second");
			return;
		}

		++job->m_last_chunk_idx;
		job->m_last_chunk_offset += job->m_last_chunk.size();
		job->m_last_chunk.clear();
	}
}

void sinsp_worker::read_chunk(dump_job_state* job)
{
	Buffer<char> buffer(16384);
	uint64_t chunk_size = m_max_chunk_size;
	bool eof = false;

	while(!eof && chunk_size)
	{
		size_t to_read = min<u_int64_t>(buffer.size(), chunk_size);
		ASSERT(job->m_fp);
		size_t res = fread(buffer.begin(), 1, to_read, job->m_fp);
		if(res != to_read)
		{
			if(feof(job->m_fp))
			{
				g_log->information(m_name + ": " + job->m_file + ": EOF");
				eof = true;
			}
			else if(ferror(job->m_fp))
			{
				g_log->error(m_name + ": ferror while reading " + job->m_file);
				job->m_error = true;
				send_error(job->m_token, "ferror while reading " + job->m_file);
				ASSERT(false);
				return;
			} else {
				g_log->error(m_name + ": unknown error while reading " + job->m_file);
				job->m_error = true;
				send_error(job->m_token, "unknown error while reading " + job->m_file);
				ASSERT(false);
				return;
			}
		}

		chunk_size -= res;
		job->m_last_chunk.append(buffer.begin(), res);
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

void sinsp_worker::process_job_requests(uint64_t ts)
{
	if(dragent_configuration::m_signal_dump)
	{
		g_log->information("Received SIGUSR1, starting dump");
		dragent_configuration::m_signal_dump = false;

		SharedPtr<sinsp_worker::dump_job_request> job_request(
			new sinsp_worker::dump_job_request());

		job_request->m_request_type = dump_job_request::JOB_START;
		job_request->m_token = string("dump").append(NumberFormatter::format(time(NULL)));
		job_request->m_duration_ns = 20000000000LL;
		job_request->m_delete_file_when_done = false;
		job_request->m_send_file = false;

		queue_job_request(job_request);
	}

	SharedPtr<dump_job_request> request;
	while(m_dump_job_requests.get(&request, 0))
	{
		g_log->debug("Dequeued dump request token=" + request->m_token);
		switch(request->m_request_type)
		{
		case dump_job_request::JOB_START:
			if(request->m_duration_ns == 0 && request->m_past_duration_ns == 0)
			{
				send_error(request->m_token, "either duration or past_duration must be nonzero");
				return;
			}

			// As a resource exaustion prevention
			// mechanism, only allow "max sysdig captures"
			// to be outstanding at one time.
			if((m_running_standard_dump_jobs.size() + m_running_memdump_jobs.size()) >= m_configuration->m_max_sysdig_captures)
			{
				send_error(request->m_token, "maximum number of outstanding captures (" +
					   to_string(m_configuration->m_max_sysdig_captures) +
					   ") reached");
				return;
			}

			if(request->m_past_duration_ns == 0)
			{
				start_standard_job(*request, ts);
			}
			else
			{
				start_memdump_job(*request, ts);
			}
			break;
		case dump_job_request::JOB_STOP:
			{
				bool found = false;

				for(vector<SharedPtr<dump_job_state>>::iterator it = m_running_standard_dump_jobs.begin();
					it != m_running_standard_dump_jobs.end(); ++it)
				{
					if((*it)->m_token == request->m_token)
					{
						stop_standard_job(*it);
						found = true;
						break;
					}
				}

				for(vector<SharedPtr<dump_job_state>>::iterator it = m_running_memdump_jobs.begin();
					it != m_running_memdump_jobs.end(); ++it)
				{
					if((*it)->m_token == request->m_token)
					{
						stop_memdump_job(*it);
						found = true;
						break;
					}
				}

				if(!found)
				{
					g_log->error("Can't find job " + request->m_token);
				}

				break;
			}
		default:
			ASSERT(false);
		}
	}
}

void sinsp_worker::start_standard_job(const dump_job_request& request, uint64_t ts)
{
	SharedPtr<dump_job_state> job_state(new dump_job_state());

	if(m_configuration->m_sysdig_capture_enabled == false)
	{
		send_error(request.m_token, "Sysdig capture disabled from agent configuration file, not starting capture");
		return;
	}

	if(!request.m_filter.empty())
	{
		try
		{
			sinsp_filter_compiler compiler(m_inspector, request.m_filter);
			job_state->m_filter = compiler.compile();
		}
		catch(sinsp_exception& e)
		{
			send_error(request.m_token, e.what());
			return;
		}
	}

	job_state->m_token = request.m_token;

	job_state->m_dumper = new sinsp_dumper(m_inspector);
	job_state->m_file = m_configuration->m_dump_dir + request.m_token + ".scap";
	g_log->information("Starting dump job in " + job_state->m_file +
		", filter '" + request.m_filter + "'");
	job_state->m_dumper->open(job_state->m_file, true);

	job_state->m_fp = fopen(job_state->m_file.c_str(), "r");
	if(job_state->m_fp == NULL)
	{
		send_error(request.m_token, strerror(errno));
		return;
	}

	job_state->m_duration_ns = request.m_duration_ns;
	job_state->m_max_size = request.m_max_size;
	job_state->m_past_duration_ns = 0;
	job_state->m_delete_file_when_done = request.m_delete_file_when_done;
	job_state->m_send_file = request.m_send_file;
	job_state->m_start_ns = ts;
	job_state->m_memdumper_job = NULL;

	if(m_running_standard_dump_jobs.empty())
	{
		g_log->information("Disabling dropping mode");
		m_analyzer->set_autodrop_enabled(false);
		m_analyzer->stop_dropping_mode();
		m_driver_stopped_dropping_ns = ts;
	}

	m_running_standard_dump_jobs.push_back(job_state);
}

void sinsp_worker::start_memdump_job(const dump_job_request& request, uint64_t ts)
{
	SharedPtr<dump_job_state> job_state(new dump_job_state());

	if(m_configuration->m_sysdig_capture_enabled == false)
	{
		send_error(request.m_token, "Sysdig capture disabled from agent configuration file, not starting capture");
		return;
	}

	if(!m_analyzer->is_memdump_active())
	{
		send_error(request.m_token, "memory dump functionality not enabled in the target agent. Cannot perform back in time capture.");
		return;
	}

	//
	// Populate the job state
	//
	job_state->m_token = request.m_token;
	job_state->m_dumper = NULL;
	job_state->m_file = m_configuration->m_dump_dir + request.m_token + ".scap";

	//
	// Create the dumper job
	//
	sinsp_memory_dumper* memdumper = m_analyzer->get_memory_dumper();
	if(memdumper == NULL)
	{
		send_error(request.m_token, "memory dump functionality not working in the target agent. Cannot perform back in time capture.");
		ASSERT(false);
		return;
	}

	// We inject a notification to make it easier to identify the starting point
	memdumper->push_notification(ts, m_inspector->m_sysdig_pid, request.m_token, "starting capture job " + request.m_token);

	job_state->m_memdumper_job = memdumper->add_job(ts, job_state->m_file, request.m_filter, request.m_past_duration_ns, request.m_duration_ns);
	if(job_state->m_memdumper_job->m_state == sinsp_memory_dumper_job::ST_DONE_ERROR)
	{
		send_error(request.m_token, job_state->m_memdumper_job->m_lasterr);
		return;
	}

	//
	// Open the job output file for reading so we are ready to send it to the backend
	//
	job_state->m_fp = fopen(job_state->m_file.c_str(), "r");
	if(job_state->m_fp == NULL)
	{
		send_error(request.m_token, "unable to open file " + job_state->m_file);
		return;
	}

	//
	// Finish populating the job state
	//
	job_state->m_duration_ns = request.m_duration_ns;
	job_state->m_max_size = request.m_max_size;
	job_state->m_past_duration_ns = request.m_past_duration_ns;
	job_state->m_delete_file_when_done = request.m_delete_file_when_done;
	job_state->m_send_file = request.m_send_file;
	job_state->m_start_ns = ts;

	g_log->debug("starting memory dumper job, file: " + job_state->m_file
		     + " start time " + Poco::DateTimeFormatter::format(Poco::Timestamp((job_state->m_start_ns - job_state->m_past_duration_ns) / 1000), "%Y-%m-%d %H:%M:%S.%i")
		     + " end time " + Poco::DateTimeFormatter::format(Poco::Timestamp((job_state->m_start_ns + job_state->m_duration_ns) /1000), "%Y-%m-%d %H:%M:%S.%i"));

	m_running_memdump_jobs.push_back(job_state);
}

void sinsp_worker::flush_jobs(uint64_t ts, vector<SharedPtr<dump_job_state>>* jobs, bool restore_drop_mode)
{
	vector<SharedPtr<dump_job_state>>::iterator it = jobs->begin();

	while(it != jobs->end())
	{
		SharedPtr<dump_job_state> job = *it;

		if((ts - job->m_last_keepalive_ns > m_keepalive_interval_ns)
			&& job->m_send_file)
		{
			job->m_last_keepalive_ns = ts;
			draiosproto::dump_response response;
			prepare_response(job->m_token, &response);
			response.set_keep_alive(true);
			g_log->information("Job " + job->m_token + ": sending keepalive");
			queue_response(response, protocol_queue::BQ_PRIORITY_HIGH);
		}

		struct stat st;
		if(stat(job->m_file.c_str(), &st) != 0)
		{
			g_log->error("Error checking file size");
			send_error(job->m_token, "Error checking file size");
			job->m_error = true;
			ASSERT(false);
		}

		job->m_file_size = st.st_size;

		if(!job->m_error && job->m_send_file)
		{
			send_dump_chunks(job);
		}

		if(job->m_error)
		{
			g_log->information("Job " + job->m_token
				+ ": in error state, deleting");
			it = jobs->erase(it);
		}
		else if(job->m_terminated &&
			(!job->m_send_file ||
			job->m_last_chunk_offset >= job->m_file_size))
		{
			ASSERT(job->m_last_chunk_offset <= job->m_file_size);
			g_log->information("Job " + job->m_token
				+ ": sent all chunks to backend, deleting");
			it = jobs->erase(it);
		}
		else
		{
			++it;
		}

		if(restore_drop_mode)
		{
			if(jobs->empty())
			{
				g_log->information("Restoring dropping mode state");

				if(m_configuration->m_autodrop_enabled)
				{
					m_analyzer->set_autodrop_enabled(true);
					m_analyzer->start_dropping_mode(1);
				}
			}
		}
	}
}
