#include "sinsp_worker.h"
#include "configuration_manager.h"
#include "error_handler.h"
#include "logger.h"
#include "memdumper.h"
#include "sinsp_factory.h"
#include "utils.h"
#include "user_event_logger.h"
#include "type_config.h"
#include "statsite_config.h"
#include <grpc/grpc.h>
#include <grpc/support/log.h>
#include <Poco/DateTimeFormatter.h>

type_config<uint16_t> config_increased_snaplen_port_range_start(0,
						   "Starting port in the range of ports to enable a larger snaplen on",
						   "increased_snaplen_port_range_start");
type_config<uint16_t> config_increased_snaplen_port_range_end(0,
						   "Ending port in the range of ports to enable a larger snaplen on",
						   "increased_snaplen_port_range_end");

DRAGENT_LOGGER();

const string sinsp_worker::m_name = "sinsp_worker";

sinsp_worker::sinsp_worker(dragent_configuration* configuration,
			   internal_metrics::sptr_t im,
			   protocol_queue* queue,
			   atomic<bool> *enable_autodrop,
			   capture_job_handler *capture_job_handler):
	m_job_requests_interval(1000000000),
	m_initialized(false),
	m_configuration(configuration),
	m_queue(queue),
	m_enable_autodrop(enable_autodrop),
	m_autodrop_currently_enabled(true),
	m_analyzer(NULL),
#ifndef CYGWING_AGENT
	m_security_mgr(NULL),
	m_compliance_mgr(NULL),
#endif
	m_capture_job_handler(capture_job_handler),
	m_sinsp_handler(configuration, queue),
	m_dump_job_requests(10),
	m_last_loop_ns(0),
	m_statsd_capture_localhost(false),
	m_app_checks_enabled(false),
	m_grpc_trace_enabled(false),
	m_next_iflist_refresh_ns(0),
	m_aws_metadata_refresher(*configuration),
	m_internal_metrics(im)
{
	m_last_mode_switch_time = 0;
}

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

void sinsp_worker::init()
{
	if(m_initialized)
	{
		return;
	}

	m_initialized = true;

	m_inspector = sinsp_factory::build();
	m_analyzer = new sinsp_analyzer(m_inspector.get(), m_configuration->c_root_dir.get());

	m_analyzer->set_procfs_scan_thread(m_configuration->m_procfs_scan_thread);
	m_analyzer->get_configuration()->set_procfs_scan_delay_ms(m_configuration->m_procfs_scan_delay_ms);
	m_analyzer->get_configuration()->set_procfs_scan_interval_ms(m_configuration->m_procfs_scan_interval_ms);
	m_analyzer->get_configuration()->set_procfs_scan_mem_interval_ms(m_configuration->m_procfs_scan_mem_interval_ms);

	// custom metrics filters (!!!do not move - needed by jmx, statsd and appchecks, so it must be
	// set before checks are created!!!)
	m_analyzer->get_configuration()->set_metrics_filter(m_configuration->m_metrics_filter);
	m_analyzer->get_configuration()->set_labels_filter(m_configuration->m_labels_filter);
	m_analyzer->get_configuration()->set_excess_labels_log(m_configuration->m_excess_labels_log);
	m_analyzer->get_configuration()->set_labels_cache(m_configuration->m_labels_cache);
	m_analyzer->get_configuration()->set_k8s_filter(m_configuration->m_k8s_filter);
	m_analyzer->get_configuration()->set_excess_k8s_log(m_configuration->m_excess_k8s_log);
	m_analyzer->get_configuration()->set_k8s_cache(m_configuration->m_k8s_cache_size);
	m_analyzer->get_configuration()->set_mounts_filter(m_configuration->m_mounts_filter);
	m_analyzer->get_configuration()->set_mounts_limit_size(m_configuration->m_mounts_limit_size);
	m_analyzer->get_configuration()->set_excess_metrics_log(m_configuration->m_excess_metric_log);
	m_analyzer->get_configuration()->set_metrics_cache(m_configuration->m_metrics_cache);
	m_analyzer->set_internal_metrics(m_internal_metrics);
#ifndef CYGWING_AGENT
	m_analyzer->init_k8s_limits();
#endif

	if(m_configuration->java_present() && m_configuration->m_sdjagent_enabled)
	{
		m_analyzer->enable_jmx(m_configuration->m_print_protobuf, m_configuration->m_jmx_sampling);
	}

	if(m_statsite_pipes)
	{
		const bool enable_statsite_forwarder =
			configuration_manager::instance().get_config<bool>(
					"statsd.use_forwarder")->get() ||
			(m_configuration->m_mode == dragent_mode_t::NODRIVER);

		m_analyzer->set_statsd_iofds(m_statsite_pipes->get_io_fds(),
		                             enable_statsite_forwarder);
	}

	m_inspector->m_analyzer = m_analyzer;

	m_inspector->set_debug_mode(true);
	m_inspector->set_internal_events_mode(true);
	m_inspector->set_hostname_and_port_resolution_mode(false);
	m_inspector->set_large_envs(m_configuration->m_large_envs);

	if(m_configuration->m_max_thread_table_size > 0)
	{
		g_log->information("Overriding sinsp thread table size to " + to_string(m_configuration->m_max_thread_table_size));
		m_inspector->set_max_thread_table_size(m_configuration->m_max_thread_table_size);
	}

	m_inspector->m_max_n_proc_lookups = m_configuration->m_max_n_proc_lookups;
	m_inspector->m_max_n_proc_socket_lookups = m_configuration->m_max_n_proc_socket_lookups;

	//
	// Attach our transmit callback to the analyzer
	//
	m_analyzer->set_sample_callback(&m_sinsp_handler);

	//
	// Plug the sinsp logger into our one
	//
	m_inspector->set_log_callback(dragent_logger::sinsp_logger_callback);
	g_logger.disable_timestamps();
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
	m_analyzer->get_configuration()->set_machine_id(m_configuration->machine_id());

	m_analyzer->get_configuration()->set_customer_id(m_configuration->m_customer_id);

	//
	// kubernetes
	//
#ifndef CYGWING_AGENT

	m_analyzer->get_configuration()->set_k8s_delegated_nodes(m_configuration->m_k8s_delegated_nodes);

	if(m_configuration->m_k8s_extensions.size())
	{
		m_analyzer->get_configuration()->set_k8s_extensions(m_configuration->m_k8s_extensions);
	}
	if(m_configuration->m_use_new_k8s)
	{
		m_analyzer->set_use_new_k8s(m_configuration->m_use_new_k8s);
		m_analyzer->set_k8s_local_update_frequency(m_configuration->m_k8s_local_update_frequency);
		m_analyzer->set_k8s_cluster_update_frequency(m_configuration->m_k8s_cluster_update_frequency);
	}
	m_analyzer->get_configuration()->set_k8s_cluster_name(m_configuration->m_k8s_cluster_name);

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
#endif // CYGWING_AGENT

	// curl
	m_analyzer->get_configuration()->set_curl_debug(m_configuration->m_curl_debug);

	// user-configured events
	m_analyzer->get_configuration()->set_k8s_event_filter(m_configuration->m_k8s_event_filter);
	m_analyzer->get_configuration()->set_docker_event_filter(m_configuration->m_docker_event_filter);
	m_analyzer->get_configuration()->set_containerd_event_filter(m_configuration->m_containerd_event_filter);

	// percentiles
	m_analyzer->get_configuration()->set_percentiles(m_configuration->m_percentiles,
			m_configuration->m_group_pctl_conf);
	m_analyzer->set_percentiles();

	m_analyzer->get_configuration()->set_container_filter(m_configuration->m_container_filter);
	m_analyzer->get_configuration()->set_smart_container_reporting(m_configuration->m_smart_container_reporting);

	// configure CPU tracing
	m_analyzer->get_configuration()->set_dragent_cpu_profile_enabled(m_configuration->m_dragent_cpu_profile_enabled);
	m_analyzer->get_configuration()->set_dragent_profile_time_seconds(m_configuration->m_dragent_profile_time_seconds);
	m_analyzer->get_configuration()->set_dragent_total_profiles(m_configuration->m_dragent_total_profiles);

	m_analyzer->get_configuration()->set_statsite_check_format(m_configuration->m_statsite_check_format);
	m_analyzer->get_configuration()->set_log_dir(m_configuration->m_log_dir);

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

	if(m_configuration->m_tracepoint_hits_threshold > 0)
	{
		m_analyzer->get_configuration()->set_tracepoint_hits_threshold(m_configuration->m_tracepoint_hits_threshold, m_configuration->m_tracepoint_hits_ntimes);
	}

	if(m_configuration->m_cpu_usage_max_sr_threshold > 0)
	{
		m_analyzer->get_configuration()->set_cpu_max_sr_threshold(m_configuration->m_cpu_usage_max_sr_threshold, m_configuration->m_cpu_usage_max_sr_ntimes);
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
		m_analyzer->get_configuration()->set_command_lines_include_container_healthchecks(
			m_configuration->m_command_lines_include_container_healthchecks);
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
	m_analyzer->get_configuration()->set_app_checks_always_send(m_configuration->m_app_checks_always_send);
	m_analyzer->get_configuration()->set_protocols_truncation_size(m_configuration->m_protocols_truncation_size);
	m_analyzer->set_fs_usage_from_external_proc(m_configuration->m_system_supports_containers);

	m_analyzer->get_configuration()->set_security_enabled(m_configuration->m_security_enabled);
	m_analyzer->get_configuration()->set_cointerface_enabled(m_configuration->m_cointerface_enabled);
	m_analyzer->get_configuration()->set_swarm_enabled(m_configuration->m_swarm_enabled);
	m_analyzer->get_configuration()->set_security_baseline_report_interval_ns(m_configuration->m_security_baseline_report_interval_ns);

	stress_tool_matcher::set_comm_list(m_configuration->m_stress_tools);

#ifndef CYGWING_AGENT
	m_analyzer->set_prometheus_conf(m_configuration->m_prom_conf);
	if (m_configuration->m_config_test)
	{
		m_configuration->m_custom_container.set_config_test(true);
	}
	m_analyzer->set_custom_container_conf(move(m_configuration->m_custom_container));
#endif

	m_analyzer->get_configuration()->set_procfs_scan_procs(m_configuration->m_procfs_scan_procs, m_configuration->m_procfs_scan_interval);

	//
	// Load the chisels
	//
	for(auto chinfo : m_configuration->m_chisel_details)
	{
		g_log->information("Loading chisel " + chinfo.m_name);
		m_analyzer->add_chisel(&chinfo);
	}

	m_analyzer->initialize_chisels();

#ifndef CYGWING_AGENT
	if(m_configuration->m_security_enabled)
	{
		if(!m_configuration->m_cointerface_enabled)
		{
			LOGGED_THROW(sinsp_exception, "Security capabilities depend on cointerface, but cointerface is disabled.");
		}

		m_security_mgr = new security_mgr(m_configuration->c_root_dir.get());
		m_security_mgr->init(m_inspector.get(),
				     &m_sinsp_handler,
				     m_analyzer,
				     m_capture_job_handler,
				     m_configuration,
				     m_internal_metrics);

		if(m_configuration->m_security_policies_file != "")
		{
			string errstr;

			if(!m_security_mgr->load_policies_file(m_configuration->m_security_policies_file.c_str(), errstr))
			{
				LOGGED_THROW(sinsp_exception, "Could not load policies from file: %s", errstr.c_str());
			}
		}

		if(m_configuration->m_security_baselines_file != "")
		{
			string errstr;

			if(!m_security_mgr->load_baselines_file(m_configuration->m_security_baselines_file.c_str(), errstr))
			{
				LOGGED_THROW(sinsp_exception, "Could not load baselines from file: %s", errstr.c_str());
			}
		}
	}

	if(m_configuration->m_cointerface_enabled)
	{
		std::string run_dir = m_configuration->c_root_dir.get() + "/run";
		m_compliance_mgr = new compliance_mgr(run_dir);
		m_compliance_mgr->init(&m_sinsp_handler,
				       m_analyzer,
				       m_configuration);

		if(m_configuration->m_security_default_compliance_schedule != "")
		{
			string errstr;
			draiosproto::comp_calendar cal;

			draiosproto::comp_task *k8s_task = cal.add_tasks();
			k8s_task->set_id(1);
			k8s_task->set_name("Check K8s Environment");
			k8s_task->set_mod_name("kube-bench");
			k8s_task->set_enabled(true);
			k8s_task->set_schedule(m_configuration->m_security_default_compliance_schedule);

			draiosproto::comp_task *docker_task = cal.add_tasks();
		        docker_task->set_id(2);
			docker_task->set_name("Check Docker Environment");
			docker_task->set_mod_name("docker-bench-security");
			docker_task->set_enabled(true);
			docker_task->set_schedule(m_configuration->m_security_default_compliance_schedule);

			// When using a default calendar, never send results or events
			if(! set_compliance_calendar(cal, false, false, errstr))
			{
				LOGGED_THROW(sinsp_exception, "Could not set default compliance calendar: %s", errstr.c_str());
			}
		}
	}


#endif // CYGWING_AGENT

	for(const auto &comm : m_configuration->m_suppressed_comms)
	{
		m_inspector->suppress_events_comm(comm);
	}

	m_inspector->set_query_docker_image_info(m_configuration->m_query_docker_image_info);
	m_inspector->set_cri_socket_path(m_configuration->m_cri_socket_path);
	m_inspector->set_cri_timeout(m_configuration->m_cri_timeout_ms);
	m_inspector->set_cri_extra_queries(m_configuration->m_cri_extra_queries);

	m_analyzer->set_track_environment(m_configuration->m_track_environment);
	m_analyzer->set_envs_per_flush(m_configuration->m_envs_per_flush);
	m_analyzer->set_max_env_size(m_configuration->m_max_env_size);
	m_analyzer->set_env_blacklist(std::move(m_configuration->m_env_blacklist));
	m_analyzer->set_env_hash_ttl(m_configuration->m_env_hash_ttl);
	m_analyzer->set_env_emit(m_configuration->m_env_metrics, m_configuration->m_env_audit_tap);

	if(m_configuration->m_audit_tap_enabled)
	{
		m_analyzer->enable_audit_tap(m_configuration->m_audit_tap_emit_local_connections);
	}

	m_analyzer->set_extra_internal_metrics(m_configuration->m_extra_internal_metrics);

	m_analyzer->set_remotefs_enabled(m_configuration->m_remotefs_enabled);
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
		m_inspector->set_simpledriver_mode();
		m_analyzer->set_simpledriver_mode();
	}
	else
	{
		m_analyzer->get_configuration()->set_detect_stress_tools(m_configuration->m_detect_stress_tools);

		m_inspector->open("");

		if(m_configuration->m_snaplen != 0)
		{
			m_inspector->set_snaplen(m_configuration->m_snaplen);
		}

		uint16_t range_start = config_increased_snaplen_port_range_start.get();
		uint16_t range_end = config_increased_snaplen_port_range_end.get();

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
		g_log->debug("Setting eventmask for ignored type: " + to_string(type));
		try
		{
			m_inspector->unset_eventmask(type);
		}
		catch (sinsp_exception& e)
		{
			g_log->error("Setting eventmask failed: " + string(e.what()));
		}
	}
#endif // CYGWING_AGENT

	if(m_configuration->m_procfs_scan_thread)
	{
		g_log->information("Procfs scan thread enabled, ignoring switch events");
		m_inspector->unset_eventmask(PPME_SCHEDSWITCH_1_E);
		m_inspector->unset_eventmask(PPME_SCHEDSWITCH_6_E);
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
	m_analyzer->set_statsd_capture_localhost(m_statsd_capture_localhost);
	if(m_app_checks_enabled)
	{
		m_analyzer->set_app_checks(m_configuration->m_app_checks);
	}

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
	uint64_t nevts = 0;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;

	m_pthread_id = pthread_self();

	g_log->information("sinsp_worker: Starting");

	init();

	if (m_configuration->m_config_test)
	{
		dragent_configuration::m_terminate = true;
		m_analyzer->dump_config_test();
	}

	m_last_loop_ns = sinsp_utils::get_current_time_ns();

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration->m_evtcnt != 0 && nevts == m_configuration->m_evtcnt)
		{
			dragent_configuration::m_terminate = true;
			break;
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
				user_event_logger::log(
						sinsp_user_event::to_string(
							ev->get_ts() / ONE_SECOND_IN_NS,
							"Agent switch to nodriver",
							"Agent switched to nodriver mode due to high overhead",
							event_scope("host.mac", m_configuration->machine_id()),
							{ {"source", "agent"} },
							4),
						user_event_logger::SEV_EVT_WARNING);
				m_last_mode_switch_time = ev->get_ts();

				m_inspector->close();
				m_analyzer->set_mode_switch_state(sinsp_analyzer::MSR_SWITCHED_TO_NODRIVER);
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
					user_event_logger::log(
							sinsp_user_event::to_string(
								ev->get_ts() / ONE_SECOND_IN_NS,
								"Agent restore full mode",
								"Agent restarting to restore full operation mode",
								event_scope("host.mac", m_configuration->machine_id()),
								{ {"source", "agent"} },
								4),
							user_event_logger::SEV_EVT_WARNING);
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

#ifndef CYGWING_AGENT
		// Possibly pass the event to the security manager
		if(m_security_mgr)
		{
			m_security_mgr->process_event(ev);
		}

		if(m_compliance_mgr)
		{
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
bool sinsp_worker::load_policies(draiosproto::policies &policies, std::string &errstr)
{
	if(m_security_mgr)
	{
		return m_security_mgr->load_policies(policies, errstr);
	}
	else
	{
		errstr = "No Security Manager object created";
		return false;
	}
}

bool sinsp_worker::is_stall_fatal() const
{
	// If the input filename is not empty then we are reading an scap file
	// that has old timestamps so tell the caller to not check for stalls
	return m_configuration->m_input_filename.empty();
}

bool sinsp_worker::set_compliance_calendar(draiosproto::comp_calendar &calendar,
					   bool send_results,
					   bool send_events,
					   std::string &errstr)
{
	if(m_compliance_mgr)
	{
		m_compliance_mgr->set_compliance_calendar(calendar,
							  send_results,
							  send_events);
		return true;
	}
	else
	{
		errstr = "No Compliance Manager object created";
		return false;
	}
}

bool sinsp_worker::run_compliance_tasks(draiosproto::comp_run &run, std::string &errstr)
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

bool sinsp_worker::load_baselines(draiosproto::baselines &baselines, std::string &errstr)
{
	if(m_security_mgr)
	{
		return m_security_mgr->load_baselines(baselines, errstr);
	}
	else
	{
		errstr = "No Security Manager object created";
		return false;
	}
}

void sinsp_worker::receive_hosts_metadata(draiosproto::orchestrator_events &evts)
{
	m_analyzer->infra_state()->receive_hosts_metadata(evts.events());
	m_compliance_mgr->request_refresh_compliance_tasks();
	std::string errstr;
	if (!m_security_mgr->reload_policies(errstr))
	{
		g_log->error("Could not reload policies after receiving new hosts metadata: " + errstr);
	}
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
