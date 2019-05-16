#include "process_emitter.h"
#include "analyzer_thread.h"
#include "tracer_emitter.h"

process_emitter::process_emitter(const bool simpledriver_enabled,
				 const bool nodriver,
				 tracer_emitter& proc_trc,
				 const uint32_t top_files_per_prog,
				 const unordered_map<dev_t, string>& device_map,
				 const bool username_lookups,
				 const bool track_environment,
				 const uint32_t top_file_devices_per_prog,
				 const jmx_proxy* jmx_proxy,
				 const app_checks_proxy* app_proxy,
				 const bool procfs_scan_thread,
				 sinsp_procfs_parser& procfs_parser,
				 const uint32_t sampling_ratio,
				 const uint32_t num_cpus,
				 environment_emitter& the_environment_emitter,
				 jmx_emitter& the_jmx_emitter,
				 app_check_emitter& the_app_check_emitter)
	: m_simpledriver_enabled(simpledriver_enabled),
	  m_nodriver(nodriver),
	  m_proc_trc(proc_trc),
	  m_top_files_per_prog(top_files_per_prog),
	  m_device_map(device_map),
	  m_username_lookups(username_lookups),
	  m_track_environment(track_environment),
	  m_top_file_devices_per_prog(top_file_devices_per_prog),
	  m_jmx_proxy(jmx_proxy),
	  m_app_proxy(app_proxy),
	  m_procfs_scan_thread(procfs_scan_thread),
	  m_procfs_parser(procfs_parser),
	  m_sampling_ratio(sampling_ratio),
	  m_num_cpus(num_cpus),
	  m_environment_emitter(the_environment_emitter),
	  m_jmx_emitter(the_jmx_emitter),
	  m_app_check_emitter(the_app_check_emitter)
{
}

void process_emitter::emit_process(sinsp_threadinfo& tinfo,
				   draiosproto::program& prog,
				   const analyzer_emitter::progtable_by_container_t& progtable_by_container,
				   sinsp_procinfo& procinfo,
				   const sinsp_counter_time& tot,
				   draiosproto::metrics& metrics,
				   std::set<uint64_t>& all_uids)
{
	auto main_thread = tinfo.get_main_thread();
	if(!main_thread)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Thread %lu without main process %lu\n", tinfo.m_tid, tinfo.m_pid);
		return;
	}

	for(const auto pid : procinfo.m_program_pids) {
		prog.add_pids(pid);
	}

	if(m_track_environment) {
		m_environment_emitter.emit_environment(tinfo, prog);
	}

	for(const auto uid : procinfo.m_program_uids) {
		if(m_username_lookups) {
			all_uids.insert(uid);
		}
		prog.add_uids(uid);
	}


	draiosproto::process* proc = prog.mutable_procinfo();

	proc->mutable_details()->set_comm(main_thread->m_comm);
	proc->mutable_details()->set_exe(main_thread->m_exe);
	for(vector<string>::const_iterator arg_it = main_thread->m_args.begin();
	    arg_it != main_thread->m_args.end(); ++arg_it)
	{
		if(*arg_it != "")
		{
			if(arg_it->size() <= ARG_SIZE_LIMIT)
			{
				proc->mutable_details()->add_args(*arg_it);
			}
			else
			{
				auto arg_capped = arg_it->substr(0, ARG_SIZE_LIMIT);
				proc->mutable_details()->add_args(arg_capped);
			}
		}
	}

	if(!main_thread->m_container_id.empty())
	{
		proc->mutable_details()->set_container_id(main_thread->m_container_id);
	}

	tinfo.m_flags &= ~PPM_CL_NAME_CHANGED;

	procinfo.m_files_stat.emit(proc, m_top_files_per_prog);
	procinfo.m_devs_stat.emit(proc, m_device_map, m_top_file_devices_per_prog);

	//
	// client-server role
	//
	uint32_t netrole = 0;

	if(tinfo.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER)
	{
		netrole |= draiosproto::IS_REMOTE_IPV4_SERVER;
	}
	else if(tinfo.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER)
	{
		netrole |= draiosproto::IS_LOCAL_IPV4_SERVER;
	}
	else if(tinfo.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_SERVER)
	{
		netrole |= draiosproto::IS_UNIX_SERVER;
	}

	if(tinfo.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT)
	{
		netrole |= draiosproto::IS_REMOTE_IPV4_CLIENT;
	}
	else if(tinfo.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT)
	{
		netrole |= draiosproto::IS_LOCAL_IPV4_CLIENT;
	}
	else if(tinfo.m_ainfo->m_th_analysis_flags & thread_analyzer_info::AF_IS_UNIX_CLIENT)
	{
		netrole |= draiosproto::IS_UNIX_CLIENT;
	}

	proc->set_netrole(netrole);
#ifndef _WIN32
	proc->mutable_resource_counters()->set_jmx_sent(0);
	proc->mutable_resource_counters()->set_jmx_total(0);
	proc->mutable_resource_counters()->set_app_checks_sent(0);
	proc->mutable_resource_counters()->set_app_checks_total(0);
	proc->mutable_resource_counters()->set_prometheus_sent(0);
	proc->mutable_resource_counters()->set_prometheus_total(0);

	// Add JMX metrics
	if(m_jmx_proxy)
	{
		m_jmx_emitter.emit_jmx(procinfo, tinfo, *proc);
	}
	if(m_app_proxy)
	{
		m_app_check_emitter.emit_apps(procinfo, tinfo, *proc);
	}
#endif

	//
	// CPU utilization
	//
	if(procinfo.m_cpuload >= 0)
	{
		if(procinfo.m_cpuload > (int32_t)(100 * m_num_cpus))
		{
			procinfo.m_cpuload = (int32_t)100 * m_num_cpus;
		}

		proc->mutable_resource_counters()->set_cpu_pct((uint32_t)(procinfo.m_cpuload * 100));
	}
	else
	{
		proc->mutable_resource_counters()->set_cpu_pct(0);
	}

	if (m_procfs_scan_thread)
	{
		struct proc_metrics::mem_metrics pm;
		if (m_procfs_parser.get_process_mem_metrics(tinfo.m_pid, &pm))
		{
			proc->mutable_resource_counters()->set_resident_memory_usage_kb(pm.vmrss_kb);
			proc->mutable_resource_counters()->set_virtual_memory_usage_kb(pm.vmsize_kb);
			proc->mutable_resource_counters()->set_swap_memory_usage_kb(pm.vmswap_kb);
			proc->mutable_resource_counters()->set_major_pagefaults(pm.pfmajor);
			proc->mutable_resource_counters()->set_minor_pagefaults(pm.pfminor);
		}
	}
	else
	{
		proc->mutable_resource_counters()->set_resident_memory_usage_kb(procinfo.m_vmrss_kb);
		proc->mutable_resource_counters()->set_virtual_memory_usage_kb(procinfo.m_vmsize_kb);
		proc->mutable_resource_counters()->set_swap_memory_usage_kb(procinfo.m_vmswap_kb);
		proc->mutable_resource_counters()->set_major_pagefaults(procinfo.m_pfmajor);
		proc->mutable_resource_counters()->set_minor_pagefaults(procinfo.m_pfminor);
	}

	proc->mutable_resource_counters()->set_threads_count(procinfo.m_threads_count);

	if(tot.m_count != 0)
	{
		sinsp_delays_info* prog_delays = &procinfo.m_transaction_delays;

		//
		// Main metrics

		procinfo.m_proc_metrics.to_protobuf(proc->mutable_tcounters(), m_sampling_ratio);

		//
		// Transaction-related metrics
		//
		if(prog_delays->m_local_processing_delay_ns != -1)
		{
			proc->set_transaction_processing_delay(prog_delays->m_local_processing_delay_ns * m_sampling_ratio);
			proc->set_next_tiers_delay(prog_delays->m_merged_client_delay * m_sampling_ratio);
		}

		procinfo.m_proc_transaction_metrics.to_protobuf(proc->mutable_transaction_counters(),
								 proc->mutable_max_transaction_counters(),
								 m_sampling_ratio);

		proc->mutable_resource_counters()->set_capacity_score((uint32_t)(procinfo.m_capacity_score * 100));
		proc->mutable_resource_counters()->set_stolen_capacity_score((uint32_t)(procinfo.m_stolen_capacity_score * 100));
		proc->mutable_resource_counters()->set_connection_queue_usage_pct(procinfo.m_connection_queue_usage_pct);
		if(!m_nodriver)
		{
			// These metrics are not correct in nodriver mode
			proc->mutable_resource_counters()->set_fd_usage_pct(procinfo.m_fd_usage_pct);
			proc->mutable_resource_counters()->set_fd_count(procinfo.m_fd_count);
		}

		//
		// Error-related metrics
		//
		procinfo.m_syscall_errors.to_protobuf(proc->mutable_syscall_errors(), m_sampling_ratio);

		//
		// Protocol tables
		//
		proc->set_start_count(procinfo.m_start_count);
		proc->set_count_processes(procinfo.m_proc_count);
	}
}
