#include "process_emitter.h"
#include "analyzer_thread.h"
#include "tracer_emitter.h"

process_emitter::process_emitter(const process_manager& the_process_manager,
				 sinsp& inspector,
				 const bool simpledriver_enabled,
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
	: m_process_manager(the_process_manager),
	m_inspector(inspector),
	m_simpledriver_enabled(simpledriver_enabled),
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

template<class Iterator> void process_emitter::filter_top_programs(Iterator progtable_begin,
								   Iterator progtable_end,
								   bool cs_only,
								   uint32_t how_many,
								   const std::set<sinsp_threadinfo*>& blacklist,
								   std::set<sinsp_threadinfo*>& processes_to_emit)
{
	// build the list of things we can emit here based on cs_only and driver type
	vector<sinsp_threadinfo*> prog_sortable_list;

	for (auto ptit = progtable_begin; ptit != progtable_end; ++ptit)
	{
		if (blacklist.find(*ptit) != blacklist.end()) {
			continue;
		}

		if(m_simpledriver_enabled &&
		   (!cs_only ||
		    (*ptit)->m_ainfo->m_procinfo->m_proc_metrics.m_net.m_count != 0))
		{
			prog_sortable_list.push_back(*ptit);
		}

		if (!m_simpledriver_enabled &&
		    (!cs_only ||
		     (*ptit)->m_ainfo->m_th_analysis_flags &
		     (thread_analyzer_info::AF_IS_LOCAL_IPV4_SERVER | // this should probably be defined by thread_analyzer_info
		      thread_analyzer_info::AF_IS_REMOTE_IPV4_SERVER |
		      thread_analyzer_info::AF_IS_LOCAL_IPV4_CLIENT |
		      thread_analyzer_info::AF_IS_REMOTE_IPV4_CLIENT)))
		{
			prog_sortable_list.push_back(*ptit);
		}
	}

	if(prog_sortable_list.size() <= how_many)
	{
		for(uint32_t i = 0; i < prog_sortable_list.size(); i++)
		{
			processes_to_emit.insert(prog_sortable_list[i]);
		}

		return;
	}

	//
	// Mark the top CPU consumers
	//
	partial_sort(prog_sortable_list.begin(),
		     prog_sortable_list.begin() + how_many,
		     prog_sortable_list.end(),
		     (cs_only) ? threadinfo_cmp_cpu_cs : threadinfo_cmp_cpu);

	// the zero check here does not use the same value as the comparator, which uses
	// m_ainfo->m_procinfo->m_cpuload. This is probably wrong, but it's how legacy code
	// did it.
	for(uint32_t i = 0; i < how_many && prog_sortable_list[i]->m_ainfo->m_cpuload > 0; i++)
	{
		processes_to_emit.insert(prog_sortable_list[i]);
	}

	//
	// Mark the top memory consumers
	//
	partial_sort(prog_sortable_list.begin(),
		     prog_sortable_list.begin() + how_many,
		     prog_sortable_list.end(),
		     (cs_only) ? threadinfo_cmp_memory_cs : threadinfo_cmp_memory);

	// the zero check here does not use the same value as the comparator, which uses
	// m_ainfo->m_procinfo->m_vmrss_kb. This is probably wrong, but it's how legacy code
	// did it.
	for(uint32_t i = 0; i < how_many && prog_sortable_list[i]->m_vmsize_kb > 0; i++)
	{
		processes_to_emit.insert(prog_sortable_list[i]);
	}

	//
	// Mark the top network I/O consumers
	//
	// does not work on NODRIVER mode
	if(!m_nodriver)
	{
		partial_sort(prog_sortable_list.begin(),
			     prog_sortable_list.begin() + how_many,
			     prog_sortable_list.end(),
			     (cs_only) ? threadinfo_cmp_net_cs : threadinfo_cmp_net);

		for(uint32_t i = 0; i < how_many && prog_sortable_list[i]->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 0; i++)
		{
			processes_to_emit.insert(prog_sortable_list[i]);
		}
	}

	if (m_simpledriver_enabled)
	{
		//
		// Mark the top syscall producers
		//
		partial_sort(prog_sortable_list.begin(),
			     prog_sortable_list.begin() + how_many,
			     prog_sortable_list.end(),
			     threadinfo_cmp_evtcnt);

		// not sure why we just use net io for the 0 check.
		for(uint32_t i = 0; i < how_many && prog_sortable_list[i]->m_ainfo->m_procinfo->m_proc_metrics.m_io_net.get_tot_bytes() > 0; i++)
		{
			processes_to_emit.insert(prog_sortable_list[i]);
		}
	}
	else
	{
		//
		// Mark the top disk I/O consumers
		//
		partial_sort(prog_sortable_list.begin(),
			     prog_sortable_list.begin() + how_many,
			     prog_sortable_list.end(),
			     (cs_only) ? threadinfo_cmp_io_cs : threadinfo_cmp_io);

		for(uint32_t i = 0; i < how_many && prog_sortable_list[i]->m_ainfo->m_procinfo->m_proc_metrics.m_io_file.get_tot_bytes() > 0; i++)
		{
			processes_to_emit.insert(prog_sortable_list[i]);
		}
	}
}

void process_emitter::filter_process(sinsp_threadinfo* tinfo,
				     const sinsp_container_info* container_info,
				     std::set<sinsp_threadinfo*>& high_priority_processes,
				     std::set<sinsp_threadinfo*>& low_priority_processes,
				     std::set<sinsp_threadinfo*>& blacklist_processes)
{
	// already matched this process. bail.
	if (high_priority_processes.find(tinfo) != high_priority_processes.end() ||
	    low_priority_processes.find(tinfo) != low_priority_processes.end() ||
	    blacklist_processes.find(tinfo) != blacklist_processes.end())
	{
		return;
	}

	bool generic_match;
	if (m_process_manager.get_flush_filter().matches(tinfo,
							 tinfo,
							 container_info,
							 NULL,
							 &generic_match,
							 NULL))
	{
		if (generic_match)
		{
			low_priority_processes.insert(tinfo);
		}
		else
		{
			high_priority_processes.insert(tinfo);
		}
	}
	else
	{
		blacklist_processes.insert(tinfo);
	}
}

void process_emitter::emit_processes(analyzer_emitter::flush_flags flushflags,
				     const analyzer_emitter::progtable_t& progtable,
				     const analyzer_emitter::progtable_by_container_t& progtable_by_container,
				     const vector<std::string>& emitted_containers,
				     draiosproto::metrics& metrics,
				     std::set<uint64_t>& all_uids,
				     std::set<sinsp_threadinfo*>& emitted_processes)
{
	if(flushflags != analyzer_emitter::DF_FORCE_FLUSH_BUT_DONT_EMIT)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "progtable size: %u", progtable.size());
	}

	std::set<sinsp_threadinfo*>& processes_to_emit = emitted_processes;

	std::set<sinsp_threadinfo*> high_priority_processes;
	std::set<sinsp_threadinfo*> low_priority_processes;
	std::set<sinsp_threadinfo*> blacklist_processes;

	// first step: get list of emittable processes
	for(auto container_it = progtable_by_container.begin(); container_it != progtable_by_container.end(); ++container_it)
	{
		const sinsp_container_info* container_info = m_inspector.m_container_manager.get_container(container_it->first);
		for (auto thread_it = container_it->second.begin(); thread_it != container_it->second.end(); ++thread_it)
		{
			sinsp_threadinfo* thread_info = *thread_it;
			filter_process(thread_info,
				       container_info,
				       high_priority_processes,
				       low_priority_processes,
				       blacklist_processes);
		}
	}

	// have to also go through the progtable for processes that AREN'T in the
	// container progtable. filter_process deals with duplicates for us.
	for(auto thread_it : progtable)
	{
		filter_process(thread_it,
			       nullptr,
			       high_priority_processes,
			       low_priority_processes,
			       blacklist_processes);
	}

	// Next: get the top processes on the host in each stat category
	if(!m_inspector.is_capture())
	{
		tracer_emitter filter_trc("filter_progtable", m_proc_trc);

		// Filter top active programs
		filter_top_programs(progtable.begin(),
				    progtable.end(),
				    false, //!cs_only
				    process_manager::c_top_processes_per_host.get(),
				    blacklist_processes,
				    processes_to_emit);

		// Filter top client/server programs
		filter_top_programs(progtable.begin(),
				    progtable.end(),
				    true, //cs_only
				    process_manager::c_top_processes_per_host.get(),
				    blacklist_processes,
				    processes_to_emit);
	}

	// Next: grab the whitelisted processes. If you whitelist too many processes, too bad for you.
	for(const auto it : high_priority_processes)
	{
		if(processes_to_emit.size() >= process_manager::c_process_limit.get())
		{
			break;
		}

		processes_to_emit.insert(it);
	}

	// Next: grab processes at the top of each stat category in each container.
	if(!m_inspector.is_capture())
	{
		// Add at least one process per emitted_container
		for(const auto& container_id : emitted_containers)
		{
			if(processes_to_emit.size() >= process_manager::c_process_limit.get())
			{
				break;
			}

			auto progs_it = progtable_by_container.find(container_id);
			if(progs_it != progtable_by_container.end())
			{
				auto progs = progs_it->second;
				filter_top_programs(progs.begin(),
						    progs.end(),
						    false, //!cs_only
						    process_manager::c_top_processes_per_container.get(),
						    blacklist_processes,
						    processes_to_emit);
			}
		}
	}

	// Last: fill up the list with processes from the host
	if(!m_inspector.is_capture() && processes_to_emit.size() < process_manager::c_process_limit.get())
	{
		// Filter top active programs
		filter_top_programs(progtable.begin(),
				    progtable.end(),
				    false, //!cs_only
				    (process_manager::c_process_limit.get() - processes_to_emit.size()) / 8,
				    blacklist_processes,
				    processes_to_emit);

		// Filter top client/server programs
		filter_top_programs(progtable.begin(),
				    progtable.end(),
				    true, //cs_only
				    (process_manager::c_process_limit.get() - processes_to_emit.size()) / 8,
				    blacklist_processes,
				    processes_to_emit);
	}

	///////////////////////////////////////////////////////////////////////////
	// Second pass of the list of threads: aggregate threads into processes
	// or programs.
	///////////////////////////////////////////////////////////////////////////
	tracer_emitter at_trc("aggregate_threads", m_proc_trc);
	for(auto it = progtable.begin(); it != progtable.end(); ++it)
	{
		sinsp_threadinfo* tinfo = *it;
		if (!tinfo)
		{
			continue;
		}

		//
		// If this is the main thread of a process, add an entry into the processes
		// section too
		//
		sinsp_procinfo* procinfo = tinfo->m_ainfo->m_procinfo;

		sinsp_counter_time tot;

		ASSERT(procinfo != NULL);

		procinfo->m_proc_metrics.get_total(&tot);

		if(processes_to_emit.find(tinfo) != processes_to_emit.end())
		{

			draiosproto::program* prog = metrics.add_programs();
			emit_process(*tinfo,
				     *prog,
				     progtable_by_container,
				     *procinfo,
				     tot,
				     metrics,
				     all_uids,
				     high_priority_processes.find(tinfo) != high_priority_processes.end());
		}

		//
		// Clear the thread metrics, so we're ready for the next sample
		//
		tinfo->m_ainfo->clear_all_metrics();
	}
	at_trc.stop();
}

void process_emitter::emit_process(sinsp_threadinfo& tinfo,
				   draiosproto::program& prog,
				   const analyzer_emitter::progtable_by_container_t& progtable_by_container,
				   sinsp_procinfo& procinfo,
				   const sinsp_counter_time& tot,
				   draiosproto::metrics& metrics,
				   std::set<uint64_t>& all_uids,
				   bool high_priority)
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

	// only one group right now....whitelist...so just need to add something
	// to the groups for the backend
	if (high_priority)
	{
		prog.add_program_reporting_group_id(1);
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
