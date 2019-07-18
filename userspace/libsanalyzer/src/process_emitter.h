#pragma once
#include "process_manager.h"
#include "analyzer_emitter.h"
#include "jmx_emitter.h"
#include "environment_emitter.h"
#include "app_check_emitter.h"
#include "threadinfo.h"
#include "tracer_emitter.h"
#include "draios.pb.h"
#include "procfs_parser.h"
#include "metrics.h"

/**
 * manages data and activity related to processes during a SINGLE flush instance
 */
class process_emitter {
public:
	process_emitter(const process_manager& the_process_manager,
			sinsp& inspector,
			const bool simpledriver_enabled,
			const bool nodriver,
			tracer_emitter& proc_trc,
			const uint32_t top_files_per_prog,
			const std::unordered_map<dev_t, std::string>& device_map,
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
			app_check_emitter& the_app_check_emitter);
	
	/**
	 * emit data for all processes in the progtable, as defined by the logic of this
	 * process_emitter.
	 */
	void emit_processes(analyzer_emitter::flush_flags flushflags,
			    const analyzer_emitter::progtable_t& progtable,
			    const analyzer_emitter::progtable_by_container_t& progtable_by_container,
			    const std::vector<std::string>& emitted_containers,
			    draiosproto::metrics& metrics,
			    std::set<uint64_t>& all_uids,
			    std::set<sinsp_threadinfo*>& emitted_processes);

	/**
	 * emit data for a single process
	 */
	void emit_process(sinsp_threadinfo& tinfo,
			  draiosproto::program& prog,
			  const analyzer_emitter::progtable_by_container_t& progtable_by_container,
			  sinsp_procinfo& procinfo,
			  const sinsp_counter_time& tot,
			  draiosproto::metrics& metrics,
			  std::set<uint64_t>& all_uids,
			  bool high_priority);


private:

	/**
	 * get the top "how many" programs which pass the process filter. Must be a template
	 * to deal with both const and non-const iterators
	 *
	 * @param how_many maximum number of processes to take from the top of each stat category
	 * @param blacklist processes to skip. These will never be in set of processes_to_emit
	 * @param[out] the list of the top how_many processes of each stat category
	 */
	template<class Iterator> void filter_top_programs(Iterator progtable_begin,
							  Iterator progtable_end,
							  bool cs_only,
							  uint32_t how_many,
							  const std::set<sinsp_threadinfo*>& blacklist,
							  std::set<sinsp_threadinfo*>& processes_to_emit);

	/**
	 * take a given thread and sort it into the appropriate list
	 * based on the process_manager's object filter.
	 *
	 * appropriately deals with multiple calls with the same thread.
	 */
	void filter_process(sinsp_threadinfo* tinfo,
			   const sinsp_container_info* container_info,
			   std::set<sinsp_threadinfo*>& high_priority_processes,
			   std::set<sinsp_threadinfo*>& low_priority_processes,
			   std::set<sinsp_threadinfo*>& blacklist_processes);

	const process_manager& m_process_manager;
	sinsp& m_inspector;
	const bool m_simpledriver_enabled;
	const bool m_nodriver;
	tracer_emitter& m_proc_trc;
	const uint32_t m_top_files_per_prog;
	const std::unordered_map<dev_t, std::string>& m_device_map;
	const bool m_username_lookups;
	const bool m_track_environment;
	const uint32_t m_top_file_devices_per_prog;
	const jmx_proxy* m_jmx_proxy;
	const app_checks_proxy* m_app_proxy;
	const bool m_procfs_scan_thread;
	sinsp_procfs_parser& m_procfs_parser;
	const uint32_t m_sampling_ratio;
	const uint32_t m_num_cpus;

	environment_emitter& m_environment_emitter;
	jmx_emitter& m_jmx_emitter;
	app_check_emitter& m_app_check_emitter;

	friend class test_helper;
};

