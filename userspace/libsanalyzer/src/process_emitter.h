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
	process_emitter(const bool simpledriver_enabled,
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
			app_check_emitter& the_app_check_emitter);

	void emit_process(sinsp_threadinfo& tinfo,
			  draiosproto::program& prog,
			  const analyzer_emitter::progtable_by_container_t& progtable_by_container,
			  sinsp_procinfo& procinfo,
			  const sinsp_counter_time& tot,
			  draiosproto::metrics& metrics,
			  std::set<uint64_t>& all_uids);


private:
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
};

