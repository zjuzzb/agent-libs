#pragma once

#include "main.h"

#ifndef CYGWING_AGENT
#ifndef _WIN32
#include <sys/prctl.h>
#endif
#endif

#include "coclient.h"
#include "crash_handler.h"
#include "configuration.h"
#include "connection_manager.h"
#include "error_handler.h"
#include "capture_job_handler.h"
#include "sinsp_worker.h"
#include "common_logger.h"
#include "monitor.h"
#include "subprocesses_logger.h"
#include "internal_metrics.h"
#include <atomic>
#include <memory>
#include "metric_serializer.h"
#include "async_aggregator.h"
#include "dragent_message_queues.h"
#include "protobuf_compression.h"
#include "watchdog_runnable_pool.h"

#ifndef CYGWING_AGENT
#include "sdc_internal.pb.h"
#else
#include "windows_helpers.h"
#endif
#include "draios.pb.h"
#include "analyzer_utils.h"
#include "timer_thread.h"
#include "watchdog.h"


class promscrape;
class promscrape_proxy;
class promscrape_stats_proxy;
class user_event_channel;

///////////////////////////////////////////////////////////////////////////////
// The main application class
///////////////////////////////////////////////////////////////////////////////
class dragent_app: public Poco::Util::ServerApplication
{
public:
	dragent_app();
	~dragent_app();

protected:
	void initialize(Application& self);
	void uninitialize();
	void defineOptions(OptionSet& options);
	void handleOption(const std::string& name, const std::string& value);
	void displayHelp();
	int main(const std::vector<std::string>& args);

private:
	int sdagent_main();
	inline bool timeout_expired(int64_t last_activity_age_ns, uint64_t timeout_s, const char* label, const char* tail);
	void watchdog_check(uint64_t uptime_s);
	void dump_heap_profile(uint64_t uptime_s, bool throttle = true);
	void initialize_logging();
	void check_for_clean_shutdown();
	void mark_clean_shutdown();
	Logger* make_event_channel();
	void send_internal_metrics(pid_t pid, const std::string& name);
	void log_watchdog_report() const;
	void update_subprocesses();
	void update_subprocesses_priority();
	void monitor_files(uint64_t uptime_s);
	void init_inspector(sinsp::ptr inspector);
	sinsp_analyzer* build_analyzer(
		const sinsp::ptr& inspector,
		flush_queue& flush_queue,
		const metric_limits::sptr_t& the_metric_limits,
		const label_limits::sptr_t& the_label_limits,
		const k8s_limits::sptr_t& the_k8s_limits,
		std::shared_ptr<app_checks_proxy_interface> the_app_checks_proxy,
		std::shared_ptr<promscrape> promscrape);
	void setup_coredumps();
	void log_sysinfo();

	/**
	 * Create a file
	 * @param dir Directory name
	 * @param f File name
	 * @return true on success,fail otherwise
	 */
	bool create_file(const std::string& dir, const std::string& f);

	/**
	 * Check for a file existence and remove it
	 * @param dir Directory name
	 * @param f File name
	 * @return true if the file existed (and then removed), 0 otherwise
	 */
	bool remove_file_if_exists(const std::string& dir, const std::string& f);

	/**
	 * Create a sentinel file as soon as the agent had initialized and connected to the
	 * backend. The file is used as a k8s probe and for auto detecting
	 * unclean shutdown as well
	 * @param cm Connection manager. It holds the BE <--> agent connection status
	 */
	void setup_startup_probe(const connection_manager& cm);

	/**
	 * The agent has feature negotiation with the backend. This is 
	 * the response to that negotiation with the metric limit that 
	 * the backend has selected. 
	 * This will be running on the connection manager thread. 
	 */
	void handle_metric_limit(bool has_limit, draiosproto::custom_metric_limit_value value);


	/**
	 * Cointerface notifies its readiness with a flag in the pong message.
	 * Some time after having received this flag, the dragent considers cointerface ready.
	 * This function is useful for the kubernetes readiness probe implementation
	 * @return true if cointerface is ready, false otherwise
	 **/
	bool cointerface_ready() const;

	bool m_help_requested;
	bool m_version_requested;
#ifdef CYGWING_AGENT
	windows_helpers m_windows_helpers;
	bool m_windows_service_parent;
#endif
	std::string m_pidfile;
#ifndef CYGWING_AGENT
	bool m_unshare_ipcns;
#endif
	dragent_configuration m_configuration;
	watchdog_error_handler m_error_handler;
	/// Queue for input to the aggregator
	flush_queue m_aggregator_queue;
	/// Queue for input to the serializer
	flush_queue m_serializer_queue;
	/// Queue consumed by connection_manager for transmission to backend
	protocol_queue m_transmit_queue;
	std::atomic<bool> m_enable_autodrop;

	std::unique_ptr<errpipe_manager> m_jmx_pipes;
	std::shared_ptr<pipe_manager> m_statsite_pipes;
	std::unique_ptr<errpipe_manager> m_sdchecks_pipes;
	std::unique_ptr<errpipe_manager> m_mounted_fs_reader_pipe;
	std::unique_ptr<errpipe_manager> m_statsite_forwarder_pipe;
	std::unique_ptr<pipe_manager> m_cointerface_pipes;
	std::unique_ptr<pipe_manager> m_coldstart_manager_pipes;
	std::unique_ptr<pipe_manager> m_promex_pipes;
	std::unique_ptr<pipe_manager> m_promscrape_pipes;

	std::shared_ptr<promscrape_proxy> m_promscrape_proxy;
	std::shared_ptr<promscrape_stats_proxy> m_promscrape_stats_proxy;

	std::shared_ptr<timer_thread> m_timer_thread;

	internal_metrics::sptr_t m_internal_metrics;
	protocol_handler m_protocol_handler;
	capture_job_handler m_capture_job_handler;
	sinsp_worker m_sinsp_worker;

	log_reporter m_log_reporter;
	subprocesses_logger m_subprocesses_logger;
	typedef std::unordered_map<std::string, watchdog_state> ProcessStateMap;
	ProcessStateMap m_subprocesses_state;
	bool m_cointerface_ready;
	uint64_t m_last_dump_s;
#ifndef CYGWING_AGENT
	std::unique_ptr<coclient> m_coclient;
	run_on_interval m_cointerface_ping_interval = {5*ONE_SECOND_IN_NS};
#endif

	struct monitor_file_state {
		monitor_file_state(std::string const &path,
		                   time_t &mod_time,
		                   std::string const &digest):
			m_path(path), m_mod_time(mod_time), m_digest(digest) {}

		std::string m_path;
		time_t m_mod_time;
		std::string m_digest;
	};
	std::vector<monitor_file_state> m_monitored_files;
	watchdog_runnable_pool m_pool;
	bool m_had_unclean_shutdown = false;
	bool m_startup_probe_set = false;
	static const std::string K8S_PROBE_FILE;
};
