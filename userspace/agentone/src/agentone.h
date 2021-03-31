#pragma once

#include "main.h"

#include <sys/prctl.h>

#include "coclient.h"
#include "crash_handler.h"
#include "configuration.h"
#include "connection_manager.h"
#include "error_handler.h"
#include "sinsp_worker.h"
#include "common_logger.h"
#include "monitor.h"
#include "subprocesses_logger.h"
#include "internal_metrics.h"
#include <atomic>
#include <memory>
#include "metric_serializer.h"
#include "dragent_message_queues.h"
#include "protobuf_compression.h"
#include "watchdog_runnable_pool.h"

#include "sdc_internal.pb.h"
#include "draios.pb.h"
#include "analyzer_utils.h"
#include "watchdog.h"

class user_event_channel;

///////////////////////////////////////////////////////////////////////////////
// The main application class
///////////////////////////////////////////////////////////////////////////////
class agentone_app: public Poco::Util::ServerApplication
{
public:
	agentone_app();
	~agentone_app();

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
	Logger* make_console_channel(AutoPtr<Formatter> formatter);
	Logger* make_event_channel();
	void send_internal_metrics(pid_t pid, const std::string& name);
	void log_watchdog_report() const;
	void update_subprocesses();
	void update_subprocesses_priority();
	void monitor_files(uint64_t uptime_s);
	void setup_coredumps();

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

	/*
	 * Create a sentinel file as soon as the agent had initialized and connected to the
	 * backend. The file is used as a k8s probe and for auto detecting
	 * unclean shutdown as well
	 * @param cm Connection manager. It holds the BE <--> agent connection status
	 */
	void setup_startup_probe(const connection_manager& cm);

	std::string m_pidfile;
	bool m_unshare_ipcns;

	dragent_configuration m_configuration;
	dragent_error_handler m_error_handler;

	/// Queue for input to the serializer
	flush_queue m_serializer_queue;
	/// Queue consumed by connection_manager for transmission to backend
	protocol_queue m_transmit_queue;

	std::unique_ptr<pipe_manager> m_cointerface_pipes;

	protocol_handler m_protocol_handler;

	log_reporter m_log_reporter;
	subprocesses_logger m_subprocesses_logger;
	typedef std::unordered_map<std::string, watchdog_state> ProcessStateMap;
	ProcessStateMap m_subprocesses_state;
	uint64_t m_last_dump_s;
	std::unique_ptr<coclient> m_coclient;
	run_on_interval m_cointerface_ping_interval = {5*ONE_SECOND_IN_NS};

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

	// input parameter. Used in the hostname field in the protobuf.
	std::string m_hostname;
};
