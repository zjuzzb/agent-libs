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
#include "watchdog_runnable_pool.h"
#include "blocking_queue.h"
#include "error_handler.h"
#include "capture_job_handler.h"
#include "sinsp_worker.h"
#include "logger.h"
#include "monitor.h"
#include "subprocesses_logger.h"
#include "internal_metrics.h"
#include <atomic>
#include <memory>

#ifndef CYGWING_AGENT
#include "sdc_internal.pb.h"
#else
#include "windows_helpers.h"
#endif
#include "draios.pb.h"
#include "analyzer_utils.h"

class watchdog_state
{
public:
	watchdog_state() noexcept:
		m_pid(0),
		m_memory_used(0),
		m_last_loop_s(0)
	{}

	pid_t pid() const noexcept { return m_pid.load(); }
	uint64_t memory_used() const noexcept { return m_memory_used.load(); }
	uint64_t last_loop_s() const noexcept { return m_last_loop_s.load(); }

	void reset(pid_t pid, uint64_t memory_used, uint64_t last_loop_s)
	{
		m_memory_used.store(memory_used);
		m_last_loop_s.store(last_loop_s);
		m_pid.store(pid);
	}

	void reset()
	{
		reset(0, 0, 0);
	}

	bool valid() const
	{
		return m_pid.load() > 0;
	}

	const std::string& name() const
	{
		return m_name;
	}

private:
	// careful here - only app should access this function
	// at a well-defined time (preferably immediately after object
	// creation); the name string will be read from subprocess
	// logger thread
	void set_name(const std::string& name)
	{
		m_name = name;
	}

	std::atomic<pid_t> m_pid;
	std::atomic<uint64_t> m_memory_used;
	std::atomic<uint64_t> m_last_loop_s;
	std::string m_name;

	// Dragent calls set_name just after construction
	friend class dragent_app;
};

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

	bool m_help_requested;
	bool m_version_requested;
#ifdef CYGWING_AGENT
	windows_helpers m_windows_helpers;
	bool m_windows_service_parent;
#endif
	string m_pidfile;
#ifndef CYGWING_AGENT
	bool m_unshare_ipcns;
#endif
	dragent_configuration m_configuration;
	dragent_error_handler m_error_handler;
	protocol_queue m_queue;
	atomic<bool> m_enable_autodrop;

	unique_ptr<errpipe_manager> m_jmx_pipes;
	shared_ptr<pipe_manager> m_statsite_pipes;
	unique_ptr<errpipe_manager> m_sdchecks_pipes;
	unique_ptr<errpipe_manager> m_mounted_fs_reader_pipe;
	unique_ptr<errpipe_manager> m_statsite_forwarder_pipe;
	unique_ptr<pipe_manager> m_cointerface_pipes;
	unique_ptr<pipe_manager> m_promex_pipes;

	internal_metrics::sptr_t m_internal_metrics;
	sinsp_worker m_sinsp_worker;
	capture_job_handler m_capture_job_handler;
	connection_manager m_connection_manager;
	log_reporter m_log_reporter;
	subprocesses_logger m_subprocesses_logger;
	typedef std::unordered_map<string, watchdog_state> ProcessStateMap;
	ProcessStateMap m_subprocesses_state;
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
	dragent::watchdog_runnable_pool m_pool;
};
