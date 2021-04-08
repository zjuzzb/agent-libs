#include "secure_audit_filter.h"

#define ONE_SECOND_IN_NS 1000000000LL

namespace
{
COMMON_LOGGER();
const uint64_t FREQUENCY_THRESHOLD_NS = 10 * ONE_SECOND_IN_NS;  // 10s
uint64_t seconds_to_ns(const int seconds)
{
	return ((uint64_t)seconds * ONE_SECOND_IN_NS);
}
}  // namespace

type_config<bool> secure_audit_filter::c_secure_audit_filter_enabled(
    true,
    "Enable activity audit filtering",
    "secure_audit_filter",
    "enabled");

type_config<bool> secure_audit_filter::c_secure_audit_filter_commands_enabled(
    true,
    "Enable activity audit filtering on commands",
    "secure_audit_filter",
    "commands_enabled");

type_config<bool> secure_audit_filter::c_secure_audit_filter_connections_enabled(
    true,
    "Enable activity audit filtering on connections",
    "secure_audit_filter",
    "connections_enabled");

type_config<bool> secure_audit_filter::c_secure_audit_filter_files_enabled(
    true,
    "Enable activity audit filtering on files",
    "secure_audit_filter",
    "files_enabled");

type_config<int> secure_audit_filter::c_secure_audit_filter_commands_threshold(
    10,
    "Minimum threshold for commands filtering",
    "secure_audit_filter",
    "commands_threshold");

type_config<int> secure_audit_filter::c_secure_audit_filter_connections_threshold(
    20,
    "Minimum threshold for connections filtering",
    "secure_audit_filter",
    "connections_threshold");

type_config<int> secure_audit_filter::c_secure_audit_filter_files_threshold(
    20,
    "Minimum threshold for files filtering",
    "secure_audit_filter",
    "files_threshold");

type_config<int> secure_audit_filter::c_secure_audit_filter_commands_max_lru(
    10000,
    "Maximum LRU cache size",
    "secure_audit_filter",
    "commands_max_lru");

type_config<int> secure_audit_filter::c_secure_audit_filter_connections_max_lru(
    40000,
    "Maximum LRU cache size",
    "secure_audit_filter",
    "connections_max_lru");

type_config<int> secure_audit_filter::c_secure_audit_filter_files_max_lru(40000,
                                                                          "Maximum LRU cache size",
                                                                          "secure_audit_filter",
                                                                          "files_max_lru");

type_config<int> secure_audit_filter::c_secure_audit_filter_sliding_window(
    8 * 60 * 60,
    "Sliding window for counters",
    "secure_audit_filter",
    "sliding_window");

type_config<int> secure_audit_filter::c_secure_audit_filter_stats_window(8 * 60 * 60,
                                                                         "Sliding window for stats",
                                                                         "secure_audit_filter",
                                                                         "stats_window");

secure_audit_filter::secure_audit_filter()
    : m_commands_processed(0),
      m_connections_processed(0),
      m_files_processed(0),
      m_commands_discarded(0),
      m_connections_discarded(0),
      m_files_discarded(0),
      m_window_interval(make_unique<run_on_interval>(seconds_to_ns(28800), FREQUENCY_THRESHOLD_NS)),
      m_stats_interval(make_unique<run_on_interval>(seconds_to_ns(3600), FREQUENCY_THRESHOLD_NS))
{
	m_lru_commands =
	    new audit_cache::AuditFilterLRUCache(c_secure_audit_filter_commands_max_lru.get_value());
	m_lru_connections =
	    new audit_cache::AuditFilterLRUCache(c_secure_audit_filter_connections_max_lru.get_value());
	m_lru_files =
	    new audit_cache::AuditFilterLRUCache(c_secure_audit_filter_files_max_lru.get_value());

	m_window_interval->interval(seconds_to_ns(c_secure_audit_filter_sliding_window.get_value()));
	m_stats_interval->interval(seconds_to_ns(c_secure_audit_filter_stats_window.get_value()));
}

secure_audit_filter::~secure_audit_filter()
{
	delete m_lru_commands;
	delete m_lru_connections;
	delete m_lru_files;
}

// key used to identify a command into the LRU cache
std::string secure_audit_filter::cmd_to_key(const std::string& container_id,
                                            const std::string& cwd,
                                            const std::string& cmdline)
{
	return container_id + cwd + cmdline;
}

// key used to identify a connection into the LRU cache
std::string secure_audit_filter::conn_to_key(const std::string& container_id,
                                             const std::string& process,
                                             const uint64_t pid)
{
	std::string pid_str = std::to_string(pid);
	return container_id + process + pid_str;
}

// key used to identify a file into the LRU cache
std::string secure_audit_filter::file_to_key(const std::string& container_id,
                                             const std::string& process,
                                             const uint64_t pid)
{
	std::string pid_str = std::to_string(pid);
	return container_id + process + pid_str;
}

// if we have more than 10 similar commands, then start discarding them
// and start discarding connections/files with the same PID.
// check the 8h sliding window interval and reset the cache if necessary.
bool secure_audit_filter::discard_activity_audit_command(const std::string& container_id,
                                                         const std::string& cwd,
                                                         const std::string& cmdline,
                                                         const std::string& process,
                                                         const uint64_t pid,
                                                         uint64_t ts)
{
	if (!(c_secure_audit_filter_enabled.get_value() &&
	      c_secure_audit_filter_commands_enabled.get_value()))
	{
		return false;
	}

	change_window_on_interval(ts);

	if (m_lru_commands == nullptr)
	{
		return false;
	}

	std::string key = cmd_to_key(container_id, cwd, cmdline);
	m_commands_processed++;
	int count = m_lru_commands->Get(key);

	m_lru_commands->Put(key, ++count);

	if (count > c_secure_audit_filter_commands_threshold.get_value())
	{
		if (c_secure_audit_filter_connections_enabled.get_value() && m_lru_connections != nullptr)
		{
			std::string conn_key = conn_to_key(container_id, process, pid);
			int conn_count = m_lru_connections->Get(conn_key);
			conn_count += c_secure_audit_filter_connections_threshold.get_value();
			m_lru_connections->Put(conn_key, conn_count);
		}
		if (c_secure_audit_filter_files_enabled.get_value() && m_lru_files != nullptr)
		{
			std::string file_key = file_to_key(container_id, process, pid);
			int file_count = m_lru_files->Get(file_key);
			file_count += c_secure_audit_filter_files_threshold.get_value();
			m_lru_files->Put(file_key, file_count);
		}
		m_commands_discarded++;
		return true;
	}
	return false;
}

// if we have more than 20 similar connections, then start discarding them.
// if a command with the same pid is discarded, discard also the related connections.
// (when a command is discarded, the discard_activity_audit_command increase the
// connection count by connections_threshold for the same process and pid.
// the related connection will be immediately discarded, independently on the # of occurrences)
// check the 8h sliding window interval and reset the cache if necessary.
bool secure_audit_filter::discard_activity_audit_connection(const std::string& container_id,
                                                            const std::string& process,
                                                            const uint64_t pid,
                                                            uint64_t ts)
{
	if (!(c_secure_audit_filter_enabled.get_value() &&
	      c_secure_audit_filter_connections_enabled.get_value()))
	{
		return false;
	}

	change_window_on_interval(ts);

	if (m_lru_connections == nullptr)
	{
		return false;
	}

	std::string key = conn_to_key(container_id, process, pid);
	m_connections_processed++;
	int count = m_lru_connections->Get(key);

	m_lru_connections->Put(key, ++count);

	if (count > c_secure_audit_filter_connections_threshold.get_value())
	{
		m_connections_discarded++;
		return true;
	}
	return false;
}

// if we have more than 20 similar files, then start discarding them.
// if a command with the same pid is discarded, discard also the related files.
// (when a command is discarded, the discard_activity_audit_command increase the
// file count by files_threshold for the same process and pid.
// the related file will be immediately discarded, independently on the # of occurrences)
// check the 8h sliding window interval and reset the cache if necessary.
bool secure_audit_filter::discard_activity_audit_file(const std::string& container_id,
                                                      const std::string& process,
                                                      const uint64_t pid,
                                                      uint64_t ts)
{
	if (!(c_secure_audit_filter_enabled.get_value() &&
	      c_secure_audit_filter_files_enabled.get_value()))
	{
		return false;
	}

	change_window_on_interval(ts);

	if (m_lru_files == nullptr)
	{
		return false;
	}

	std::string key = file_to_key(container_id, process, pid);
	m_files_processed++;
	int count = m_lru_files->Get(key);

	m_lru_files->Put(key, ++count);

	if (count > c_secure_audit_filter_files_threshold.get_value())
	{
		m_files_discarded++;
		return true;
	}
	return false;
}

// change sliding window every 8h
// reset all counters and stats
void secure_audit_filter::change_window_on_interval(uint64_t ts)
{
	m_window_interval->run([this, ts]() { reset_lru(); }, ts);

	m_stats_interval->run([this, ts]() { print_reset_counters(ts); }, ts);
}

// logs at INFO level stats about
// activity audit commands/conn/files discarded
// usage of the LRU cache
void secure_audit_filter::print_reset_counters(uint64_t ts)
{
	LOG_INFO("secure_audit_filter - stats for last %d min",
	         c_secure_audit_filter_stats_window.get_value() / 60);
	LOG_INFO("secure_audit_filter - cmds (%d/%d - %.2f%%) - cache usage (%d/%d - %.2f%%)",
	         m_commands_discarded,
	         m_commands_processed,
	         m_commands_processed != 0
	             ? (float)m_commands_discarded / (float)m_commands_processed * 100
	             : 0,
	         (int)m_lru_commands->Size(),
	         c_secure_audit_filter_commands_max_lru.get_value(),
	         (float)m_lru_commands->Size() /
	             (float)c_secure_audit_filter_commands_max_lru.get_value() * 100);
	LOG_INFO("secure_audit_filter - conn (%d/%d - %.2f%%) - cache usage (%d/%d - %.2f%%)",
	         m_connections_discarded,
	         m_connections_processed,
	         m_connections_processed != 0
	             ? (float)m_connections_discarded / (float)m_connections_processed * 100
	             : 0,
	         (int)m_lru_connections->Size(),
	         c_secure_audit_filter_connections_max_lru.get_value(),
	         (float)m_lru_connections->Size() /
	             (float)c_secure_audit_filter_connections_max_lru.get_value() * 100);
	LOG_INFO(
	    "secure_audit_filter - file (%d/%d - %.2f%%) - cache usage (%d/%d - %.2f%%)",
	    m_files_discarded,
	    m_files_processed,
	    m_files_processed != 0 ? (float)m_files_discarded / (float)m_files_processed * 100 : 0,
	    (int)m_lru_files->Size(),
	    c_secure_audit_filter_files_max_lru.get_value(),
	    (float)m_lru_files->Size() / (float)c_secure_audit_filter_files_max_lru.get_value() * 100);

	m_commands_discarded = 0;
	m_commands_processed = 0;
	m_connections_discarded = 0;
	m_connections_processed = 0;
	m_files_discarded = 0;
	m_files_processed = 0;
}

// reset counters for the LRU cache
void secure_audit_filter::reset_lru()
{
	LOG_INFO("secure_audit_filter - switching to next filtering window");

	// Reset LRU caches
	delete m_lru_commands;
	delete m_lru_connections;
	delete m_lru_files;

	m_lru_commands =
	    new audit_cache::AuditFilterLRUCache(c_secure_audit_filter_commands_max_lru.get_value());
	m_lru_connections =
	    new audit_cache::AuditFilterLRUCache(c_secure_audit_filter_connections_max_lru.get_value());
	m_lru_files =
	    new audit_cache::AuditFilterLRUCache(c_secure_audit_filter_files_max_lru.get_value());
}