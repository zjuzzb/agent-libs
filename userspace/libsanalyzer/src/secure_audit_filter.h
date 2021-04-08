#pragma once

#include "analyzer_utils.h"
#include "common_logger.h"
#include "secure_audit_filter_lru_cache.h"
#include "type_config.h"

/**
 * secure_audit_filter implements an in-memory LRU mechanism to filter out noisy activity for
 * cmd/conn/files.
 *
 * 8h sliding window: every 8 hours the cache in initialized and re-starts from clean.
 *
 * commands threshold : if more than 10 similar cmds appears, start discarding them.
 *
 * conn/files threshold: if more than 20 similar appears, or we discard the related cmd (same pid),
 * start discarding.
 *
 * stats: print stats about discarded activity-audit periodically.
 */
class secure_audit_filter
{
public:
	secure_audit_filter();
	~secure_audit_filter();

	/**
	 * @brief decide whether to discard or not an activity audit command
	 * @param container_id container id
	 * @param cwd current working directory
	 * @param cmdline full cmdline
	 * @param process process name
	 * @param pid pid
	 * @param ts current timestamp
	 * @return true if the command should be discarded
	 */
	bool discard_activity_audit_command(const std::string& container_id,
	                                    const std::string& cwd,
	                                    const std::string& cmdline,
	                                    const std::string& process,
	                                    const uint64_t pid,
	                                    uint64_t ts);
	/**
	 * @brief decide whether to discard or not an activity audit connection
	 * @param container_id container id
	 * @param process process name
	 * @param pid pid
	 * @param ts current timestamp
	 * @return true if the connection should be discarded
	 */
	bool discard_activity_audit_connection(const std::string& container_id,
	                                       const std::string& process,
	                                       const uint64_t pid,
	                                       uint64_t ts);
	/**
	 * @brief decide whether to discard or not an activity audit file
	 * @param container_id container id
	 * @param process process name
	 * @param pid pid
	 * @param ts current timestamp
	 * @return true if the file should be discarded
	 */
	bool discard_activity_audit_file(const std::string& container_id,
	                                 const std::string& process,
	                                 const uint64_t pid,
	                                 uint64_t ts);

	static type_config<bool> c_secure_audit_filter_enabled;
	static type_config<bool> c_secure_audit_filter_commands_enabled;
	static type_config<bool> c_secure_audit_filter_connections_enabled;
	static type_config<bool> c_secure_audit_filter_files_enabled;
	static type_config<int> c_secure_audit_filter_commands_threshold;
	static type_config<int> c_secure_audit_filter_connections_threshold;
	static type_config<int> c_secure_audit_filter_files_threshold;
	static type_config<int> c_secure_audit_filter_commands_max_lru;
	static type_config<int> c_secure_audit_filter_connections_max_lru;
	static type_config<int> c_secure_audit_filter_files_max_lru;

	static type_config<int> c_secure_audit_filter_sliding_window;
	static type_config<int> c_secure_audit_filter_stats_window;

private:
	void change_window_on_interval(uint64_t ts);

	void reset_lru();
	void print_reset_counters(uint64_t ts);

	std::string cmd_to_key(const std::string& container_id,
	                       const std::string& cwd,
	                       const std::string& cmdline);
	std::string conn_to_key(const std::string& container_id,
	                        const std::string& process,
	                        const uint64_t pid);
	std::string file_to_key(const std::string& container_id,
	                        const std::string& process,
	                        const uint64_t pid);

	audit_cache::AuditFilterLRUCache* m_lru_commands;
	audit_cache::AuditFilterLRUCache* m_lru_connections;
	audit_cache::AuditFilterLRUCache* m_lru_files;

	int m_commands_processed;
	int m_connections_processed;
	int m_files_processed;
	int m_commands_discarded;
	int m_connections_discarded;
	int m_files_discarded;

	std::unique_ptr<run_on_interval> m_window_interval;
	std::unique_ptr<run_on_interval> m_stats_interval;
};