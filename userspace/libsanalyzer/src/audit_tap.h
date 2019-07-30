#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>

#include "env_hash.h"

namespace tap {
class AuditLog;
class NewProcess;
}

class sinsp_ipv4_connection_manager;
class sinsp_threadinfo;
class sinsp;
class userdb;

/**
 * A special view of process data built for Goldman that is sent out via
 * the AuditLog protobuf.
 */
class audit_tap {
public:

	audit_tap(env_hash_config *config, const std::string& machine_id, bool emit_local_connections);

	/**
	 * Called when the process exits. This will all special process exit events
	 * to the buffer.
	 */
	void on_exit(uint64_t pid);

	/**
	 * Using the given connection table, emit the network connections between
	 * processes.
	 */
	void emit_connections(sinsp_ipv4_connection_manager* conn_manager, userdb* userdb);

	/**
	 * When connections are emitted, we limit the number of environments
	 * that we emit at once.  If previous emissions had unsent environments
	 * then this is used to grab them to send at a later time.
	 */
	void emit_pending_envs(sinsp* inspector);

	/**
	 * Put the events into the audit log.
	 */
	const tap::AuditLog* get_events();

	/**
	 * After a batch of events is sent, this is called to clear the buffer.
	 */
	void clear();

	/**
	 * Return the (configured) maximum length to send for arguments to the
	 * command line.
	 */
	static unsigned int max_command_argument_length();

private:
	void emit_process(sinsp_threadinfo *tinfo, userdb *userdb);
	bool emit_environment(tap::NewProcess *proc, sinsp_threadinfo *tinfo);

	std::string m_machine_id;
	std::string m_hostname;
	bool m_emit_local_connections;

	tap::AuditLog* m_event_batch;
	std::unordered_set<uint64_t> m_pids;
	std::unordered_set<uint64_t> m_unsent_envs;
	std::unordered_map<env_hash, uint64_t> m_sent_envs;
	env_hash_config* m_config;
	int m_num_envs_sent;
};