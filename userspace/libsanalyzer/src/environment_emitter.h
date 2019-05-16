#pragma once
#include <unordered_map>
#include "env_hash.h"
#include "draios.pb.h"

/**
 * Does the work of emitting the environment of processes during the scope of a SINGLE flush.
 *
 * emit_environment must be invoked on each process which is inteded to have its environment
 * flushed
 */
class environment_emitter
{
public:
	environment_emitter(const uint64_t prev_flush_time_ns,
			    const env_hash_config& the_env_hash_config,
			    draiosproto::metrics& metrics);

	/**
	 * emit the environment of a single process
	 */
	void emit_environment(sinsp_threadinfo& tinfo,
			      draiosproto::program& prog);

private:
	uint64_t m_num_envs_sent = 0;
	std::unordered_map<env_hash, uint64_t> m_sent_envs;
	const uint64_t m_prev_flush_time_ns;
	const env_hash_config& m_env_hash_config;
	draiosproto::metrics& m_metrics;

};
