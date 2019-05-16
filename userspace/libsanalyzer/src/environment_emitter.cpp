#include "environment_emitter.h"
#include "threadinfo.h"
#include "analyzer_thread.h"

environment_emitter::environment_emitter(const uint64_t prev_flush_time_ns,
					 const env_hash_config& the_env_hash_config,
					 draiosproto::metrics& metrics)
	: m_sent_envs(),
	  m_prev_flush_time_ns(prev_flush_time_ns),
	  m_env_hash_config(the_env_hash_config),
	  m_metrics(metrics)
{
}

void environment_emitter::emit_environment(sinsp_threadinfo& tinfo,
					   draiosproto::program& prog)
{
	auto mt_ainfo = tinfo.m_ainfo->main_thread_ainfo();
        auto env_hash = mt_ainfo->m_env_hash.get_hash();
        prog.set_environment_hash(env_hash.data(), env_hash.size());

        auto af_flag = thread_analyzer_info::AF_IS_NET_CLIENT;
        if(!(tinfo.m_ainfo->m_th_analysis_flags & af_flag)) {
                return;
        }

        auto new_env = m_sent_envs.insert({mt_ainfo->m_env_hash, m_prev_flush_time_ns + m_env_hash_config.m_env_hash_ttl});
        // new_env.first->first: env_hash
        // new_env.first->second: last sent timestamp
        // new_env.second: if true, insertion took place (first time we're sending this hash)

        if(!new_env.second && new_env.first->second >= m_prev_flush_time_ns) {
                return;
        }

        if(++m_num_envs_sent > m_env_hash_config.m_envs_per_flush) {
                g_logger.format(sinsp_logger::SEV_INFO,
				"Environment flush limit reached, throttling");
                if(new_env.second) {
                        m_sent_envs.erase(new_env.first);
                }
        } else {
                size_t env_bytes_sent = 0;

                auto env = m_metrics.add_environments();
                env->set_hash(env_hash.data(), env_hash.size());

                for(const auto& entry : tinfo.get_env()) {
                        if(entry.empty() || entry[0] == '=') {
                                continue;
                        }
                        bool blacklisted = false;
                        for(const auto& regex : *m_env_hash_config.m_env_blacklist) {
                                if(regex.match(entry)) {
                                        blacklisted = true;
                                        break;
                                }
                        }

                        if(blacklisted) {
                                continue;
                        }

                        env_bytes_sent += entry.size() + 1; // 1 for the trailing NUL
                        if(env_bytes_sent > m_env_hash_config.m_max_env_size) {
                                break;
                        }

                        env->add_variables(entry);
                }

                if(env_bytes_sent > m_env_hash_config.m_max_env_size) {
                        g_logger.format(sinsp_logger::SEV_INFO,
					"Environment of process %lu (%s) too large, truncating",
					tinfo.m_pid,
					tinfo.m_comm.c_str());
                        for(const auto& entry : tinfo.m_env) {
                                g_logger.format(sinsp_logger::SEV_DEBUG,
						"Environment of process %lu (%s): %s",
						tinfo.m_pid, 
						tinfo.m_comm.c_str(),
						entry.c_str());
                        }
                }

                if(!new_env.second) {
                        new_env.first->second = m_prev_flush_time_ns + m_env_hash_config.m_env_hash_ttl;
                }
        }
}

