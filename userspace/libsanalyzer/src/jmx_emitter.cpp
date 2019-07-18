#include "jmx_emitter.h"
#include "draios.pb.h"
#include "analyzer_thread.h"
#include "metric_forwarding_configuration.h"

jmx_emitter::jmx_emitter(const std::unordered_map<int, java_process>& jmx_metrics,
			 const uint32_t jmx_sampling,
			 const uint32_t jmx_limit,
			 std::unordered_map<std::string, std::tuple<unsigned, unsigned>>& jmx_metrics_by_container)
	: m_jmx_metrics(jmx_metrics),
	  m_jmx_sampling(jmx_sampling),
	  m_jmx_limit_remaining(jmx_limit),
	  m_jmx_limit(jmx_limit),
	  m_jmx_metrics_by_container(jmx_metrics_by_container)
{
}

void jmx_emitter::emit_jmx(sinsp_procinfo& procinfo,
			   sinsp_threadinfo& tinfo,
			   draiosproto::process& proc)
{
	if((m_jmx_limit_remaining > 0) || metric_limits::log_enabled())
	{
		unsigned jmx_proc_limit = std::min(m_jmx_limit_remaining, JMX_METRICS_HARD_LIMIT_PER_PROC);
		auto jmx_metrics_it = m_jmx_metrics.end();
		for(auto pid_it = procinfo.m_program_pids.begin();
		    pid_it != procinfo.m_program_pids.end() && jmx_metrics_it == m_jmx_metrics.end();
		    ++pid_it)
		{
			jmx_metrics_it = m_jmx_metrics.find(*pid_it);
		}
		if(jmx_metrics_it != m_jmx_metrics.end())
		{
			if(m_jmx_limit_remaining > 0)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "Found JMX metrics for pid %d", tinfo.m_pid);
				auto java_proto = proc.mutable_protos()->mutable_java();
				unsigned jmx_total = jmx_metrics_it->second.total_metrics();
				unsigned jmx_sent = jmx_metrics_it->second.to_protobuf(java_proto,
										       m_jmx_sampling,
										       jmx_proc_limit,
										       "process",
										       std::min(m_jmx_limit,
												JMX_METRICS_HARD_LIMIT_PER_PROC));
				m_jmx_limit_remaining -= jmx_sent;
				if(m_jmx_limit_remaining == 0)
				{
					g_logger.format(sinsp_logger::SEV_WARNING,
							"JMX metrics limit (%u) reached",
							m_jmx_limit);
				}

				proc.mutable_resource_counters()->set_jmx_sent(jmx_sent);
				proc.mutable_resource_counters()->set_jmx_total(jmx_total);
				if(!tinfo.m_container_id.empty())
				{
					std::get<0>(m_jmx_metrics_by_container[tinfo.m_container_id]) += jmx_sent;
					std::get<1>(m_jmx_metrics_by_container[tinfo.m_container_id]) += jmx_total;
				}
				std::get<0>(m_jmx_metrics_by_container[""]) += jmx_sent;
				std::get<1>(m_jmx_metrics_by_container[""]) += jmx_total;
			}
			else if(metric_limits::log_enabled())
			{
				g_logger.format(sinsp_logger::SEV_WARNING,
						"All JMX metrics for pid %d exceed limit, will not be emitted.", tinfo.m_pid);
				// dummy call, only to print excessive metrics
				jmx_metrics_it->second.to_protobuf(nullptr,
								   0,
								   m_jmx_limit,
								   "total",
								   m_jmx_limit);
			}
		}
	}
}
