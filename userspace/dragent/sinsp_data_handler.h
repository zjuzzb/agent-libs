#pragma once

#include "main.h"
#include "protocol.h"
#include "draios.pb.h"

class dragent_configuration;

class sinsp_data_handler : public analyzer_callback_interface
{
public:
	sinsp_data_handler(dragent_configuration* configuration,
			   protocol_queue* queue);

	virtual ~sinsp_data_handler();

	void sinsp_analyzer_data_ready(uint64_t ts_ns,
				       uint64_t nevts,
				       uint64_t num_drop_events,
				       draiosproto::metrics* metrics,
				       uint32_t sampling_ratio,
				       double analyzer_cpu_pct,
				       double flush_cpu_pct,
				       uint64_t analyzer_flush_duration_ns,
				       uint64_t num_suppressed_threads);

	void security_mgr_policy_events_ready(uint64_t ts_ns, draiosproto::policy_events *events);

	void security_mgr_throttled_events_ready(uint64_t ts_ns,
						 draiosproto::throttled_policy_events *events,
						 uint32_t total_throttled_count);

	uint64_t get_last_loop_ns() const
	{
		return m_last_loop_ns;
	}

private:
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	std::atomic<uint64_t> m_last_loop_ns;
};
