#pragma once

#include "uncompressed_sample_handler.h"
#include "audit_tap_handler.h"
#include "security_result_handler.h"
#include "log_report_handler.h"

#include "protocol.h"
#include "type_config.h"

/**
 * implementation of various handlers which serialize the input data to the provided
 * protocol queue
 */
class protocol_handler : public uncompressed_sample_handler,
			 public audit_tap_handler,
			 public security_result_handler,
			 public log_report_handler
{
public: // constructor/destructor

	/**
	 * @param[in] queue the ultimate output of any data that comes into the protocol handler
	 */
	protocol_handler(protocol_queue& queue);

	virtual ~protocol_handler();

public: // functions from uncompressed_sample_handler
	void handle_uncompressed_sample(uint64_t ts_ns,
					uint64_t nevts,
					uint64_t num_drop_events,
					draiosproto::metrics* metrics,
					uint32_t sampling_ratio,
					double analyzer_cpu_pct,
					double flush_cpu_pct,
					uint64_t analyzer_flush_duration_ns,
					uint64_t num_suppressed_threads);

	uint64_t get_last_loop_ns() const;

private:
	std::atomic<uint64_t> m_last_loop_ns;

public: // functions from security_result_handler
	void security_mgr_policy_events_ready(uint64_t ts_ns, draiosproto::policy_events *events);

	void security_mgr_throttled_events_ready(uint64_t ts_ns,
						 draiosproto::throttled_policy_events *events,
						 uint32_t total_throttled_count);

	void security_mgr_comp_results_ready(uint64_t ts_ns, const draiosproto::comp_results *results);

public: // functions from audit_tap_handler
	void audit_tap_data_ready(uint64_t ts_ns, const tap::AuditLog *audit_log);

public: // functions from log_report_handler
	void handle_log_report(uint64_t ts_ns,
			       const draiosproto::dirty_shutdown_report& report);
public: // configs
	static type_config<bool> c_print_protobuf;
	static type_config<bool> c_compression_enabled;
	static type_config<bool> c_audit_tap_debug_only;

private:
	protocol_queue& m_queue;
};
