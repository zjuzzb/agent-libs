#pragma once

#include "uncompressed_sample_handler.h"
#include "audit_tap_handler.h"
#include "secure_audit_handler.h"
#include "security_result_handler.h"
#include "log_report_handler.h"
#include "dragent_message_queues.h"

#include "protocol.h"
#include "type_config.h"

/**
 * implementation of various handlers which serialize the input data to the provided
 * protocol queue
 */
class protocol_handler : public uncompressed_sample_handler,
                         public audit_tap_handler,
                         public secure_audit_handler,
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
	std::shared_ptr<serialized_buffer> handle_uncompressed_sample(
	                uint64_t ts_ns,
	                std::shared_ptr<draiosproto::metrics>& metrics,
	                uint32_t flush_interval,
	                std::shared_ptr<protobuf_compressor>& compressor) override;

	uint64_t get_last_loop_ns() const;

private:
	std::atomic<uint64_t> m_last_loop_ns;

public: // functions from security_result_handler
	void security_mgr_policy_events_ready(uint64_t ts_ns, draiosproto::policy_events *events) override;

	void security_mgr_throttled_events_ready(uint64_t ts_ns,
						 draiosproto::throttled_policy_events *events,
	                     uint32_t total_throttled_count) override;

	void security_mgr_comp_results_ready(uint64_t ts_ns, const draiosproto::comp_results *results) override;

public: // functions from audit_tap_handler
	void audit_tap_data_ready(uint64_t ts_ns, const tap::AuditLog *audit_log) override;

public: // functions from audit_tap_handler
	void secure_audit_data_ready(uint64_t ts_ns, const secure::Audit *secure_audit) override;

public: // functions from log_report_handler
	std::shared_ptr<serialized_buffer> handle_log_report(uint64_t ts_ns,
	               const draiosproto::dirty_shutdown_report& report) override;
public: // configs
	static type_config<bool> c_print_protobuf;
	static type_config<bool> c_compression_enabled;
	static type_config<bool> c_audit_tap_debug_only;
	static type_config<bool> c_secure_audit_debug_enabled;

private:
	protocol_queue& m_queue;
};
