/**
 * @file
 *
 * Interface to analyzer_callback_interface
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <cstdint>

namespace draiosproto
{
class metrics;
}

namespace tap
{
class AuditLog;
}

/**
 * Prototype of the callback invoked by the analyzer when a sample is ready
 */
class analyzer_callback_interface
{
public:
	virtual ~analyzer_callback_interface() = default;

	virtual void sinsp_analyzer_data_ready(uint64_t ts_ns,
	                                       uint64_t nevts,
	                                       uint64_t num_drop_events,
	                                       draiosproto::metrics* metrics,
	                                       uint32_t sampling_ratio,
	                                       double analyzer_cpu_pct,
	                                       double flush_cpu_cpt,
	                                       uint64_t analyzer_flush_duration_ns,
	                                       uint64_t num_suppressed_threads) = 0;

	virtual void audit_tap_data_ready(uint64_t ts_ns, const tap::AuditLog *audit_log) = 0;

};
