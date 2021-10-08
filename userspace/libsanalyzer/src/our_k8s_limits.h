#ifndef CYGWING_AGENT
#ifndef OUR_K8S_LIMITS_H
#define OUR_K8S_LIMITS_H

#include "sinsp.h"
#include "analyzer_utils.h"
#include "sdc_internal.pb.h"

class our_k8s_limits {
private:
	// (for now) hardcoded interval/thresholds
	static const uint64_t INFO_INTERVAL = 10 * 60; // log info every 10 minutes
	static const uint64_t WARNING_INTERVAL = 2 * 60; // log warning every 2 minutes
	static const uint32_t REQUESTS_THRESHOLD = 5; // 5% threshold for requests
	static const uint32_t LIMITS_THRESHOLD = 10;  // 10% threshold for limits

public:
	our_k8s_limits(uint64_t info_interval = INFO_INTERVAL,
                   uint64_t warning_interval = WARNING_INTERVAL,
                   uint32_t requests_threshold_pct = REQUESTS_THRESHOLD,
                   uint32_t limits_threshold_pct = LIMITS_THRESHOLD);
	void import_k8s_limits(const draiosproto::k8s_container_status_details &our_container);
	// Periodically log our requests/limits
	void periodically_log_our_k8s_limits(uint64_t ts);

	bool log_warnings() const;
	void log_info() const;
	bool imported() const { return m_imported; }

private:
	//
	// Periodic logging of our requests/limits
	//
	run_on_interval m_k8s_limits_logging_info_interval;
	run_on_interval m_k8s_limits_logging_warning_interval;

	uint32_t m_requests_threshold_pct;
	uint32_t m_limits_threshold_pct;

	double m_requests_cpu_cores;
	double m_limits_cpu_cores;
	double m_total_cpu_cores;

	uint64_t m_requests_mem_bytes;
	uint64_t m_limits_mem_bytes;
	uint64_t m_total_mem_bytes;

	bool m_imported;

};

#endif // OUR_K8S_LIMITS_H
#endif // CYGWING_AGENT
