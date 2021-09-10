/**
 * @file
 *
 * Implementation of statsd_emitter
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "statsd_emitter.h"
#include "logger.h"
#include "limits/metric_forwarding_configuration.h"
#include "security_config.h"

namespace libsanalyzer {

const unsigned statsd_emitter::MAX_SECURITY_METRICS = 250;

unsigned statsd_emitter::get_limit()
{
	unsigned limit = metric_forwarding_configuration::instance().statsd_limit();

	if(security_config::instance().get_enabled())
	{
		// If security is enabled the increase the limit on the number
		// of statsd metrics by 100. When compliance is enabled, up to
		// 88 new metrics can be emitted when running
		// docker-bench/k8s-bench tasks.
		limit += MAX_SECURITY_METRICS;
	}

	return limit;
}

} // namespace libsanalyzer
