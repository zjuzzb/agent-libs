/**
 * @file
 *
 * Implementation of statsd_emitter
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "statsd_emitter.h"
#include "metric_forwarding_configuration.h"

namespace libsanalyzer {

unsigned statsd_emitter::get_limit(const bool security_enabled)
{
	unsigned limit = metric_forwarding_configuration::c_statsd_max->get();

	if(security_enabled)
	{
		// If security is enabled the increase the limit on the number
		// of statsd metrics by 100. When compliance is enabled, up to
		// 88 new metrics can be emitted when running
		// docker-bench/k8s-bench tasks.
		limit += 100;
	}

	return limit;
}

} // namespace libsanalyzer
