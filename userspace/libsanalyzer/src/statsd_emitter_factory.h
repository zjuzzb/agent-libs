/**
 * @file
 *
 * Interface to statsd_emitter_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "metric_limits.h"
#include "statsd_emitter.h"
#include "statsite_proxy.h"

namespace libsanalyzer {

/**
 * Factory for creating concrete statsd_emitter%s.
 */
namespace statsd_emitter_factory {

        /**
         * Create a new concrete statsd_emitter.
         *
         * @param[in] security_enabled Is security enabled?
         * @param[in] source           A reference to a source of statsd metrics
         * @param[in] metric_limit     Configured metric limits (if any).
         *
         * @returns a smart pointer to the newly-created statsd_emitter.
         */
	statsd_emitter::ptr create(bool security_enabled,
	                           const statsd_stats_source::ptr& source,
	                           const metric_limits::sptr_t& metric_limits);

#if defined(SYSDIG_TEST)
	/**
	 * Inject a pre-build statsd_emitter.
	 *
	 * @param[in] emitter The emitter to return on the next call to create()
	 */
	void inject(statsd_emitter::ptr emitter);
#endif

} // namespace statsd_emitter_factory
} // namespace libsanalyzer
