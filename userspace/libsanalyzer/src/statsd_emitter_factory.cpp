/**
 * @file
 *
 * Implementation of statsd_emitter_factory.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "statsd_emitter_factory.h"
#include "statsd_emitter.h"
#include "statsite_proxy.h"

#if defined(_WIN32)
#    include "null_statsd_emitter.h"
#else
#    include "statsite_statsd_emitter.h"
#endif

namespace
{

libsanalyzer::statsd_emitter::ptr s_emitter;

} // namespace

namespace libsanalyzer
{

statsd_emitter::ptr statsd_emitter_factory::create(
	        const statsd_stats_source::ptr& source,
		const metric_limits::sptr_t& metric_limits)
{
	statsd_emitter::ptr emitter;

	if(s_emitter)
	{
		statsd_emitter::ptr temp = s_emitter;
		s_emitter.reset();
		return temp;
	}

#if defined(_WIN32) || defined(CYGWING_AGENT)
	emitter.reset(new null_statsd_emitter());
#else
	emitter.reset(new statsite_statsd_emitter(source,
	                                          metric_limits));
#endif

	return emitter;
}

#if defined(SYSDIG_TEST)
void statsd_emitter_factory::inject(statsd_emitter::ptr emitter)
{
	s_emitter = emitter;
}
#endif

} // namespace libsanalyzer
