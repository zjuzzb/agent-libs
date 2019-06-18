/**
 * @file
 *
 * Implementation of null_statsd_emitter
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "null_statsd_emitter.h"

namespace libsanalyzer {

void null_statsd_emitter::fetch_metrics(const uint64_t prev_flush_time_ns)
{ }

void null_statsd_emitter::emit(::draiosproto::host* const host,
                               ::draiosproto::statsd_info* const metrics)
{
}

unsigned null_statsd_emitter::emit(const std::string& container_id,
                                   const std::string& container_name,
                                   ::draiosproto::container* const container,
                                   const unsigned limit)
{
	return limit;
}

} // namespace libsanalyzer
