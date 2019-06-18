/**
 * @file
 *
 * Interface to null_statsd_emitter
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "statsd_emitter.h"

namespace libsanalyzer {

/**
 * A realization of the statsd_emitter that does nothing.  This is useful
 * in scenarios where statsd is disabled.
 */
class null_statsd_emitter : public statsd_emitter
{
public:
	/** Does nothing. */
	void fetch_metrics(uint64_t prev_flush_time_ns) override;

	/** Does nothing. Does not modify parameters. */
	void emit(::draiosproto::host* host,
	          ::draiosproto::statsd_info* metrics) override;

	/** Does nothing. Does not modify parameters.  Returns limit. */
	unsigned emit(const std::string& container_id,
	              const std::string& container_name,
	              ::draiosproto::container* container,
	              unsigned limit) override;
};

} // namespace libsanalyzer
