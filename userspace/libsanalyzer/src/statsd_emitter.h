/**
 * @file
 *
 * Interface to statsd_emitter.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "noncopyable.h"
#include <memory>
#include <string>

namespace draiosproto {
class container;
class host;
class statsd_info;
} // namespace draiosproto

namespace libsanalyzer {

/**
 * Interface to a statsd emitter.
 */
class statsd_emitter : public noncopyable
{
public:
	using ptr = std::shared_ptr<statsd_emitter>;

	virtual ~statsd_emitter() = default;

	/**
	 * Fetch the metrics from the entity that is collating them
	 * (e.g., from statsite).  Keep only the relevant ones based on
	 * the given prev_flush_time_ns timestamp.
	 */
	virtual void fetch_metrics(uint64_t prev_flush_time_ns) = 0;

	/**
	 * Emit host-related statsd metrics.
	 */
	virtual void emit(::draiosproto::host* host,
	                  ::draiosproto::statsd_info* metrics) = 0;

	/**
	 * Emit container-related statsd metrics.
	 *
	 * @return the given limit minus the number of metrics emitted by this
	 *         method.  For example, if the limit is 5, and this method
	 *         emitted 2 metrics, the new limit (returned by this method)
	 *         is 3.
	 */
	virtual unsigned emit(const std::string& container_id,
	                      const std::string& container_name,
	                      ::draiosproto::container* container,
	                      unsigned limit) = 0;

	/**
	 * Get the configured limit for statsd messages.
	 */
	static unsigned get_limit(bool security_enabled);
};

} // namespace libsanalyzer
