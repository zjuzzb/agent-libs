/**
 * @file
 *
 * Interface to statsd_stats_destination.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <memory>
#include <string>

/**
 * Interface to an object to which clients can send statsd messages.
 */
class statsd_stats_destination
{
public:
	using ptr = std::shared_ptr<statsd_stats_destination>;

	virtual ~statsd_stats_destination() = default;

	/**
	 * Send statsd message(s) associated with the host.
	 *
	 * @param[in] buf A c-string with the statsd messages.  If there's
	 *                more than one message, then the messages are separated
	 *                by newline characters.
	 * @param[in] len The length of buf.
	 */
	virtual void send_metric(const char* buf, uint64_t len) = 0;

	/**
	 * Send statsd message(s) associated with the container with the given
	 * container_id.
	 *
	 * @param[in] container-id The ID of the container that is sending
	 *                         statsd message(s).
	 * @param[in] buf          A c-string with the statsd messages.  If
	 *                         there's more than one message, then the
	 *                         messages are separated by newline characters.
	 * @param[in] len          The length of buf.
	 */
	virtual void send_container_metric(const std::string& container_id,
	                                   const char* data,
	                                   uint64_t len) = 0;
};
