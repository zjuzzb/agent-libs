/**
 * @file
 *
 * Interface to namespace statsite_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "feature_manager.h"

#include <cstdint>
#include <ostream>
#include <set>
#include <string>

namespace libsanalyzer
{
/**
 * APIs for accessing and managing the statsite statsd configuration.
 */
class statsite_config : public feature_base
{
private:
	static statsite_config* c_statsite_config;

public:
	static statsite_config& instance();

	statsite_config();

	/** The default statsd port: 8125 */
	static const uint16_t DEFAULT_STATSD_PORT;

	/** The default address to which statsite will bind. */
	static const std::string DEFAULT_IP_ADDRESS;

	/** Expect a statsd server on the host? false. */
	static const bool DEFAULT_USE_HOST_STATSD;

	/** Sitesite flush interval in seconds: 1 */
	static const uint16_t DEFAULT_FLUSH_INTERVAL;

	/**
	 * Returns the statsite flush interval, in seconds.
	 */
	uint16_t get_flush_interval();

	/**
	 * Returns the TCP port on which statsite will listen for statsd messages.
	 */
	uint16_t get_tcp_port();

	/**
	 * Returns the UDP port on which statsite will listen for statsd messages.
	 */
	uint16_t get_udp_port();

	/**
	 * Returns the IP address to which statsite will bind to receive incoming
	 * TCP/UDP messages.
	 */
	std::string get_ip_address();

	/**
	 * Returns true if we expect that the host is running its own statsd server,
	 * false otherwise.  If we expect that the host is running its on statsd
	 * server, then statsite will not attempt to bind to any network ports.
	 */
	bool use_host_statsd();

	/**
	 * Write the statsite.ini configuration to the given output stream,
	 * with the given loglevel and percentiles.  When is_enabled() returns false,
	 * this method does nothing.
	 *
	 * @param[out] ini         The output stream to which to write the statsite.ini
	 *                         content
	 * @param[in]  loglevel    The current configured agent log level.
	 * @param[in]  percentiles The set of quantiles to write to the config.  If
	 *                         this set is empty, then this method writes no
	 *                         quantiles.
	 */
	void write_statsite_configuration(std::ostream& ini,
	                                  const std::string& loglevel,
	                                  const std::set<double>& percentiles);

	/**
	 * Write the statsite.ini configuration to the given filename with the given
	 * loglevel and percentiles.  When is_enabled() returns false, this method
	 * does nothing.
	 *
	 * @param[out] filename    The filename to which to write the statsite.ini
	 *                         content
	 * @param[in]  loglevel    The current configured agent log level.
	 * @param[in]  percentiles The set of quantiles to write to the config.  If
	 *                         this set is empty, then this method writes no
	 *                         quantiles.
	 */
	void write_statsite_configuration(const std::string& filename,
	                                  const std::string& loglevel,
	                                  const std::set<double>& percentiles);
};

}  // namespace libsanalyzer
