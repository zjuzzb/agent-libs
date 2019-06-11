/**
 * @file
 *
 * Interface to namespace statsite_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <cstdint>
#include <ostream>
#include <set>
#include <string>

namespace libsanalyzer {

/**
 * APIs for accessing and managing the statsite statsd configuration.
 */
namespace statsite_config {

/** Is statsite enabled by default? Linux? true.  Windows? false. */
extern const bool DEFAULT_ENABLED;

/** The default statsd port: 8125 */
extern const uint16_t DEFAULT_STATSD_PORT;

/** Expect a statsd server on the host? false. */
extern const bool DEFAULT_USE_HOST_STATSD;

/** Sitesite flush interval in seconds: 1 */
extern const uint16_t DEFAULT_FLUSH_INTERVAL;

/**
 * Enable or disable statsd processing.  This should be called only in
 * special test scenarios.
 *
 * @param[in] enabled If true, statsd processing will be enabled, otherwise
 *                    statsd process will be disabled.
 */
void set_enabled(bool enabled);

/**
 * Returns true if statsd processing is enabled, false otherwise.
 */
bool is_enabled();

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

} // namespace statsite_config
} // namespace libsanalyzer
