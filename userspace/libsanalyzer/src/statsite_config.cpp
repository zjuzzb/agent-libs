/**
 * @file
 *
 * Implementation of namespace statsite_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "common.pb.h"
#include "statsite_config.h"
#include "type_config.h"

#include <fstream>
#include <set>
#include <string>
#include <unordered_map>

namespace libsanalyzer
{
const uint16_t statsite_config::DEFAULT_STATSD_PORT = 8125;
const std::string statsite_config::DEFAULT_IP_ADDRESS = "127.0.0.1";
const bool statsite_config::DEFAULT_USE_HOST_STATSD = false;
const uint16_t statsite_config::DEFAULT_FLUSH_INTERVAL = 1;

}  // namespace libsanalyzer

namespace
{
type_config<bool> c_use_host_statsd(
    libsanalyzer::statsite_config::DEFAULT_USE_HOST_STATSD,
    "If true, the Agent will not listen for statsd messages on the host's TCP/UDP ports",
    "statsd",
    "use_host_statsd");

/**
 * Post-init callback for the UDP and TCP port configurations.  If the Agent
 * is configured to allow for the host to run a statsd server, then the port
 * values should be 0.
 */
void set_port_to_zero_if_using_host_statsd(type_config<uint16_t>& config)
{
	if (c_use_host_statsd.get_value())
	{
		config.set(0);
	}
}

type_config<uint16_t>::ptr c_udp_port =
    type_config_builder<uint16_t>(libsanalyzer::statsite_config::DEFAULT_STATSD_PORT,
                                  "The UDP port on which to listen for statsd messages",
                                  "statsd",
                                  "udp_port")
        .post_init(set_port_to_zero_if_using_host_statsd)
        .build();

type_config<uint16_t>::ptr c_tcp_port =
    type_config_builder<uint16_t>(libsanalyzer::statsite_config::DEFAULT_STATSD_PORT,
                                  "The TCP port on which to listen for "
                                  "statsd messages",
                                  "statsd",
                                  "tcp_port")
        .post_init(set_port_to_zero_if_using_host_statsd)
        .build();

type_config<std::string> c_ip_address(
    libsanalyzer::statsite_config::DEFAULT_IP_ADDRESS,
    "The IP address to which statsite will bind when listening for "
    "incoming network messages",
    "statsd",
    "ip_address");

type_config<uint16_t> c_flush_interval(
    libsanalyzer::statsite_config::DEFAULT_FLUSH_INTERVAL,
    "How frequently, in seconds, statsite should flush metrics to the Agent",
    "statsd",
    "flush_interval");

}  // end namespace

namespace libsanalyzer
{
statsite_config* statsite_config::c_statsite_config = new statsite_config();

statsite_config::statsite_config()
    : feature_base(STATSD, &draiosproto::feature_status::set_statsd_enabled, {})
{
}

statsite_config& statsite_config::instance()
{
	return *c_statsite_config;
}

uint16_t statsite_config::get_flush_interval()
{
	return c_flush_interval.get_value();
}

uint16_t statsite_config::get_tcp_port()
{
	return c_tcp_port->get_value();
}

uint16_t statsite_config::get_udp_port()
{
	return c_udp_port->get_value();
}

std::string statsite_config::get_ip_address()
{
	return c_ip_address.get_value();
}

bool statsite_config::use_host_statsd()
{
	return c_use_host_statsd.get_value();
}

void statsite_config::write_statsite_configuration(std::ostream& ini,
                                                   const std::string& loglevel,
                                                   const std::set<double>& percentiles)
{
	if (!get_enabled())
	{
		return;
	}

	// Convert our log level to a statsite log level
	// Our levels:
	//     trace, debug, info, notice, warning, error, critical, fatal
	// statsite levels:
	//     DEBUG, INFO, WARN, ERROR, CRITICAL
	const std::unordered_map<std::string, std::string> conversion_map{
	    {"trace", "DEBUG"},
	    {"debug", "DEBUG"},
	    {"info", "INFO"},
	    {"notice", "WARN"},
	    {"warning", "WARN"},
	    {"error", "ERROR"},
	    {"critical", "CRITICAL"},
	    {"fatal", "CRITICAL"},
	};

	const std::string statsite_loglevel = (conversion_map.find(loglevel) != conversion_map.end())
	                                          ? conversion_map.at(loglevel)
	                                          : "INFO";
	const int parse_stdin = 1;

	// clang-format off
	ini << "#"                                                 << std::endl;
	ini << "# WARNING: File generated automatically, do not edit. ";
	ini << "Please use \"dragent.yaml\" instead"               << std::endl;
	ini << "#"                                                 << std::endl;
	ini << "[statsite]"                                        << std::endl;
	ini << "bind_address = "   << c_ip_address.get_value()     << std::endl;
	ini << "port = "           << c_tcp_port->get_value()      << std::endl;
	ini << "udp_port = "       << c_udp_port->get_value()      << std::endl;
	ini << "log_level = "      << statsite_loglevel            << std::endl;
	ini << "flush_interval = " << c_flush_interval.get_value() << std::endl;
	ini << "parse_stdin = "    << parse_stdin                  << std::endl;
	// clang-format on

	auto i = percentiles.begin();
	if (i != percentiles.end())
	{
		ini << "quantiles = " << (*i / 100.0);

		for (++i; i != percentiles.end(); ++i)
		{
			ini << "," << (*i / 100.0);
		}

		ini << std::endl;
	}
}

void statsite_config::write_statsite_configuration(const std::string& filename,
                                                   const std::string& loglevel,
                                                   const std::set<double>& percentiles)
{
	if (!get_enabled())
	{
		return;
	}

	std::ofstream out(filename.c_str());

	if (out)
	{
		write_statsite_configuration(out, loglevel, percentiles);
	}
}

}  // namespace libsanalyzer
