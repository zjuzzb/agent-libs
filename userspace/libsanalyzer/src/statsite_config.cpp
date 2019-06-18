/**
 * @file
 *
 * Implementation of namespace statsite_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "statsite_config.h"
#include "type_config.h"
#include <fstream>
#include <set>
#include <string>
#include <unordered_map>

namespace libsanalyzer {
namespace statsite_config {

#if defined(CYGWING_AGENT)
const bool        DEFAULT_ENABLED         = false;
#else
const bool        DEFAULT_ENABLED         = true;
#endif

const uint16_t    DEFAULT_STATSD_PORT     = 8125;
const std::string DEFAULT_IP_ADDRESS      = "127.0.0.1";
const bool        DEFAULT_USE_HOST_STATSD = false;
const uint16_t    DEFAULT_FLUSH_INTERVAL  = 1;

} // namespace statsite_config
} // namespace libsanalyzer

namespace
{

type_config<bool> c_enabled(
		libsanalyzer::statsite_config::DEFAULT_ENABLED,
		"If true, statsd metric processing is enabled",
		"statsd",
		"enabled");

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
	if(c_use_host_statsd.get())
	{
		config.set(0);
	}
}

type_config<uint16_t>::ptr c_udp_port = type_config_builder<uint16_t>(
		libsanalyzer::statsite_config::DEFAULT_STATSD_PORT,
		"The TCP port on which to listen for "
		"statsd messages",
		"statsd",
		"udp_port")
	.post_init(set_port_to_zero_if_using_host_statsd)
        .get();

type_config<uint16_t>::ptr c_tcp_port = type_config_builder<uint16_t>(
		libsanalyzer::statsite_config::DEFAULT_STATSD_PORT,
		"The UDP port on which to listen for statsd messages",
		"statsd",
		"tcp_port")
	.post_init(set_port_to_zero_if_using_host_statsd)
        .get();

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

} // end namespace

namespace libsanalyzer
{

void statsite_config::set_enabled(const bool enabled)
{
	c_enabled.set(enabled);
}

bool statsite_config::is_enabled()
{
	return c_enabled.get();
}

uint16_t statsite_config::get_flush_interval()
{
	return c_flush_interval.get();
}

uint16_t statsite_config::get_tcp_port()
{
	return c_tcp_port->get();
}

uint16_t statsite_config::get_udp_port()
{
	return c_udp_port->get();
}

std::string statsite_config::get_ip_address()
{
	return c_ip_address.get();
}

bool statsite_config::use_host_statsd()
{
	return c_use_host_statsd.get();
}

void statsite_config::write_statsite_configuration(std::ostream& ini,
                                                   const std::string& loglevel,
                                                   const std::set<double>& percentiles)
{
	if(!c_enabled.get())
	{
		return;
	}

	// Convert our log level to a statsite log level
	// Our levels:
	//     trace, debug, info, notice, warning, error, critical, fatal
	// statsite levels:
	//     DEBUG, INFO, WARN, ERROR, CRITICAL
	const std::unordered_map<std::string, std::string> conversion_map{
		{ "trace",    "DEBUG"    },
		{ "debug",    "DEBUG"    },
		{ "info",     "INFO"     },
		{ "notice",   "WARN"     },
		{ "warning",  "WARN"     },
		{ "error",    "ERROR"    },
		{ "critical", "CRITICAL" },
		{ "fatal",    "CRITICAL" },
	};

	const std::string statsite_loglevel =
		(conversion_map.find(loglevel) != conversion_map.end())
		? conversion_map.at(loglevel)
		: "INFO";
	const int parse_stdin = 1;

	ini << "#"                                           << std::endl;
	ini << "# WARNING: File generated automatically, do not edit. ";
	ini << "Please use \"dragent.yaml\" instead"         << std::endl;
	ini << "#"                                           << std::endl;
	ini << "[statsite]"                                  << std::endl;
	ini << "bind_address = "   << c_ip_address.get()     << std::endl;
	ini << "port = "           << c_tcp_port->get()      << std::endl;
	ini << "udp_port = "       << c_udp_port->get()      << std::endl;
	ini << "log_level = "      << statsite_loglevel      << std::endl;
	ini << "flush_interval = " << c_flush_interval.get() << std::endl;
	ini << "parse_stdin = "    << parse_stdin            << std::endl;

	auto i = percentiles.begin();
	if(i != percentiles.end())
	{
		ini << "quantiles = " << (*i / 100.0);

		for(++i; i != percentiles.end(); ++i)
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
	if(!c_enabled.get())
	{
		return;
	}

	std::ofstream out(filename.c_str());

	if(out)
	{
		write_statsite_configuration(out, loglevel, percentiles);
	}
}

} // namespace libsanalyzer
