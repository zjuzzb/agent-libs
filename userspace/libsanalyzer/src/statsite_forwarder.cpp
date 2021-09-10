/**
 * @file
 *
 * Implementation of statsite_forwarder.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#include "statsite_forwarder.h"

#include "analyzer_utils.h"
#include "common_logger.h"
#include "posix_queue.h"
#include "statsd_server.h"
#include "statsd_stats_destination.h"
#include "statsite_proxy.h"
#include "subprocess.h"
#include "type_config.h"
#include "sinsp_exception.h"

#include <Poco/Thread.h>

#include <json/json.h>
#include <unordered_set>

namespace
{
COMMON_LOGGER();

type_config<uint32_t> c_statsd_start_delay_sec(
    10,
    "The number of seconds the agent will wait between identifying"
    " a new container and creating a statsd server within the"
    " context of that container.  This applies only when the"
    " use_forward option is true",
    "statsd",
    "container_server_creation_delay_s");

/**
 * Returns the current time, in seconds, from a monotonic clock (i.e.,
 * a clock that will never run "backwards" because of a host time change).
 */
uint64_t get_monotonic_time_seconds()
{
	using namespace std::chrono;

	return duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
}

}  // end namespace

/**
 * Wrapper over a statsd_server.  Instances of statsd_server_wrapper record
 * the time at which they are created.  Their needs_starting() method will
 * return true only after c_statsd_start_delay_sec seconds have passed since
 * the object was created.
 */
class statsite_forwarder::statsd_server_wrapper
{
public:
	statsd_server_wrapper() : m_creation_time_sec(get_monotonic_time_seconds()), m_server() {}

	/**
	 * Returns true if (1) this statsd_server_wrapper has no server and
	 * (2) if at least c_statsd_start_delay_sec seconds has passed since
	 * this statsd_server_wrapper was created.
	 */
	bool needs_starting() const
	{
		const uint64_t time_since_creation = get_monotonic_time_seconds() - m_creation_time_sec;
		return (m_server == nullptr) &&
		       (time_since_creation >= c_statsd_start_delay_sec.get_value());
	}

	/**
	 * Starts the underlying statsd_server for the given container.
	 *
	 * @param[in] containerid   The ID of the container
	 * @param[in] container_pid The process ID of some process in the
	 *                          network namespace of the given container.
	 * @param[in] proxy         The object to which received statsd messages
	 *                          will be forwarded (e.g., statsite_proxy).
	 * @param[in] reactor       The Poco Reactor with which the newly
	 *                          created statsd_server will register for
	 *                          socket events.
	 * @param[in] port          The UDP port on which the statsd_server
	 *                          will listen.
	 */
	void start(const std::string& containerid,
	           const uint64_t container_pid,
	           statsd_stats_destination& proxy,
	           Poco::Net::SocketReactor& reactor,
	           const uint16_t port)
	{
		try
		{
			// We enter the network namespace of the container so
			// that we start the statsd_server in that network
			// namespace.  Once the socket is bound to the port,
			// we can switch back to the previous network namespace.
			nsenter enter(container_pid, "net");

			g_logger.log("Starting statsd server on container=" + containerid +
			             " pid=" + std::to_string(container_pid));

			m_server = make_unique<statsd_server>(containerid, proxy, reactor, port);
		}
		catch (const sinsp_exception& ex)
		{
			m_server.reset();
			g_logger.log("Warning Cannot init statsd server on container=" + containerid +
			             " pid=" + std::to_string(container_pid) + ": " + ex.what());
		}
	}

private:
	const uint64_t m_creation_time_sec;
	std::unique_ptr<statsd_server> m_server;
};

statsite_forwarder::statsite_forwarder(const std::pair<FILE*, FILE*>& pipes, const uint16_t port)
    : m_proxy(make_unique<statsite_proxy>(pipes)),
      m_inqueue(make_unique<posix_queue>("/sdc_statsite_forwarder_in", posix_queue::RECEIVE, 1)),
      m_servers(),
      m_reactor(),
      m_exitcode(0),
      m_port(port),
      m_terminate(false)
{
}

statsite_forwarder::~statsite_forwarder()
{
	// This doesn't do anything explicitly, so it might appear as though
	// it's not needed, but it is.  Without this, the  compiler will try to
	// automatically generate an inline destructor wherever
	// statsite_forwarder is destroyed.  With that, it needs the
	// complete definition of statsd_server_wrapper, which isn't available
	// at that point.
	//
	// Putting this here will cause the compiler to generate the automatic
	// stuff here --- where it knows the full type of the wrapper --- and
	// this will get called when statsite_forwarder is destroyed.
}

int statsite_forwarder::run()
{
#ifndef CYGWING_AGENT
	ErrorHandler::set(this);

	g_logger.log("Info Starting with pid=" + std::to_string(getpid()));

	Poco::Thread reactor_thread;
	reactor_thread.start(m_reactor);

	while (!m_terminate)
	{
		if (!reactor_thread.isRunning())
		{
			terminate(1, "unexpected reactor shutdown");
		}
		send_subprocess_heartbeat();
		auto msg = m_inqueue->receive(1);
		std::string msg_str(msg.begin(), msg.end());

		if (msg.empty())
		{
			continue;
		}

		g_logger.log("Received msg=" + msg_str);

		Json::Reader json_reader;
		Json::Value root;
		if (!json_reader.parse(&msg[0], &msg[msg.size()], root))
		{
			g_logger.log("Error parsing msg=" + msg_str);
			continue;
		}

		std::unordered_set<std::string> containers_in_msg;

		// Add any new containers and start any servers that need to
		// be started
		for (const auto& container : root["containers"])
		{
			const std::string containerid = container["id"].asString();

			containers_in_msg.emplace(containerid);

			auto server_itr = m_servers.find(containerid);
			if (server_itr == m_servers.end())
			{
				// This is the first time we've seen this
				// container, create the wrapper
				m_servers[containerid] = make_unique<statsd_server_wrapper>();
				server_itr = m_servers.find(containerid);
			}

			if (server_itr->second->needs_starting())
			{
				// The wrapper was created more than
				// c_statsd_start_delay_sec ago, and still has
				// no statsd_server, so create one now.
				server_itr->second->start(containerid,
				                          container["pid"].asUInt64(),
				                          *m_proxy,
				                          m_reactor,
				                          m_port);
			}
		}

		// Remove servers for any containers that no longer exist
		// in the container list provided by the agent
		for (auto it = m_servers.begin(); it != m_servers.end();)
		{
			if (containers_in_msg.find(it->first) == containers_in_msg.end())
			{
				// This container does not exists anymore,
				// turning off statsd server so we can release
				// resources
				LOG_DEBUG("Stopping statsd server on container=%s", it->first.c_str());
				it = m_servers.erase(it);
			}
			else
			{
				++it;
			}
		}
	}

	reactor_thread.join();

	return m_exitcode;

#else   // CYGWING_AGENT
	ASSERT(false);

	throw sinsp_exception("statsite_forwarder::run not implemented on Windows");
#endif  // CYGWING_AGENT
}

void statsite_forwarder::exception(const Poco::Exception& ex)
{
	terminate(1, ex.displayText());
}

void statsite_forwarder::exception(const std::exception& ex)
{
	terminate(1, ex.what());
}

void statsite_forwarder::exception()
{
	terminate(1, "Unknown exception");
}

void statsite_forwarder::terminate(const int code, const std::string& reason)
{
	g_logger.log("Error: " + reason + " Fatal, terminating");
	m_reactor.stop();
	m_terminate = true;
	m_exitcode = code;
}
