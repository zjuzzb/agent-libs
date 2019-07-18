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
#include "statsite_proxy.h"
#include "statsd_server.h"
#include "subprocess.h"
#include <json/json.h>
#include <unordered_set>
#include <Poco/Thread.h>

namespace
{

COMMON_LOGGER();

} // end namespace

statsite_forwarder::statsite_forwarder(const std::pair<FILE*, FILE*>& pipes,
				       const uint16_t port,
				       const bool check_format):
	m_proxy(make_unique<statsite_proxy>(pipes, check_format)),
	m_inqueue(make_unique<posix_queue>("/sdc_statsite_forwarder_in",
	                                   posix_queue::RECEIVE,
	                                   1)),
	m_exitcode(0),
	m_port(port),
	m_terminate(false)
{
	g_logger.add_stderr_log();
}

int statsite_forwarder::run()
{
#ifndef CYGWING_AGENT
	ErrorHandler::set(this);

	LOG_INFO("Info Starting with pid=%d\n", getpid());

	Poco::Thread reactor_thread;
	reactor_thread.start(m_reactor);

	while(!m_terminate)
	{
		if(!reactor_thread.isRunning())
		{
			terminate(1, "unexpected reactor shutdown");
		}
		send_subprocess_heartbeat();
		auto msg = m_inqueue->receive(1);

		if(msg.empty())
		{
			continue;
		}

		LOG_DEBUG("Received msg=%s", msg.c_str());

		Json::Reader json_reader;
		Json::Value root;
		if(!json_reader.parse(msg, root))
		{
			LOG_ERROR("Error parsing msg=%s", msg.c_str());
			continue;
		}

		std::unordered_set<std::string> containerids;
		for(const auto& container : root["containers"])
		{
			auto containerid = container["id"].asString();
			auto container_pid = container["pid"].asInt64();

			containerids.emplace(containerid);

			if(m_sockets.find(containerid) == m_sockets.end())
			{
				try
				{
					nsenter enter(container_pid, "net");

					LOG_DEBUG("Starting statsd server on container=%s pid=%lld",
					          containerid.c_str(),
					          container_pid);
					m_sockets[containerid] =
						make_unique<statsd_server>(containerid,
						                           *m_proxy,
						                           m_reactor,
						                           m_port);
				}
				catch(const sinsp_exception& ex)
				{
					LOG_WARNING("Cannot init statsd server on container=%s pid=%lld",
					            containerid.c_str(),
					            container_pid);
				}
			}
		}

		auto it = m_sockets.begin();
		while(it != m_sockets.end())
		{
			if(containerids.find(it->first) == containerids.end())
			{
				// This container does not exists anymore,
				// turning off statsd server so we can release
				// resources
				LOG_DEBUG("Stopping statsd server on container=%s",
				          it->first.c_str());
				it = m_sockets.erase(it);
			}
			else
			{
				// container still exists, keep iterating
				++it;
			}
		}
	}
	reactor_thread.join();
	return m_exitcode;
#else // CYGWING_AGENT
	ASSERT(false);
	throw sinsp_exception("statsite_forwarder::run not implemented on Windows");
#endif // CYGWING_AGENT
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
	LOG_ERROR("Fatal error occurred: %s, terminating", reason.c_str());
	m_reactor.stop();
	m_terminate = true;
	m_exitcode = code;
}
