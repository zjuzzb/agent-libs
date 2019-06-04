/**
 * @file
 *
 * Implementation of rest_server.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "rest_server.h"
#include "rest_exception.h"
#include <chrono>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>

#if defined(REST_DEBUG)

#include <sstream>

#define LOG(fmt, ...)                                                          \
	do {                                                                   \
		std::stringstream out;                                         \
		out << std::this_thread::get_id();                             \
		fprintf(stderr,                                                \
		        ("[%9s] %s:%d: " fmt "\n"),                            \
		        out.str().c_str(),                                     \
		        __FUNCTION__,                                          \
		        __LINE__,                                              \
		        ##__VA_ARGS__);                                        \
	} while(false)
#else
#define LOG(fmt, ...)
#endif

namespace librest
{


const uint16_t rest_server::SELECT_EPHEMERAL_PORT = 0;
const std::string rest_server::LOCALHOST = "127.0.0.1";

rest_server::rest_server(const Poco::Net::HTTPRequestHandlerFactory::Ptr factory,
                         const uint16_t port,
                         const std::string& host):
	m_thread(),
	m_mutex(),
	m_running_condition(),
	m_stopping_condition(),
	m_running(false),
	m_handler_factory(factory),
	m_host(host),
	m_port(port)
{ }

rest_server::~rest_server()
{
	stop();
}

void rest_server::start()
{
	std::unique_lock<std::mutex> guard(m_mutex);

	if(m_running)
	{
		return;
	}

	LOG("Starting thread");
	m_thread = std::thread(&rest_server::run, this);
	LOG("Thread started");

	// Wait for the thread to get started before we return
	while(!m_running)
	{
		const uint32_t START_WAIT_MS = 10 * 1000;

		LOG("Waiting for notification that the thread is running");
		const std::cv_status status = m_running_condition.wait_for(
				guard,
				std::chrono::milliseconds(START_WAIT_MS));

		if(status == std::cv_status::timeout)
		{
			throw rest_exception("Timeout waiting for server "
					     "thread to start");
		}

		LOG("Notification received, thread is running...");
	}
	LOG("Returning...");
}

void rest_server::stop()
{
	{
		std::unique_lock<std::mutex> guard(m_mutex);

		if(!m_running)
		{
			return;
		}

		LOG("Notifying thread to terminate...");
		m_running = false;
		m_stopping_condition.notify_one();
	}

	// Need to drop the lock to let run wake up and terminate
	LOG("Joining...");
	m_thread.join();
}

bool rest_server::is_running() const
{
	std::unique_lock<std::mutex> guard(m_mutex);

	return m_running;
}

uint16_t rest_server::get_port() const
{
	std::unique_lock<std::mutex> guard(m_mutex);

	if(m_server.get() != nullptr)
	{
		return m_server->port();
	}

	return m_port;
}

const std::string& rest_server::get_host() const
{
	// m_host is const, no lock is needed
	return m_host;
}

void rest_server::run()
{
	std::unique_lock<std::mutex> guard(m_mutex);

	auto parms = new Poco::Net::HTTPServerParams();

	parms->setKeepAlive(false);

	m_server = std::unique_ptr<Poco::Net::HTTPServer>(
			new Poco::Net::HTTPServer(
				m_handler_factory,
				Poco::Net::ServerSocket(Poco::UInt16(m_port)),
				parms));

	m_server->start();
	m_running = true;

	// Unblock start()
	m_running_condition.notify_one();

	// Wait for someone to call stop()
	while(m_running)
	{
		LOG("Waiting to be asked to stop");
		m_stopping_condition.wait(guard);
		LOG("Asked to stop");
	}

	LOG("Telling server to stop");
	m_server->stop();
	m_server.reset();

	LOG("run() returning");
}

} // end namespace librest
