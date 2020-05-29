/**
 * @file
 *
 * Interface to statsite_forwarder.
 *
 * @copyright Copyright (c) 2015-2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <atomic>
#include <memory>
#include <unordered_map>
#include <Poco/ErrorHandler.h>
#include <Poco/Net/SocketReactor.h>

class posix_queue;
class statsd_server;
class statsd_stats_destination;

/**
 * Manages a collection of statsd_server objects, one for each known container.
 * Forwards any messages received by those statsd_servers to the output end
 * of the pipes provided to the constructor.
 */
class statsite_forwarder: public Poco::ErrorHandler
{
public:
	/**
	 * Initializes this statsite_forwarder.
	 *
	 * @param[in] pipes        A pair of FILE* assocaited with some process
	 *                         that will read and process statsd messages
	 *                         that this statsite_forwarder forwards to it.
	 * @param[in] statsd_port  The port on which statsd_servers will listen.
	 */
	statsite_forwarder(const std::pair<FILE*, FILE*>& pipes,
	                   uint16_t statsd_port);
	~statsite_forwarder();


	/**
	 * @see Poco::ErrorHandler
	 */
	virtual void exception(const Poco::Exception& ex) override;

	/**
	 * @see Poco::ErrorHandler
	 */
	virtual void exception(const std::exception& ex) override;

	/**
	 * @see Poco::ErrorHandler
	 */
	virtual void exception() override;

	/**
	 * Starts this statsite_forwarder.  Manages statsd_server%s for all
	 * containers.  Manages the heartbeat with the main agent process.
	 */
	int run();

private:
	class statsd_server_wrapper;

	void terminate(int code, const std::string& reason);

	const std::unique_ptr<statsd_stats_destination> m_proxy;
	const std::unique_ptr<posix_queue> m_inqueue;
	std::unordered_map<std::string, std::unique_ptr<statsd_server_wrapper>> m_servers;
	Poco::Net::SocketReactor m_reactor;
	int m_exitcode;
	const uint16_t m_port;
	std::atomic<bool> m_terminate;
};
