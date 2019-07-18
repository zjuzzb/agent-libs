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
class statsite_proxy;

class statsite_forwarder: public Poco::ErrorHandler
{
public:
	statsite_forwarder(const std::pair<FILE*, FILE*>& pipes,
			   uint16_t statsd_port,
			   bool check_format);

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
	void terminate(int code, const std::string& reason);

	std::unique_ptr<statsite_proxy> m_proxy;
	std::unique_ptr<posix_queue> m_inqueue;

	std::unordered_map<std::string, std::unique_ptr<statsd_server>> m_sockets;
	Poco::Net::SocketReactor m_reactor;
	int m_exitcode;
	uint16_t m_port;
	std::atomic<bool> m_terminate;
};
