#pragma once

#include "main.h"
#include "configuration.h"
#include "protocol.h"
#include "log_report_handler.h"
#include "dragent_message_queues.h"

class dragent_error_handler : public Poco::ErrorHandler
{
public:
	dragent_error_handler();

	void exception(const Poco::Exception& exc);
	void exception(const std::exception& exc);
	void exception();

	static volatile bool m_exception;
protected:
    void handle_std_exception(const std::exception& exc);
};

/**
 * A basic derivation of dragent_error_handler to be
 * used by the watchdog_runnable - basically to avoid 
 * restarting the agent within this error handler. 
 */
class watchdog_error_handler : public dragent_error_handler
{
public:
	watchdog_error_handler();

	void exception(const Poco::Exception& exc);
	void exception(const std::exception& exc);
	void exception();
};


class log_reporter
{
public:
	log_reporter(log_report_handler& handler, dragent_configuration*);
	void send_report(protocol_queue& transmit_queue, uint64_t ts_ns);
private:
	log_report_handler& m_report_handler;
	dragent_configuration* m_configuration;
};
