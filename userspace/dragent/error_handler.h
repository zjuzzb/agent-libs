#pragma once

#include "main.h"
#include "configuration.h"
#include "protocol.h"

class dragent_error_handler : public Poco::ErrorHandler
{
public:
	dragent_error_handler();

	void exception(const Poco::Exception& exc);
	void exception(const std::exception& exc);
	void exception();

	static volatile bool m_exception;
};

class log_reporter
{
public:
	log_reporter(protocol_queue*, dragent_configuration*);
	void send_report(uint64_t ts_ns);
private:
	protocol_queue* m_queue;
	dragent_configuration* m_configuration;
};