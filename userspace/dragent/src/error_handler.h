#pragma once

#include "main.h"
#include "configuration.h"
#include "protocol.h"
#include "log_report_handler.h"

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
	log_reporter(log_report_handler& handler, dragent_configuration*);
	void send_report(uint64_t ts_ns);
private:
	log_report_handler& m_report_handler;
	dragent_configuration* m_configuration;
};
