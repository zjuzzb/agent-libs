#pragma once

#include "main.h"

class dragent_error_handler : public Poco::ErrorHandler
{
public:
	dragent_error_handler()
	{
	}

	void exception(const Poco::Exception& exc)
	{
		g_log->error(exc.displayText());
		m_exception = true;
	}
		
	void exception(const std::exception& exc)
	{
		g_log->error(exc.what());
		m_exception = true;
	}

	void exception()
	{
		g_log->error("Unknown exception");
		m_exception = true;
	}

	static volatile bool m_exception;
};
