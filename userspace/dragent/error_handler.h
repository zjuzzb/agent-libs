#pragma once

#include "main.h"
#include "configuration.h"

class dragent_error_handler : public Poco::ErrorHandler
{
public:
	dragent_error_handler();

	void exception(const Poco::Exception& exc);
	void exception(const std::exception& exc);
	void exception();

	static volatile bool m_exception;
};
