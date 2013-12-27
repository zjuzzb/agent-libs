#include "error_handler.h"

volatile bool dragent_error_handler::m_exception = false;

dragent_error_handler::dragent_error_handler()
{
}

void dragent_error_handler::exception(const Poco::Exception& exc)
{
	g_log->error(exc.displayText());
	m_exception = true;
	dragent_configuration::m_terminate = true;
}
	
void dragent_error_handler::exception(const std::exception& exc)
{
	g_log->error(exc.what());
	m_exception = true;
	dragent_configuration::m_terminate = true;
}

void dragent_error_handler::exception()
{
	g_log->error("Unknown exception");
	m_exception = true;
	dragent_configuration::m_terminate = true;
}
