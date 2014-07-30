#pragma once

#include "main.h"

#include "main.h"
#ifndef _WIN32
#include <sys/prctl.h>
#endif

#include "crash_handler.h"
#include "configuration.h"
#include "connection_manager.h"
#include "blocking_queue.h"
#include "error_handler.h"
#include "sinsp_worker.h"
#include "logger.h"
#include "monitor.h"

///////////////////////////////////////////////////////////////////////////////
// The main application class
///////////////////////////////////////////////////////////////////////////////
class dragent_app: public Poco::Util::ServerApplication
{
public:
	dragent_app();
	~dragent_app();

protected:
	void initialize(Application& self);
	void uninitialize();
	void defineOptions(OptionSet& options);
	void handleOption(const std::string& name, const std::string& value);
	void displayHelp();
	int main(const std::vector<std::string>& args);

private:
	void watchdog_check();
	void initialize_logging();
	void check_for_clean_shutdown();
	void mark_clean_shutdown();

	bool m_help_requested;
	string m_pidfile;
	dragent_configuration m_configuration;
	dragent_error_handler m_error_handler;
	protocol_queue m_queue;
	sinsp_worker m_sinsp_worker;
	connection_manager m_connection_manager;
};
