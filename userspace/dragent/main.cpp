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

#define AGENT_PRIORITY 19

static void g_signal_callback(int sig)
{
	dragent_configuration::m_terminate = true;
}

static void g_usr_signal_callback(int sig)
{
	g_log->information("Received SIGUSR1, toggling capture state"); 
	dragent_configuration::m_dump_enabled = !dragent_configuration::m_dump_enabled;
}

///////////////////////////////////////////////////////////////////////////////
// The main application class
///////////////////////////////////////////////////////////////////////////////
class dragent_app: public Poco::Util::ServerApplication
{
public:
	dragent_app(): 
		m_help_requested(false),
		m_queue(MAX_SAMPLE_STORE_SIZE),
		m_connection_manager(&m_configuration, &m_queue),
		m_sinsp_worker(&m_configuration, &m_queue)
	{
	}
	
	~dragent_app()
	{
		if(g_log != NULL)
		{
			delete g_log;
		}
	}

protected:
	void initialize(Application& self)
	{
		ServerApplication::initialize(self);
	}
		
	void uninitialize()
	{
		ServerApplication::uninitialize();
	}

	void defineOptions(OptionSet& options)
	{
		ServerApplication::defineOptions(options);
		
		options.addOption(
			Option("help", "h", "display help information on command line arguments")
				.required(false)
				.repeatable(false));

		options.addOption(
			Option("consolepriority", "", "min priority of the log messages that go on console. Can be 'error', 'warning', 'info' or 'debug'.")
				.required(false)
				.repeatable(false)
				.argument("priority"));

		options.addOption(
			Option("filepriority", "", "min priority of the log messages that go on file. Can be 'error', 'warning', 'info' or 'debug'.")
				.required(false)
				.repeatable(false)
				.argument("priority"));

		options.addOption(
			Option("readfile", "r", "file to open.")
				.required(false)
				.repeatable(false)
				.argument("filename"));

		options.addOption(
			Option("evtcount", "c", "numer of events after which the capture stops.")
				.required(false)
				.repeatable(false)
				.argument("count"));

		options.addOption(
			Option("customerid", "i", "force the customer id.")
				.required(false)
				.repeatable(false)
				.argument("id"));

		options.addOption(
			Option("writefile", "w", "specify this flag to save all the capture events to the 'filename' file.")
				.required(false)
				.repeatable(false)
				.argument("filename"));

		options.addOption(
			Option("srvaddr", "", "the address of the server to connect to.")
				.required(false)
				.repeatable(false)
				.argument("address"));

		options.addOption(
			Option("srvport", "", "the TCP port to use.")
				.required(false)
				.repeatable(false)
				.argument("port"));
	}

	void handleOption(const std::string& name, const std::string& value)
	{
		ServerApplication::handleOption(name, value);

		if(name == "help")
		{
			m_help_requested = true;
		}
		else if(name == "consolepriority")
		{
			m_configuration.m_min_console_priority = dragent_configuration::string_to_priority(value);
		}
		else if(name == "filepriority")
		{
			m_configuration.m_min_file_priority = dragent_configuration::string_to_priority(value);
		}
		else if(name == "readfile")
		{
			m_configuration.m_input_filename = value;
		}
		else if(name == "evtcount")
		{
			m_configuration.m_evtcnt = NumberParser::parse64(value);
		}
		else if(name == "customerid")
		{
			m_configuration.m_customer_id = value;
		}
		else if(name == "writefile")
		{
			dragent_configuration::m_dump_enabled = true;
			m_configuration.m_dump_file = value;
		}
		else if(name == "srvaddr")
		{
			m_configuration.m_server_addr = value;
		}
		else if(name == "srvport")
		{
			m_configuration.m_server_port = (uint16_t)NumberParser::parse(value);
		}
		else if(name == "pidfile")
		{
			m_pidfile = value;
		}
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS");
		helpFormatter.setHeader("Draios Agent.");
		helpFormatter.format(std::cout);
	}

	///////////////////////////////////////////////////////////////////////////
	// MAIN
	///////////////////////////////////////////////////////////////////////////
	int main(const std::vector<std::string>& args)
	{
		if(m_help_requested)
		{
			displayHelp();
			return Application::EXIT_OK;
		}

#ifndef _WIN32
		if(config().getBool("application.runAsDaemon", false))
		{
			run_monitor(m_pidfile);

			//
			// We want to terminate when the monitor is killed by init
			//
			prctl(PR_SET_PDEATHSIG, SIGTERM);
		}

		signal(SIGINT, g_signal_callback);
		signal(SIGQUIT, g_signal_callback);
		signal(SIGTERM, g_signal_callback);
		signal(SIGUSR1, g_usr_signal_callback);

		if(crash_handler::initialize() == false)
		{
			ASSERT(false);
		}
#endif

		Poco::ErrorHandler::set(&m_error_handler);

		m_configuration.init(this);

		//
		// Create the logs directory if it doesn't exist
		//
		File d(m_configuration.m_log_dir);
		d.createDirectories();
		Path p;
		p.parseDirectory(m_configuration.m_log_dir);
		p.setFileName("draios.log");
		string logsdir = p.toString();

		//
		// Setup the logging
		//
		AutoPtr<Channel> console_channel(new ConsoleChannel());
		AutoPtr<FileChannel> file_channel(new FileChannel(logsdir));

		file_channel->setProperty("rotation", "10M");
		file_channel->setProperty("purgeCount", "5");
		file_channel->setProperty("archive", "timestamp");

		AutoPtr<Formatter> formatter(new PatternFormatter("%h-%M-%S.%i, %p, %t"));

		AutoPtr<Channel> formatting_channel_file(new FormattingChannel(formatter, file_channel));
		AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));

		Logger& loggerf = Logger::create("DraiosLogF", formatting_channel_file, m_configuration.m_min_file_priority);
		Logger& loggerc = Logger::create("DraiosLogC", formatting_channel_console, m_configuration.m_min_console_priority);
		
		if(m_configuration.m_min_console_priority != -1)
		{
			g_log = new dragent_logger(&loggerf, &loggerc);
		}
		else
		{
			g_log = new dragent_logger(&loggerf, NULL);
		}

		g_log->information("Agent starting");

		m_configuration.print_configuration();

#if 0
		if(m_configuration.m_daemon)
		{
#ifndef _WIN32
			if(nice(AGENT_PRIORITY) == -1)
			{
				ASSERT(false);
				g_log->error("Cannot set priority: " + string(strerror(errno)));
			}

			//
			// Since 2.6.36, the previous code is not enough since
			// the kernel will make the nice level of the process effective
			// only within the process group, which is useless.
			// I found out the following hack by looking in the kernel source
			//
			ofstream autogroup_file("/proc/" + NumberFormatter::format(getpid()) + "/autogroup", std::ofstream::out);
			if(autogroup_file.is_open())
			{
				autogroup_file << AGENT_PRIORITY;
				if(autogroup_file.fail())
				{
					g_log->warning("Cannot set the autogroup priority");
				}

				autogroup_file.close();
			}
			else
			{
				g_log->warning("Cannot open the autogroup file");
			}
#endif
		}
#endif

		ExitCode exit_code;

		//
		// From now on we can get exceptions
		//
		try
		{
			m_configuration.m_machine_id = Environment::nodeId();

			//
			// Connect to the server
			//
			if(m_connection_manager.init())
			{
				ThreadPool::defaultPool().start(m_connection_manager, "connection_manager");
			}
			
			m_sinsp_worker.init();

			//
			// Start consuming the captured events
			//
			m_sinsp_worker.do_inspect();

			if(dragent_error_handler::m_exception)
			{
				g_log->error("Application::EXIT_SOFTWARE\n");
				exit_code = Application::EXIT_SOFTWARE;
			}
			else
			{
				g_log->information("Application::EXIT_OK\n");
				exit_code = Application::EXIT_OK;
			}
		}
		catch(sinsp_exception& e)
		{
			g_log->error(e.what());
			exit_code = Application::EXIT_SOFTWARE;
		}
		catch(Poco::Exception& e)
		{
			g_log->error(e.displayText());
			exit_code = Application::EXIT_SOFTWARE;
		}
		catch(...)
		{
			g_log->error("Application::EXIT_SOFTWARE\n");
			exit_code = Application::EXIT_SOFTWARE;
		}

		ThreadPool::defaultPool().stopAll();

		g_log->information("Terminating");
		return exit_code;
	}
	
private:
	bool m_help_requested;
	string m_pidfile;
	dragent_configuration m_configuration;
	dragent_error_handler m_error_handler;
	dragent_queue m_queue;
	connection_manager m_connection_manager;
	sinsp_worker m_sinsp_worker;
};


int main(int argc, char** argv)
{
	dragent_app app;
	return app.run(argc, argv);
}
