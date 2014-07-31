#include "main.h"
#include "dragent.h"
#include "crash_handler.h"
#include "configuration.h"
#include "connection_manager.h"
#include "blocking_queue.h"
#include "error_handler.h"
#include "sinsp_worker.h"
#include "logger.h"
#include "monitor.h"

#if 0
#define AGENT_PRIORITY 19
#endif

static void g_signal_callback(int sig)
{
	dragent_configuration::m_terminate = true;
}

static void g_usr_signal_callback(int sig)
{
	g_log->information("Received SIGUSR1, starting dump"); 
	dragent_configuration::m_signal_dump = true;
}

dragent_app::dragent_app(): 
	m_help_requested(false),
	m_queue(MAX_SAMPLE_STORE_SIZE),
	m_sinsp_worker(&m_configuration, &m_queue),
	m_connection_manager(&m_configuration, &m_queue, &m_sinsp_worker)
{
}
	
dragent_app::~dragent_app()
{
	if(g_log != NULL)
	{
		delete g_log;
	}
}

void dragent_app::initialize(Application& self)
{
	ServerApplication::initialize(self);
}
		
void dragent_app::uninitialize()
{
	ServerApplication::uninitialize();
}

void dragent_app::defineOptions(OptionSet& options)
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

void dragent_app::handleOption(const std::string& name, const std::string& value)
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

void dragent_app::displayHelp()
{
	HelpFormatter helpFormatter(options());
	helpFormatter.setCommand(commandName());
	helpFormatter.setUsage("OPTIONS");
	helpFormatter.setHeader("Draios Agent.");
	helpFormatter.format(std::cout);
}

int dragent_app::main(const std::vector<std::string>& args)
{
	if(m_help_requested)
	{
		displayHelp();
		return Application::EXIT_OK;
	}

#ifndef _WIN32
	//
	// Before running the monitor, unblock all the signals,
	// because dragent might be restarted from a Poco thread (e.g.
	// during auto-update), and the Poco implementation blocks
	// signals by default in threads in order to allow a deterministic
	// signal recipient instead of a random one.
	//
	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGQUIT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGPIPE); 
	sigprocmask(SIG_UNBLOCK, &sigs, NULL);

	if(config().getBool("application.runAsDaemon", false))
	{
		run_monitor(m_pidfile);

		//
		// We want to terminate when the monitor is killed by init
		//
		prctl(PR_SET_PDEATHSIG, SIGKILL);
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = g_signal_callback;
	
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = g_usr_signal_callback;
	sigaction(SIGUSR1, &sa, NULL);

	if(crash_handler::initialize() == false)
	{
		ASSERT(false);
	}
#endif

	Poco::ErrorHandler::set(&m_error_handler);

	m_configuration.init(this);

	initialize_logging();

	g_log->information("Agent starting (version " + string(AGENT_VERSION) + ")");

	m_configuration.print_configuration();

	check_for_clean_shutdown();

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

	ThreadPool::defaultPool().start(m_connection_manager, "connection_manager");
	ThreadPool::defaultPool().start(m_sinsp_worker, "sinsp_worker");

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration.m_watchdog_enabled)
		{
			watchdog_check();
		}

		Thread::sleep(1000);
	}

	if(dragent_error_handler::m_exception)
	{
		g_log->error("Application::EXIT_SOFTWARE");
		exit_code = Application::EXIT_SOFTWARE;
	}
	else
	{
		g_log->information("Application::EXIT_OK");
		exit_code = Application::EXIT_OK;
	}

	dragent_configuration::m_terminate = true;
	ThreadPool::defaultPool().stopAll();

	mark_clean_shutdown();

	g_log->information("Terminating");
	return exit_code;
}

void dragent_app::watchdog_check()
{
	bool to_kill = false;

	if(m_sinsp_worker.get_last_loop_ns() != 0)
	{
		int64_t diff = dragent_configuration::get_current_time_ns() 
			- m_sinsp_worker.get_last_loop_ns();

#if _DEBUG
		g_log->debug("watchdog: sinsp_worker last activity " + NumberFormatter::format(diff) + " ns ago");
#endif

		if(diff > (int64_t) m_configuration.m_watchdog_sinsp_worker_timeout_s * 1000000000LL)
		{
#if _DEBUG
			g_log->error("watchdog: Detected sinsp_worker stall, last activity " + NumberFormatter::format(diff) + " ns ago");
#endif
			pthread_kill(m_sinsp_worker.get_pthread_id(), SIGABRT);
			to_kill = true;
		}
	}

	if(m_connection_manager.get_last_loop_ns() != 0)
	{
		int64_t diff = dragent_configuration::get_current_time_ns() 
			- m_connection_manager.get_last_loop_ns();

#if _DEBUG
		g_log->debug("watchdog: connection_manager last activity " + NumberFormatter::format(diff) + " ns ago");
#endif

		if(diff > (int64_t) m_configuration.m_watchdog_connection_manager_timeout_s * 1000000000LL)
		{
#if _DEBUG
			g_log->error("watchdog: Detected connection_manager stall, last activity " + NumberFormatter::format(diff) + " ns ago");
#endif
			pthread_kill(m_connection_manager.get_pthread_id(), SIGABRT);
			to_kill = true;
		}
	}

	uint64_t memory;
	if(dragent_configuration::get_memory_usage_mb(&memory))
	{
		g_log->debug("watchdog: memory usage " + NumberFormatter::format(memory) + " MB");

		if(memory > m_configuration.m_watchdog_max_memory_usage_mb)
		{
			g_log->error("watchdog: High memory usage, " + NumberFormatter::format(memory) + " MB");
			to_kill = true;
		}
	}
	else
	{
		ASSERT(false);
	}

	//
	// Just wait a bit to give time to the other threads to print stacktrace
	//
	if(to_kill)
	{
		sleep(5);
#if _DEBUG
		g_log->error("watchdog: committing suicide");
#endif
		kill(getpid(), SIGKILL);
	}
}

void dragent_app::check_for_clean_shutdown()
{
	Path p;
	p.parseDirectory(m_configuration.m_log_dir);
	p.setFileName("running");

	File f(p);
	if(f.exists())
	{
		g_log->error("agent didn't terminate cleanly, sending the last " 
			+ NumberFormatter::format(m_configuration.m_dirty_shutdown_report_log_size_b) 
			+ "B to collector");

		p.setFileName("draios.log");

		FILE* fp = fopen(p.toString().c_str(), "r");
		if(fp == NULL)
		{
			g_log->error(string("fopen: ") + strerror(errno));
			return;
		}

		if(fseek(fp, 0, SEEK_END) == -1)
		{
			g_log->error(string("fseek (1): ") + strerror(errno));
			fclose(fp);
			return;
		}

		long offset = ftell(fp);
		if(offset == -1)
		{
			g_log->error(string("ftell: ") + strerror(errno));
			fclose(fp);
			return;
		}

		if((uint64_t) offset > m_configuration.m_dirty_shutdown_report_log_size_b)
		{
			offset = m_configuration.m_dirty_shutdown_report_log_size_b;
		}

		if(fseek(fp, -offset, SEEK_END) == -1)
		{
			g_log->error(string("fseek (2): ") + strerror(errno));
			fclose(fp);
			return;
		}

		Buffer<char> buf(offset);
		if(fread(buf.begin(), offset, 1, fp) != 1)
		{
			g_log->error("fread error");
			fclose(fp);
			return;
		}

		draiosproto::dirty_shutdown_report report;
		report.set_timestamp_ns(dragent_configuration::get_current_time_ns());
		report.set_customer_id(m_configuration.m_customer_id);
		report.set_machine_id(m_configuration.m_machine_id);
		report.set_log(buf.begin(), buf.size());

		SharedPtr<protocol_queue_item> report_serialized = dragent_protocol::message_to_buffer(
			draiosproto::message_type::DIRTY_SHUTDOWN_REPORT, 
			report, 
			m_configuration.m_compression_enabled);

		if(report_serialized.isNull())
		{
			g_log->error("NULL converting message to buffer");
			return;
		}

		if(!m_queue.put(report_serialized, protocol_queue::BQ_PRIORITY_LOW))
		{
			g_log->error("Queue full");
			return;
		}

		fclose(fp);
	}
	else
	{
		f.createFile();
	}
}

void dragent_app::mark_clean_shutdown()
{
	Path p;
	p.parseDirectory(m_configuration.m_log_dir);
	p.setFileName("running");

	File f(p);
	if(f.exists())
	{
		f.remove();
	}
}

void dragent_app::initialize_logging()
{
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
	file_channel->setProperty("purgeCount", "10");
	file_channel->setProperty("archive", "timestamp");

	AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %h:%M:%S.%i, %P, %p, %t"));

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
}
