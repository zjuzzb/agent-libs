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
#include "utils.h"

static void g_signal_callback(int sig)
{
	g_log->information("Received signal " + NumberFormatter::format(sig) + ", terminating"); 
	dragent_configuration::m_terminate = true;
}

static void g_usr_signal_callback(int sig)
{
	g_log->information("Received SIGUSR1, starting dump"); 
	dragent_configuration::m_signal_dump = true;
}

static void g_usr2_signal_callback(int sig)
{
	g_log->information("Received SIGUSR2");
	dragent_configuration::m_send_log_report = true;
}

dragent_app::dragent_app(): 
	m_help_requested(false),
	m_queue(MAX_SAMPLE_STORE_SIZE),
	m_sinsp_worker(&m_configuration, &m_connection_manager, &m_queue),
	m_connection_manager(&m_configuration, &m_queue, &m_sinsp_worker),
	m_log_reporter(&m_queue, &m_configuration),
	m_subprocesses_logger(&m_configuration, &m_log_reporter)
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

	options.addOption(
		Option("dragentpid", "", "pid file.")
			.required(false)
			.repeatable(false)
			.argument("dragentpid"));
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
	else if(name == "dragentpid")
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

	//
	// Never move this further down!
	// It's important that the pidfile gets created immediately!
	//
	monitor monitor_process(m_pidfile);

	m_configuration.init(this);
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

	// Add our main process
	monitor_process.emplace_process("sdagent",[this]()
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sigemptyset(&sa.sa_mask);
		sa.sa_handler = g_signal_callback;

		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGQUIT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);

		sa.sa_handler = g_usr_signal_callback;
		sigaction(SIGUSR1, &sa, NULL);
		sa.sa_handler = g_usr2_signal_callback;
		sigaction(SIGUSR2, &sa, NULL);

		if(crash_handler::initialize() == false)
		{
			ASSERT(false);
		}
		return this->sdagent_main();
	}, true);

	if(m_configuration.java_present() && m_configuration.m_sdjagent_enabled && getpid() != 1)
	{
		m_jmx_pipes = make_shared<pipe_manager>();
		m_sinsp_worker.set_jmx_pipes(m_jmx_pipes);
		m_subprocesses_logger.add_logfd(m_jmx_pipes->get_err_fd(), sdjagent_parser());

		monitor_process.emplace_process("sdjagent", [this](void) -> int
		{
			static const auto MAX_SDJAGENT_ARGS = 50;
			this->m_jmx_pipes->attach_child_stdio();

			// Our option parser is pretty simple, for example an arg with spaces inside
			// double quotes will not work, eg:
			// -Xmx:myamazingconfig="test with spaces" -Xmx256m
			auto sdjagent_opts_split = sinsp_split(m_configuration.m_sdjagent_opts, ' ');

			const char* args[MAX_SDJAGENT_ARGS];
			unsigned j = 0;
			args[j++] = "java";
			for(const auto& opt : sdjagent_opts_split)
			{
				args[j++] = opt.c_str();
			}
			args[j++] = "-Djava.library.path=/opt/draios/lib";
			args[j++] = "-Dsun.rmi.transport.connectionTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-Dsun.rmi.transport.tcp.handshakeTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-Dsun.rmi.transport.tcp.responseTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-Dsun.rmi.transport.tcp.readTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-jar";
			File sdjagent_jar("/opt/draios/share/sdjagent.jar");
			if(sdjagent_jar.exists())
			{
				args[j++] = "/opt/draios/share/sdjagent.jar";
			}
			else
			{
				args[j++] = "../sdjagent/java/sdjagent-1.0-jar-with-dependencies.jar";
			}
			args[j++] = NULL;

			execv(this->m_configuration.m_java_binary.c_str(), (char* const*)args);

			std::cerr << "{ \"pid\": 0, \"level\": \"SEVERE\", \"message\": \"Cannot load sdjagent, errno: " << errno <<"\" }" << std::endl;
			return (EXIT_FAILURE);
		});
	}

	// Configure statsite subprocess
	if(m_configuration.m_statsd_enabled)
	{
		m_statsite_pipes = make_shared<pipe_manager>();
		m_sinsp_worker.set_statsite_pipes(m_statsite_pipes);
		m_subprocesses_logger.add_logfd(m_statsite_pipes->get_err_fd(), [this](const string& data)
		{
			if(data.find("Failed to bind") != string::npos)
			{
				this->m_sinsp_worker.set_statsd_capture_localhost(true);
			}
			// statsite logs does not have info about level, use error if keyword `Failed` is inside or use
			// information
			if(data.find("Failed") != string::npos)
			{
				g_log->error(data);
			}
			else
			{
				g_log->information(data);
			}
		});

		monitor_process.emplace_process("statsite", [this](void) -> int
		{
			this->m_statsite_pipes->attach_child_stdio();
			if(this->m_configuration.m_agent_installed)
			{
				execl("/opt/draios/bin/statsite", "statsite", "-f", "/opt/draios/etc/statsite.ini", (char*)NULL);
			}
			else
			{
				execl("../../../../dependencies/statsite-private-0.7.0-sysdig3/statsite",
					  "statsite", "-f", "statsite.ini", (char*)NULL);
			}
			return (EXIT_FAILURE);
		});
	}

	return monitor_process.run();
#else
	return sdagent_main();
#endif
}

int dragent_app::sdagent_main()
{
	Poco::ErrorHandler::set(&m_error_handler);

	initialize_logging();

	g_log->information("Agent starting (version " + string(AGENT_VERSION) + ")");

	m_configuration.refresh_machine_id();
	m_configuration.refresh_aws_metadata();
	m_configuration.print_configuration();

	if(m_configuration.m_customer_id.empty())
	{
		g_log->error("customerid not specified");
		return Application::EXIT_SOFTWARE;
	}

	if(m_configuration.m_machine_id == "00:00:00:00:00:00")
	{
		g_log->error("Invalid machine_id detected");
		return Application::EXIT_SOFTWARE;
	}

	if(m_configuration.m_watchdog_enabled)
	{
		check_for_clean_shutdown();
	}

	ExitCode exit_code;

	ThreadPool::defaultPool().start(m_subprocesses_logger, "subprocesses_logger");
	ThreadPool::defaultPool().start(m_connection_manager, "connection_manager");
	ThreadPool::defaultPool().start(m_sinsp_worker, "sinsp_worker");

	uint64_t uptime_s = 0;

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration.m_watchdog_enabled)
		{
			watchdog_check(uptime_s);
		}

		Thread::sleep(1000);
		++uptime_s;
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

	if(m_configuration.m_watchdog_enabled)
	{
		mark_clean_shutdown();
	}

	g_log->information("Terminating");
	return exit_code;
}

void dragent_app::watchdog_check(uint64_t uptime_s)
{
	bool to_kill = false;

	if(m_sinsp_worker.get_last_loop_ns() != 0)
	{
		int64_t diff = sinsp_utils::get_current_time_ns() 
			- m_sinsp_worker.get_last_loop_ns();

#if _DEBUG
		g_log->debug("watchdog: sinsp_worker last activity " + NumberFormatter::format(diff) + " ns ago");
#endif

		if(diff > (int64_t) m_configuration.m_watchdog_sinsp_worker_timeout_s * 1000000000LL)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: Detected sinsp_worker stall, last activity %" PRId64 " ns ago\n", diff);
			crash_handler::log_crashdump_message(line);
			pthread_kill(m_sinsp_worker.get_pthread_id(), SIGABRT);
			to_kill = true;
		}

		if((uptime_s % m_configuration.m_watchdog_analyzer_tid_collision_check_interval_s) == 0 &&
			m_sinsp_worker.m_analyzer->m_die)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: too many tid collisions\n");
			crash_handler::log_crashdump_message(line);

			if(m_sinsp_worker.get_last_loop_ns())
			{
				char buf[1024];
				m_sinsp_worker.get_inspector()->m_analyzer->generate_memory_report(buf, sizeof(buf));
				crash_handler::log_crashdump_message(buf);
			}

			to_kill = true;
		}
	}

	if(m_sinsp_worker.get_sinsp_data_handler()->get_last_loop_ns() != 0)
	{
		int64_t diff = sinsp_utils::get_current_time_ns() 
			- m_sinsp_worker.get_sinsp_data_handler()->get_last_loop_ns();

#if _DEBUG
		g_log->debug("watchdog: sinsp_data_handler last activity " + NumberFormatter::format(diff) + " ns ago");
#endif

		if(diff > (int64_t) m_configuration.m_watchdog_sinsp_data_handler_timeout_s * 1000000000LL)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: Detected sinsp_data_handler stall, last activity %" PRId64 " ns ago\n", diff);
			crash_handler::log_crashdump_message(line);
			to_kill = true;
		}
	}

	if(m_connection_manager.get_last_loop_ns() != 0)
	{
		int64_t diff = sinsp_utils::get_current_time_ns() 
			- m_connection_manager.get_last_loop_ns();

#if _DEBUG
		g_log->debug("watchdog: connection_manager last activity " + NumberFormatter::format(diff) + " ns ago");
#endif

		if(diff > (int64_t) m_configuration.m_watchdog_connection_manager_timeout_s * 1000000000LL)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: Detected connection_manager stall, last activity %" PRId64 " ns ago\n", diff);
			crash_handler::log_crashdump_message(line);
			pthread_kill(m_connection_manager.get_pthread_id(), SIGABRT);
			to_kill = true;
		}
	}

	if(m_subprocesses_logger.get_last_loop_ns() != 0)
	{
		int64_t diff = sinsp_utils::get_current_time_ns()
					   - m_subprocesses_logger.get_last_loop_ns();

#if _DEBUG
		g_log->debug("watchdog: subprocesses_logger last activity " + NumberFormatter::format(diff) + " ns ago");
#endif

		if(diff > (int64_t) m_configuration.m_watchdog_subprocesses_logger_timeout_s * 1000000000LL)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: Detected subprocesses_logger stall, last activity %" PRId64 " ns ago\n", diff);
			crash_handler::log_crashdump_message(line);
			pthread_kill(m_subprocesses_logger.get_pthread_id(), SIGABRT);
			to_kill = true;
		}
	}

	uint64_t memory;
	if(dragent_configuration::get_memory_usage_mb(&memory))
	{
#if _DEBUG
		g_log->debug("watchdog: memory usage " + NumberFormatter::format(memory) + " MB");
#endif

		if(memory > m_configuration.m_watchdog_max_memory_usage_mb)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: High memory usage, %" PRId64 " MB\n", memory);
			crash_handler::log_crashdump_message(line);

			if(m_sinsp_worker.get_last_loop_ns())
			{
				char buf[1024];
				m_sinsp_worker.get_inspector()->m_analyzer->generate_memory_report(buf, sizeof(buf));
				crash_handler::log_crashdump_message(buf);
			}

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
		char line[128];
		snprintf(line, sizeof(line), "watchdog: committing suicide\n");
		crash_handler::log_crashdump_message(line);
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
		m_log_reporter.send_report();
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

	crash_handler::set_crashdump_file(p.toString());
	crash_handler::set_sinsp_worker(&m_sinsp_worker);
	
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
