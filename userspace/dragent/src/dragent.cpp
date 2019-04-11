#include <time.h>

#include "main.h"
#include "dragent.h"
#include "crash_handler.h"
#include "configuration.h"
#include "connection_manager.h"
#include "user_event_channel.h"
#include "blocking_queue.h"
#include "error_handler.h"
#include "capture_job_handler.h"
#include "sinsp_worker.h"
#include "logger.h"
#include "monitor.h"
#include "process_helpers.h"
#include "utils.h"
#ifndef CYGWING_AGENT
#include <gperftools/malloc_extension.h>
#include <grpc/support/log.h>
#include <sched.h>
#else
#include "windows_helpers.h"
#endif
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <procfs_parser.h>
#include <sys/resource.h>

using namespace std;
using namespace dragent;

DRAGENT_LOGGER();

// local helper functions
namespace {
string compute_sha1_digest(SHA1Engine &engine, const string &path)
{
	engine.reset();
	ifstream fs(path);
	char readbuf[4096];
	while(fs.good()) {
		fs.read(readbuf, sizeof(readbuf));
		engine.update(readbuf, fs.gcount());
	}
	return DigestEngine::digestToHex(engine.digest());
}

// Number of seconds (of uptime) after which to update the priority of the
// processes. This was chosen arbitrarily to be after the processes had time
// to start.
const uint32_t TIME_TO_UPDATE_PROCESS_PRIORITY = 5;

};

static void g_signal_callback(int sig)
{
	dragent_configuration::m_terminate = true;
}

static void g_usr_signal_callback(int sig)
{
	dragent_configuration::m_signal_dump = true;
}

static void g_usr2_signal_callback(int sig)
{
	dragent_configuration::m_send_log_report = true;
}

static void g_winch_signal_callback(int sig)
{
	dragent_configuration::m_enable_trace = true;
}

dragent_app::dragent_app():
	m_help_requested(false),
	m_version_requested(false),
#ifdef CYGWING_AGENT
	m_windows_service_parent(false),
#endif
#ifndef CYGWING_AGENT
    m_unshare_ipcns(true),
#endif
	m_queue(MAX_SAMPLE_STORE_SIZE),
	m_enable_autodrop(true),
	m_internal_metrics(new internal_metrics()),
	m_sinsp_worker(&m_configuration, m_internal_metrics, &m_queue, &m_enable_autodrop, &m_capture_job_handler),
	m_capture_job_handler(&m_configuration, &m_queue, &m_enable_autodrop),
	m_connection_manager(&m_configuration, &m_queue, &m_sinsp_worker, &m_capture_job_handler),
	m_log_reporter(&m_queue, &m_configuration),
	m_subprocesses_logger(&m_configuration, &m_log_reporter),
	m_last_dump_s(0)
{
}

dragent_app::~dragent_app()
{
	google::protobuf::ShutdownProtobufLibrary();
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
		Option("configtest", "t", "test config file and exit.")
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

#ifndef CYGWING_AGENT
	options.addOption(
		Option("noipcns", "", "keep IPC namespace (for internal use)")
			.required(false)
			.repeatable(false));
#endif

	options.addOption(
		Option("dragentpid", "", "pid file.")
			.required(false)
			.repeatable(false)
			.argument("dragentpid"));

	options.addOption(
		Option("version", "v", "display version")
			.required(false)
			.repeatable(false));

#ifdef CYGWING_AGENT
	options.addOption(
		Option("serviceparent", "", "assume we are run by a windows service and listen to the service event.")
			.required(false)
			.repeatable(false));
#endif
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
	else if(name == "configtest")
	{
		m_configuration.m_cointerface_enabled = false;
		m_configuration.m_system_supports_containers = false;
		m_configuration.m_app_checks_enabled = false;
		m_configuration.m_statsd_enabled = false;
		m_configuration.m_sdjagent_enabled = false;
		m_configuration.m_config_test = true;
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
#ifndef CYGWING_AGENT
	else if(name == "noipcns")
	{
		m_unshare_ipcns = false;
	}
#endif
	else if(name == "dragentpid")
	{
		m_pidfile = value;
	}
	else if(name == "version")
	{
		m_version_requested = true;
	}
#ifdef CYGWING_AGENT
	else if(name == "serviceparent")
	{
		m_windows_service_parent = true;
	}
#endif
}

void dragent_app::displayHelp()
{
	HelpFormatter helpFormatter(options());
	helpFormatter.setCommand(commandName());
	helpFormatter.setUsage("OPTIONS");
	helpFormatter.setHeader("Draios Agent.");
	helpFormatter.format(std::cout);
}

#ifndef CYGWING_AGENT
static void dragent_gpr_log(gpr_log_func_args *args)
{
	// If logging hasn't been set up yet, skip the message. Add an
	// ASSSERT so we'll notice for dev builds, though.
	ostringstream os;

	if (!g_log)
	{
		ASSERT(false);
		return;
	}

	os << "GRPC: [" << args->file << ":" << args->line << "] " << args->message;

	switch (args->severity)
	{
	case GPR_LOG_SEVERITY_DEBUG:
		LOG_DEBUG(os.str());
		break;
	case GPR_LOG_SEVERITY_INFO:
		LOG_INFO(os.str());
		break;
	case GPR_LOG_SEVERITY_ERROR:
		LOG_ERROR(os.str());
		break;
	default:
		LOG_DEBUG(os.str());
		break;
	}
}
#endif

int dragent_app::main(const std::vector<std::string>& args)
{
	if(m_help_requested)
	{
		displayHelp();
		return Application::EXIT_OK;
	}

	if(m_version_requested)
	{
		printf(AGENT_VERSION "\n");
		return Application::EXIT_OK;
	}

	//
	// Set up logging with grpc.
	//
#ifndef CYGWING_AGENT
	gpr_set_log_function(dragent_gpr_log);
#endif

	//
	// Make sure the agent never creates world-writable files
	//
	umask(0027);

	//
	// Never move this further down!
	// It's important that the pidfile gets created immediately!
	//
#ifndef CYGWING_AGENT
	string me = config().getString("application.path", CMAKE_INSTALL_PREFIX "/bin/dragent");
	monitor monitor_process(m_pidfile, move(me));
#else
	monitor monitor_process(m_pidfile, m_windows_service_parent);
#endif

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

#ifndef CYGWING_AGENT
	if(m_unshare_ipcns && unshare(CLONE_NEWIPC) < 0)
	{
		std::cerr << "Cannot create private IPC namespace: " << strerror(errno) << '\n';
	}
#endif

	struct rlimit msgqueue_rlimits = {
		.rlim_cur = m_configuration.m_rlimit_msgqueue,
		.rlim_max = m_configuration.m_rlimit_msgqueue
	};
	if(setrlimit(RLIMIT_MSGQUEUE, &msgqueue_rlimits) != 0)
	{
		std::cerr << "Cannot set msgqueue limits: " << strerror(errno) << '\n';
	}

	// Add our main process
	monitor_process.emplace_process("sdagent",[this]()
	{
		// only set to get agent show in the watchdog loop
		m_subprocesses_state["sdagent"].set_name("sdagent");

		// Unlike the other processes, the agent itself
		// doesn't get a pid from the log file. So set it
		// here.
		m_subprocesses_state["sdagent"].reset(getpid(), 0, 0);

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
		sa.sa_handler = g_winch_signal_callback;
		sigaction(SIGWINCH, &sa, NULL);

		if(crash_handler::initialize() == false)
		{
			ASSERT(false);
		}

		struct rlimit core_limits = {};
		if(m_configuration.m_enable_coredump)
		{
			core_limits.rlim_cur = RLIM_INFINITY;
			core_limits.rlim_max = RLIM_INFINITY;
		}
		else
		{
			core_limits.rlim_cur = 0;
			core_limits.rlim_max = 0;
		}
		if(setrlimit(RLIMIT_CORE, &core_limits) != 0)
		{
			LOG_WARNING(string("Cannot set coredump limits: ") + strerror(errno));
		}

		return this->sdagent_main();
	}, true);
	if(m_configuration.java_present() && m_configuration.m_sdjagent_enabled && getpid() != 1)
	{
		m_jmx_pipes = make_unique<errpipe_manager>();
		auto* state = &m_subprocesses_state["sdjagent"];
		state->set_name("sdjagent");
		m_subprocesses_logger.add_logfd(m_jmx_pipes->get_file(), sdjagent_parser(), state);

		monitor_process.emplace_process("sdjagent", [this]() -> int
		{
			static const auto MAX_SDJAGENT_ARGS = 50;
			this->m_jmx_pipes->attach_child();

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

			const string java_library_path = string("-Djava.library.path=") + m_configuration.m_root_dir + "/lib";
			args[j++] = java_library_path.c_str();
			args[j++] = "-Dsun.rmi.transport.connectionTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-Dsun.rmi.transport.tcp.handshakeTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-Dsun.rmi.transport.tcp.responseTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-Dsun.rmi.transport.tcp.readTimeout=" SDJAGENT_JMX_TIMEOUT;
			args[j++] = "-jar";
			File sdjagent_jar(m_configuration.m_root_dir + "/share/sdjagent.jar");

			std::string jar_file = sdjagent_jar.exists() ?
				(m_configuration.m_root_dir + "/share/sdjagent.jar") :
				"../sdjagent/java/sdjagent-1.0-jar-with-dependencies.jar";

			args[j++] = jar_file.c_str();
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
				LOG_ERROR(data);
			}
			else
			{
				LOG_INFO(data);
			}
		});

		monitor_process.emplace_process("statsite", [this]() -> int
		{
			this->m_statsite_pipes->attach_child_stdio();
			if(this->m_configuration.m_agent_installed)
			{
				execl((m_configuration.m_root_dir + "/bin/statsite").c_str(), "statsite", "-f",
					(m_configuration.m_root_dir + "/etc/statsite.ini").c_str(), (char*)NULL);
			}
			else
			{
				execl("../../../../dependencies/statsite-private-0.7.0-sysdig3/statsite",
					  "statsite", "-f", "statsite.ini", (char*)NULL);
			}
			return (EXIT_FAILURE);
		});
		if(m_configuration.m_mode == dragent_mode_t::NODRIVER)
		{
			m_statsite_forwarder_pipe = make_unique<errpipe_manager>();
			auto state = &m_subprocesses_state["statsite_forwarder"];
			state->set_name("statsite_forwarder");
			m_subprocesses_logger.add_logfd(m_statsite_forwarder_pipe->get_file(), sinsp_logger_parser("statsite_forwarder"), state);
			monitor_process.emplace_process("statsite_forwarder", [this]() -> int
			{
				m_statsite_forwarder_pipe->attach_child();
				statsite_forwarder fwd(this->m_statsite_pipes->get_io_fds(),
						       m_configuration.m_statsd_port,
						       m_configuration.m_statsite_buffer_warning_length,
						       m_configuration.m_statsite_check_format);
				return fwd.run();
			});
		}
	}

#ifndef CYGWING_AGENT
	if(m_configuration.python_present() && (m_configuration.m_app_checks_enabled || m_configuration.m_prom_conf.enabled()))
	{
		m_sdchecks_pipes = make_unique<errpipe_manager>();
		auto state = &m_subprocesses_state["sdchecks"];
		state->set_name("sdchecks");
		m_subprocesses_logger.add_logfd(m_sdchecks_pipes->get_file(), sdchecks_parser(), state);
		monitor_process.emplace_process("sdchecks", [this]()
		{
			this->m_sdchecks_pipes->attach_child();

			setenv("LD_LIBRARY_PATH", (m_configuration.m_root_dir + "/lib").c_str(), 1);
			const char *python = this->m_configuration.m_python_binary.c_str();
			execl(python, python, (m_configuration.m_root_dir + "/bin/sdchecks").c_str(), "run", NULL);

			return (EXIT_FAILURE);
		});
		if (m_configuration.m_app_checks_enabled)
		{
			m_sinsp_worker.set_app_checks_enabled(true);
		}
	}
	if(m_configuration.m_system_supports_containers)
	{
		m_mounted_fs_reader_pipe = make_unique<errpipe_manager>();
		auto* state = &m_subprocesses_state["mountedfs_reader"];
		state->set_name("mountedfs_reader");
		m_subprocesses_logger.add_logfd(m_mounted_fs_reader_pipe->get_file(), sinsp_logger_parser("mountedfs_reader"), state);
		monitor_process.emplace_process("mountedfs_reader", [this]()
		{
			m_mounted_fs_reader_pipe->attach_child();
			mounted_fs_reader proc(this->m_configuration.m_remotefs_enabled,
						this->m_configuration.m_mounts_filter,
						this->m_configuration.m_mounts_limit_size);
			return proc.run();
		});
	}
#endif
	if(m_configuration.m_cointerface_enabled)
	{
		m_cointerface_pipes = make_unique<pipe_manager>();
		auto* state = &m_subprocesses_state["cointerface"];
		state->set_name("cointerface");
		m_subprocesses_logger.add_logfd(m_cointerface_pipes->get_err_fd(), cointerface_parser(), state);
		m_subprocesses_logger.add_logfd(m_cointerface_pipes->get_out_fd(), cointerface_parser(), state);
		monitor_process.emplace_process("cointerface", [this]()
		{
			m_cointerface_pipes->attach_child_stdio();

			if(m_configuration.m_cointerface_cpu_profile_enabled)
			{
				string logfile = m_configuration.m_log_dir + "/cpu.prof";
				execl((m_configuration.m_root_dir + "/bin/cointerface").c_str(), "cointerface",
				      "-cpuprofile", logfile.c_str(),
				      "-eventspertrace", to_string(m_configuration.m_cointerface_events_per_profile).c_str(),
				      "-keeptraces", to_string(m_configuration.m_cointerface_total_profiles).c_str(),
				      "-memprofile", m_configuration.m_cointerface_mem_profile_enabled ? "true" : "false",
				      (char *) NULL);
			} else {
				execl((m_configuration.m_root_dir + "/bin/cointerface").c_str(), "cointerface", (char *) NULL);
			}

			return (EXIT_FAILURE);
		});
	}
#ifndef CYGWING_AGENT
	if(m_configuration.m_promex_enabled && m_configuration.m_promex_connect_url.empty())
	{
		m_promex_pipes = make_unique<pipe_manager>();
		auto* state = &m_subprocesses_state["promex"];
		state->set_name("promex");
		m_subprocesses_logger.add_logfd(m_promex_pipes->get_out_fd(), sinsp_logger_parser("promex", true), state);
		m_subprocesses_logger.add_logfd(m_promex_pipes->get_err_fd(), sinsp_logger_parser("promex", true), state);
		monitor_process.emplace_process("promex", [this]()
		{
			m_promex_pipes->attach_child_stdio();

			execl((m_configuration.m_root_dir + "/bin/promex").c_str(), "promex",
			      "-prom-addr", m_configuration.m_promex_url.c_str(),
			      "-container-labels", m_configuration.m_promex_container_labels.c_str(),
			      (char *) NULL);

			return (EXIT_FAILURE);
		});
	}
#endif

	monitor_process.set_cleanup_function(
			[this](void)
			{
				this->m_sdchecks_pipes.reset();
				this->m_jmx_pipes.reset();
				this->m_mounted_fs_reader_pipe.reset();
				this->m_statsite_pipes.reset();
				m_statsite_forwarder_pipe.reset();
				this->m_cointerface_pipes.reset();
#ifndef CYGWING_AGENT
				for(const auto& queue : {"/sdc_app_checks_in", "/sdc_app_checks_out",
									  "/sdc_mounted_fs_reader_out", "/sdc_mounted_fs_reader_in",
									  "/sdc_sdjagent_out", "/sdc_sdjagent_in", "/sdc_statsite_forwarder_in"})
				{
					posix_queue::remove(queue);
				}

				coclient::cleanup();
#endif
			});
	return monitor_process.run();
#else // _WIN32
	return sdagent_main();
#endif // _WIN32
}

int dragent_app::sdagent_main()
{
	Poco::ErrorHandler::set(&m_error_handler);

	initialize_logging();

	// The following message was provided to Goldman Sachs (Oct 2018). Do not change.
	LOG_INFO("Agent starting (version " + string(AGENT_VERSION) + ")");

	struct sysinfo info;
	auto error = sysinfo(&info);
	if(error == 0)
	{
		LOG_INFO("System uptime: " + NumberFormatter::format(info.uptime) + "s");
	}
	else
	{
		g_log->warning("Cannot get system uptime");
	}
	struct utsname osname;
	if(uname(&osname) == 0)
	{
		LOG_INFO(string("Kernel version: ") + osname.release);
	}
	else
	{
		g_log->warning("Cannot get kernel version");
	}
	m_configuration.refresh_machine_id();
	m_configuration.refresh_aws_metadata();
	m_configuration.print_configuration();

	if(m_configuration.load_error())
	{
		LOG_ERROR("Unable to load configuration file");
		// XXX Return EXIT_OK even on an error so we won't restart
		return Application::EXIT_OK;
	}

	if(m_statsite_pipes)
	{
		LOG_DEBUG("statsite pipes size in=" + NumberFormatter::format(m_statsite_pipes->inpipe_size()) + " out=" + NumberFormatter::format(m_statsite_pipes->outpipe_size()));
		m_sinsp_worker.set_statsite_pipes(m_statsite_pipes);
	}
	if(m_configuration.m_customer_id.empty())
	{
		LOG_ERROR("customerid not specified");
		return Application::EXIT_SOFTWARE;
	}

	if(m_configuration.machine_id() == "00:00:00:00:00:00")
	{
		LOG_ERROR("Invalid machine_id detected");
		return Application::EXIT_SOFTWARE;
	}

	if(m_configuration.m_watchdog_enabled)
	{
		check_for_clean_shutdown();

#ifndef CYGWING_AGENT
		if(m_configuration.m_watchdog_heap_profiling_interval_s > 0)
		{
			// Heap profiling needs TCMALLOC_SAMPLE_PARAMETER to be set to a non-zero value
			// XXX hacky way to ensure that TCMALLOC_SAMPLE_PARAMETER was set correctly
			int32_t sample_period = 0;
			void **unused_ret = MallocExtension::instance()->ReadStackTraces(&sample_period);
			delete[] unused_ret;

			// If the env var isn't set, disable the dumping interval because it'll be garbage data
			if(sample_period <= 0)
			{
				LOG_ERROR("Disabling watchdog:heap_profiling_interval_s because TCMALLOC_SAMPLE_PARAMETER is not set");
				m_configuration.m_watchdog_heap_profiling_interval_s = 0;
				ASSERT(false);
			}
		}
#endif
	}

	ExitCode exit_code;

	if (!m_configuration.m_config_test)
	{
		m_pool.start(m_subprocesses_logger, m_configuration.m_watchdog_subprocesses_logger_timeout_s);
		m_pool.start(m_connection_manager, m_configuration.m_watchdog_connection_manager_timeout_s);
	}
	try {
		m_sinsp_worker.init();
	}
	catch (const sinsp_exception &e)
	{
		LOG_ERROR(string("Failed to init sinsp_worker. Exception message: ") + string(e.what()));
		dragent_configuration::m_terminate = true;
		dragent_error_handler::m_exception = true;
	}

	g_log->set_capture_job_handler(&m_capture_job_handler);

	if(!dragent_configuration::m_terminate)
	{
		m_capture_job_handler.init(m_sinsp_worker.get_inspector());
		m_pool.start(m_capture_job_handler, watchdog_runnable::NO_TIMEOUT);
		// sinsp_worker has not been changed to a watchdog_runnable
		ThreadPool::defaultPool().start(m_sinsp_worker, "sinsp_worker");
	}

	uint64_t uptime_s = 0;

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration.m_watchdog_enabled)
		{
			watchdog_check(uptime_s);
		}

#ifdef CYGWING_AGENT
		if(m_windows_service_parent)
		{
			if(!m_windows_helpers.is_parent_service_running())
			{
				LOG_INFO("Windows service stopped");
				dragent_configuration::m_terminate = true;
				break;
			}
		}
#endif
		if ((m_configuration.m_monitor_files_freq_sec > 0) &&
		    (uptime_s % m_configuration.m_monitor_files_freq_sec == 0)) {
			monitor_files(uptime_s);
		}

		Thread::sleep(1000);
		++uptime_s;
	}

#ifndef CYGWING_AGENT
	if(m_configuration.m_watchdog_heap_profiling_interval_s > 0)
	{
		// Do a throttled dump in case we don't have anything recent
		dump_heap_profile(uptime_s, true);
	}
#endif

	if(dragent_error_handler::m_exception)
	{
		LOG_ERROR("Application::EXIT_SOFTWARE");
		exit_code = Application::EXIT_SOFTWARE;
	}
	else if(dragent_configuration::m_config_update)
	{
		LOG_INFO("Application::EXIT_CONFIG_UPDATE");
		exit_code = ExitCode(monitor::CONFIG_UPDATE_EXIT_CODE);
	}
	else
	{
		LOG_INFO("Application::EXIT_OK");
		exit_code = Application::EXIT_OK;
	}

	dragent_configuration::m_terminate = true;
	// This will stop everything in the default pool
	m_pool.stop_all();

	if(m_configuration.m_watchdog_enabled)
	{
		mark_clean_shutdown();
	}

	LOG_INFO("Terminating");
	g_log->set_capture_job_handler(nullptr);
	return exit_code;
}

bool dragent_app::timeout_expired(int64_t last_activity_age_ns, uint64_t timeout_s, const char* label, const char* tail)
{
	if(timeout_s == 0 || last_activity_age_ns <= timeout_s * 1000000000LL)
	{
		return false;
	}

	char line[128];
	snprintf(line, sizeof(line), "watchdog: Detected %s stall, last activity %" PRId64 " ns ago%s\n",
		label, last_activity_age_ns, tail);
	crash_handler::log_crashdump_message(line);

	return true;
}

void dragent_app::watchdog_check(uint64_t uptime_s)
{
	bool to_kill = false;

	if(m_sinsp_worker.get_last_loop_ns() != 0)
	{
		int64_t diff_ns = sinsp_utils::get_current_time_ns() - m_sinsp_worker.get_last_loop_ns();

#if _DEBUG
		LOG_DEBUG("watchdog: sinsp_worker last activity " + NumberFormatter::format(diff_ns) + " ns ago");
#endif

		if(timeout_expired(diff_ns, m_configuration.m_watchdog_sinsp_worker_debug_timeout_s,
			"sinsp_worker", ", enabling tracing"))
		{
			pthread_kill(m_sinsp_worker.get_pthread_id(), SIGWINCH);
		}

		if(timeout_expired(diff_ns, m_configuration.m_watchdog_sinsp_worker_timeout_s,
			"sinsp_worker", ", terminating process"))
		{
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
		int64_t diff_ns = sinsp_utils::get_current_time_ns() - m_sinsp_worker.get_sinsp_data_handler()->get_last_loop_ns();

#if _DEBUG
		LOG_DEBUG("watchdog: sinsp_data_handler last activity " + NumberFormatter::format(diff_ns) + " ns ago");
#endif

		if(timeout_expired(diff_ns, m_configuration.m_watchdog_sinsp_data_handler_timeout_s,
			"sinsp_data_handler", ""))
		{
			to_kill = true;
		}
	}

	auto unhealthy = m_pool.unhealthy_list();
	if(!unhealthy.empty())
	{
		for(const watchdog_runnable_pool::unhealthy_runnable& current : unhealthy)
		{
			if(current.health == watchdog_runnable::health::TIMEOUT)
			{
				char line[128];
				snprintf(line,
					 sizeof(line),
					 "watchdog: Detected %s stall, last activity %" PRId64 " ms ago with timeout %" PRId64 "\n",
					 current.runnable.name().c_str(),
					 current.since_last_heartbeat_ms,
					 current.runnable.timeout_ms());
				crash_handler::log_crashdump_message(line);
				pthread_kill(current.runnable.pthread_id(), SIGABRT);
			}
			else
			{
				LOG_FATAL("Detected %s fatal error, last activity %" PRId64 " ms ago\n",
					  current.runnable.name().c_str(),
					  current.since_last_heartbeat_ms);
			}
		}

		to_kill = true;
	}

#ifndef CYGWING_AGENT
	if(m_configuration.m_cointerface_enabled)
	{
		if(!m_coclient) {
			// Actually allocate the coclient object
			m_coclient = make_unique<coclient>(m_configuration.m_root_dir);
		}

		// Ping every 5 seconds. If it's ever more than
		// watchdog_cointerface_timeout_s seconds from a pong,
		// declare it stuck and kill it.
		//
		// Note that we use the time from the ping as the
		// liveness time. So if cointerface somehow falls
		// behind by more than the timeout, it gets declared
		// stuck.

		m_cointerface_ping_interval.run([this]()
		{
			coclient::response_cb_t callback = [this] (bool successful, google::protobuf::Message *response_msg) {
				if(successful)
				{
					sdc_internal::pong *pong = (sdc_internal::pong *) response_msg;
					m_subprocesses_state["cointerface"].reset(pong->pid(),
										  pong->memory_used(),
										  pong->token());
				}
			};

			m_coclient->ping(time(NULL), callback);
		});

		// Try to read any responses
		m_coclient->process_queue();
	}
#endif // CYGWING_AGENT

	// We now have started all the subprocesses, so pass them to internal_metrics
	update_subprocesses();


	// We only want this to happen once
	if(TIME_TO_UPDATE_PROCESS_PRIORITY == uptime_s)
	{
		update_subprocesses_priority();
	}

	uint64_t memory;
	if(dragent_configuration::get_memory_usage_mb(&memory))
	{
#if _DEBUG
		LOG_DEBUG("watchdog: memory usage " + NumberFormatter::format(memory) + " MiB");
#endif

#ifndef CYGWING_AGENT
		const bool heap_profiling = (m_configuration.m_watchdog_heap_profiling_interval_s > 0);
		bool dump_heap = false;
		bool throttle = true;

		// Once the worker is looping, we can dump the initial
		// memory state for diffing against later dumps
		if(heap_profiling && m_last_dump_s == 0 && m_sinsp_worker.get_last_loop_ns() != 0)
		{
			LOG_INFO("watchdog: heap profiling enabled, dumping initial memory state");
			dump_heap = true;
			throttle = false;
		}

		if(memory > m_configuration.m_watchdog_max_memory_usage_mb)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: Fatal memory usage, %" PRId64 " MiB\n", memory);
			crash_handler::log_crashdump_message(line);

			if(m_sinsp_worker.get_last_loop_ns())
			{
				char buf[1024];
				m_sinsp_worker.get_inspector()->m_analyzer->generate_memory_report(buf, sizeof(buf));
				crash_handler::log_crashdump_message(buf);
			}

			if(heap_profiling)
			{
				dump_heap = true;
				throttle = false;
			}
			to_kill = true;
		}
		else if(memory > m_configuration.m_watchdog_warn_memory_usage_mb)
		{
			LOG_NOTICE("watchdog: memory usage " + NumberFormatter::format(memory) + " MiB");
			if(heap_profiling)
			{
				dump_heap = true;
			}
		}

		if(dump_heap)
		{
			ASSERT(heap_profiling);
			dump_heap_profile(uptime_s, throttle);
		}
#endif
	}
	else
	{
		ASSERT(false);
	}

	//
	// Just wait a bit to give time to the other threads to print stacktrace
  	// or to terminate gracefully.
	//
	if(to_kill)
	{
		log_watchdog_report();

 		LOG_FATAL("Killing dragent process");

		sleep(5);
		char line[128];
		snprintf(line, sizeof(line), "watchdog: committing suicide\n");
		crash_handler::log_crashdump_message(line);
		kill(getpid(), SIGKILL);
	}

	uint64_t now = sinsp_utils::get_current_time_ns()/ONE_SECOND_IN_NS;
	for(auto& proc : m_subprocesses_state)
	{
		auto& state = proc.second;
		if(state.valid())
		{
			LOG_DEBUG("valid subprocess: " + proc.first + ", " + to_string(state.memory_used()) + " KiB");
			bool to_kill = false;
			if(m_configuration.m_watchdog_max_memory_usage_subprocesses_mb.find(proc.first) != m_configuration.m_watchdog_max_memory_usage_subprocesses_mb.end() &&
			   state.memory_used()/1024 > m_configuration.m_watchdog_max_memory_usage_subprocesses_mb.at(proc.first))
			{
				g_log->critical("watchdog: " + proc.first + " using " + to_string(state.memory_used()/1024) + "MiB of memory, killing");
				to_kill = true;
			}
			uint64_t last_loop_s = state.last_loop_s();
			uint64_t diff = 0;
			if(now > last_loop_s)
			{
				diff = now - last_loop_s;
			}
			else if(last_loop_s > now)
			{
				LOG_DEBUG("watchdog: " + proc.first + " last activity " + NumberFormatter::format(last_loop_s - now) + " s in the future!");
			}
			if(m_configuration.m_watchdog_subprocesses_timeout_s.find(proc.first) != m_configuration.m_watchdog_subprocesses_timeout_s.end() &&
			   diff > m_configuration.m_watchdog_subprocesses_timeout_s.at(proc.first))
			{
				g_log->critical("watchdog: " + proc.first + " last activity " + NumberFormatter::format(diff) + " s ago");
				// sdchecks implements the SIGHUP handler for handling stalls
				if (proc.first == "sdchecks") {
					kill(state.pid(), SIGHUP);
					state.reset();
				} else {
					to_kill = true;
				}
			}
			if(to_kill)
			{
				kill(state.pid(), SIGKILL);
				state.reset();
			}
		}
	}

	// Pass the (potentially) updated list of subprocesses to the internal metrics module.
	update_subprocesses();
}

void dragent_app::log_watchdog_report() const
{
	LOG_INFO("About to kill dragent. Listing all running processes...");
	m_pool.log_report();

	const uint64_t now_ns = sinsp_utils::get_current_time_ns();
	const int64_t sinsp_worker_diff_ns = now_ns - m_sinsp_worker.get_last_loop_ns();
	const int64_t data_handler_diff_ns = now_ns - m_sinsp_worker.get_sinsp_data_handler()->get_last_loop_ns();

	LOG_INFO("sinsp_worker last activity in  %" PRId64" ms ago", sinsp_worker_diff_ns/1000000);
	LOG_INFO("data_handler last activity in  %" PRId64" ms ago", data_handler_diff_ns/1000000);

	uint64_t now_s = now_ns / ONE_SECOND_IN_NS;
	for(auto& proc : m_subprocesses_state)
	{
		// Sdagent doesn't update this status (and we're currently running on it)
		// so don't bother printing it out.
		if(proc.first == "sdagent")
		{
			continue;
		}

		auto& state = proc.second;
		if(!state.valid())
		{
			continue;
		}

		const int64_t diff_s = now_s - state.last_loop_s();
		LOG_INFO("%s last activity %" PRId64" s ago", proc.first.c_str(), diff_s);
	}
}

void dragent_app::update_subprocesses()
{
	internal_metrics::subprocs_t subprocs;

	for(auto& proc : m_subprocesses_state)
	{
		// The agent might not immediately know the pid for
		// each of the subprocesses, as it may not have read
		// the heartbeat message or gotten the ping
		// response. In that case, just skip the subprocess.

		if(proc.second.pid() > 0)
		{
			subprocs.insert(std::pair<std::string,uint64_t>(proc.second.name(),proc.second.pid()));
		}
	}

	m_internal_metrics->set_subprocesses(subprocs);
}

void dragent_app::update_subprocesses_priority()
{
	for(const dragent_configuration::ProcessValueMap::value_type& value : m_configuration.m_subprocesses_priority)
	{
		// This is the value configured by the yaml file. If it is the
		// default of 0, then we just ignore it.
		if(value.second == 0)
		{
			continue;
		}

		ProcessStateMap::const_iterator state = m_subprocesses_state.find(value.first);
		if(m_subprocesses_state.end() == state)
		{
			LOG_ERROR("Unable to change priority for process %s because pid was not saved",
				  value.first.c_str());
			continue;
		}

		LOG_INFO("Changing %s priority (%d) to %d",
			 value.first.c_str(),
			 state->second.pid(),
			 value.second);

		if(!process_helpers::change_priority(state->second.pid(), value.second))
		{
			LOG_ERROR("Unable to change priority for process %s", value.first.c_str());
		}
	}
}

#ifndef CYGWING_AGENT
void dragent_app::dump_heap_profile(uint64_t uptime_s, bool throttle)
{
	ASSERT(m_configuration.m_watchdog_heap_profiling_interval_s > 0);

	// Dump at most once every m_watchdog_heap_profiling_interval_s seconds
	// unless the caller tells us not to throttle
	if(throttle && (m_last_dump_s == 0 ||
			(uptime_s - m_last_dump_s < m_configuration.m_watchdog_heap_profiling_interval_s)))
	{
		return;
	}

	m_last_dump_s = uptime_s;

	// scripts/parse_heap_profiling.py depends on this format, so
	// don't change or add logs without updating the script
	auto malloc_extension = MallocExtension::instance();
	char heap_stats[2048];
	malloc_extension->GetStats(heap_stats, sizeof(heap_stats));
	static const auto separator = "\n---------------------\n";

	crash_handler::log_crashdump_message(heap_stats);

	string heap_sample;
	malloc_extension->GetHeapSample(&heap_sample);
	crash_handler::log_crashdump_message(separator);
	crash_handler::log_crashdump_message(heap_sample.c_str());
	crash_handler::log_crashdump_message(separator);
}
#endif

void dragent_app::check_for_clean_shutdown()
{
	Path p;
	p.parseDirectory(m_configuration.m_log_dir);
	p.setFileName("running");

	File f(p);
	if(f.exists())
	{
		m_log_reporter.send_report(sinsp_utils::get_current_time_ns());
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

Logger* dragent_app::make_console_channel(AutoPtr<Formatter> formatter)
{
	if(m_configuration.m_min_console_priority != -1)
	{
		AutoPtr<Channel> console_channel(new ConsoleChannel());
		AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));
		Logger& loggerc = Logger::create("DraiosLogC", formatting_channel_console, m_configuration.m_min_console_priority);
		return &loggerc;
	}
	return NULL;
}

Logger* dragent_app::make_event_channel()
{
	if(m_configuration.m_min_event_priority != -1)
	{
		AutoPtr<user_event_channel> event_channel = new user_event_channel();
		Logger& loggere = Logger::create("DraiosLogE", event_channel, m_configuration.m_min_event_priority);
		m_sinsp_worker.set_user_event_queue(event_channel->get_event_queue());
		return &loggere;
	}
	return NULL;
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

	AutoPtr<FileChannel> file_channel(new FileChannel(logsdir));

	file_channel->setProperty("purgeCount", std::to_string(m_configuration.m_log_rotate));
	file_channel->setProperty("rotation", std::to_string(m_configuration.m_max_log_size) + "M");
	file_channel->setProperty("archive", "timestamp");

	AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));
	AutoPtr<Channel> avoid_block(new avoid_block_channel(file_channel, m_configuration.machine_id()));
	AutoPtr<Channel> formatting_channel_file(new FormattingChannel(formatter, avoid_block));

	Logger& loggerf = Logger::create("DraiosLogF", formatting_channel_file, m_configuration.m_min_file_priority);

	g_log = unique_ptr<dragent_logger>(new dragent_logger(&loggerf, make_console_channel(formatter), make_event_channel()));

	g_log->init_user_events_throttling(m_configuration.m_user_events_rate,
					   m_configuration.m_user_max_burst_events);

	g_log->set_internal_metrics(m_internal_metrics);
}

void dragent_app::monitor_files(uint64_t uptime_s)
{
	static SHA1Engine engine;
	bool detected_change = false;

	// init the file states when called for the first time
	if (uptime_s == 0) {
		m_monitored_files.reserve(m_configuration.m_monitor_files.size());
		for (auto const &path : m_configuration.m_monitor_files) {
			std::string digest = "";
			struct stat f_stat;
			if (stat(path.c_str(), &f_stat) == 0) {
				digest = compute_sha1_digest(engine, path);
			} else {
				// if the file doesn't exist, still add an entry with
				// mtime of zero.
				f_stat.st_mtime = 0;
			}

			m_monitored_files.emplace_back(path, f_stat.st_mtime, digest);
		}
	} else {
		// iterate through files that need to be monitored and detect
		// changes to them by first checking for change in mtime and then
		// for changes in contents. if either has changed, update the
		// values in the state.
		for (auto &state : m_monitored_files) {
			struct stat f_stat;
			bool file_exists = stat(state.m_path.c_str(), &f_stat) == 0;
			if (file_exists && (f_stat.st_mtime != state.m_mod_time)) {
				LOG_DEBUG("Modification time changed for file: " + state.m_path);
				state.m_mod_time = f_stat.st_mtime;

				// check modification of contents of the file
				auto new_digest = compute_sha1_digest(engine, state.m_path);
				if(new_digest != state.m_digest)
				{
					LOG_INFO("Detected changes to file: " + state.m_path);
					state.m_digest = new_digest;
					detected_change = true;
				}
			}
			else if (! file_exists && (state.m_mod_time != 0))
			{
				g_log->warning("Detected removal of file: " + state.m_path);
				detected_change = true;
			}
		}
	}

	// exit on detecting changes to files chosen to be monitored and
	// trigger restart of all related processes
	if (detected_change) {
		dragent_configuration::m_terminate = true;
		dragent_configuration::m_config_update = true;
	}
}
