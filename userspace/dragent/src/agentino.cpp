#include "agentino.h"
#include "avoid_block_channel.h"
#include "common_logger.h"
#include "configuration.h"
#include "configuration_manager.h"
#include "connection_manager.h"
#include "crash_handler.h"
#include "error_handler.h"
#include "exit_code.h"
#include "globally_readable_file_channel.h"
#include "security_policies_v2_message_handler.h"
#include "type_config.h"
#include "utils.h"

#include <gperftools/malloc_extension.h>
#include <grpc/support/log.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <time.h>

using namespace std;
using namespace dragent;

// local helper functions
namespace
{
COMMON_LOGGER();

// Number of seconds (of uptime) after which to update the priority of the
// processes. This was chosen arbitrarily to be after the processes had time
// to start.
const uint32_t TIME_TO_UPDATE_PROCESS_PRIORITY = 5;

static void g_signal_callback(int sig)
{
	running_state::instance().shut_down();
}

static void g_usr_signal_callback(int sig)
{
	dragent_configuration::m_signal_dump = true;
}

static void g_usr2_signal_callback(int sig)
{
	dragent_configuration::m_send_log_report = true;
}

static void g_trace_signal_callback(int sig)
{
	dragent_configuration::m_enable_trace = true;
}

}  // end namespace

agentino_app::agentino_app()
    : m_transmit_queue(MAX_SAMPLE_STORE_SIZE),
      m_protocol_handler(m_transmit_queue),
      m_log_reporter(m_protocol_handler, &m_configuration),
      m_subprocesses_logger(&m_configuration, &m_log_reporter, m_transmit_queue)
{
}

agentino_app::~agentino_app()
{
	google::protobuf::ShutdownProtobufLibrary();
}

void agentino_app::initialize(Application& self)
{
	ServerApplication::initialize(self);
}

void agentino_app::uninitialize()
{
	ServerApplication::uninitialize();
}

void agentino_app::defineOptions(OptionSet& options)
{
	ServerApplication::defineOptions(options);
}

void agentino_app::handleOption(const std::string& name, const std::string& value)
{
	ServerApplication::handleOption(name, value);
}

void agentino_app::displayHelp() {}

static void dragent_gpr_log(gpr_log_func_args* args)
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

int agentino_app::main(const std::vector<std::string>& args)
{
	//
	// Set up logging with grpc.
	//
	gpr_set_log_function(dragent_gpr_log);

	//
	// Make sure the agent never creates world-writable files
	//
	umask(0027);

	try
	{
		m_configuration.init(this, true);
	}
	catch (const yaml_configuration_exception& ex)
	{
		std::cerr << "Failed to init sinsp_worker. Exception message: " << ex.what() << '\n';
		running_state::instance().shut_down();
	}

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

	// Ignore SIGSTKFLT. It's used to enable tracing (sent from watchdog to sinsp_worker)
	// but the default action is to kill the process. Ignore this signal before setting
	// a handler in sinsp_worker so that `killall -STKFLT dragent` can be used for testing
	// and for manually enabling tracing
	signal(SIGSTKFLT, SIG_IGN);

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
	sa.sa_handler = g_trace_signal_callback;
	sigaction(SIGSTKFLT, &sa, NULL);

	return sdagent_main();
}

void agentino_app::setup_coredumps()
{
	struct rlimit core_limits = {};
	if (m_configuration.m_enable_coredump)
	{
		core_limits.rlim_cur = RLIM_INFINITY;
		core_limits.rlim_max = RLIM_INFINITY;
	}
	else
	{
		core_limits.rlim_cur = 0;
		core_limits.rlim_max = 0;
	}
	errno = 0;
	if (setrlimit(RLIMIT_CORE, &core_limits) != 0)
	{
		LOG_WARNING("Cannot set coredump limits: %s", strerror(errno));
	}
	else
	{
		LOG_DEBUG("Successfully set coredump limits");
	}
}

int agentino_app::sdagent_main()
{
	Poco::ErrorHandler::set(&m_error_handler);

	initialize_logging();

	LOG_INFO("agentino starting (version " + string(AGENT_VERSION) + ")");

	setup_coredumps();

	//
	// Load the configuration
	//
	m_configuration.refresh_machine_id();
	if (dragent_configuration::c_enable_aws_metadata.get_value())
	{
		m_configuration.refresh_aws_metadata();
	}
	m_configuration.print_configuration();

	if (m_configuration.load_error())
	{
		LOG_ERROR("Unable to load configuration file");
		return exit_code::SHUT_DOWN;
	}

	ExitCode exit_code;

	//
	// Start threads
	//
	if (!m_configuration.m_config_test)
	{
		m_pool.start(m_subprocesses_logger,
		             m_configuration.m_watchdog_subprocesses_logger_timeout_s);
	}

	////////////////
	// Here is where the top-level objects are created.
	////////////////
	connection_manager* cm = nullptr;
	try
	{
		cm = new connection_manager(&m_configuration,
		                            &m_transmit_queue,
		                            std::initializer_list<dragent_protocol::protocol_version>{4, 5},
		                            {
		                                // TODO add policies v2 handler
		                            });
		m_pool.start(*cm, m_configuration.m_watchdog_connection_manager_timeout_s);
	}
	catch (const sinsp_exception& e)
	{
		LOG_ERROR("Failed to setup internal components. Exception message: %s", e.what());
		running_state::instance().restart();
	}

	auto& state = running_state::instance();

	uint64_t uptime_s = 0;

	///////////////////////////////
	// Main exec loop
	// This is where the dragent thread sits while the other threads do the
	// actual work involved in making the agent work. It sits here checking
	// the watch dog and monitoring config files until someone decides it's
	// time to terminate.
	//////////////////////////////
	while (!state.is_terminated())
	{
		watchdog_check(uptime_s);

		Thread::sleep(1000);
		++uptime_s;
	}

	//
	// Begin cleanup
	//
	if (!state.is_terminated())
	{
		state.shut_down();
	}

	exit_code = ExitCode(state.exit_code());

	//
	// Shut. Down. Everything.
	//
	// This will stop everything in the default pool
	m_pool.stop_all();

	LOG_INFO("Terminating");
	return exit_code;
}

bool agentino_app::timeout_expired(int64_t last_activity_age_ns,
                                   uint64_t timeout_s,
                                   const char* label,
                                   const char* tail)
{
	if (timeout_s == 0 || last_activity_age_ns <= static_cast<int64_t>(timeout_s) * 1000000000LL)
	{
		return false;
	}

	char line[128];
	snprintf(line,
	         sizeof(line),
	         "watchdog: Detected %s stall, last activity %" PRId64 " ns ago%s\n",
	         label,
	         last_activity_age_ns,
	         tail);
	crash_handler::log_crashdump_message(line);

	return true;
}

void agentino_app::watchdog_check(uint64_t uptime_s)
{
	auto unhealthy = m_pool.unhealthy_list();
	if (!unhealthy.empty())
	{
		for (const watchdog_runnable_pool::unhealthy_runnable& current : unhealthy)
		{
			if (current.health == watchdog_runnable::health::TIMEOUT)
			{
				char line[128];
				snprintf(line,
				         sizeof(line),
				         "watchdog: Detected %s stall, last activity %" PRId64
				         " ms ago with timeout %" PRId64 "\n",
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
	}
}

Logger* agentino_app::make_console_channel(AutoPtr<Formatter> formatter)
{
	if (m_configuration.m_min_console_priority != -1)
	{
		AutoPtr<Channel> console_channel(new ConsoleChannel());
		AutoPtr<Channel> formatting_channel_console(
		    new FormattingChannel(formatter, console_channel));
		Logger& loggerc = Logger::create("DraiosLogC",
		                                 formatting_channel_console,
		                                 m_configuration.m_min_console_priority);
		return &loggerc;
	}
	return NULL;
}

void agentino_app::initialize_logging()
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

	//
	// Setup the logging
	//

	AutoPtr<globally_readable_file_channel> file_channel(
	    new globally_readable_file_channel(logsdir, m_configuration.m_globally_readable_log_files));

	file_channel->setProperty("purgeCount", std::to_string(m_configuration.m_log_rotate));
	file_channel->setProperty("rotation", std::to_string(m_configuration.m_max_log_size) + "M");
	file_channel->setProperty("archive", "timestamp");

	AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P.%I, %p, %t"));
	AutoPtr<Channel> avoid_block(
	    new avoid_block_channel(file_channel, m_configuration.machine_id()));
	AutoPtr<Channel> formatting_channel_file(new FormattingChannel(formatter, avoid_block));

	Logger& loggerf =
	    Logger::create("DraiosLogF", formatting_channel_file, m_configuration.m_min_file_priority);

	g_log = unique_ptr<common_logger>(new common_logger(&loggerf, make_console_channel(formatter)));
}
