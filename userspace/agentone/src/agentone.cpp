#include "agentino_manager.h"
#include "agentone.h"
#include "async_aggregator.h"
#include "avoid_block_channel.h"
#include "common_logger.h"
#include "config_data_message_handler.h"
#include "config_data_rest_request_handler.h"
#include "config_rest_request_handler.h"
#include "configlist_rest_request_handler.h"
#include "configuration.h"
#include "configuration_manager.h"
#include "connection_manager.h"
#include "container_manager.h"
#include "crash_handler.h"
#include "dragent_memdump_logger.h"
#include "dragent_user_event_callback.h"
#include "dump_request_start_message_handler.h"
#include "dump_request_stop_message_handler.h"
#include "error_handler.h"
#include "exit_code.h"
#include "fault_rest_request_handler.h"
#include "faultlist_rest_request_handler.h"
#include "file_rest_request_handler.h"
#include "globally_readable_file_channel.h"
#include "memdump_logger.h"
#include "metric_serializer.h"
#include "monitor.h"
#include "null_message_handler.h"
#include "post_aggregated_metrics_rest_request_handler.h"
#include "pre_aggregated_metrics_rest_request_handler.h"
#include "process_helpers.h"
#include "protobuf_compression.h"
#include "protobuf_metric_serializer.h"
#include "rest_request_handler_factory.h"
#include "rest_server.h"
#include "running_state.h"
#include "security_compliance_calendar_message_handler.h"
#include "security_compliance_run_message_handler.h"
#include "security_orchestrator_events_message_handler.h"
#include "security_policies_v2_message_handler.h"
#include "type_config.h"
#include "user_event_channel.h"
#include "utils.h"
#include "webpage_rest_request_handler.h"

#include <gperftools/malloc_extension.h>
#include <grpc/support/log.h>
#include <memory>
#include <sched.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <time.h>

// local helper functions
namespace
{
COMMON_LOGGER();
type_config<bool>::ptr c_rest_feature_flag =
    type_config_builder<bool>(false,
                              "Feature flag to turn on the REST server.",
                              "feature_flag_rest_server")
        .hidden()
        .mutable_only_in_internal_build()
        .build();

type_config<uint16_t>::ptr c_rest_port =
    type_config_builder<uint16_t>(24482,
                                  "TCP port on which the Agent REST server listens for connections",
                                  "rest_server",
                                  "tcp_port")
        .hidden()  // Hidden until feature is released
        .build();

type_config<uint64_t> c_serializer_timeout_s(10,
                                             "Watchdog timeout for the serializer thread",
                                             "serializer_timeout");

type_config<bool> c_10s_flush_enabled(true, "Enable agent-side aggregation", "10s_flush_enable");

type_config<uint64_t> c_watchdog_max_memory_usage_mb(512,
                                                     "maximum memory usage for watchdog",
                                                     "watchdog",
                                                     "max_memory_usage_mb");

type_config<uint64_t> c_watchdog_warn_memory_usage_mb(256,
                                                      "warn memory usage for watchdog",
                                                      "watchdog",
                                                      "warn_memory_usage_mb");

type_config<std::vector<std::string>> c_log_file_component_overrides(
					{},
					"Component level overrides to global log level",
					"log",
					"file_priority_by_component");

type_config<std::vector<std::string>> c_log_console_component_overrides(
					{},
					"Component level overrides to global console log level",
					"log",
					"console_priority_by_component");

string compute_sha1_digest(SHA1Engine& engine, const string& path)
{
	engine.reset();
	ifstream fs(path);
	char readbuf[4096];

	while (fs.good())
	{
		fs.read(readbuf, sizeof(readbuf));
		engine.update(readbuf, fs.gcount());
	}

	return DigestEngine::digestToHex(engine.digest());
}

// Number of seconds (of uptime) after which to update the priority of the
// processes. This was chosen arbitrarily to be after the processes had time
// to start.
const uint32_t TIME_TO_UPDATE_PROCESS_PRIORITY = 5;

static void g_signal_callback(int sig)
{
	dragent::running_state::instance().shut_down();
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

std::unique_ptr<librest::rest_server> s_rest_server;

/**
 * Enable the REST server (if enabled); otherwise, do nothing.
 */
void enable_rest_server(dragent_configuration& configuration)
{
	if (!c_rest_feature_flag->get_value())
	{
		return;
	}

	if (s_rest_server)
	{
		return;
	}

	Poco::SharedPtr<librest::rest_request_handler_factory> factory(
	    new librest::rest_request_handler_factory());

	// Register path handlers with the factory...
	factory->register_path_handler<dragent::configlist_rest_request_handler>();
	factory->register_path_handler<dragent::config_rest_request_handler>();
	factory->register_path_handler<dragent::post_aggregated_metrics_rest_request_handler>();
	factory->register_path_handler<dragent::pre_aggregated_metrics_rest_request_handler>();
	factory->register_path_handler<dragent::config_data_rest_request_handler>();
	factory->register_path_handler<dragent::webpage_rest_request_handler>();
	factory->register_path_handler<dragent::file_rest_request_handler>();
#if defined(FAULT_INJECTION_ENABLED)
	factory->register_path_handler<dragent::faultlist_rest_request_handler>();
	factory->register_path_handler<dragent::fault_rest_request_handler>();
#endif  // defined(FAULT_INJECTION_ENABLED)

	dragent::config_data_rest_request_handler::set_config_data_message_handler(
	    std::make_shared<dragent::config_data_message_handler>(configuration));

	s_rest_server = make_unique<librest::rest_server>(factory, c_rest_port->get_value());
	s_rest_server->start();
}

/**
 * Disable the REST server (if enabled); otherwise, do nothing.
 */
void disable_rest_server()
{
	if (s_rest_server.get() == nullptr)
	{
		return;
	}

	s_rest_server->stop();
	s_rest_server.reset();
}

}  // end namespace

agentone_app::agentone_app()
    : m_unshare_ipcns(true),
      m_serializer_queue(MAX_SAMPLE_STORE_SIZE),
      m_transmit_queue(MAX_SAMPLE_STORE_SIZE),
      m_protocol_handler(m_transmit_queue),
      m_log_reporter(m_protocol_handler, &m_configuration),
      m_subprocesses_logger(&m_configuration, &m_log_reporter, m_transmit_queue),
      m_last_dump_s(0)
{
}

agentone_app::~agentone_app()
{
	std::shared_ptr<dragent::config_data_message_handler> ptr;

	dragent::config_data_rest_request_handler::set_config_data_message_handler(ptr);
	google::protobuf::ShutdownProtobufLibrary();
}

void agentone_app::initialize(Application& self)
{
	ServerApplication::initialize(self);

	// Poco's argument processing library doesn't seem to actually work, nor is it easily
	// debuggable. So we'll just roll our own. Yes this code is super raw, no I'm not concerned, as
	// this application will in effect never be manually executed by a customer
	for (auto i = argv().begin() + 1; i != argv().end(); ++i)
	{
		if (*i == "--noipcns")
		{
			std::cerr << "Setting no-icpns flag\n";
			m_unshare_ipcns = false;
		}
		else if (*i == "--name")
		{
			i++;
			if (i == argv().end())
			{
				std::cerr << "Invalid arguments. No argument provided to \"--name\"\n";
				exit(EXIT_FAILURE);
			}
			std::string value = *i;
			std::cerr << "Hostname = " << value << "\n";
			m_hostname = value;
		}
	}
}

void agentone_app::uninitialize()
{
	ServerApplication::uninitialize();
}

void agentone_app::defineOptions(OptionSet& options)
{
	ServerApplication::defineOptions(options);

	// This is used when we restart the agent from the same monitor process
	options.addOption(Option("noipcns", "", "keep IPC namespace (for internal use)")
	                      .required(false)
	                      .repeatable(false));

	options.addOption(Option("name", "", "the name used to identify this agentone to the backend")
	                      .required(true)
	                      .repeatable(false));
}

void agentone_app::handleOption(const std::string& name, const std::string& value)
{
	ServerApplication::handleOption(name, value);
}

void agentone_app::displayHelp() {}

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

int agentone_app::main(const std::vector<std::string>& args)
{
	//
	// Set up logging with grpc.
	//
	gpr_set_log_function(dragent_gpr_log);

	//
	// Make sure the agent never creates world-writable files
	//
	umask(0027);

	//
	// Never move this further down!
	// It's important that the pidfile gets created immediately!
	//
	string me = config().getString("application.path", CMAKE_INSTALL_PREFIX "/bin/dragent");
	monitor monitor_process(m_pidfile, move(me), {"--noipcns", "--name", m_hostname});

	try
	{
		m_configuration.init(this, true);
	}
	catch (const yaml_configuration_exception& ex)
	{
		std::cerr << "Failed to init sinsp_worker. Exception message: " << ex.what() << '\n';
		dragent::running_state::instance().shut_down();
	}

	m_had_unclean_shutdown = remove_file_if_exists(m_configuration.m_log_dir, K8S_PROBE_FILE);

	// Ensure the feature manager has validatead the config
	if (!feature_manager::instance().initialize(feature_manager::agent_mode::AGENT_MODE_AGENTONE))
	{
		std::cerr << "Failed to init features." << '\n';
		dragent::running_state::instance().shut_down();
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

	if (m_unshare_ipcns && unshare(CLONE_NEWIPC) < 0)
	{
		std::cerr << "Cannot create private IPC namespace: " << strerror(errno) << '\n';
	}

	struct rlimit msgqueue_rlimits = {.rlim_cur = m_configuration.m_rlimit_msgqueue,
	                                  .rlim_max = m_configuration.m_rlimit_msgqueue};
	if (setrlimit(RLIMIT_MSGQUEUE, &msgqueue_rlimits) != 0)
	{
		std::cerr << "Cannot set msgqueue limits: " << strerror(errno) << '\n';
	}

	process_helpers::subprocess_cpu_cgroup default_cpu_cgroup("/default",
	                                                          c_default_cpu_shares.get_value(),
	                                                          c_default_cpu_quota.get_value());
	default_cpu_cgroup.create();

	process_helpers::subprocess_cpu_cgroup cointerface_cpu_cgroup(
	    "/cointerface",
	    c_cointerface_cpu_shares.get_value(),
	    c_cointerface_cpu_quota.get_value());
	cointerface_cpu_cgroup.create();

	// Add our main process
	monitor_process.emplace_process(
	    "sdagent",
	    [=]() {
		    default_cpu_cgroup.enter();

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
		    sa.sa_handler = g_trace_signal_callback;
		    sigaction(SIGSTKFLT, &sa, NULL);

		    if (crash_handler::initialize() == false)
		    {
			    ASSERT(false);
		    }

		    return this->sdagent_main();
	    },
	    true);

	if (feature_manager::instance().get_enabled(COINTERFACE))
	{
		m_cointerface_pipes = make_unique<pipe_manager>();
		auto* state = &m_subprocesses_state["cointerface"];
		state->set_name("cointerface");
		m_subprocesses_logger.add_logfd(m_cointerface_pipes->get_err_fd(),
		                                cointerface_parser(),
		                                state);
		m_subprocesses_logger.add_logfd(m_cointerface_pipes->get_out_fd(),
		                                cointerface_parser(),
		                                state);
		monitor_process.emplace_process("cointerface", [=]() {
			cointerface_cpu_cgroup.enter();
			m_cointerface_pipes->attach_child_stdio();

			if (m_configuration.m_cointerface_cpu_profile_enabled)
			{
				string logfile = m_configuration.m_log_dir + "/cpu.prof";
				execl((m_configuration.c_root_dir.get_value() + "/bin/cointerface").c_str(),
				      "cointerface",
				      "-cpuprofile",
				      logfile.c_str(),
				      "-eventspertrace",
				      to_string(m_configuration.m_cointerface_events_per_profile).c_str(),
				      "-keeptraces",
				      to_string(m_configuration.m_cointerface_total_profiles).c_str(),
				      "-memprofile",
				      m_configuration.m_cointerface_mem_profile_enabled ? "true" : "false",
				      (char*)NULL);
			}
			else
			{
				execl((m_configuration.c_root_dir.get_value() + "/bin/cointerface").c_str(),
				      "cointerface",
				      (char*)NULL);
			}

			return (EXIT_FAILURE);
		});
	}

	monitor_process.set_cleanup_function([=]() {
		this->m_cointerface_pipes.reset();
		coclient::cleanup();
		default_cpu_cgroup.remove(c_cgroup_cleanup_timeout_ms.get_value());
		cointerface_cpu_cgroup.remove(c_cgroup_cleanup_timeout_ms.get_value());
	});

	return monitor_process.run();
}

void agentone_app::setup_coredumps()
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

bool agentone_app::create_file(const std::string& dir, const std::string& file_name)
{
	Path p;
	p.parseDirectory(dir).setFileName(file_name);

	File f(p);

	return f.createFile();
}

bool agentone_app::remove_file_if_exists(const std::string& dir, const std::string& file_name)
{
	bool ret = false;
	Path p;
	p.parseDirectory(dir).setFileName(file_name);

	File f(p);
	if (f.exists())
	{
		ret = true;
		f.remove();
	}
	return ret;
}

int agentone_app::sdagent_main()
{
	Poco::ErrorHandler::set(&m_error_handler);

	initialize_logging();

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
		return dragent::exit_code::SHUT_DOWN;
	}

	// Set the configured default compression method
	protobuf_compressor_factory::set_default(protocol_handler::c_compression_enabled.get_value()
	                                             ? protocol_compression_method::GZIP
	                                             : protocol_compression_method::NONE);

	//
	// Gather identifying information about this agent instance
	//
	if (m_configuration.m_customer_id.empty())
	{
		LOG_ERROR("customerid not specified");
		return dragent::exit_code::RESTART;
	}

	if (m_configuration.machine_id() == "00:00:00:00:00:00")
	{
		LOG_ERROR("Invalid machine_id detected");
		return dragent::exit_code::RESTART;
	}

	// MAC addresses are not suitable for uniqueness in virtualized environments (and
	// certainly not in fargate), so add hostname, which we ask customers to make unique
	m_configuration.set_machine_id_prefix(m_hostname);

	//
	// Set up the memory watchdog
	//
	if (m_configuration.m_watchdog_enabled)
	{
		check_for_clean_shutdown();

		if (m_configuration.m_watchdog_heap_profiling_interval_s > 0)
		{
			// Heap profiling needs TCMALLOC_SAMPLE_PARAMETER to be set to a non-zero value
			// XXX hacky way to ensure that TCMALLOC_SAMPLE_PARAMETER was set correctly
			int32_t sample_period = 0;
			void** unused_ret = MallocExtension::instance()->ReadStackTraces(&sample_period);
			delete[] unused_ret;

			// If the env var isn't set, disable the dumping interval because it'll be garbage
			// data
			if (sample_period <= 0)
			{
				LOG_ERROR(
				    "Disabling watchdog:heap_profiling_interval_s because "
				    "TCMALLOC_SAMPLE_PARAMETER is not set");
				m_configuration.m_watchdog_heap_profiling_interval_s = 0;
				ASSERT(false);
			}
		}
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

	//
	// Get the default compression values
	//
	// In the 10s flush world, compression is negotiated between the agent and
	// the collector. The configuration values determine 1. What values are
	// supported in the negotiation and 2. What values are illegal.
	//
	// These default values are what the agent will use going forward in the
	// legacy case and will be the basis of the negotiation in the protocol v5
	// case.
	//
	std::shared_ptr<protobuf_compressor> compressor =
	    protobuf_compressor_factory::get(protobuf_compressor_factory::get_default());

	////////////////
	// Here is where the top-level objects are created. These are the objects
	// that interact with the sysdig component and deliver flush data to the
	// connection_manager for delivery to the backend.
	////////////////

	connection_manager* cm = nullptr;
	dragent::metric_serializer* serializer = nullptr;
	agentone::container_manager* container_manager_instance = nullptr;
	std::shared_ptr<agentone::agentino_manager> agentino_manager_instance = nullptr;
	auto null_handler = std::make_shared<dragent::null_message_handler>();
	try
	{
		// Create and set up the container manager and agentino manager.
		// Creating them here first so that they can register their message
		// handlers on CM startup, ensuring that the agentino manager doesn't
		// miss any policy messages coming from the collector.
		// SMAGENT-2871: Initializing these two objects first means they can't
		//               negotiate any parameters on connection. A callback
		//               will help.
		container_manager_instance = new agentone::container_manager();
		agentino_manager_instance =
		    std::make_shared<agentone::agentino_manager>(m_protocol_handler,
		                                                 *container_manager_instance,
		                                                 m_configuration.machine_id(),
		                                                 m_configuration.m_customer_id);
		LOG_INFO("Created and started Container and Agentino Managers.");

		cm = new connection_manager(
		{
			m_configuration.c_root_dir.get_value(),
			m_configuration.m_server_addr,
			m_configuration.m_server_port,
			m_configuration.m_ssl_enabled,
			m_configuration.m_ssl_ca_cert_paths,
			m_configuration.m_ssl_ca_certificate,
			m_configuration.m_promex_enabled,
			m_configuration.m_promex_connect_url,
			m_configuration.m_customer_id,
			m_configuration.machine_id(),
			m_configuration.c_root_dir.get_value()
		},
		&m_transmit_queue,
		c_10s_flush_enabled.get_value()
			? std::initializer_list<dragent_protocol::protocol_version>{4, 5}
			: std::initializer_list<dragent_protocol::protocol_version>{4},
		{
			{draiosproto::message_type::CONFIG_DATA,
			   std::make_shared<dragent::config_data_message_handler>(m_configuration)},
			{draiosproto::message_type::AGGREGATION_CONTEXT,
			   dragent::aggregator_limits::global_limits},
			{draiosproto::message_type::POLICIES_V2, agentino_manager_instance},
			// These message types are not supported, but the backend
			// might still send them. They're not an error condition, so
			// just send them into the void
			{draiosproto::message_type::DUMP_REQUEST_START, null_handler},
			{draiosproto::message_type::DUMP_REQUEST_STOP, null_handler},
			{draiosproto::message_type::CONFIG_DATA, null_handler},
			{draiosproto::message_type::POLICIES, null_handler},
			{draiosproto::message_type::COMP_CALENDAR, null_handler},
			{draiosproto::message_type::COMP_RUN, null_handler},
			{draiosproto::message_type::ORCHESTRATOR_EVENTS, null_handler},
			{draiosproto::message_type::BASELINES, null_handler}
		});
		m_pool.start(*cm, m_configuration.m_watchdog_connection_manager_timeout_s);

		k8s_limits::sptr_t the_k8s_limits = k8s_limits::build(m_configuration.m_k8s_filter,
		                                                      m_configuration.m_excess_k8s_log,
		                                                      m_configuration.m_k8s_cache_size);

		// Create and set up the serializer
		auto s = new dragent::protobuf_metric_serializer(nullptr,
		                                                 m_configuration.c_root_dir.get_value(),
		                                                 m_protocol_handler,
		                                                 &m_serializer_queue,
		                                                 &m_transmit_queue,
		                                                 compressor,
		                                                 cm);
		m_pool.start(*s, c_serializer_timeout_s.get_value());
		serializer = s;
		LOG_INFO("Created and started serializer");
	}
	catch (const sinsp_exception& e)
	{
		LOG_ERROR("Failed to setup internal components. Exception message: %s", e.what());
		dragent::running_state::instance().restart();
	}

	auto& state = dragent::running_state::instance();

	uint64_t uptime_s = 0;

	///////////////////////////////
	// Main exec loop
	// This is where the dragent thread sits while the other threads do the
	// actual work involved in making the agent work. It sits here checking
	// the watch dog and monitoring config files until someone decides it's
	// time to terminate.
	//////////////////////////////
	int index = 0;

	uint64_t last_flush_time_ns = sinsp_utils::get_current_time_ns();
	uint64_t flush_time_interval_ns = (c_10s_flush_enabled.get_value() ? 10 : 1) * ONE_SECOND_IN_NS;
	while (!state.is_terminated())
	{
		if (m_configuration.m_watchdog_enabled)
		{
			watchdog_check(uptime_s);
		}

		if ((m_configuration.m_monitor_files_freq_sec > 0) &&
		    (uptime_s % m_configuration.m_monitor_files_freq_sec == 0))
		{
			monitor_files(uptime_s);
		}

		setup_startup_probe(*cm);

		uint64_t cur_time_ns = sinsp_utils::get_current_time_ns();
		if ((cur_time_ns > last_flush_time_ns) &&
		    ((cur_time_ns - last_flush_time_ns) >= flush_time_interval_ns))
		{
			last_flush_time_ns = cur_time_ns;

			auto metrics = make_unique<draiosproto::metrics>();
			metrics->set_timestamp_ns(time(nullptr) * ONE_SECOND_IN_NS);
			metrics->set_index(++index);
			metrics->set_machine_id(m_configuration.machine_id());
			metrics->set_customer_id(m_configuration.m_customer_id);
			metrics->mutable_hostinfo()->set_hostname(m_hostname);

			// Report number of agentinos attached
			uint32_t num_agentino_connections = agentino_manager_instance->get_num_connections();
			internal_metrics::write_metric(metrics->mutable_protos()->mutable_statsd(),
			                               "serverlessdragent.workload_agent.count",
			                               draiosproto::STATSD_GAUGE,
			                               num_agentino_connections);

			agentone::container_serializer<draiosproto::metrics> cs;
			cs.serialize(*container_manager_instance, *metrics);

			m_serializer_queue.put(
			    std::make_shared<flush_data_message>(time(nullptr) * ONE_SECOND_IN_NS,
			                                         nullptr,
			                                         std::move(metrics),
			                                         0,
			                                         0,
			                                         0,
			                                         1,
			                                         0));
		}
		Thread::sleep(1000);
		++uptime_s;
	}

	//
	// Begin cleanup
	//
	if (m_configuration.m_watchdog_heap_profiling_interval_s > 0)
	{
		// Do a throttled dump in case we don't have anything recent
		dump_heap_profile(uptime_s, true);
	}

	if (!state.is_terminated())
	{
		state.shut_down();
	}

	exit_code = ExitCode(state.exit_code());

	//
	// Shut. Down. Everything.
	//
	
	// Must be destructed first to stop the thread pool in roughly LIFO order. Ideally
	// this would all be in a single thread pool organizing it all, but such is life.
	agentino_manager_instance = nullptr;

	// This will stop everything in the default pool
	m_pool.stop_all();

	if (serializer)
	{
		serializer->stop();
	}

	if (m_configuration.m_watchdog_enabled)
	{
		mark_clean_shutdown();
	}

	LOG_INFO("Terminating");
	memdump_logger::register_callback(nullptr);
	return exit_code;
}

bool agentone_app::timeout_expired(int64_t last_activity_age_ns,
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

void agentone_app::watchdog_check(uint64_t uptime_s)
{
	bool to_kill = false;

	if (m_protocol_handler.get_last_loop_ns() != 0)
	{
		int64_t diff_ns =
		    sinsp_utils::get_current_time_ns() - m_protocol_handler.get_last_loop_ns();

		if (diff_ns < 0)
		{
			static ratelimit r;
			r.run([&] {
				LOG_WARNING("watchdog: sinsp_data_handler last activity " +
				            NumberFormatter::format(-diff_ns) + " ns in the future");
			});
		}

		if (timeout_expired(diff_ns,
		                    m_configuration.m_watchdog_sinsp_data_handler_timeout_s,
		                    "sinsp_data_handler",
		                    ""))
		{
			to_kill = true;
		}
	}

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

		to_kill = true;
	}

	if (feature_manager::instance().get_enabled(COINTERFACE))
	{
		if (!m_coclient)
		{
			// Actually allocate the coclient object
			m_coclient = make_unique<coclient>(m_configuration.c_root_dir.get_value());
		}

		// Ping every 5 seconds. If it's ever more than
		// watchdog_cointerface_timeout_s seconds from a pong,
		// declare it stuck and kill it.
		//
		// Note that we use the time from the ping as the
		// liveness time. So if cointerface somehow falls
		// behind by more than the timeout, it gets declared
		// stuck.

		m_cointerface_ping_interval.run(
		    [this]() {
			    coclient::response_cb_t callback = [this](bool successful,
			                                              google::protobuf::Message* response_msg) {
				    if (successful)
				    {
					    sdc_internal::pong* pong = (sdc_internal::pong*)response_msg;
					    m_subprocesses_state["cointerface"].reset(pong->pid(),
					                                              pong->memory_used(),
					                                              pong->token());
				    }
			    };

			    m_coclient->ping(time(NULL), callback);
		    },
		    sinsp_utils::get_current_time_ns());

		// Try to read any responses
		m_coclient->process_queue();
	}

	// We now have started all the subprocesses, so pass them to internal_metrics
	update_subprocesses();

	// We only want this to happen once
	if (TIME_TO_UPDATE_PROCESS_PRIORITY == uptime_s)
	{
		update_subprocesses_priority();
	}

	uint64_t memory;
	if (dragent_configuration::get_memory_usage_mb(&memory))
	{
#if _DEBUG
		LOG_DEBUG("watchdog: memory usage " + NumberFormatter::format(memory) + " MiB");
#endif

		const bool heap_profiling = (m_configuration.m_watchdog_heap_profiling_interval_s > 0);
		bool dump_heap = false;
		bool throttle = true;

		// Once the worker is looping, we can dump the initial
		// memory state for diffing against later dumps
		if (heap_profiling && m_last_dump_s == 0)
		{
			LOG_INFO("watchdog: heap profiling enabled, dumping initial memory state");
			dump_heap = true;
			throttle = false;
		}

		uint64_t watchdog_max = c_watchdog_max_memory_usage_mb.get_value();
		uint64_t watchdog_warn = c_watchdog_warn_memory_usage_mb.get_value();
		if (watchdog_warn > watchdog_max)
		{
			LOG_WARNING(
			    "watchdog:warn_memory_usage_mb cannot be higher than "
			    "watchdog:max_memory_usage_mb. "
			    "Lowering Warn.");
			watchdog_warn = watchdog_max;
		}

		if (memory > watchdog_max)
		{
			char line[128];
			snprintf(line, sizeof(line), "watchdog: Fatal memory usage, %" PRId64 " MiB\n", memory);
			crash_handler::log_crashdump_message(line);

			if (heap_profiling)
			{
				dump_heap = true;
				throttle = false;
			}
			to_kill = true;
		}
		else if (memory > watchdog_warn)
		{
			LOG_NOTICE("watchdog: memory usage " + NumberFormatter::format(memory) + " MiB");
			if (heap_profiling)
			{
				dump_heap = true;
			}
		}

		if (dump_heap)
		{
			ASSERT(heap_profiling);
			dump_heap_profile(uptime_s, throttle);
		}
	}
	else
	{
		ASSERT(false);
	}

	if (to_kill)
	{
		log_watchdog_report();

		LOG_FATAL("Restarting dragent process immediately.");

		// Wait a bit to give time to the other threads to print stacktrace
		// or to terminate gracefully.
		sleep(5);
		char line[128];
		snprintf(line, sizeof(line), "watchdog: restarting immediately\n");
		crash_handler::log_crashdump_message(line);

		// Kill the process immediately. Monitor will restart it.
		//
		// The SIGKILL will immediately be handled by the operating system and
		// dragent will not get any more cpu time. After the operating system
		// handles the kill, the monitor will see that the dragent process died.
		// The monitor only has specific behavior for individual exit() codes, not
		// death by signals, so this gets handled in the default way, i.e. by
		// restarting the process.
		kill(getpid(), SIGKILL);
	}

	uint64_t now = sinsp_utils::get_current_time_ns() / ONE_SECOND_IN_NS;
	for (auto& proc : m_subprocesses_state)
	{
		auto& state = proc.second;
		if (state.valid())
		{
			LOG_DEBUG("valid subprocess: " + proc.first + ", " + to_string(state.memory_used()) +
			          " KiB");
			bool subprocess_to_kill = false;
			if (m_configuration.m_watchdog_max_memory_usage_subprocesses_mb.find(proc.first) !=
			        m_configuration.m_watchdog_max_memory_usage_subprocesses_mb.end() &&
			    state.memory_used() / 1024 >
			        m_configuration.m_watchdog_max_memory_usage_subprocesses_mb.at(proc.first))
			{
				LOG_CRITICAL("watchdog: " + proc.first + " using " +
				             to_string(state.memory_used() / 1024) + "MiB of memory, killing");
				subprocess_to_kill = true;
			}
			uint64_t last_loop_s = state.last_loop_s();
			uint64_t diff = 0;
			if (now > last_loop_s)
			{
				diff = now - last_loop_s;
			}
			else if (last_loop_s > now)
			{
				LOG_DEBUG("watchdog: " + proc.first + " last activity " +
				          NumberFormatter::format(last_loop_s - now) + " s in the future!");
			}
			if (m_configuration.m_watchdog_subprocesses_timeout_s.find(proc.first) !=
			        m_configuration.m_watchdog_subprocesses_timeout_s.end() &&
			    diff > m_configuration.m_watchdog_subprocesses_timeout_s.at(proc.first))
			{
				LOG_CRITICAL("watchdog: " + proc.first + " last activity " +
				             NumberFormatter::format(diff) + " s ago");
				// sdchecks implements the SIGHUP handler for handling stalls
				if (proc.first == "sdchecks")
				{
					kill(state.pid(), SIGHUP);
					state.reset();
				}
				else
				{
					subprocess_to_kill = true;
				}
			}
			if (subprocess_to_kill)
			{
				kill(state.pid(), SIGKILL);
				state.reset();
			}
		}
	}

	// Pass the (potentially) updated list of subprocesses to the internal metrics module.
	update_subprocesses();
}

void agentone_app::log_watchdog_report() const
{
	LOG_INFO("About to kill dragent. Listing all running processes...");
	m_pool.log_report();

	const uint64_t now_ns = sinsp_utils::get_current_time_ns();
	const int64_t data_handler_diff_ns = now_ns - m_protocol_handler.get_last_loop_ns();

	LOG_INFO("data_handler last activity in  %" PRId64 " ms ago", data_handler_diff_ns / 1000000);

	uint64_t now_s = now_ns / ONE_SECOND_IN_NS;
	for (auto& proc : m_subprocesses_state)
	{
		// Sdagent doesn't update this status (and we're currently running on it)
		// so don't bother printing it out.
		if (proc.first == "sdagent")
		{
			continue;
		}

		auto& state = proc.second;
		if (!state.valid())
		{
			continue;
		}

		const int64_t diff_s = now_s - state.last_loop_s();
		LOG_INFO("%s last activity %" PRId64 " s ago", proc.first.c_str(), diff_s);
	}
}

void agentone_app::update_subprocesses()
{
	internal_metrics::subprocs_t subprocs;

	for (auto& proc : m_subprocesses_state)
	{
		// The agent might not immediately know the pid for
		// each of the subprocesses, as it may not have read
		// the heartbeat message or gotten the ping
		// response. In that case, just skip the subprocess.

		if (proc.second.pid() > 0)
		{
			subprocs.insert(
			    std::pair<std::string, uint64_t>(proc.second.name(), proc.second.pid()));
		}
	}
}

void agentone_app::update_subprocesses_priority()
{
	for (const dragent_configuration::ProcessValueMap::value_type& value :
	     m_configuration.m_subprocesses_priority)
	{
		// This is the value configured by the yaml file. If it is the
		// default of 0, then we just ignore it.
		if (value.second == 0)
		{
			continue;
		}

		ProcessStateMap::const_iterator state = m_subprocesses_state.find(value.first);
		if (m_subprocesses_state.end() == state)
		{
			LOG_ERROR("Unable to change priority for process %s because pid was not saved",
			          value.first.c_str());
			continue;
		}

		LOG_INFO("Changing %s priority (%d) to %d",
		         value.first.c_str(),
		         state->second.pid(),
		         value.second);

		if (!process_helpers::change_priority(state->second.pid(), value.second))
		{
			LOG_ERROR("Unable to change priority for process %s", value.first.c_str());
		}
	}
}

void agentone_app::dump_heap_profile(uint64_t uptime_s, bool throttle)
{
	ASSERT(m_configuration.m_watchdog_heap_profiling_interval_s > 0);

	// Dump at most once every m_watchdog_heap_profiling_interval_s seconds
	// unless the caller tells us not to throttle
	if (throttle && (m_last_dump_s == 0 || (uptime_s - m_last_dump_s <
	                                        m_configuration.m_watchdog_heap_profiling_interval_s)))
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

void agentone_app::check_for_clean_shutdown()
{
	if (m_had_unclean_shutdown)
	{
		LOG_DEBUG("Detected an unclean shutdown. Reporting to the backend");
		m_log_reporter.send_report(m_transmit_queue, sinsp_utils::get_current_time_ns());
	}
}

void agentone_app::mark_clean_shutdown()
{
	remove_file_if_exists(m_configuration.m_log_dir, K8S_PROBE_FILE);
}

Logger* agentone_app::make_event_channel()
{
	if (m_configuration.m_min_event_priority != -1)
	{
		AutoPtr<user_event_channel> event_channel = new user_event_channel();
		Logger& loggere =
		    Logger::create("DraiosLogE", event_channel, m_configuration.m_min_event_priority);
		// TODO fix this
		// m_sinsp_worker.set_user_event_queue(event_channel->get_event_queue());
		return &loggere;
	}
	return NULL;
}

void agentone_app::initialize_logging()
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

	AutoPtr<dragent::globally_readable_file_channel> file_channel(
	    new dragent::globally_readable_file_channel(logsdir,
	                                                m_configuration.m_globally_readable_log_files));

	file_channel->setProperty("purgeCount", std::to_string(m_configuration.m_log_rotate));
	file_channel->setProperty("rotation", std::to_string(m_configuration.m_max_log_size) + "M");
	file_channel->setProperty("archive", "timestamp");

	AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P.%I, %p, %t"));
	AutoPtr<Channel> avoid_block(
	    new avoid_block_channel(file_channel, m_configuration.machine_id()));
	AutoPtr<Channel> formatting_channel_file(new FormattingChannel(formatter, avoid_block));

	// Create file logger at most permissive level (trace). This allows all messages to flow.
	// Log severity of messages actually emitted through the channel will be managed by
	// the consumers of the channel
	Logger& loggerf = Logger::create("DraiosLogF", formatting_channel_file, Message::PRIO_TRACE);

	// Note: We are not responsible for managing the memory where
	//       event_logger points; no free()/delete needed
	Logger* const event_logger = make_event_channel();
	if (event_logger != nullptr)
	{
		user_event_logger::register_callback(
		    std::make_shared<dragent_user_event_callback>(*event_logger,
		                                                  m_configuration.m_user_events_rate,
		                                                  m_configuration.m_user_max_burst_events));
	}

	AutoPtr<Channel> console_channel(new ConsoleChannel());
	AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));
	// Create console logger at most permissive level (trace). This allows all messages to flow.
	// Log severity of messages actually emitted through the channel will be managed by
	// the consumers of the channel
	Logger& loggerc =
	    Logger::create("DraiosLogC", formatting_channel_console, Message::PRIO_TRACE);

	g_log = unique_ptr<common_logger>(new common_logger(&loggerf,
	                                                    &loggerc,
	                                                    m_configuration.m_min_file_priority,
	                                                    m_configuration.m_min_console_priority,
	                                                    c_log_file_component_overrides.get_value(),
	                                                    c_log_console_component_overrides.get_value()));

	LOG_INFO("Agentone starting (version " + string(AGENT_VERSION) + ")");
	common_logger_cache::log_and_purge();
}

void agentone_app::monitor_files(uint64_t uptime_s)
{
	static SHA1Engine engine;
	bool detected_change = false;

	// init the file states when called for the first time
	if (uptime_s == 0)
	{
		m_monitored_files.reserve(m_configuration.m_monitor_files.size());
		for (auto const& path : m_configuration.m_monitor_files)
		{
			std::string digest = "";
			struct stat f_stat;
			if (stat(path.c_str(), &f_stat) == 0)
			{
				digest = compute_sha1_digest(engine, path);
			}
			else
			{
				// if the file doesn't exist, still add an entry with
				// mtime of zero.
				f_stat.st_mtime = 0;
			}

			m_monitored_files.emplace_back(path, f_stat.st_mtime, digest);
		}
	}
	else
	{
		// iterate through files that need to be monitored and detect
		// changes to them by first checking for change in mtime and then
		// for changes in contents. if either has changed, update the
		// values in the state.
		for (auto& state : m_monitored_files)
		{
			struct stat f_stat;
			bool file_exists = stat(state.m_path.c_str(), &f_stat) == 0;
			if (file_exists && (f_stat.st_mtime != state.m_mod_time))
			{
				LOG_DEBUG("Modification time changed for file: " + state.m_path);
				state.m_mod_time = f_stat.st_mtime;

				// check modification of contents of the file
				auto new_digest = compute_sha1_digest(engine, state.m_path);
				if (new_digest != state.m_digest)
				{
					LOG_INFO("Detected changes to file: " + state.m_path);
					state.m_digest = new_digest;
					detected_change = true;
				}
			}
			else if (!file_exists && (state.m_mod_time != 0))
			{
				LOG_WARNING("Detected removal of file: " + state.m_path);
				detected_change = true;
			}
		}
	}

	// exit on detecting changes to files chosen to be monitored and
	// trigger restart of all related processes
	if (detected_change)
	{
		dragent::running_state::instance().restart_for_config_update();
	}
}

void agentone_app::setup_startup_probe(const connection_manager& cm)
{
	if (!m_startup_probe_set)
	{
		if (cm.is_connected())
		{
			m_startup_probe_set = create_file(m_configuration.m_log_dir, K8S_PROBE_FILE);
		}
	}
}

const std::string agentone_app::K8S_PROBE_FILE = "running";
