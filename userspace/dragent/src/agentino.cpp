#define __STDC_FORMAT_MACROS
#include "agent-config.h"
#include "agentino.h"
#include "agentino.pb.h"
#include "avoid_block_channel.h"
#include "capture_job_handler.h"
#include "common_logger.h"
#include "configuration.h"
#include "configuration_manager.h"
#include "connection_manager.h"
#include "crash_handler.h"
#include "dragent_memdump_logger.h"
#include "error_handler.h"
#include "exit_code.h"
#include "protobuf_metric_serializer.h"
#include "security_mgr.h"
#include "security_policies_v2_message_handler.h"
#include "sinsp_event_source.h"
#include "type_config.h"
#include "utils.h"

#include <Poco/AutoPtr.h>
#include "Poco/ConsoleChannel.h"
#include <Poco/Formatter.h>
#include <Poco/FormattingChannel.h>                  
#include <Poco/Logger.h>
#include <Poco/NullChannel.h>
#include <Poco/PatternFormatter.h>
#include <Poco/Thread.h>
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionSet.h>

#include <grpc/support/log.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <time.h>

using namespace std;
using namespace dragent;
using namespace Poco;
using Poco::Util::Option;

// local helper functions
namespace
{
COMMON_LOGGER();

type_config<bool> c_wait_until_policies(
    true,
    "should we stall application startup until policies have been acquired? If set to true, "
    "application may not start if no connectivity",
    "agentino",
    "delay_startup_until_policies");

type_config<uint32_t> c_heartbeat_interval_s(2,
                                             "Agentino / agentone heartbeat in seconds",
                                             "agentone_heartbeat");

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

type_config<uint64_t> c_memdump_size(60 * 1024 * 1024, "", "memdump", "size");

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

agentino_app* s_instance = nullptr;

static const std::string task_arn_arg = "aws-fargate-task-arn";

}  // end namespace

agentino_app::agentino_app()
    : m_serializer_queue(MAX_SAMPLE_STORE_SIZE),
      m_transmit_queue(MAX_SAMPLE_STORE_SIZE),
      m_protocol_handler(m_transmit_queue),
      m_log_reporter(m_protocol_handler, &m_configuration),
      m_subprocesses_logger(&m_configuration, &m_log_reporter, m_transmit_queue),
      m_direct(false),
      m_enable_logging(false)
{
	s_instance = this;
}

agentino_app::~agentino_app()
{
	google::protobuf::ShutdownProtobufLibrary();
	s_instance = nullptr;
}

agentino_app* agentino_app::instance()
{
	return s_instance;
}

void agentino_app::initialize(Application& self)
{
	ServerApplication::initialize(self);

	// Poco's argument processing library doesn't seem to actually work, nor is it easily
	// debuggable. So we'll just roll our own. Yes this code is super raw, no I'm not concerned, as
	// this application will in effect never be manually executed by a customer
	for (auto i = argv().begin() + 1; i != argv().end(); ++i)
	{
		if (*i == "--name")
		{
			std::string value = *(++i);
			std::cerr << "Hostname = " << value << "\n";
			m_hostname = value;
		}
		else if (*i == "--container-name")
		{
			std::string value = *(++i);
			std::cerr << "Container name = " << value << "\n";
			m_container_name = value;
			m_metadata.insert(std::pair<std::string, std::string>("aws-container-name", value));
		}
		else if (*i == "--image")
		{
			std::string value = *(++i);
			std::cerr << "Container Image = " << value << "\n";
			m_container_image = value;
			m_metadata.insert(std::pair<std::string, std::string>("aws-container-image", value));
		}
		else if (*i == "--container-id")
		{
			std::string value = *(++i);
			std::cerr << "Container Id = " << value << "\n";
			m_container_id = value;
		}
		else if (*i == "--direct")
		{
			std::cerr << "Communicating directly with backend\n";
			m_direct = true;
		}
		else if (*i == "--conf-file")
		{
			std::string value = *(++i);
			std::cerr << "Config file = " << value << "\n";
			m_conf_file_override_path = value;
		}
		else if (*i == "--debug-logging")
		{
			std::cerr << "Enabling debug logging\n";
			m_enable_logging = true;
		}
		else
		{
			std::string key = (i++)->substr(2);
			std::string value = *i;
			std::cerr << "Metadata key " << key << " = " << value << "\n";
			m_metadata.insert(std::pair<std::string, std::string>(key, value));
		}
	}
}

void agentino_app::uninitialize()
{
	ServerApplication::uninitialize();
}

void agentino_app::defineOptions(Poco::Util::OptionSet& options)
{
	ServerApplication::defineOptions(options);

	// Even though we roll our own argument parser, the failure mode of Poco parser is that it gets
	// the "key" for the argument, but not the value, so we can still use the otions here to
	// validate that the proper options are provide
	options.addOption(Option("name", "", "the name used to identify this agentone to the backend")
	                      .required(true)
	                      .repeatable(false));
	options.addOption(Option("aws-account-id", "", "").repeatable(false));
	options.addOption(Option("aws-region", "", "").repeatable(false));
	options.addOption(Option("aws-az", "", "").repeatable(false));
	options.addOption(Option("aws-fargate-cluster-arn", "", "").repeatable(false));
	options.addOption(Option(task_arn_arg, "", "").repeatable(false));
	options.addOption(Option("image-id", "", "").repeatable(false));
	options.addOption(
	    Option("container-name", "", "the name used to identify this agentone to the backend")
	        .required(true)
	        .repeatable(false));
	options.addOption(Option("image", "", "the name used to identify this agentone to the backend")
	                      .required(true)
	                      .repeatable(false));
	options.addOption(
	    Option("container-id", "", "the name used to identify this agentone to the backend")
	        .required(true)
	        .repeatable(false));
	options.addOption(
	    Option("direct", "", "used to indicate the agentino should talk directly to the backend")
	        .repeatable(false));
	options.addOption(
	    Option("conf-file", "", "used to specify path to config file").repeatable(false));
	options.addOption(
	    Option("debug-logging", "", "used to enable logging for the agentino").repeatable(false));
}

void agentino_app::handleOption(const std::string& name, const std::string& value)
{
	ServerApplication::handleOption(name, value);
}

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
		m_configuration.init(this, true, &m_conf_file_override_path);
	}
	catch (const yaml_configuration_exception& ex)
	{
		std::cerr << "Failed to init sinsp_worker. Exception message: " << ex.what() << '\n';
		running_state::instance().shut_down();
	}

	// Normally we have to do some translation of features from the config for
	// the feature manager, but none of that is supported in agentino, so
	// we pretty much just have to ensure that features are "marked" as enabled or
	// disabled properly
	if (!feature_manager::instance().initialize(feature_manager::agent_variant::AGENT_VARIANT_AGENTINO,
	                                            feature_manager::agent_mode::AGENT_MODE_AGENTINO))
	{
		std::cerr << "Failed to init features." << '\n';
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

	// MAC addresses are not suitable for uniqueness in virtualized environments (and
	// certainly not in fargate), so add hostname, which we ask customers to make unique
	std::string prefix = m_container_id;
	if (m_metadata.find(task_arn_arg) != m_metadata.end())
	{
		prefix += "." + m_metadata.find(task_arn_arg)->second;
	}
	m_configuration.set_machine_id_prefix(prefix);
	LOG_INFO("Using machine prefix %s", prefix.c_str());

	ExitCode exit_code;

	// Add the configured stuff to the agent tags so secure events pick it up
	// In secure's own words: "Should probably have some sort of tag manager, but this
	// will have to do"
	std::string tags =
	    configuration_manager::instance().get_config<std::string>("tags")->get_value();
	for (auto i : m_metadata)
	{
		if (tags != "")
		{
			tags += ",";
		}
		tags += i.first;
		tags += ":";
		tags += i.second;
	}
	configuration_manager::instance().get_mutable_config<std::string>("tags")->set(tags);

	std::vector<std::string> include_labels =
	    configuration_manager::instance()
	        .get_config<std::vector<std::string>>("event_labels.include")
	        ->get_value();
	include_labels.push_back("agent.tag");
	configuration_manager::instance()
	    .get_mutable_config<std::vector<std::string>>("event_labels.include")
	    ->set(include_labels);

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

	// The connection manager doesn't provide a way to guarantee all messages
	// of a given type reach all components, so we have to unfortunately
	// build this stuff first instead of using the dynamic registration
	sinsp_event_source* es =
	    new sinsp_event_source(true, m_container_id, m_container_name, m_container_image);

	std::shared_ptr<timer_thread> the_timer_thread = std::make_shared<timer_thread>();
	m_pool.start(the_timer_thread, m_configuration.m_watchdog_timer_thread_timeout_s);

	// Capture job handler
	// OK, so we need a shared pointer because that's what the event_listener takes,
	// but we need a bare pointer because that's what everything else takes. Just...don't
	// ever delete the shared pointer and we'll be fine.
	auto capture_handler =
	    std::make_shared<capture_job_handler>(&m_configuration,
	                                          &m_transmit_queue,
	                                          the_timer_thread,
	                                          c_memdump_size.get_value());
	es->register_event_listener(capture_handler);
	memdump_logger::register_callback(
	    std::make_shared<dragent_memdump_logger>(capture_handler.get()));

	// Security manager
	auto sm =
	    std::make_shared<security_mgr>(m_configuration.c_root_dir.get_value(), m_protocol_handler);
	sm->init(es->get_sinsp(),
	         m_container_id,         // This doesn't really make sense as the security manager
	                                 // is hard coded to expect an agent container id, which this
	                                 // isn't, really.
	         nullptr,                // infrastructure_state_iface*
	         nullptr,                // secure_k8s_audit_event_sink_iface*
	         capture_handler.get(),  // capture_job_queue_handler*
	         &m_configuration,       // dragent_configuration*
	         nullptr);               // const internal_metrics::sptr_t&
	es->register_event_listener(sm);

	connection_manager* cm = nullptr;

	try
	{
		cm = new connection_manager(
		    {m_configuration.c_root_dir.get_value(),
		     m_configuration.m_server_addr,
		     m_configuration.m_server_port,
		     m_configuration.m_ssl_enabled,
		     m_configuration.m_ssl_ca_cert_paths,
		     m_configuration.m_ssl_ca_certificate,
		     m_configuration.m_promex_enabled,
		     m_configuration.m_promex_connect_url,
		     m_configuration.m_customer_id,
		     m_configuration.machine_id(),
		     m_configuration.c_root_dir.get_value()},
		    &m_transmit_queue,
		    std::initializer_list<dragent_protocol::protocol_version>{5},
		    {{draiosproto::message_type::POLICIES_V2,
		      std::make_shared<security_policies_v2_message_handler>(*sm)}},
		    m_direct ? false : true /* use agentino handshake instead of regular */,
		    m_direct ? nullptr : &handshake_prepare_callback);
		m_pool.start(*cm, m_configuration.m_watchdog_connection_manager_timeout_s);
	}
	catch (const sinsp_exception& e)
	{
		LOG_ERROR("Failed to setup internal components. Exception message: %s", e.what());
		running_state::instance().restart();
	}

	// In cases where we are talking directly to the backend, we need to spin up
	// the proper infrastructure. This should probably be owned by some abstract metrics
	// source, but given it's not doing much, that would likely be overengineered for now
	if (m_direct)
	{
		std::shared_ptr<protobuf_compressor> compressor =
		    protobuf_compressor_factory::get(protocol_compression_method::GZIP);

		auto serializer = new protobuf_metric_serializer(nullptr,
		                                                 m_configuration.c_root_dir.get_value(),
		                                                 m_protocol_handler,
		                                                 &m_serializer_queue,
		                                                 &m_transmit_queue,
		                                                 compressor,
		                                                 cm);
		m_pool.start(*serializer, 10);
	}

	// This is jank. There is a BE bug where it doesn't send policies until
	// it gets metrics messages. So we need to allow the thread to continue to the metrics
	// message loop, while waiting asynchronously for policies to get here
	// and then starting the event source. One might argue maybe the metrics loop
	// should be the async part. Oh well.
	auto event_starter = [es, sm, &capture_handler, this]() {
		if (c_wait_until_policies.get_value())
		{
			while (!sm->has_received_policies() && !running_state::instance().is_terminated())
			{
				usleep(100 * 1000);
			}
		}
		// We can't actually start the event source until now, since we have to
		// guarantee the policies have been loaded by the security manager
		LOG_INFO("Starting event source");
		es->start();
		m_pool.start(*es, watchdog_runnable::NO_TIMEOUT);

		// We can't init the capture job handler until the event source has been started
		capture_handler->init(es->get_sinsp());
		m_pool.start(*capture_handler, watchdog_runnable::NO_TIMEOUT);
	};
	auto throwaway = std::async(std::launch::async, event_starter);

	auto& state = running_state::instance();

	uint64_t uptime_s = 0;

	///////////////////////////////
	// Main exec loop
	// This is where the dragent thread sits while the other threads do the
	// actual work involved in making the agent work. It sits here checking
	// the watch dog and monitoring config files until someone decides it's
	// time to terminate.
	//////////////////////////////
	int index = 0;
	uint64_t last_heartbeat = 0;
	uint64_t last_flush_time_ns = sinsp_utils::get_current_time_ns();
	uint64_t flush_time_interval_ns = 10 * ONE_SECOND_IN_NS;
	while (!state.is_terminated())
	{
		watchdog_check(uptime_s);

		if (m_direct)
		{
			uint64_t cur_time_ns = sinsp_utils::get_current_time_ns();
			if ((cur_time_ns > last_flush_time_ns) &&
			    ((cur_time_ns - last_flush_time_ns) >= flush_time_interval_ns))
			{
				last_flush_time_ns = cur_time_ns;

				auto metrics = make_unique<draiosproto::metrics>();
				metrics->set_timestamp_ns(cur_time_ns);
				metrics->set_index(++index);
				metrics->set_machine_id(m_configuration.machine_id());
				metrics->set_customer_id(m_configuration.m_customer_id);
				metrics->mutable_hostinfo()->set_hostname(m_hostname);
				metrics->set_version(AGENT_VERSION);

				// This makes the agentino direct show up as a container
				// so we can scope policies to it
				auto container = metrics->add_containers();
				container->set_id(m_container_id);
				container->set_image(m_container_image);
				container->set_name(m_container_name);

				// Report this single instance of the agentino
				internal_metrics::write_metric(metrics->mutable_protos()->mutable_statsd(),
				                               "serverlessdragent.workload_agent.count",
				                               draiosproto::STATSD_GAUGE,
				                               1);

				m_serializer_queue.put(
				    std::make_shared<flush_data_message>(cur_time_ns,
				                                         nullptr,
				                                         std::move(metrics),
				                                         0,
				                                         0,
				                                         0,
				                                         1,
				                                         0));
			}
		}
		else
		{
			if (uptime_s - last_heartbeat >= c_heartbeat_interval_s.get_value())
			{
				send_heartbeat();
				last_heartbeat = uptime_s;
			}
		}

		Poco::Thread::sleep(1000);
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

void agentino_app::build_metadata_message(draiosproto::agentino_metadata& msg) const
{
	msg.set_container_id(m_container_id);
	msg.set_container_image(m_container_image);
	msg.set_container_name(m_container_name);
	for (auto& i : m_metadata)
	{
		(*msg.mutable_other_metadata())[i.first] = i.second;
	}
}

void agentino_app::send_heartbeat()
{
	// A heartbeat is just a header
	auto hb_buf = std::make_shared<serialized_buffer>();
	hb_buf->message_type = draiosproto::message_type::AGENTINO_HEARTBEAT;
	hb_buf->ts_ns = time(nullptr) * ONE_SECOND_IN_NS;
	m_transmit_queue.put(hb_buf, protocol_queue::BQ_PRIORITY_LOW);
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

void agentino_app::initialize_logging()
{
	AutoPtr<Poco::Channel> null_channel(new Poco::NullChannel());
	Logger& loggerf = Logger::create("DraiosLogF", null_channel, -1);
	AutoPtr<Formatter> formatter(new Poco::PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P.%I, %p, %t"));
	AutoPtr<Channel> console_channel(new Poco::ConsoleChannel());
	AutoPtr<Channel> formatting_channel_console(new Poco::FormattingChannel(formatter, console_channel));
	// Create console logger, choosing logger level as follows:
	// - If console logging is enabled via --debug_logging command line parameter,
	//   specify most permissive logger level (PRIO_TRACE).  This allows all
	//   messages to flow.  Log severity of messages actually emitted through the
	//   channel will be managed by the consumers of the channel.
	// - Otherwise, choose logger level -1 to disable console logging.
	Logger& loggerc = Logger::create("DraiosLogC",
		                         formatting_channel_console,
					 ((m_enable_logging) ? Message::PRIO_TRACE : -1));

	g_log =
	    unique_ptr<common_logger>(new common_logger(&loggerf,
	                                                &loggerc,
	                                                m_configuration.m_min_file_priority,
	                                                m_configuration.m_min_console_priority,
	                                                c_log_file_component_overrides.get_value(),
	                                                c_log_console_component_overrides.get_value()));

	LOG_INFO("agentino starting (version " + string(AGENT_VERSION) + ")");
	common_logger_cache::log_and_purge();
}

void agentino_app::handshake_prepare_callback(void* handshake_data)
{
	draiosproto::agentino_handshake* agentino_handshake_data =
	    static_cast<draiosproto::agentino_handshake*>(handshake_data);

	if (!agentino_handshake_data)
	{
		LOG_ERROR("Invalid handshake data type. Handshake data may be invalid.");
		return;
	}

	s_instance->build_metadata_message(*agentino_handshake_data->mutable_metadata());
}
