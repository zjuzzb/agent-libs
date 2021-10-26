#include <configuration.h>
#include <fcntl.h>
#include <fstream>
#include <chrono>
#include <memory>
#include <sinsp.h>
#include <sys/types.h>

#include <benchmark/benchmark.h>
#include <gperftools/profiler.h>
#include <Poco/AutoPtr.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/FormattingChannel.h>
#include <Poco/Logger.h>
#include <Poco/NullChannel.h>
#include <Poco/PatternFormatter.h>

#include <google/protobuf/io/zero_copy_stream_impl.h>

#include <container_config.h>
#include <scoped_config.h>
#include <security_config.h>
#include <test_security_stub.h>
#include <protocol_handler.h>
#include <security_mgr.h>
#include "common_logger.h"

COMMON_LOGGER();

using namespace std;
using namespace libsanalyzer;
using namespace Poco;

class security_mgr_benchmarks : public ::benchmark::Fixture
{

	// With the 10k packet size and our relatively slow
	// reading of responses, we need a bigger than normal
	// queue length.
	const uint32_t DEFAULT_QUEUE_LEN = 1000;

public:
	/* path to the cointerface unix socket domain */
	security_mgr_benchmarks()
	    : m_transmit_queue(DEFAULT_QUEUE_LEN),
	      m_data_handler(m_transmit_queue),
	      m_mgr("./resources", m_data_handler)
	{
	}

protected:
	void SetUp(::benchmark::State& state)
	{
		// dragent_configuration::init() takes an app, but I
		// don't see it used anywhere.
		m_configuration.init(NULL, false);

		m_configuration.m_capture_dragent_events = true;

		// so long as this is in scope when we initialize the feature manager, we're
		// good. It's annoying that we can't easily keep it in scope for the whole test,
		// but such is life.
		test_helpers::scoped_config<bool> memdump("memdump.enabled", false);
		test_helpers::scoped_config<bool> secure("security.enabled", true);

		m_configuration.m_max_sysdig_captures = 10;

		security_config::instance().set_k8s_audit_server_enabled(false);
		m_configuration.m_falco_engine_sampling_multiplier = 0;
		m_configuration.m_containers_labels_max_len = 100;

		// The (global) logger only needs to be set up once
		if (!g_log)
		{
			AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));

			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(
			    new FormattingChannel(formatter, console_channel));

			// To enable debug logging, change the tailing -1 to Message::Priority::PRIO_DEBUG
			Logger& loggerc = Logger::create("DraiosLogC", formatting_channel_console, -1);

			AutoPtr<Channel> null_channel(new Poco::NullChannel());
			Logger& nullc = Logger::create("NullC", null_channel, -1);

			g_log = std::unique_ptr<common_logger>(new common_logger(&nullc, &loggerc));
		}

		m_inspector = new sinsp();
		m_inspector->set_debug_mode(true);
		m_inspector->set_internal_events_mode(true);
		m_inspector->set_hostname_and_port_resolution_mode(false);

		m_k8s_audit_event_sink = new test_secure_k8s_audit_event_sink();
		m_infra_state = new test_infrastructure_state();
		m_internal_metrics = std::make_shared<internal_metrics>();

		// Container id doesn't really matter for the benchmark.
		m_agent_container_id = "";

		m_mgr.init(m_inspector,
			   m_agent_container_id,
			   m_infra_state,
			   m_k8s_audit_event_sink,
			   m_capture_job_queue_handler,
			   &m_configuration,
			   m_internal_metrics);
	}

	void TearDown()
	{
		delete m_inspector;
		delete m_infra_state;
		delete m_k8s_audit_event_sink;
	}

	void read_capture_file(::benchmark::State& state, const std::string &filename, bool collect_profile, uint64_t iterations=1)
	{
		sinsp_evt* ev;
		int rc;
		uint64_t nevts = 0;
		std::clock_t start, end;

		std::string errstr;

		if (!m_mgr.request_load_policies_v2_file("./resources/security_policies_messages/default_prod_trimmed_policies_v2.txt", errstr)) {
			std::string msg = "Could not load policies file: " + errstr;
			state.SkipWithError(msg.c_str());
		}

		start = std::clock();

		if(collect_profile)
		{
			ProfilerStart("./benchmark-securitymgr.prof");
		}

		for(uint64_t i=0; i < iterations; i++)
		{
			try {
				std::clock_t open_start, open_end;
				open_start = std::clock();

				m_inspector->open(filename);
				open_end = std::clock();

				LOG_INFO("Done opening: %f ms", 1000.0 * (open_end-open_start) / CLOCKS_PER_SEC);

				LOG_DEBUG("Reading events from file: " + filename);
			}
			catch(sinsp_exception &e)
			{
				std::string msg = "Could not open capture file " + filename + " for reading: " + e.what();
				state.SkipWithError(msg.c_str());
			}

			while(1)
			{
				rc = m_inspector->next(&ev);

				if(rc == SCAP_TIMEOUT)
				{
					continue;
				}
				else if(rc == SCAP_EOF)
				{
					break;
				}
				else if(rc != SCAP_SUCCESS)
				{
					std::string msg = "Error " + m_inspector->getlasterr() + " reading capture file";
					state.SkipWithError(msg.c_str());
				}

				m_mgr.process_event(ev);
				nevts++;
			}

			m_inspector->close();
		}

		end = std::clock();
		if(collect_profile)
		{
			ProfilerStop();
		}

		uint64_t elapsed_ms = (1000.0 * (end-start) / CLOCKS_PER_SEC);
		std::string msg = string("Done. ") + std::to_string(nevts) + " events read in " + std::to_string(elapsed_ms) + " ms. (" + std::to_string(nevts*1000.0/elapsed_ms) + " evts/sec)\n";
		std::cerr << "[          ] [ INFO ] " << msg;

		LOG_DEBUG(msg);
	}

	protocol_queue m_transmit_queue;
	sinsp* m_inspector;
	std::string m_agent_container_id;
	test_infrastructure_state *m_infra_state;
	test_secure_k8s_audit_event_sink *m_k8s_audit_event_sink;
	internal_metrics::sptr_t m_internal_metrics;
	protocol_handler m_data_handler;
	security_mgr m_mgr;
	test_capture_job_queue_handler *m_capture_job_queue_handler;
	dragent_configuration m_configuration;
};

BENCHMARK_DEFINE_F(security_mgr_benchmarks, filesystem_network_tracefile)(benchmark::State& st)
{
	for(auto _ : st)
	{
		// These files are available on s3 at
		// s3://download.draios.com/test/security_policies_benchmark_traces.zip
		read_capture_file(st, string("./stress-ng-filesystem-network.scap"), false, 10);
	}
}
BENCHMARK_REGISTER_F(security_mgr_benchmarks, filesystem_network_tracefile);

BENCHMARK_DEFINE_F(security_mgr_benchmarks, filesystem_network_tracefile_container)(benchmark::State& st)
{
	for(auto _ : st)
	{
		// These files are available on s3 at
		// s3://download.draios.com/test/security_policies_benchmark_traces.zip
		read_capture_file(st, string("stress-ng-filesystem-network-containers.scap"), false, 10);
	}
}
BENCHMARK_REGISTER_F(security_mgr_benchmarks, filesystem_network_tracefile_container);
