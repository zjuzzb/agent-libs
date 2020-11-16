#include "container_config.h"
#include "docker_utils.h"
#include "scoped_config.h"
#include "security_config.h"
#include "sys_call_test.h"
#include "test_security_stub.h"
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/NullChannel.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include <configuration.h>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <gtest.h>
#include <chrono>
#include <map>
#include <memory>
#include <metrics.h>
#include <protocol.h>
#include <running_state.h>
#include <scap.h>
#include <sinsp.h>
#include <sinsp_worker.h>
#include <sys/quota.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>

using namespace std;
using namespace libsanalyzer;

class test_helper
{
public:
	static bool send_all(internal_metrics& im, draiosproto::statsd_info* statsd_info)
	{
		return im.send_all(statsd_info, 0);
	}
};

class security_policy_error_handler : public Poco::ErrorHandler
{
public:
	security_policy_error_handler(){};

	void exception(const Poco::Exception& exc)
	{
		dragent::running_state::instance().shut_down();
		FAIL() << "Got Poco::Exception " << exc.displayText();
	}

	void exception(const std::exception& exc)
	{
		dragent::running_state::instance().shut_down();
		FAIL() << "Got std::exception " << exc.what();
	}

	void exception()
	{
		dragent::running_state::instance().shut_down();
		FAIL() << "Got unknown exception";
	}
};

// Performs a role similar to sinsp_worker, but much simpler. Only
// contains the inspector loop, security_mgr, and a sinsp_data_handler
// to accept policy events.
namespace
{
uncompressed_sample_handler_dummy g_sample_handler;
audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_audit_handler;
null_secure_profiling_handler g_secure_profiling_handler;
null_secure_netsec_handler g_secure_netsec_handler;

class test_sinsp_worker : public Runnable
{
public:
	test_sinsp_worker(sinsp* inspector,
	                  security_mgr* mgr,
	                  std::string policies_file)
	    : m_ready(false),
	      m_mgr(mgr),
	      m_inspector(inspector),
	      m_policies_file(policies_file),
	      m_policies_loaded(false)
	{
		m_inspector->set_log_callback(common_logger::sinsp_logger_callback);
		m_inspector->start_dropping_mode(1);
	}

	~test_sinsp_worker() { m_inspector->set_log_callback(0); }

	void run()
	{
		g_log->information("test_sinsp_worker: Starting");

		while (!dragent::running_state::instance().is_terminated())
		{
			int32_t res;
			sinsp_evt* ev;

			res = m_inspector->next(&ev);

			if (res == SCAP_TIMEOUT)
			{
				continue;
			}
			else if (res == SCAP_EOF)
			{
				break;
			}
			else if (res != SCAP_SUCCESS)
			{
				cerr << "res = " << res << endl;
				throw sinsp_exception(m_inspector->getlasterr().c_str());
			}

			// At this point infra state has been initialized with
			// host information, so we can load policies.
			if (!m_policies_loaded)
			{
				std::string errstr;
				ASSERT_TRUE(m_mgr->request_load_policies_v2_file(m_policies_file.c_str(), errstr))
					<< "Could not load v2 security policies file: " + errstr;
				m_policies_loaded = true;
			}

			m_mgr->process_event(ev);

			if (!m_ready)
			{
				g_log->information("test_sinsp_worker: ready");
				string filter =
				    "(proc.name = tests or proc.aname = tests) or container.id = "
				    "aec4c703604b4504df03108eef12e8256870eca8aabcb251855a35bf4f0337f1 or "
				    "container.name in (sec_ut, stop_me_docker_test, kill_me_docker_test, capture_me_docker_test, fs-root-image, "
				    "blacklisted_image, non_alpine, busybox_some_tag, denyme, "
				    "inout_test, fs_usecase, mycurl, overlap_test, helloworld, syscall-whitelist) or container.image "
				    "= swarm_service_ut_image:latest";
				m_inspector->set_filter(filter.c_str());
				m_ready = true;
			}
		}

		scap_stats st;
		m_inspector->get_capture_stats(&st);

		g_log->information("sinsp_worker: Terminating. events=" + to_string(st.n_evts) +
		                   " dropped=" + to_string(st.n_drops + st.n_drops_buffer));
	}

	atomic<bool> m_ready;

private:
	security_mgr* m_mgr;
	sinsp* m_inspector;
	std::string m_policies_file;
	bool m_policies_loaded;
};
}  // namespace

bool check_output_fields(map<string, string>& received, map<string, string>& expected)
{
	// the following fields *may* be unknown in the unit tests, so if they aren't in the expected
	// set they are removed before the check
	std::set<string> unknowns =
	    {"container.id", "proc.name", "proc.cmdline", "fd.cip", "fd.sip", "fd.cport"};
	for (const auto& u : unknowns)
	{
		if (expected.find(u) == expected.end())
		{
			received.erase(u);
		}
	}

	// in recent versions, glibc open use openat
	if (received.find("evt.type") != received.end() && received["evt.type"] == "openat" &&
	    expected.find("evt.type") != expected.end() && expected["evt.type"] == "open")
	{
		received["evt.type"] = "open";
	}

	return received.size() == expected.size() &&
	       std::equal(received.begin(), received.end(), expected.begin());
}

std::ostream& operator<<(std::ostream& os, const map<string, string>& map)
{
	os << "[";

	for (auto& pair : map)
	{
		os << "(" << pair.first << "," << pair.second << ") ";
	}

	os << "]";

	return os;
}

class security_policies_v2_test : public testing::Test
{
	// With the 10k packet size and our relatively slow
	// reading of responses, we need a bigger than normal
	// queue length.
	const uint32_t DEFAULT_QUEUE_LEN = 1000;

public:
	/* path to the cointerface unix socket domain */
	security_policies_v2_test()
	    : m_flush_queue(DEFAULT_QUEUE_LEN),
	      m_transmit_queue(DEFAULT_QUEUE_LEN),
	      m_data_handler(m_transmit_queue),
	      m_mgr("./resources", m_data_handler)
	{
	}

protected:
	virtual std::string policies_file()
	{
		return string("./resources/security_policies_messages/all_policy_v2_types.txt");
	}

	void SetUpTest(const string& fake_cri_socket = "")
	{
		// dragent_configuration::init() takes an app, but I
		// don't see it used anywhere.
		m_configuration.init(NULL, false);
		m_configuration.m_capture_dragent_events = true;

		std::ostringstream os;
		os << "security:" << std::endl <<
			"  enabled: true" << std::endl <<
			"memdump:" << std::endl <<
			"  enabled: true" << std::endl;

		if (!fake_cri_socket.empty())
		{
			os << "cri:" << std::endl <<
				"  socket_path: " << fake_cri_socket << std::endl;
		}

		configuration_manager::instance().init_config(os.str());
		feature_manager::instance().initialize();

		m_configuration.m_max_sysdig_captures = 10;
		security_config::instance().set_policies_v2_file(policies_file());
		security_config::instance().set_k8s_audit_server_enabled(m_enable_k8s_audit_server);
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
		m_internal_metrics = std::make_shared<internal_metrics>();

		if (!fake_cri_socket.empty())
		{
			m_inspector->set_cri_socket_path(fake_cri_socket);
		}

		m_analyzer = new sinsp_analyzer(m_inspector,
		                                "/opt/draios",
		                                m_internal_metrics,
		                                g_audit_handler,
		                                g_secure_audit_handler,
		                                g_secure_profiling_handler,
		                                g_secure_netsec_handler,
		                                &m_flush_queue,
		                                []() -> bool { return true; });
		m_inspector->register_external_event_processor(*m_analyzer);

		m_analyzer->get_configuration()->set_machine_id(m_configuration.machine_id());

		if (m_k8s_cluster_name != "")
		{
			m_analyzer->get_configuration()->set_k8s_cluster_name(m_k8s_cluster_name);
		}

		m_analyzer->set_containers_labels_max_len(m_configuration.m_containers_labels_max_len);

		m_inspector->set_debug_mode(true);
		m_inspector->set_internal_events_mode(true);
		m_inspector->set_hostname_and_port_resolution_mode(false);

		m_inspector->open("");

		m_capture_job_queue_handler = new test_capture_job_queue_handler();

		m_k8s_audit_event_sink = new test_secure_k8s_audit_event_sink();

		m_mgr.init(m_inspector, m_analyzer->mutable_infra_state(), m_k8s_audit_event_sink, m_capture_job_queue_handler, &m_configuration, m_internal_metrics);

		m_sinsp_worker = new test_sinsp_worker(m_inspector,
		                                       &m_mgr,
						       security_config::instance().get_policies_v2_file());

		Poco::ErrorHandler::set(&m_error_handler);

		ThreadPool::defaultPool().start(*m_sinsp_worker, "test_sinsp_worker");

		// Wait for the test_sinsp_worker to be ready.
		while (!m_sinsp_worker->m_ready)
		{
			Poco::Thread::sleep(100);
		}
	}

	void createFile(const char* path)
	{
		fstream fs;
		fs.open(path, ios::out);
		fs.close();
	}

	void initFiles()
	{
		// create files/dirs used to test fs policies
		createFile("/tmp/sample-sensitive-file-1.txt");
		createFile("/tmp/sample-sensitive-file-2.txt");
		createFile("/tmp/sample-sensitive-file-3.txt");
		createFile("/tmp/sample-sensitive-file-4.txt");
		createFile("/tmp/sample-sensitive-file-5.txt");
		createFile("/tmp/matchlist-order.txt");
		createFile("/tmp/matchlist-order-2.txt");
		createFile("/tmp/overall-order-1.txt");
		createFile("/tmp/overall-order-2.txt");
		createFile("/tmp/overall-order-3.txt");
		mkdir("/tmp/one", 0777);
		mkdir("/tmp/one/two", 0777);
		mkdir("/tmp/one/two/three", 0777);
		mkdir("/tmp/two", 0777);
		mkdir("/tmp/two/three", 0777);
		createFile("/tmp/second");
		createFile("/tmp/third");
	}

	virtual void SetUp()
	{
		initFiles();

		SetUpTest();
	}

	void TearDownTest()
	{
		dragent::running_state::instance().shut_down();

		ThreadPool::defaultPool().joinAll();
		ThreadPool::defaultPool().stopAll();

		delete m_capture_job_queue_handler;
		delete m_sinsp_worker;
		delete m_inspector;
		delete m_analyzer;
		delete m_k8s_audit_event_sink;

		dragent::running_state::instance().reset_for_test();
	}

	virtual void TearDown()
	{
		TearDownTest();

		remove("/tmp/sample-sensitive-file-1.txt");
		remove("/tmp/sample-sensitive-file-2.txt");
		remove("/tmp/sample-sensitive-file-3.txt");
		remove("/tmp/sample-sensitive-file-4.txt");
		remove("/tmp/sample-sensitive-file-5.txt");
		remove("/tmp/matchlist-order.txt");
		remove("/tmp/matchlist-order-2.txt");
		remove("/tmp/overall-order-1.txt");
		remove("/tmp/overall-order-2.txt");
		remove("/tmp/overall-order-3.txt");
		rmdir("/tmp/one/two/three");
		rmdir("/tmp/one/two");
		rmdir("/tmp/one");
		rmdir("/tmp/two/three");
		rmdir("/tmp/two");
		remove("/tmp/second");
		remove("/tmp/third");
	}

public:
	struct expected_policy_event
	{
		typedef enum
		{
			HOST_OR_CONTAINER = 0,
			CONTAINER_ONLY,
			HOST_ONLY
		} event_scope_t;

		expected_policy_event(uint64_t p, draiosproto::policy_type ot, map<string, string> ofk)
		    : policy_id(p),
		      output_type(ot),
		      output_fields(ofk),
		      event_scope(HOST_OR_CONTAINER),
		      check_v2act_result(false)
		{
		}
		expected_policy_event(uint64_t p,
		                      draiosproto::policy_type ot,
		                      map<string, string> ofk,
		                      event_scope_t scope)
		    : policy_id(p),
		      output_type(ot),
		      output_fields(ofk),
		      event_scope(scope),
		      check_v2act_result(false)
		{
		}
		expected_policy_event(uint64_t p,
		                      draiosproto::policy_type ot,
		                      map<string, string> ofk,
		                      event_scope_t scope,
				      bool check_v2action_result,
				      int atype,
				      bool asuccessful,
				      std::string aerrmsg)

		    : policy_id(p),
		      output_type(ot),
		      output_fields(ofk),
		      event_scope(scope),
		      check_v2act_result(check_v2action_result),
		      act_type(atype),
		      act_successful(asuccessful),
		      act_errmsg(aerrmsg)
		{
		}

		uint64_t policy_id;
		draiosproto::policy_type output_type;
		map<string, string> output_fields;
		event_scope_t event_scope;

		// Note, only checking a single actionv2 result
		bool check_v2act_result;

		int act_type;
		bool act_successful;
		string act_errmsg;
	};

	bool capture_jobs_empty()
	{
		return m_capture_job_queue_handler->m_job_requests.empty();
	}

	void check_policy_events(std::vector<expected_policy_event>& expected)
	{
		std::vector<bool> seen;
		seen.assign(expected.size(), false);

		for (uint32_t attempts = 0; attempts < 50; attempts++)
		{
			draiosproto::message_type mtype;
			unique_ptr<::google::protobuf::Message> msg = NULL;
			draiosproto::policy_events* pe;

			get_next_msg(100, mtype, msg);
			if (msg == NULL)
			{
				continue;
			}

			ASSERT_EQ(mtype, draiosproto::message_type::POLICY_EVENTS);
			pe = (draiosproto::policy_events*)msg.get();

			for (auto& evt : pe->events())
			{
				const draiosproto::output_event_detail& details =
				    evt.event_details().output_details();
				map<string, string> evt_output_fields;

				for (auto& pair : details.output_fields())
				{
					evt_output_fields.insert(pair);
				}

				bool matched_any = false;
				for (uint32_t i = 0; i < expected.size(); i++)
				{
					// The scope of the event must match
					if (expected[i].event_scope == expected_policy_event::CONTAINER_ONLY &&
					    (!evt.has_container_id() || evt.container_id() == ""))
					{
						FAIL() << "Policy event occurred not in container but expected scope was "
						          "only containers: "
						       << evt.DebugString();
					}

					if (expected[i].event_scope == expected_policy_event::HOST_ONLY &&
					    (evt.has_container_id() && evt.container_id() != ""))
					{
						FAIL() << "Policy event occurred in container but expected scope was only "
						          "hosts: "
						       << evt.DebugString();
					}

					if (evt.policy_id() == expected[i].policy_id &&
					    details.output_type() == expected[i].output_type &&
					    check_output_fields(evt_output_fields, expected[i].output_fields))
					{
						check_v2action_result(evt, expected[i]);
						seen[i] = true;
						matched_any = true;
					}
				}

				if (!matched_any)
				{
					FAIL() << "Policy event not in expected set: " << evt.DebugString();
				}
			}

			if (std::find(std::begin(seen), std::end(seen), false) == std::end(seen))
			{
				// Found all expected messages, we can stop immediately
				break;
			}
		}

		for (uint32_t i = 0; i < expected.size(); i++)
		{
			if (!seen[i])
			{
				FAIL() << "Did not see expected event: "
				       << " policy_id: " << expected[i].policy_id
				       << " output_type: " << draiosproto::policy_type_Name(expected[i].output_type)
				       << " output_fields: " << expected[i].output_fields;
			}
		}
	}

	void compare_act_type(int evttype, int exptype, const char *atype)
	{
		if(evttype != exptype)
		{
			FAIL() << "Policy Event"
			       << atype
			       << "action result type mismatch. Evt: "
			       << evttype
			       << " Expected: "
			       << exptype;
		}
	}

	void compare_act_successful(bool evtsuccessful, bool expsuccessful, const char *atype)
	{
		if(evtsuccessful != expsuccessful)
		{
			FAIL() << "Policy Event"
			       << atype
			       << "action result successful mismatch. Evt: "
			       << evtsuccessful
			       << " Expected: "
			       << expsuccessful;
		}
	}

	void compare_act_errmsg(const std::string &evterrmsg, const std::string &experrmsg, const char *atype)
	{
		if(evterrmsg != experrmsg)
		{
			FAIL() << "Policy Event"
			       << atype
			       << "action result errmsg mismatch. Evt: "
			       << evterrmsg
			       << " Expected: "
			       << experrmsg;
		}
	}

	void check_v2action_result(const draiosproto::policy_event &evt,
				   const expected_policy_event &expevt)
	{
		if(!expevt.check_v2act_result)
		{
			return;
		}

		if(evt.v2action_results_size() != 1)
		{
			FAIL() << "Policy Event did not have exactly 1 v2 action result. Evt: "
			       << evt.DebugString();
		}

		const draiosproto::v2action_result &res = evt.v2action_results(0);
		compare_act_type(res.type(), expevt.act_type, " v2 ");
		compare_act_successful(res.successful(), expevt.act_successful, " v2 ");
		compare_act_errmsg(res.errmsg(), expevt.act_errmsg, " v2 ");
	}

	struct expected_internal_metric
	{
		enum
		{
			CMP_EQ,
			CMP_GE
		} op;
		uint64_t value;

		std::string to_string()
		{
			std::string str;
			str = (op == CMP_EQ ? "==" : ">=") + std::string(" ") + std::to_string(value);

			return str;
		}
	};

	std::string expected_as_string(std::map<string, expected_internal_metric>& expected)
	{
		string str;
		for (auto& pair : expected)
		{
			str += pair.first + pair.second.to_string();
		}

		return str;
	}

	void check_expected_internal_metrics(std::map<std::string, expected_internal_metric>& expected)
	{
		draiosproto::statsd_info statsd_info;
		uint32_t num_match = 0;

		test_helper::send_all(*m_internal_metrics, &statsd_info);

		for (auto& metric : statsd_info.statsd_metrics())
		{
			auto it = expected.find(metric.name());
			if (it != expected.end())
			{
				if (it->second.op == expected_internal_metric::CMP_EQ)
				{
					ASSERT_EQ(metric.value(), it->second.value)
					    << "Different values for " << it->first << ": expected "
					    << it->second.to_string() << ", actual " << metric.value();
				}
				else if (it->second.op == expected_internal_metric::CMP_GE)
				{
					ASSERT_GE(metric.value(), it->second.value)
					    << "Different values for " << it->first << ": expected "
					    << it->second.to_string() << ", actual " << metric.value();
				}
				num_match++;
			}
		}

		ASSERT_EQ(num_match, expected.size())
		    << "Not all expected metrics were found with actual values. Actual Metrics: "
		    << statsd_info.DebugString() << "Expected Metrics: " << expected_as_string(expected);
	}

	void get_next_msg(uint64_t delay_ms,
	                  draiosproto::message_type& mtype,
	                  unique_ptr<::google::protobuf::Message>& msg)
	{
		shared_ptr<serialized_buffer> item = nullptr;
		const uint8_t* buf;
		uint32_t size;

		msg = NULL;

		do
		{
			if (!m_transmit_queue.get(&item, delay_ms))
			{
				return;
			}
		} while (item == nullptr);

		buf = (const uint8_t*)item->buffer.data();
		size = item->buffer.size();

		g_log->debug("Got message type=" + to_string(item->message_type));
		mtype = (draiosproto::message_type)item->message_type;

		draiosproto::throttled_policy_events* tpe;
		draiosproto::policy_events* pe;
		switch (item->message_type)
		{
		case draiosproto::message_type::THROTTLED_POLICY_EVENTS:
			tpe = new draiosproto::throttled_policy_events();
			dragent_protocol::buffer_to_protobuf(buf, size, tpe);
			msg.reset(tpe);
			break;

		case draiosproto::message_type::POLICY_EVENTS:
			pe = new draiosproto::policy_events();
			dragent_protocol::buffer_to_protobuf(buf, size, pe);
			msg.reset(pe);
			break;

		default:
			FAIL() << "Received unknown message " << to_string(item->message_type);
		}
	}

	void get_policy_evts_msg(unique_ptr<draiosproto::policy_events>& pe)
	{
		draiosproto::message_type mtype;
		unique_ptr<::google::protobuf::Message> msg = NULL;

		get_next_msg(5000, mtype, msg);
		ASSERT_TRUE((msg != NULL));
		ASSERT_EQ(mtype, draiosproto::message_type::POLICY_EVENTS);
		pe.reset((draiosproto::policy_events*)(msg.release()));
	}

protected:
	// Helper used by several test cases that have a similar test setup/validation.
	void multiple_falco_files_test(std::string policies_file,
	                               std::string expected_output)
	{
		string errstr;

		ASSERT_TRUE(m_mgr.request_load_policies_v2_file(policies_file.c_str(), errstr));
		ASSERT_STREQ(errstr.c_str(), "");

		int fd = open("/tmp/sample-sensitive-file-2.txt", O_RDONLY);
		close(fd);

		// Not using check_policy_events for this, as it is checking keys only
		unique_ptr<draiosproto::policy_events> pe;
		get_policy_evts_msg(pe);
		ASSERT_EQ(pe->events_size(), 1);
		ASSERT_EQ(pe->events(0).policy_id(), 1u);
		ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 3);
		ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
		          "read_sensitive_file");
		ASSERT_TRUE(
		    pe->events(0).event_details().output_details().output_fields().count("proc.name") > 0);
		ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count(
		                "proc.cmdline") > 0);

		ASSERT_EQ(pe->events(0).event_details().output_details().output(), expected_output);

		std::map<string, expected_internal_metric> metrics;

		metrics = {{"security.falco.match.match_items",
			    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
			   {"security.falco.match.not_match_items",
			    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

		check_expected_internal_metrics(metrics);
	}

	string m_k8s_cluster_name;
	sinsp_analyzer::flush_queue m_flush_queue;
	protocol_queue m_transmit_queue;
	bool m_enable_k8s_audit_server = false;
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	test_secure_k8s_audit_event_sink *m_k8s_audit_event_sink;
	internal_metrics::sptr_t m_internal_metrics;
	protocol_handler m_data_handler;
	security_mgr m_mgr;
	test_capture_job_queue_handler *m_capture_job_queue_handler;
	test_sinsp_worker* m_sinsp_worker;
	dragent_configuration m_configuration;
	security_policy_error_handler m_error_handler;
};

class security_policies_v2_test_cointerface : public security_policies_v2_test
{
protected:
	virtual void SetUp()
	{
		string cointerface_sock = "./resources/run/cointerface.sock";

		Process::Args args{"-sock",
		                   cointerface_sock,
		                   "-use_json=false",
		                   "-modules_dir=./resources/modules_dir"};

		// Start a cointerface process to act as the
		// server. Capture its output and log everything at
		// debug level.
		m_colog = make_shared<Pipe>();
		m_cointerface = make_shared<ProcessHandle>(
		    Process::launch("./resources/cointerface", args, NULL, m_colog.get(), NULL));

		thread log_reader = thread(
		    [](shared_ptr<Pipe> colog) {
			    PipeInputStream cologstr(*colog);
			    string line;

			    while (std::getline(cologstr, line))
			    {
				    g_log->information(line);
			    }
		    },
		    m_colog);

		log_reader.detach();

		// Wait for the process in a sub-thread so it
		// is reaped as soon as it exits. This is
		// necessary as Process::isRunning returns
		// true for zombie processes.
		thread waiter = thread([this]() {
			int status;
			waitpid(m_cointerface->id(), &status, 0);
		});

		waiter.detach();

		Thread::sleep(500);

		if (!Process::isRunning(*m_cointerface))
		{
			FAIL() << "cointerface process not running after 1 second";
		}

		const std::string fake_cri_socket = "/tmp/fake-cri.sock";

		unlink(fake_cri_socket.c_str());
		m_fake_cri = make_shared<ProcessHandle>(Poco::Process::launch(
		    "./resources/fake_cri",
		    {"unix://" + fake_cri_socket, "resources/fake_cri_crio", "cri-o"}));

		// Wait for up to 30 seconds for the cri socket to exist
		bool sock_exists = false;
		for (int i = 0; i < 30; i++)
		{
			g_log->debug("Waiting for cri socket to appear " + std::to_string(i));
			sleep(1);
			std::string actual_path = scap_get_host_root() + fake_cri_socket;
			struct stat s = {};
			if (stat(actual_path.c_str(), &s) == 0 &&
			    (s.st_mode & S_IFMT) == S_IFSOCK)
			{
				sock_exists = true;
				break;
			}
		}

		ASSERT_TRUE(sock_exists);

		m_enable_k8s_audit_server = true;
		SetUpTest(fake_cri_socket);
		WaitForK8sAuditServer();
	}

	void WaitForK8sAuditServer()
	{
		int ret = -1;

		for (int i = 0; ret != 0 && i < 20; i++)
		{
			ret = system("curl -I localhost:7765/k8s_audit > /dev/null 2>&1");
			if (ret != 0)
			{
				Thread::sleep(500);
			}
		}

		if (ret != 0)
		{
			FAIL() << "localhost:7765/k8s_audit is not responding after 10 seconds";
		}
	}

	virtual void TearDown()
	{
		if (m_cointerface)
		{
			Process::kill(*m_cointerface);
		}

		if (m_fake_cri)
		{
			Process::kill(*m_fake_cri);
		}

		TearDownTest();
		g_log->information("TearDown() complete");
	}

private:
	shared_ptr<Pipe> m_colog;
	shared_ptr<ProcessHandle> m_cointerface;
	shared_ptr<ProcessHandle> m_fake_cri;
};

class security_policies_v2_test_cluster_name : public security_policies_v2_test
{
public:
	virtual void SetUp()
	{
		initFiles();

		m_k8s_cluster_name = "my-cluster";

		SetUpTest();
	}
};

class security_policies_v2_dont_match_container_test : public security_policies_v2_test
{
public:
	std::string policies_file()
	{
		return string("./resources/security_policies_messages/v2_policy_dont_match_container.txt");
	}

	virtual void SetUp()
	{
		SetUpTest();
	}
};

class security_policies_v2_dont_match_container_test_multi : public security_policies_v2_test
{
public:
	std::string policies_file()
	{
		return string(
		    "./resources/security_policies_messages/v2_policy_dont_match_container_multi.txt");
	}

	virtual void SetUp()
	{
		SetUpTest();
	}
};

TEST_F(security_policies_v2_test, readonly_fs_only)
{
	if (!dutils_check_docker())
	{
		return;
	}

	// Note that these file opens, that are read-only, should only
	// match the readonly policy and not the readwrite policy.
	int fd = open("/tmp/sample-sensitive-file-1.txt", O_RDONLY);
	close(fd);

	// This should not result in an event, as it runs in a container.
	ASSERT_EQ(system("docker run -d --rm --name sec_ut busybox:latest sh -c 'while true; do echo "
	                 "'' > /tmp/sample-sensitive-file-1.txt || true; done' > /dev/null 2>&1"),
	          0);

	sleep(5);

	dutils_kill_container("sec_ut");

	fd = open("/tmp/sample-sensitive-file-3.txt", O_RDONLY);
	close(fd);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {2,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/sample-sensitive-file-1.txt"},
	      {"evt.type", "open"},
	      {"proc.name", "tests"}}}};
	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics = {
		{"security.files-readonly.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		{"security.files-readonly.match.not_match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, readwrite_fs_only)
{
	if (!dutils_check_docker())
	{
		return;
	}

	// Note that these file opens, that are read-only, should only
	// match the readonly policy and not the readwrite policy.
	int fd = open("/tmp/sample-sensitive-file-1.txt", O_RDWR);
	close(fd);

	fd = open("/tmp/sample-sensitive-file-3.txt", O_RDWR);
	close(fd);

	ASSERT_EQ(
	    system("docker run -d --name sec_ut --rm busybox:latest sh -c 'while true; do echo '' > "
	           "/tmp/sample-sensitive-file-3.txt || true; sleep 1; done' > /dev/null 2>&1"),
	    0);

	sleep(5);

	dutils_kill_container("sec_ut");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {3,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/sample-sensitive-file-3.txt"},
	      {"evt.type", "open"},
	      {"proc.name", "tests"}}}};
	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;
	metrics = {{"security.files-readwrite.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.files-readwrite.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
}

enum actions_type {
	ACTIONS = 0,
	V2ACTIONS
};

TEST_F(security_policies_v2_test_cointerface, stop_action_docker_test)
{
	if (!dutils_check_docker())
	{
		return;
	}

	uint64_t policy_id;
	std::string comm;
	std::string cmd;
	int action;

	policy_id = 37;
	comm = "bzip2";
	cmd = "bzip2 -h";
	action = draiosproto::V2ACTION_STOP;

	// We want the return value to be non-zero as the container is stopped
	std::string docker_cmd = string("docker run --name stop_me_docker_test --rm busybox:latest sh -c 'sleep 2; ") +
		cmd +
		string("; sleep 40' > /dev/null 2>&1");

	ASSERT_NE(system(docker_cmd.c_str()), 0);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
		{policy_id,
		 draiosproto::policy_type::PTYPE_PROCESS,
		 {{"proc.name", comm}, {"proc.cmdline", cmd}},
		 security_policies_v2_test::expected_policy_event::HOST_OR_CONTAINER,
		 true,
		 action,
		 true,
		 ""}};

	check_policy_events(expected);

	// Perform cleanup in case the action failed
	dutils_kill_container_if_exists("stop_me_docker_test");
}

TEST_F(security_policies_v2_test_cointerface, capture_action_docker_test)
{
	if (!dutils_check_docker())
	{
		return;
	}

	uint64_t policy_id;
	std::string comm;
	std::string cmd;
	int action;

	policy_id = 40;
	comm = "bzcat";
	cmd = "bzcat -h";
	action = draiosproto::V2ACTION_CAPTURE;

	// We want the return value to be non-zero as the container is captureped
	std::string docker_cmd = string("docker run --name capture_me_docker_test --rm busybox:latest sh -c 'sleep 2; ") +
		cmd +
		string("; sleep 1' > /dev/null 2>&1");

	ASSERT_EQ(system(docker_cmd.c_str()), 0);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
		{policy_id,
		 draiosproto::policy_type::PTYPE_PROCESS,
		 {{"proc.name", comm}, {"proc.cmdline", cmd}},
		 security_policies_v2_test::expected_policy_event::HOST_OR_CONTAINER,
		 true,
		 action,
		 true,
		 ""}};

	check_policy_events(expected);

	ASSERT_FALSE(capture_jobs_empty()) << "No capture job requested";

	// Perform cleanup in case the action failed
	dutils_kill_container_if_exists("capture_me_docker_test");
}

TEST_F(security_policies_v2_test_cointerface, kill_action_docker_test)
{
	if (!dutils_check_docker())
	{
		return;
	}

	// We want the return value to be non-zero as the container is killed
	ASSERT_NE(system("docker run --name kill_me_docker_test --rm busybox:latest sh -c 'sleep 2; "
	                 "lzcat --help; sleep 40' > /dev/null 2>&1"),
	          0);

	std::vector<expected_policy_event> expected = {
		{38,
		 draiosproto::policy_type::PTYPE_PROCESS,
		 {{"proc.name", "lzcat"}, {"proc.cmdline", "lzcat --help"}},
		 expected_policy_event::HOST_OR_CONTAINER,
		 true,
		 draiosproto::V2ACTION_KILL,
		 true,
		 ""}};

	check_policy_events(expected);

	// Perform cleanup in case the action failed
	dutils_kill_container_if_exists("kill_me_docker_test");
};

TEST_F(security_policies_v2_test_cointerface, stop_action_cri_test)
{
	uint64_t policy_id;
	std::string comm;
	std::string cmd;
	int action;
	std::string test_helper_arg;

	policy_id = 37;
	comm = "bzip2";
	cmd = "bzip2 -h";
	action = draiosproto::V2ACTION_STOP;
	test_helper_arg = "cri_container_sleep_bzip2";

	proc test_proc = proc("./test_helper", {test_helper_arg.c_str()});
	auto handle = start_process(&test_proc);
	std::get<0>(handle).wait();

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
		{policy_id,
		 draiosproto::policy_type::PTYPE_PROCESS,
		 {{"proc.name", comm}, {"proc.cmdline", cmd}},
		 security_policies_v2_test::expected_policy_event::HOST_OR_CONTAINER,
		 true,
		 action,
		 true,
		 ""}};

	check_policy_events(expected);
}

TEST_F(security_policies_v2_test_cointerface, kill_action_cri_test)
{
	proc test_proc = proc("./test_helper", {"cri_container_sleep_lzcat"});
	auto handle = start_process(&test_proc);
	std::get<0>(handle).wait();

	std::vector<expected_policy_event> expected = {
		{38,
		 draiosproto::policy_type::PTYPE_PROCESS,
		 {{"proc.name", "lzcat"}, {"proc.cmdline", "lzcat --help"}},
		 expected_policy_event::HOST_OR_CONTAINER,
		 true,
		 draiosproto::V2ACTION_KILL,
		 true,
		 ""}};

	check_policy_events(expected);
};

TEST_F(security_policies_v2_test, fs_prefixes)
{
	int fd = open("/tmp/one", O_RDONLY);
	close(fd);

	fd = open("/tmp/one/two", O_RDONLY);
	close(fd);

	fd = open("/tmp/one/two/three", O_RDONLY);
	close(fd);

	fd = open("/tmp/two", O_RDONLY);
	close(fd);

	fd = open("/tmp/two/three", O_RDONLY);
	close(fd);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {12,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/one"}, {"evt.type", "open"}}},
	    {12,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/one/two"}, {"evt.type", "open"}}},
	    {12,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/one/two/three"}, {"evt.type", "open"}}},
	    {12,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/two"}, {"evt.type", "open"}}},
	    {12,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/two/three"}, {"evt.type", "open"}}}};

	check_policy_events(expected);
};

TEST_F(security_policies_v2_test, fs_root_dir)
{
	if (!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("fs-root-image");
	dutils_create_tag("busybox:test-root-writes", "busybox:latest");

	if (system("docker run -d --rm --name fs-root-image busybox:test-root-writes sh -c 'while "
	           "true; do echo '' > /allowed-file-below-root && echo '' > /not-allowed; sleep 1; "
	           "done' > /dev/null 2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	sleep(5);

	dutils_kill_container("fs-root-image");

	dutils_kill_image("busybox:test-root-writes");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {19,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/not-allowed"}, {"evt.type", "open"}}}};

	check_policy_events(expected);
};

TEST_F(security_policies_v2_test, tcp_listenport_only)
{
	int rc;
	int sock = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in localhost;

	localhost.sin_family = AF_INET;
	localhost.sin_port = htons(1234);
	inet_aton("127.0.0.1", &(localhost.sin_addr));

	if ((rc = bind(sock, (struct sockaddr*)&localhost, sizeof(localhost))) != 0)
	{
		fprintf(stderr, "Could not bind listening socket to localhost: %s\n", strerror(errno));
		return;
	}

	listen(sock, 1);

	close(sock);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {4,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "1234"}, {"fd.sip", "127.0.0.1"}, {"fd.l4proto", "tcp"}}}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.listenports-tcp.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.listenports-tcp.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, udp_listenport_only)
{
	int rc;
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in localhost;

	localhost.sin_family = AF_INET;
	localhost.sin_port = htons(12345);
	inet_aton("127.0.0.1", &(localhost.sin_addr));

	if ((rc = bind(sock, (struct sockaddr*)&localhost, sizeof(localhost))) != 0)
	{
		fprintf(stderr, "Could not bind listening socket to localhost: %s\n", strerror(errno));
		return;
	}

	struct timeval read_timeout;
	read_timeout.tv_sec = 0;
	read_timeout.tv_usec = 10;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));

	char buffer;
	recvfrom(sock, &buffer, 1, 0, NULL, NULL);

	close(sock);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {5,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "12345"}, {"fd.sip", "127.0.0.1"}, {"fd.l4proto", "udp"}}}};
	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.listenports-udp.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.listenports-udp.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, syscall_only)
{
	// It doesn't matter that the quotactl fails, just that it attempts
	struct dqblk quota;
	quotactl(Q_GETQUOTA, "/no/such/file", 0, (caddr_t)&quota);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {6, draiosproto::policy_type::PTYPE_SYSCALL, {{"evt.type", "quotactl"}}}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.syscalls.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.syscalls.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, syscall_only_whitelist)
{
	if (!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("syscall-whitelist");
	dutils_create_tag("busybox:syscall-whitelist", "busybox:latest");

	if (system("docker run -d --rm --name syscall-whitelist busybox:syscall-whitelist sh -c 'while "
		   "true; do touch /tmp/foobar; sleep 1; "
		   "done' > /dev/null 2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	sleep(5);

	dutils_kill_container("syscall-whitelist");

	dutils_kill_image("busybox:syscall-whitelist");


	// We should only see policy events for the procexit event
	// (processes exiting). All other syscalls should be
	// whitelisted.
	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {50,
	     draiosproto::policy_type::PTYPE_SYSCALL,
	     {{"evt.type", "procexit"}}}};
	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;
	metrics = {{"security.syscalls.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}},
		   {"security.syscalls.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_GE, 1}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, container_only)
{
	if (!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	dutils_kill_image("blacklist-image-name");

	dutils_create_tag("blacklist-image-name", "busybox:1.27.2");
	dutils_kill_container("blacklisted_image");

	if (system("docker run --rm --name blacklisted_image blacklist-image-name sleep 5 > /dev/null "
	           "2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	dutils_kill_image("blacklist-image-name");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {7,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "blacklist-image-name"},
	      {"container.name", "blacklisted_image"},
	      {"container.image.id",
	       "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}}};
	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.containers.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.containers.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
}

static void run_non_alpine_container(security_policies_v2_test* ptest, bool both_policies_match)
{
	if (!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	dutils_kill_container("non_alpine");

	if (system("docker run --rm --name non_alpine busybox:1.27.2 sleep 5 > /dev/null 2>&1") != 0)
	{
		ASSERT_TRUE(false);
	}

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {3001,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "busybox:1.27.2"},
	      {"container.name", "non_alpine"},
	      {"container.image.id",
	       "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}}};

	uint64_t num_matches = 1;
	if (both_policies_match)
	{
		num_matches = 2;

		expected.push_back(
		    {3002,
		     draiosproto::policy_type::PTYPE_CONTAINER,
		     {{"container.image", "busybox:1.27.2"},
		      {"container.name", "non_alpine"},
		      {"container.image.id",
		       "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}});
	}

	ptest->check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.containers.match.match_items",
	            {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}},
	           {"security.containers.match.not_match_items",
	            {security_policies_v2_test::expected_internal_metric::CMP_EQ, num_matches}}};

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_v2_dont_match_container_test, container_dont_match)
{
	bool both_policies_match = false;
	return run_non_alpine_container(this, both_policies_match);
};

TEST_F(security_policies_v2_dont_match_container_test_multi, container_dont_match)
{
	bool both_policies_match = true;
	return run_non_alpine_container(this, both_policies_match);
};

TEST_F(security_policies_v2_test, container_match_multi_policies_one_rule)
{
	if (!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	dutils_create_tag("busybox:some-tag", "busybox:1.27.2");
	dutils_kill_container("busybox_some_tag");

	if (system(
	        "docker run --rm --name busybox_some_tag busybox:some-tag sleep 5 > /dev/null 2>&1") !=
	    0)
	{
		ASSERT_TRUE(false);
	}

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {31,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "busybox:some-tag"},
	      {"container.name", "busybox_some_tag"},
	      {"container.image.id",
	       "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}},
	    {32,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "busybox:some-tag"},
	      {"container.name", "busybox_some_tag"},
	      {"container.image.id",
	       "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"}}}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.containers.match.match_items",
	            {security_policies_v2_test::expected_internal_metric::CMP_EQ, 2}},
	           {"security.containers.match.not_match_items",
	            {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, container_only_scope)
{
	if (!dutils_check_docker())
	{
		return;
	}

	// Only the activity in the container should result in policy
	// events. The command line differentiates between the
	// container and host activity.
	int fd = open("/tmp/second", O_RDWR);
	close(fd);

	dutils_kill_container("sec_ut");

	ASSERT_EQ(system("docker run -d --rm --name sec_ut busybox:latest sh -c 'while true; do echo "
	                 "'' > /tmp/second; sleep 1; done' > /dev/null 2>&1"),
	          0);

	sleep(5);

	dutils_kill_container("sec_ut");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {33,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/second"}, {"evt.type", "open"}},
	     expected_policy_event::CONTAINER_ONLY}};

	check_policy_events(expected);
}

TEST_F(security_policies_v2_test, host_only_scope)
{
	if (!dutils_check_docker())
	{
		return;
	}

	// Only the activity in the container should result in policy
	// events. The command line differentiates between the
	// container and host activity.
	int fd = open("/tmp/third", O_RDWR);
	close(fd);

	dutils_kill_container("sec_ut");

	ASSERT_EQ(system("docker run -d --rm --name sec_ut busybox:latest sh -c 'while true; do echo "
	                 "'' > /tmp/third; sleep 1; done' > /dev/null 2>&1"),
	          0);

	sleep(5);

	dutils_kill_container("sec_ut");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {34,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/third"}, {"evt.type", "open"}},
	     expected_policy_event::HOST_ONLY}};

	check_policy_events(expected);
}

TEST_F(security_policies_v2_test, process_only)
{
	ASSERT_EQ(system("ls > /dev/null 2>&1"), 0);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {8,
	     draiosproto::policy_type::PTYPE_PROCESS,
	     {{"proc.name", "ls"}, {"proc.cmdline", "ls"}}}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.processes.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.processes.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_v2_test, falco_only)
{
	int fd = open("/tmp/sample-sensitive-file-2.txt", O_RDONLY);
	close(fd);

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	get_policy_evts_msg(pe);
	ASSERT_NE(pe, nullptr);
	// Note that for v2 policies this skips policy 42, which has a substring of the actual rule name
	ASSERT_EQ(pe->events_size(), 1);
	ASSERT_EQ(pe->events(0).policy_id(), 1u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
	          "read_sensitive_file");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.name"),
	          "/tmp/sample-sensitive-file-2.txt");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") >
	            0);
	ASSERT_TRUE(
	    pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.pname") >
	            0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") >
	            0);

	string prefix = "tests read /tmp/sample-sensitive-file-*.txt";
	ASSERT_EQ(
	    pe->events(0).event_details().output_details().output().compare(0, prefix.size(), prefix),
	    0);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.falco.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.falco.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, falco_no_evttype)
{
	int fd = open("/tmp/banned-file.txt", O_RDONLY);
	close(fd);

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 26u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
	          "anything_for_banned_file");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.name"),
	          "/tmp/banned-file.txt");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") >
	            0);
	ASSERT_TRUE(
	    pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.pname") >
	            0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") >
	            0);

	string prefix = "some operation related to /tmp/banned-file.txt";
	ASSERT_EQ(
	    pe->events(0).event_details().output_details().output().compare(0, prefix.size(), prefix),
	    0);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.falco.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.falco.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, DISABLED_falco_fqdn)
{
	ASSERT_EQ(system("echo 'ping' | timeout 2 nc github.com 80 > /dev/null 2>&1"), 0);

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 27u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
	          "contacted_blacklisted_host");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.sip.name"),
	          "github.com");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("fd.name") >
	            0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") >
	            0);
	ASSERT_TRUE(
	    pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") >
	            0);

	string prefix = "tests contacted the blacklisted host github.com";
	ASSERT_EQ(
	    pe->events(0).event_details().output_details().output().compare(0, prefix.size(), prefix),
	    0);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {{"security.falco.match.match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		   {"security.falco.match.not_match_items",
		    {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_v2_test, multiple_falco_variants)
{
	multiple_falco_files_test(
	    "./resources/security_policies_messages/multiple_falco_variants_v2.txt",
	    "v2 output");
}

TEST_F(security_policies_v2_test, multiple_falco_files)
{
	multiple_falco_files_test("./resources/security_policies_messages/multiple_falco_files_v2.txt",
	                          "some output");
}

TEST_F(security_policies_v2_test, multiple_falco_files_override)
{
	multiple_falco_files_test(
	    "./resources/security_policies_messages/multiple_falco_files_override_v2.txt",
	    "some output");
}

TEST_F(security_policies_v2_test, custom_falco_files)
{
	multiple_falco_files_test("./resources/security_policies_messages/custom_falco_files_v2.txt",
	                          "some output");
}

TEST_F(security_policies_v2_test, custom_falco_files_override)
{
	multiple_falco_files_test(
	    "./resources/security_policies_messages/custom_falco_files_override_v2.txt",
	    "some output");
}

static void falco_k8s_audit(security_policies_v2_test_cointerface* ptest)
{
	// send a single event (the first line of the file)
	ASSERT_EQ(system("timeout 2 curl -X POST localhost:7765/k8s_audit -d $(head -1 "
	                 "./resources/k8s_audit_events.txt) > /dev/null 2>&1"),
	          0);

	unique_ptr<draiosproto::policy_events> pe;
	ptest->get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 28u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
	          "k8s_deployment_created");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.auth.decision"),
	          "allow");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.response.code"),
	          "201");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.name"),
	          "nginx-deployment");
	ASSERT_EQ(
	    pe->events(0).event_details().output_details().output_fields().at("ka.target.namespace"),
	    "default");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.user.name"),
	          "minikube-user");

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {
		{"security.falco.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		{"security.falco.match.not_match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ,
		  0}}};

	ptest->check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit)
{
	return falco_k8s_audit(this);
};

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit_restart_security_mgr)
{
	// This will cause the security_mgr to reconnect to
	// cointerface, which will cause the earlier start() to clean
	// itself up.
	m_mgr.start_k8s_audit_server();
	WaitForK8sAuditServer();

	return falco_k8s_audit(this);
};

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit_scope)
{
	// send a single event (the first line of the file)
	ASSERT_EQ(system("timeout 2 curl -X POST localhost:7765/k8s_audit -d $(head -1 "
	                 "./resources/k8s_audit_create_namespace.txt) > /dev/null 2>&1"),
	          0);

	unique_ptr<draiosproto::policy_events> pe;
	get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() == 1);
	ASSERT_EQ(pe->events(0).policy_id(), 35u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 5);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
	          "k8s_namespace_created");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.auth.decision"),
	          "allow");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.response.code"),
	          "201");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.name"),
	          "some-namespace");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.user.name"),
	          "minikube-user");

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {
	    {"security.falco.match.match_items",
	     {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
	    {"security.falco.match.not_match_items",
	     {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit_multi_events)
{
	// send a bunch of events (one per line of the file)
	ASSERT_EQ(system("timeout 2 xargs -0 -d '\n' -I{} curl -X POST localhost:7765/k8s_audit -d {} "
	                 "< ./resources/k8s_audit_events.txt > /dev/null 2>&1"),
	          0);

	unique_ptr<draiosproto::policy_events> pe;
	get_policy_evts_msg(pe);
	ASSERT_TRUE(pe->events_size() >= 1);
	ASSERT_EQ(pe->events(0).policy_id(), 28u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
	          "k8s_deployment_created");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.auth.decision"),
	          "allow");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.response.code"),
	          "201");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.target.name"),
	          "nginx-deployment");
	ASSERT_EQ(
	    pe->events(0).event_details().output_details().output_fields().at("ka.target.namespace"),
	    "default");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("ka.user.name"),
	          "minikube-user");

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {
		{"security.falco.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_GE, 1}},
		{"security.falco.match.not_match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ,
		  0}}};

	check_expected_internal_metrics(metrics);
}

TEST_F(security_policies_v2_test_cointerface, falco_k8s_audit_messy_client)
{
	// Check for unsupported http methods (POST is the only method supported)
	ASSERT_EQ(
	    system(
	        "curl -sX GET localhost:7765/k8s_audit | grep -qx 'Method GET not allowed' || false"),
	    0);
	// Don't test method HEAD, as curl just hangs...
	// ASSERT_EQ(system("curl -sX HEAD localhost:7765/k8s_audit | grep -qx 'Method HEAD not allowed'
	// || false"), 0);
	ASSERT_EQ(
	    system(
	        "curl -sX PUT localhost:7765/k8s_audit | grep -qx 'Method PUT not allowed' || false"),
	    0);
	ASSERT_EQ(system("curl -sX DELETE localhost:7765/k8s_audit | grep -qx 'Method DELETE not "
	                 "allowed' || false"),
	          0);
	ASSERT_EQ(system("curl -sX CONNECT localhost:7765/k8s_audit | grep -qx 'Method CONNECT not "
	                 "allowed' || false"),
	          0);
	ASSERT_EQ(system("curl -sX OPTIONS localhost:7765/k8s_audit | grep -qx 'Method OPTIONS not "
	                 "allowed' || false"),
	          0);
	ASSERT_EQ(system("curl -sX TRACE localhost:7765/k8s_audit | grep -qx 'Method TRACE not "
	                 "allowed' || false"),
	          0);

	// Hit wrong URIs
	ASSERT_EQ(system("curl -sX POST localhost:7765 -d @./resources/k8s_audit_events.txt | grep -qx "
	                 "'404 page not found' || false"),
	          0);
	ASSERT_EQ(system("curl -sX POST localhost:7765/this-is-not-the-good-door -d "
	                 "@./resources/k8s_audit_events.txt | grep -qx '404 page not found' || false"),
	          0);
}

TEST_F(security_policies_v2_test, container_prefixes)
{
	if (!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("denyme");
	dutils_kill_image("my.domain.name/busybox:1.27.2");
	dutils_kill_image("my.other.domain.name:12345/cirros:0.3.3");
	dutils_kill_image("my.third.domain.name/tutum/curl:alpine");

	ASSERT_EQ(system("docker pull busybox:1.27.2 > /dev/null 2>&1"), 0);
	ASSERT_EQ(system("docker pull cirros:0.3.3 > /dev/null 2>&1"), 0);
	ASSERT_EQ(system("docker pull tutum/curl:alpine > /dev/null 2>&1"), 0);

	dutils_create_tag("blacklist-image-name:0.0.1", "busybox:1.27.2");

	ASSERT_EQ(
	    system("docker run --rm --name denyme blacklist-image-name:0.0.1 sleep 5 > /dev/null 2>&1"),
	    0);

	dutils_create_tag("my.domain.name/busybox:1.27.2", "busybox:1.27.2");

	ASSERT_EQ(
	    system(
	        "docker run --rm --name denyme my.domain.name/busybox:1.27.2 sleep 5 > /dev/null 2>&1"),
	    0);

	dutils_kill_image("my.domain.name/busybox:1.27.2");

	dutils_create_tag("my.other.domain.name:12345/cirros:0.3.3", "cirros:0.3.3");

	ASSERT_EQ(system("docker run --rm --name denyme my.other.domain.name:12345/cirros:0.3.3 "
	                 "/bin/sh -c 'sleep 5' > /dev/null 2>&1"),
	          0);

	dutils_kill_image("my.other.domain.name:12345/cirros:0.3.3");

	dutils_create_tag("my.third.domain.name/cirros:0.3.3", "cirros:0.3.3");

	ASSERT_EQ(system("docker run --rm --name denyme my.third.domain.name/cirros:0.3.3 /bin/sh -c "
	                 "'sleep 5' > /dev/null 2>&1"),
	          0);

	dutils_kill_image("my.third.domain.name/cirros:0.3.3");
	dutils_create_tag("my.third.domain.name/tutum/curl:alpine", "tutum/curl:alpine");

	ASSERT_EQ(system("docker run --rm --name denyme my.third.domain.name/tutum/curl:alpine sleep 5 "
	                 "> /dev/null 2>&1"),
	          0);

	dutils_kill_image("my.third.domain.name/tutum/curl:alpine");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {07,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "blacklist-image-name:0.0.1"},
	      {"container.image.id",
	       "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"},
	      {"container.name", "denyme"}}},
	    {14,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "my.domain.name/busybox:1.27.2"},
	      {"container.image.id",
	       "6ad733544a6317992a6fac4eb19fe1df577d4dec7529efec28a5bd0edad0fd30"},
	      {"container.name", "denyme"}}},
	    {15,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "my.other.domain.name:12345/cirros:0.3.3"},
	      {"container.image.id",
	       "231974f01f06befaa720909c29baadb586d6e6708e386190873a0d4cc5af033a"},
	      {"container.name", "denyme"}}},
	    {16,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "my.third.domain.name/cirros:0.3.3"},
	      {"container.image.id",
	       "231974f01f06befaa720909c29baadb586d6e6708e386190873a0d4cc5af033a"},
	      {"container.name", "denyme"}}},
	    {17,
	     draiosproto::policy_type::PTYPE_CONTAINER,
	     {{"container.image", "my.third.domain.name/tutum/curl:alpine"},
	      {"container.image.id",
	       "b91cd13456bbd3d65f00d0a0be24c95b802ad1f9cd0dc2b8889c4c7fbb599fef"},
	      {"container.name", "denyme"}}}};
	check_policy_events(expected);
}

TEST_F(security_policies_v2_test, net_inbound_outbound_tcp)
{
	if (!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull tutum/curl > /dev/null 2>&1"), 0);

	dutils_kill_container("inout_test");
	dutils_create_tag("curl:inout_test", "tutum/curl");
	ASSERT_EQ(system("docker run -d --name inout_test --rm curl:inout_test bash -c 'while true; do "
	                 "(timeout 5 nc -l -p 22222 -q0 &) && sleep 2 && (timeout 5 nc $(hostname -I | "
	                 "cut -f 1 -d \" \") 22222); sleep 1; done' > /dev/null 2>&1"),
	          0);

	sleep(5);
	dutils_kill_container("inout_test");
	dutils_kill_image("curl:inout_test");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {18,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "22222"},
	      {"fd.sip", "0.0.0.0"},
	      {"fd.l4proto", "tcp"},
	      {"proc.name", "nc"}}},  // listen
	    {18,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "22222"}, {"fd.l4proto", "tcp"}, {"proc.name", "nc"}}},  // connect
	    {18,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "22222"}, {"fd.l4proto", "tcp"}, {"proc.name", "nc"}}}  // accept
	};

	check_policy_events(expected);
}

TEST_F(security_policies_v2_test, net_inbound_outbound_udp)
{
	if (!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("docker pull tutum/curl > /dev/null 2>&1"), 0);

	dutils_kill_container("inout_test");
	dutils_create_tag("curl:inout_test", "tutum/curl");
	ASSERT_EQ(system("docker run -d --name inout_test --rm curl:inout_test bash -c 'ln -s `which "
	                 "nc` /bin/ncserver; while true; do (timeout 5 ncserver -ul -p 22222 -q0 &) && "
	                 "sleep 2 && (echo ping | timeout 5 nc -u $(hostname -I | cut -f 1 -d \" \") "
	                 "22222 -w 1); sleep 1; done' > /dev/null 2>&1"),
	          0);

	sleep(5);
	dutils_kill_container("inout_test");
	dutils_kill_image("curl:inout_test");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {18,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "22222"}, {"proc.name", "nc"}, {"fd.l4proto", "udp"}}},  // connect
	    {18,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "22222"}, {"proc.name", "ncserver"}, {"fd.l4proto", "udp"}}},  // recvfrom
	    {18,
	     draiosproto::policy_type::PTYPE_NETWORK,
	     {{"fd.sport", "22222"},
	      {"proc.name", "ncserver"},
	      {"fd.l4proto", "udp"}}}  // connect, used internally during libc getaddrinfo to lookup the
	                               // local address via getsockname
	};

	check_policy_events(expected);
}

TEST_F(security_policies_v2_test, fs_usecase)
{
	if (!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("fs_usecase");
	dutils_create_tag("busybox:fs_usecase", "busybox:latest");

	ASSERT_EQ(system("docker run -d --rm --name fs_usecase busybox:fs_usecase sh -c 'while true; "
	                 "do touch /home/allowed && cat /etc/passwd /home/allowed /etc/hostname > "
	                 "/bin/not-allowed; sleep 1; done'"),
	          0);

	sleep(5);

	dutils_kill_container("fs_usecase");
	dutils_kill_image("busybox:fs_usecase");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {21,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/etc/passwd"}, {"evt.type", "open"}}},
	    {21,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/bin/not-allowed"}, {"evt.type", "open"}}}};

	check_policy_events(expected);
};

TEST_F(security_policies_v2_test, nofd_operations)
{
	DIR* dirp;

	mkdir("/tmp/test_nofd_ops/", 0777);
	dirp = opendir("/tmp/test_nofd_ops/");

	mkdirat(dirfd(dirp), "./one", 0777);
	mkdirat(dirfd(dirp), "./two", 0777);

	unlinkat(dirfd(dirp), "./one", AT_REMOVEDIR);
	renameat(dirfd(dirp), "./two", dirfd(dirp), "./three");

	rename("/tmp/test_nofd_ops/three", "/tmp/test_nofd_ops/four");

	ASSERT_EQ(system("touch /tmp/test_nofd_ops/file"), 0);
	unlink("/tmp/test_nofd_ops/file");

	closedir(dirp);

	rmdir("/tmp/test_nofd_ops/four");
	rmdir("/tmp/test_nofd_ops");

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.arg[1]", "/tmp/test_nofd_ops/"}, {"evt.type", "mkdir"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.abspath", "/tmp/test_nofd_ops/one"}, {"evt.type", "mkdirat"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.abspath", "/tmp/test_nofd_ops/two"}, {"evt.type", "mkdirat"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.abspath", "/tmp/test_nofd_ops/one"}, {"evt.type", "unlinkat"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.abspath", "/tmp/test_nofd_ops/two"},
	      {"evt.abspath.dst", "/tmp/test_nofd_ops/three"},
	      {"evt.type", "renameat"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.arg[1]", "/tmp/test_nofd_ops/three"},
	      {"evt.arg[2]", "/tmp/test_nofd_ops/four"},
	      {"evt.type", "rename"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/test_nofd_ops/file"}, {"evt.type", "open"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.arg[1]", "/tmp/test_nofd_ops/file"}, {"evt.type", "unlink"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.arg[1]", "/tmp/test_nofd_ops/four"}, {"evt.type", "rmdir"}}},
	    {25,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"evt.arg[1]", "/tmp/test_nofd_ops"}, {"evt.type", "rmdir"}}}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics;

	metrics = {
		{"security.files-readwrite.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		{"security.files-readwrite-nofd.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 9}},
		{"security.files-readwrite.match.not_match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ,
		  0}}};

	check_expected_internal_metrics(metrics);
};

TEST_F(security_policies_v2_test, DISABLED_events_flood)
{
	shared_ptr<serialized_buffer> item;

	// Repeatedly try to read /tmp/sample-sensitive-file-1.txt. This will result in a flood of
	// policy events.

	// What we want to see is the following:
	//  - 1 policy event message, containing all the policy events that make it through the token
	//  bucket.
	//  - Between 8-12 throttled policy event messages. These should be sent
	//    every second while the opens are occurring.
	//  - The total count of events across both messages should equal the number of reads we did.
	//  - There should be a steady stream of metrics events without any big delays.

	g_log->debug("Reading /tmp/sample-sensitive-file-1.txt 1000 times");
	for (uint32_t i = 0; i < 1000; i++)
	{
		int fd = open("/tmp/sample-sensitive-file-1.txt", O_RDONLY);
		close(fd);

		Poco::Thread::sleep(10);
	}

	int32_t policy_event_count = 0;
	int32_t throttled_policy_event_count = 0;
	int32_t event_count = 0;

	// We'll stop when the queue is empty. This way we'll get all
	// metrics and policy event messages sent while the above
	// opens were occurring.
	draiosproto::message_type mtype;
	draiosproto::throttled_policy_events* tpe;
	draiosproto::policy_events* pe;

	// Read events for up to 10 seconds trying to read all
	// events/policy_events/throttled_policy_events messages.
	for (uint32_t attempts = 0; attempts < 100; attempts++)
	{
		unique_ptr<::google::protobuf::Message> msg;

		get_next_msg(100, mtype, msg);

		if (msg == NULL)
		{
			continue;
		}

		switch (mtype)
		{
		case draiosproto::message_type::THROTTLED_POLICY_EVENTS:
			throttled_policy_event_count++;
			tpe = (draiosproto::throttled_policy_events*)msg.get();

			event_count += tpe->events(0).count();

			break;

		case draiosproto::message_type::POLICY_EVENTS:
			pe = (draiosproto::policy_events*)msg.get();
			g_log->debug("Read policy event with " + to_string(pe->events_size()) + " events");
			policy_event_count++;
			event_count += pe->events_size();

			break;

		default:
			FAIL() << "Received unknown message " << mtype;
		}

		if (policy_event_count == 1 && throttled_policy_event_count >= 8 &&
		    throttled_policy_event_count <= 13 && event_count == 1000)
		{
			break;
		}
	}

	g_log->debug("Num policy_event messages:" + to_string(policy_event_count));
	g_log->debug("Num throttled_policy_event messages: " + to_string(throttled_policy_event_count));
	g_log->debug("Num events: " + to_string(event_count));

	ASSERT_EQ(policy_event_count, 1);
	ASSERT_GE(throttled_policy_event_count, 8);
	ASSERT_LE(throttled_policy_event_count, 13);
	ASSERT_EQ(event_count, 1000);
}

TEST_F(security_policies_v2_test, docker_swarm)
{
	if (!dutils_check_docker())
	{
		return;
	}

	ASSERT_EQ(system("(docker swarm leave --force || true) > /dev/null 2>&1"), 0);

	ASSERT_EQ(system("docker pull alpine > /dev/null 2>&1"), 0);
	dutils_create_tag("swarm_service_ut_image", "alpine");

	ASSERT_EQ(system("(docker swarm init && docker service create --replicas 1 --name helloworld "
	                 "swarm_service_ut_image /bin/sh -c \"while true; do echo touch; rm -f "
	                 "/tmp/sample-sensitive-file-2.txt; touch /tmp/sample-sensitive-file-2.txt; "
	                 "sleep 1; done\") > /dev/null 2>&1"),
	          0);

	sleep(5);

	ASSERT_EQ(system("docker swarm leave --force > /dev/null 2>&1"), 0);

	dutils_kill_image("swarm_service_ut_image");

	// Not using check_policy_events for this, as it is checking keys only
	unique_ptr<draiosproto::policy_events> pe;
	get_policy_evts_msg(pe);
	ASSERT_TRUE(pe.get() != NULL);
	ASSERT_GE(pe->events_size(), 1);
	ASSERT_EQ(pe->events(0).policy_id(), 29u);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields_size(), 6);
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("falco.rule"),
	          "read_sensitive_file");
	ASSERT_EQ(pe->events(0).event_details().output_details().output_fields().at("fd.name"),
	          "/tmp/sample-sensitive-file-2.txt");
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("user.name") >
	            0);
	ASSERT_TRUE(
	    pe->events(0).event_details().output_details().output_fields().count("proc.cmdline") > 0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.pname") >
	            0);
	ASSERT_TRUE(pe->events(0).event_details().output_details().output_fields().count("proc.name") >
	            0);
}

TEST_F(security_policies_v2_test, policy_with_unknown_action)
{
	int fd = open("/tmp/sample-sensitive-file-4.txt", O_RDONLY);
	close(fd);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {41,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/sample-sensitive-file-4.txt"},
	      {"evt.type", "open"},
	      {"proc.name", "tests"}},
	     expected_policy_event::HOST_OR_CONTAINER,
	     true,
	     draiosproto::V2ACTION_UNKNOWN,
	     false,
	     "Policy Action 0 not implemented yet"}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics = {
		{"security.files-readonly.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		{"security.files-readonly.match.not_match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
}

// This will not find any events as the cluster name has not been set
TEST_F(security_policies_v2_test, policy_scoped_k8s_cluster_name_host_nomatch)
{
	int fd = open("/tmp/sample-sensitive-file-5.txt", O_RDWR);
	close(fd);

	unique_ptr<::google::protobuf::Message> msg = NULL;
	draiosproto::message_type mtype;
	get_next_msg(5000, mtype, msg);
	ASSERT_TRUE((msg == NULL));
}


TEST_F(security_policies_v2_test_cluster_name, policy_scoped_k8s_cluster_name_host_match)
{
	int fd = open("/tmp/sample-sensitive-file-5.txt", O_RDWR);
	close(fd);

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {60,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/sample-sensitive-file-5.txt"},
	      {"evt.type", "open"},
	      {"proc.name", "tests"}}}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics = {
		{"security.files-readwrite.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 1}},
		{"security.files-readwrite.match.not_match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
}

static void open_file_5_in_container()
{
	dutils_kill_container("sec_ut");

	ASSERT_EQ(
	    system("docker run -d --name sec_ut --rm busybox:latest sh -c 'while true; do echo '' > "
	           "/tmp/sample-sensitive-file-5.txt || true; sleep 1; done' > /dev/null 2>&1"),
	    0);

	sleep(5);

	dutils_kill_container("sec_ut");
}

// This will not find any events as the cluster name has not been set
TEST_F(security_policies_v2_test, policy_scoped_k8s_cluster_name_container_nomatch)
{
	if (!dutils_check_docker())
	{
		return;
	}

	open_file_5_in_container();

	unique_ptr<::google::protobuf::Message> msg = NULL;
	draiosproto::message_type mtype;
	get_next_msg(5000, mtype, msg);
	ASSERT_TRUE((msg == NULL));
}


TEST_F(security_policies_v2_test_cluster_name, policy_scoped_k8s_cluster_name_container_match)
{
	if (!dutils_check_docker())
	{
		return;
	}

	open_file_5_in_container();

	std::vector<security_policies_v2_test::expected_policy_event> expected = {
	    {60,
	     draiosproto::policy_type::PTYPE_FILESYSTEM,
	     {{"fd.name", "/tmp/sample-sensitive-file-5.txt"},
	      {"evt.type", "open"},
	      {"proc.name", "sh"}}}};

	check_policy_events(expected);

	std::map<string, security_policies_v2_test::expected_internal_metric> metrics = {
		{"security.files-readwrite.match.match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_GE, 1}},
		{"security.files-readwrite.match.not_match_items",
		 {security_policies_v2_test::expected_internal_metric::CMP_EQ, 0}}};

	check_expected_internal_metrics(metrics);
}

