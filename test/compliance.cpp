#include <thread>
#include <memory>

#include <Poco/AutoPtr.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/Logger.h>
#include <Poco/PatternFormatter.h>
#include <Poco/NullChannel.h>
#include <Poco/Process.h>
#include <Poco/Pipe.h>

#include <gtest.h>

#include <sinsp.h>
#include <configuration.h>
#include <coclient.h>

using namespace std;
using namespace Poco;

typedef struct {
	std::string schedule;
	uint64_t id;
	std::string name;
	std::string module;
	std::string scraper_id;
	std::string sleep_time;
} task_defs_t;

class compliance_test : public testing::Test
{
protected:
	virtual void SetUp()
	{
		// The (global) logger only needs to be set up once
		if(!g_log)
		{
			AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));

			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));
			// To enable debug logging, change the tailing -1 to Message::Priority::PRIO_DEBUG
			Logger &loggerc = Logger::create("DraiosLogC", formatting_channel_console, -1);

			AutoPtr<Channel> null_channel(new NullChannel());
			Logger &nullc = Logger::create("NullC", null_channel, -1);

			g_log = std::unique_ptr<dragent_logger>(new dragent_logger(&nullc, &loggerc, &nullc));
		}

		string cointerface_sock = "./resources/compliance_test.sock";

		Process::Args args{"-sock", cointerface_sock,
				"-use_json=false",
				"-modules_dir=./resources/modules_dir"
				};

		// Start a cointerface process to act as the
		// server. Capture its output and log everything at
		// debug level.
		m_colog = make_shared<Pipe>();
		m_cointerface = make_shared<ProcessHandle>(Process::launch("./resources/cointerface", args, NULL, m_colog.get(), NULL));

		thread log_reader = thread([] (shared_ptr<Pipe> colog) {
			PipeInputStream cologstr(*colog);
			string line;

			while (std::getline(cologstr, line))
			{
				g_log->information(line);
			}
		}, m_colog);

		log_reader.detach();

		// Wait for the process in a sub-thread so it
		// is reaped as soon as it exits. This is
		// necessary as Process::isRunning returns
		// true for zombie processes.
		thread waiter = thread([this] () {
			int status;
			waitpid(m_cointerface->id(), &status, 0);
		});

		waiter.detach();

		Thread::sleep(500);

		if (!Process::isRunning(*m_cointerface))
		{
			FAIL() << "cointerface process not running after 1 second";
		}

		m_grpc_conn = grpc_connect<sdc_internal::ComplianceModuleMgr::Stub>("unix:" + cointerface_sock);
		m_grpc_start = make_shared<streaming_grpc_client(&sdc_internal::ComplianceModuleMgr::Stub::AsyncStart)>(m_grpc_conn);
		m_grpc_load = make_shared<unary_grpc_client(&sdc_internal::ComplianceModuleMgr::Stub::AsyncLoad)>(m_grpc_conn);
		m_grpc_stop = make_shared<unary_grpc_client(&sdc_internal::ComplianceModuleMgr::Stub::AsyncStop)>(m_grpc_conn);

		// Also create a server listening on the statsd port
		if ((m_statsd_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		{
			FAIL() << "Could not create socket for fake statsd server: " << strerror(errno);
		}

		struct sockaddr_in saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_ANY);
		saddr.sin_port = htons(8125);

		if(bind(m_statsd_sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
		{
			FAIL() << "Can't bind() to port for fake statsd server: " << strerror(errno);
		}

		// Set a default timeout of 100ms, so we can signal the thread

		struct timeval ts;
		ts.tv_sec = 0;
		ts.tv_usec = 100000;
		if (setsockopt(m_statsd_sock, SOL_SOCKET, SO_RCVTIMEO, &ts, sizeof(ts)) < 0)
		{
			FAIL() << "Can't set timeout of 5 seconds for fake statsd server: " << strerror(errno);
		}

		m_statsd_server_done = false;

		// In a thread, receive statsd metrics and update m_metrics
		m_statsd_server = thread([this] ()
                {
			while (!m_statsd_server_done)
			{
				char buf[1024];
				ssize_t recv_len;

				if((recv_len = recv(m_statsd_sock, buf, sizeof(buf), 0)) < 0)
				{
					if(errno != EAGAIN)
					{
						fprintf(stderr, "Could not receive statsd metric: %s\n", strerror(errno));
					}
				}
				else
				{
					std::lock_guard<std::mutex> lock(m_metrics_mutex);

					m_metrics.insert(string(buf, recv_len));
				}
			}
		});
	}

	virtual void TearDown()
	{
		if(m_cointerface)
		{
			Process::kill(*m_cointerface);
		}

		m_statsd_server_done = 1;
	        m_statsd_server.join();

		if(close(m_statsd_sock) < 0)
		{
			FAIL() << "Can't close statsd socket: " << strerror(errno);
		}

		m_grpc_load.reset();
		m_grpc_start.reset();
		m_grpc_stop.reset();
		m_grpc_conn.reset();
		g_log->information("TearDown() complete");
	}

	void stop_tasks()
	{
		bool stopped = false;
		auto callback = [this, &stopped](bool successful, sdc_internal::comp_stop_result &res)
		{
			if(!successful)
			{
				FAIL() << "Stop() call was not successful";
			}

			if(!res.successful())
			{
				FAIL() << "Stop() call returned error " << res.errstr();
			}

			stopped = true;
		};

		sdc_internal::comp_stop stop;
		m_grpc_stop->do_rpc(stop, callback);

		// Wait up to 10 seconds
		for(uint32_t i=0; i < 1000; i++)
		{
			Poco::Thread::sleep(10);
			m_grpc_stop->process_queue();

			if(stopped)
			{
				return;
			}
		}

		FAIL() << "After 10 seconds, did not get response to Stop()";
	}

	void start_tasks(std::vector<task_defs_t> &task_defs)
	{
		auto callback = [this](streaming_grpc::Status status, sdc_internal::comp_task_event &cevent)
		{
			ASSERT_NE(status, streaming_grpc::ERROR);

			if(!status == streaming_grpc::OK)
			{
				return;
			}

			if(!cevent.successful())
			{
				m_errors[cevent.task_name()].push_back(cevent.errstr());
			}
			else
			{
				for(int i=0; i < cevent.events().events_size(); i++)
				{
					m_events[cevent.task_name()].push_back(cevent.events().events(i));
				}

				for(int i=0; i < cevent.results().results_size(); i++)
				{
					m_results[cevent.task_name()].push_back(cevent.results().results(i));
				}
			}
		};

		sdc_internal::comp_start start;

		for(auto &def: task_defs)
		{
			draiosproto::comp_task *task = start.mutable_calendar()->add_tasks();
			task->set_id(def.id);
			task->set_name(def.name);
			task->set_mod_name(def.module);
			task->set_enabled(true);
			task->set_schedule(def.schedule);

			draiosproto::comp_task_param *param = task->add_task_params();
			param->set_key("iter");
			param->set_val(def.scraper_id);

			param = task->add_task_params();
			param->set_key("sleepTime");
			param->set_val(def.sleep_time);
		}

		start.set_machine_id("test-machine-id");
		start.set_customer_id("test-customer-id");

		m_grpc_start->do_rpc(start, callback);
        }

	void verify_task_result(task_defs_t &def)
	{
		// Wait up to 10 seconds
		for(uint32_t i=0; i < 1000; i++)
		{
			Poco::Thread::sleep(10);
			m_grpc_start->process_queue();

			if(m_results.find(def.name) != m_results.end())
			{
				break;
			}
		}

		ASSERT_TRUE(m_results.find(def.name) != m_results.end()) << "After 10 seconds, did not see any results with expected values for task " << def.name;
		ASSERT_EQ(m_results[def.name].size(), 1) << "After 10 seconds, did not see any results with expected values for task " << def.name;
		auto &result = m_results[def.name].front();

		Json::Value ext_result;
		Json::Reader reader;
		ASSERT_TRUE(reader.parse(result.ext_result(), ext_result));

		ASSERT_EQ(ext_result["id"].asUInt64(), def.id);
		ASSERT_STREQ(ext_result["taskName"].asString().c_str(), def.name.c_str());
		ASSERT_EQ(ext_result["testsRun"].asUInt64(), strtoul(def.scraper_id.c_str(), NULL, 10));
		ASSERT_EQ(ext_result["testsRun"].asUInt64(), strtoul(def.scraper_id.c_str(), NULL, 10));
		ASSERT_STREQ(ext_result["risk"].asString().c_str(), "low");
	}

	void verify_task_event(task_defs_t &def)
	{
		// Wait up to 10 seconds
		for(uint32_t i=0; i < 1000; i++)
		{
			Poco::Thread::sleep(10);
			m_grpc_start->process_queue();

			if(m_results.find(def.name) != m_results.end())
			{
				break;
			}
		}

		ASSERT_TRUE(m_events.find(def.name) != m_events.end()) << "After 10 seconds, did not see any events with expected values for task " << def.name;
		ASSERT_EQ(m_events[def.name].size(), 1) << "After 10 seconds, did not see any events with expected values for task " << def.name;
		auto &event = m_events[def.name].front();

		std::string output = "test output (task=" + def.name + " iter=" + def.scraper_id + ")";
		std::string output_json = "{\"task\":\"" + def.name + "\", \"iter\": " + def.scraper_id + "}";

		ASSERT_STREQ(event.task_name().c_str(), def.name.c_str());
		ASSERT_STREQ(event.container_id().c_str(), "test-container");
		ASSERT_STREQ(event.output().c_str(), output.c_str());
		ASSERT_STREQ(event.output_fields().at("task").c_str(), def.name.c_str());
		ASSERT_STREQ(event.output_fields().at("iter").c_str(), def.scraper_id.c_str());
	}

	void clear_results_events()
	{
		m_results.clear();
		m_events.clear();
		m_metrics.clear();
		m_errors.clear();
	}

	void verify_metric(task_defs_t &def)
	{
		std::string expected = string("compliance.") + def.name + ":tests_pass:" + def.scraper_id + "|g\n";

		// Wait up to 10 seconds
		for(uint32_t i=0; i < 1000; i++)
		{
			Poco::Thread::sleep(10);
			{
				std::lock_guard<std::mutex> lock(m_metrics_mutex);
				if(m_metrics.find(expected) != m_metrics.end())
				{
					return;
				}
			}
		}

		FAIL() << "After 10 seconds, did not see expected metric for task " << def.name;
	}

	void verify_error(std::string &task_name, std::string &expected)
	{
		// Wait up to 10 seconds
		for(uint32_t i=0; i < 1000; i++)
		{
			Poco::Thread::sleep(10);
			m_grpc_start->process_queue();

			if (m_errors.find(task_name) != m_errors.end())
			{
				for(auto &errstr : m_errors[task_name])
				{
					if (errstr == expected)
					{
						return;
					}
				}
			}
		}

		FAIL() << "After 10 seconds, did not see expected error \"" << expected << "\" for task name " << task_name;
	}

	shared_ptr<Pipe> m_colog;
	shared_ptr<ProcessHandle> m_cointerface;

	std::shared_ptr<sdc_internal::ComplianceModuleMgr::Stub> m_grpc_conn;
	std::shared_ptr<streaming_grpc_client(&sdc_internal::ComplianceModuleMgr::Stub::AsyncStart)> m_grpc_start;
	std::shared_ptr<unary_grpc_client(&sdc_internal::ComplianceModuleMgr::Stub::AsyncLoad)> m_grpc_load;
	std::shared_ptr<unary_grpc_client(&sdc_internal::ComplianceModuleMgr::Stub::AsyncStop)> m_grpc_stop;

	// Maps from task name to all the results that have been received for that task
	std::map<std::string, std::vector<draiosproto::comp_result>> m_results;
	std::map<std::string, std::vector<draiosproto::comp_event>> m_events;
	std::map<std::string, std::vector<std::string>> m_errors;

	// All the unique metrics that have ever been received by the fake statsd server
	std::set<std::string> m_metrics;
	std::mutex m_metrics_mutex;

	std::thread m_statsd_server;
	int m_statsd_sock;
	atomic<bool> m_statsd_server_done;
};

static std::vector<task_defs_t> one_task = {{"PT1H", 1, "my-task-1", "test-module", "1", "0"}};
static std::vector<task_defs_t> frequent_task = {{"PT10S", 1, "my-task-1", "test-module", "1", "0"}};
static std::vector<task_defs_t> task_slow = {{"PT1H", 1, "my-task-1", "test-module", "1", "5"}};
static std::vector<task_defs_t> one_task_alt_output = {{"PT1H", 1, "my-task-1", "test-module", "2", "0"}};
static std::vector<task_defs_t> task_two = {{"PT1H", 2, "my-task-2", "test-module", "2", "0"}};
static std::vector<task_defs_t> two_tasks = {{"PT1H", 1, "my-task-1", "test-module", "1", "0"}, {"PT1H", 2, "my-task-2", "test-module", "2", "0"}};
static std::vector<task_defs_t> two_tasks_alt_output = {{"PT1H", 1, "my-task-1", "test-module", "3", "0"}, {"PT1H", 2, "my-task-2", "test-module", "4", "0"}};
static std::vector<task_defs_t> one_task_twice = {{"R2/PT1S", 1, "my-task-1", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule = {{"not-a-real-schedule", 1, "bad-schedule-task", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule_2 = {{"PT1K1M", 1, "bad-schedule-task-2", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule_leading_junk = {{"junkPT1H", 1, "bad-schedule-task-leading-junk", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule_trailing_junk = {{"PT-1H", 1, "bad-schedule-task-trailing-junk", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_module = {{"PT1H", 1, "bad-module-task", "not-a-real-module", "1", "0"}};

// Test cases:
//  - DONE Schedule a task using test-module, see them all emit events/results/metrics
//  - DONE Send a second start w/ same schedule, get a second set of events/results/metrics
//  - DONE Send start while tasks are running, ensure existing task killed and does not send events/results/metrics
//  - DONE Multiple tasks using the same module. Should get meaningful results/metrics for both
//  - DONE Verify protection against same task running at once works
//  - DONE Try a schedule with an invalid calendar, get expected error
//  - DONE Try a nonexistent module, get expected error

TEST_F(compliance_test, load)
{
	bool got_response = false;

	auto callback = [this, &got_response](bool successful, sdc_internal::comp_load_result &lresult)
	{
		got_response = true;
		ASSERT_TRUE(successful);

		ASSERT_EQ(lresult.statuses_size(), 3);

		for(auto &status : lresult.statuses())
		{
			if (strcmp(status.mod_name().c_str(), "docker-bench-security") != 0 &&
			    strcmp(status.mod_name().c_str(), "kube-bench") != 0 &&
			    strcmp(status.mod_name().c_str(), "test-module") != 0)
			{
				FAIL() << "Unexpected module found: " << status.mod_name();
			}

			ASSERT_TRUE(status.running());
			ASSERT_EQ(status.has_errstr(), false);
		}
	};

	sdc_internal::comp_load load;

	load.set_machine_id("test-machine-id");
	load.set_customer_id("test-customer-id");

	m_grpc_load->do_rpc(load, callback);

	// Wait up to 10 seconds
	for(uint32_t i=0; i < 1000 && !got_response; i++)
	{
		Poco::Thread::sleep(10);
		m_grpc_load->process_queue();
	}

	ASSERT_TRUE(got_response) << "10 seconds after Load(), did not receive any response";
}

TEST_F(compliance_test, start)
{
	start_tasks(one_task);
	verify_task_result(one_task[0]);
	verify_task_event(one_task[0]);
	verify_metric(one_task[0]);

	stop_tasks();
}

TEST_F(compliance_test, start_frequent)
{
	start_tasks(frequent_task);
	verify_task_result(frequent_task[0]);
	verify_task_event(frequent_task[0]);
	verify_metric(frequent_task[0]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_start)
{
	start_tasks(one_task);
	verify_task_result(one_task[0]);
	verify_task_event(one_task[0]);
	verify_metric(one_task[0]);
	clear_results_events();

	start_tasks(one_task_alt_output);
	verify_task_result(one_task_alt_output[0]);
	verify_task_event(one_task_alt_output[0]);
	verify_metric(one_task_alt_output[0]);

	stop_tasks();
}

TEST_F(compliance_test, start_after_stop)
{
	start_tasks(one_task);
	verify_task_result(one_task[0]);
	verify_task_event(one_task[0]);
	verify_metric(one_task[0]);
	stop_tasks();
	clear_results_events();

	start_tasks(one_task_alt_output);
	verify_task_result(one_task_alt_output[0]);
	verify_task_event(one_task_alt_output[0]);
	verify_metric(one_task_alt_output[0]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_tasks_same_module)
{
	start_tasks(two_tasks);
	verify_task_result(two_tasks[0]);
	verify_task_event(two_tasks[0]);
	verify_metric(two_tasks[0]);

	verify_task_result(two_tasks[1]);
	verify_task_event(two_tasks[1]);
	verify_metric(two_tasks[1]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_tasks_multiple_start)
{
	start_tasks(two_tasks);
	verify_task_result(two_tasks[0]);
	verify_task_event(two_tasks[0]);
	verify_metric(two_tasks[0]);

	verify_task_result(two_tasks[1]);
	verify_task_event(two_tasks[1]);
	verify_metric(two_tasks[1]);

	clear_results_events();

	start_tasks(two_tasks_alt_output);
	verify_task_result(two_tasks_alt_output[0]);
	verify_task_event(two_tasks_alt_output[0]);
	verify_metric(two_tasks_alt_output[0]);

	verify_task_result(two_tasks_alt_output[1]);
	verify_task_event(two_tasks_alt_output[1]);
	verify_metric(two_tasks_alt_output[1]);

	stop_tasks();
}

TEST_F(compliance_test, start_cancels)
{
	start_tasks(task_slow);

	sleep(1);

	start_tasks(task_two);

	verify_task_result(task_two[0]);
	verify_task_event(task_two[0]);
	verify_metric(task_two[0]);

	sleep(10);
	ASSERT_TRUE(m_results.find(task_slow[0].name) == m_results.end());
	ASSERT_TRUE(m_events.find(task_slow[0].name) == m_events.end());
	ASSERT_TRUE(m_metrics.find(task_slow[0].name) == m_metrics.end());

	stop_tasks();
}

TEST_F(compliance_test, overlapping_tasks)
{
	start_tasks(one_task_twice);

	verify_task_result(one_task_twice[0]);
	verify_task_event(one_task_twice[0]);
	verify_metric(one_task_twice[0]);

	// Ensure that there is only a single result/event. The first
	// task runs for 5 seconds, so the second invocation
	// should have been skipped.

	sleep(10);

	ASSERT_EQ(m_events[one_task_twice[0].name].size(), 1);
	ASSERT_EQ(m_results[one_task_twice[0].name].size(), 1);

	stop_tasks();
}

TEST_F(compliance_test, bad_schedule)
{
	std::string expected = "Could not schedule task bad-schedule-task: Could not parse duration from schedule not-a-real-schedule: did not match expected pattern";

	start_tasks(bad_schedule);

	verify_error(bad_schedule[0].name, expected);

	stop_tasks();
}

TEST_F(compliance_test, bad_schedule_2)
{
	std::string expected = "Could not schedule task bad-schedule-task-2: Could not parse duration from schedule PT1K1M: did not match expected pattern";

	start_tasks(bad_schedule_2);

	verify_error(bad_schedule_2[0].name, expected);

	stop_tasks();
}

TEST_F(compliance_test, bad_schedule_leading_junk)
{
	std::string expected = "Could not schedule task bad-schedule-task-leading-junk: Could not parse duration from schedule junkPT1H: did not match expected pattern";

	start_tasks(bad_schedule_leading_junk);

	verify_error(bad_schedule_leading_junk[0].name, expected);

	stop_tasks();
}

TEST_F(compliance_test, bad_schedule_trailing_junk)
{
	std::string expected = "Could not schedule task bad-schedule-task-trailing-junk: Could not parse duration from schedule PT-1H: did not match expected pattern";

	start_tasks(bad_schedule_trailing_junk);

	verify_error(bad_schedule_trailing_junk[0].name, expected);

	stop_tasks();
}

TEST_F(compliance_test, bad_module)
{
	start_tasks(bad_module);

	std::string expected = "Could not schedule task bad-module-task: Module not-a-real-module does not exist";

	verify_error(bad_module[0].name, expected);

	stop_tasks();
}
