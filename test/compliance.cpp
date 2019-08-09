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
#include <Poco/RegularExpression.h>

#include <gtest.h>

#include <sinsp.h>
#include <configuration.h>
#include <protocol.h>
#include <compliance_mgr.h>

using namespace std;
using namespace Poco;

struct task_defs_t {
	std::string schedule;
	uint64_t id;
	std::string name;
	std::string module;
	std::string scraper_id;
	std::string sleep_time;
	std::string rc;
	bool successful;
	std::string start_time;
	std::vector<std::string> future_runs;

	std::shared_ptr<Poco::RegularExpression> failure_details_re;

	task_defs_t() {};
	task_defs_t(std::string tschedule,
		    uint64_t tid,
		    std::string tname,
		    std::string tmodule,
		    std::string tscraper_id,
		    std::string tsleep_time)
		: schedule(tschedule),
		  id(tid),
		  name(tname),
		  module(tmodule),
		  scraper_id(tscraper_id),
		  sleep_time(tsleep_time),
		  rc("0"),
		  successful(true),
		  start_time("")
		{};

	task_defs_t(std::string tschedule,
		    uint64_t tid,
		    std::string tname,
		    std::string tmodule,
		    std::string tscraper_id,
		    std::string tsleep_time,
		    std::string trc,
		    bool tsuccessful,
		    std::string tfailure_details)
		: schedule(tschedule),
		  id(tid),
		  name(tname),
		  module(tmodule),
		  scraper_id(tscraper_id),
		  sleep_time(tsleep_time),
		  rc(trc),
		  successful(tsuccessful),
		  start_time("")
		{
			failure_details_re = make_shared<Poco::RegularExpression>(tfailure_details);
		};

	task_defs_t(std::string tschedule,
		    uint64_t tid,
		    std::string tname,
		    std::string tmodule,
		    std::string tscraper_id,
		    std::string tsleep_time,
		    std::string tstart_time,
		    std::vector<std::string> tfuture_runs)
		: schedule(tschedule),
		  id(tid),
		  name(tname),
		  module(tmodule),
		  scraper_id(tscraper_id),
		  sleep_time(tsleep_time),
		  rc("0"),
		  successful(true),
		  start_time(tstart_time),
		  future_runs(tfuture_runs)
		{};
};

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

			g_log = std::unique_ptr<common_logger>(new common_logger(&nullc, &loggerc));
		}

		std::string cointerface_root = "./resources";
		string cointerface_sock = cointerface_root + "/cointerface.sock";

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

		m_queue = new protocol_queue(100);

		m_configuration.init(NULL, false);
		dragent_configuration::m_terminate = false;

		m_data_handler = new sinsp_data_handler(&m_configuration, m_queue);

		m_compliance_mgr = new compliance_mgr(cointerface_root);

		// These tests don't check scope of compliance tasks so analyzer is set to NULL
		bool save_errors = true;
		m_compliance_mgr->init(m_data_handler, NULL, &m_configuration, save_errors);

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

		m_done = false;

		// In a thread, receive statsd metrics and update m_metrics
		m_statsd_server = thread([this] ()
                {
			while (!m_done)
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

		// Start a thread that reads from the queue, appending results to m_results
		m_result_reader = thread([this]()
		{
			while(!m_done)
			{
				shared_ptr<protocol_queue_item> item;
				dragent_protocol_header *hdr;
				const uint8_t *buf;
				uint32_t size;

				if (!m_queue->get(&item, 100))
				{
					continue;
				}

				hdr = (dragent_protocol_header*) item->buffer.data();
				buf = (const uint8_t *) (item->buffer.data() + sizeof(dragent_protocol_header));
				size = ntohl(hdr->len) - sizeof(dragent_protocol_header);

				g_log->debug("Got message type=" + to_string(hdr->messagetype));

				draiosproto::comp_results res;
				switch (hdr->messagetype)
				{
				case draiosproto::message_type::COMP_RESULTS:
					dragent_protocol::buffer_to_protobuf(buf, size, &res);
					break;

				default:
					FAIL() << "Received unknown message " << hdr->messagetype;
				}

				for(auto &result : res.results())
				{
					m_results[result.task_name()].push_back(result);
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

		m_done = true;
	        m_statsd_server.join();
	        m_result_reader.join();

		if(close(m_statsd_sock) < 0)
		{
			FAIL() << "Can't close statsd socket: " << strerror(errno);
		}

		delete m_compliance_mgr;
		delete m_data_handler;
		delete m_queue;
		g_log->information("TearDown() complete");
	}

	void stop_tasks()
	{
		m_compliance_mgr->stop_compliance_tasks();
	}

	void get_future_runs(task_defs_t &def)
	{
		sdc_internal::comp_get_future_runs req;
		sdc_internal::comp_future_runs future_runs;

		draiosproto::comp_task *task = req.mutable_task();

		task->set_id(def.id);
		task->set_name(def.name);
		task->set_mod_name(def.module);
		task->set_enabled(true);
		task->set_schedule(def.schedule);

		req.set_start(def.start_time);
		req.set_num_runs(5);

		std::string errstr;
		ASSERT_TRUE(m_compliance_mgr->get_future_runs(req, future_runs, errstr)) << "get_future_runs() returned error:" << errstr;

		ASSERT_EQ(uint32_t(future_runs.runs().size()), def.future_runs.size());

		for(int32_t i=0; i < future_runs.runs().size(); i++)
		{
			ASSERT_STREQ(future_runs.runs(i).c_str(), def.future_runs.at(i).c_str());
		}
	}

	void start_tasks(std::vector<task_defs_t> &task_defs)
	{
		draiosproto::comp_calendar cal;

		for(auto &def: task_defs)
		{
			draiosproto::comp_task *task = cal.add_tasks();
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

			param = task->add_task_params();
			param->set_key("rc");
			param->set_val(def.rc);
		}

		bool send_results = true;
		bool send_events = true;
		m_compliance_mgr->set_compliance_calendar(cal, send_results, send_events);
        }

	void run_tasks(std::vector<task_defs_t> &task_defs)
	{
		draiosproto::comp_run run;

		for(auto &def: task_defs)
		{
			run.add_task_ids(def.id);
		}

		m_compliance_mgr->set_compliance_run(run);
        }

	void verify_task_result(task_defs_t &def, uint64_t num_results=1)
	{
		// Wait up to 10 seconds
		for(uint32_t i=0; i < 100; i++)
		{
			Poco::Thread::sleep(100);

			m_compliance_mgr->check_tasks();

			if(m_results.find(def.name) != m_results.end() &&
			   m_results[def.name].size() >= num_results)
			{
				break;
			}
		}

		ASSERT_EQ(m_compliance_mgr->m_num_grpc_errs, 0u);
		ASSERT_TRUE(m_results.find(def.name) != m_results.end()) << "After 10 seconds, did not see any results with expected values for task " << def.name;
		ASSERT_EQ(m_results[def.name].size(), num_results) << "After 10 seconds, did not see any results with expected values for task " << def.name;
		auto &result = m_results[def.name].front();

		ASSERT_EQ(result.successful(), def.successful);

		if(result.successful())
		{
			Json::Value ext_result;
			Json::Reader reader;
			ASSERT_TRUE(reader.parse(result.ext_result(), ext_result));

			ASSERT_EQ(ext_result["id"].asUInt64(), def.id);
			ASSERT_STREQ(ext_result["taskName"].asString().c_str(), def.name.c_str());
			ASSERT_EQ(ext_result["testsRun"].asUInt64(), strtoul(def.scraper_id.c_str(), NULL, 10));
			ASSERT_EQ(ext_result["passCount"].asUInt64(), strtoul(def.scraper_id.c_str(), NULL, 10));
			ASSERT_STREQ(ext_result["risk"].asString().c_str(), "low");
		}
		else
		{
			ASSERT_TRUE(def.failure_details_re->match(result.failure_details()));
		}
	}

	void clear_results()
	{
		m_results.clear();
		m_metrics.clear();
	}

	void verify_metric(task_defs_t &def)
	{
		std::string expected = string("compliance.") + def.name + ":tests_pass:" + def.scraper_id + "|g\n";

		// Wait up to 10 seconds
		for(uint32_t i=0; i < 1000; i++)
		{
			Poco::Thread::sleep(10);

			m_compliance_mgr->check_tasks();

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

			m_compliance_mgr->check_tasks();

			if (m_compliance_mgr->m_task_errors.find(task_name) != m_compliance_mgr->m_task_errors.end())
			{
				for(auto &errstr : m_compliance_mgr->m_task_errors[task_name])
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

	protocol_queue *m_queue;
	sinsp_data_handler *m_data_handler;
	compliance_mgr *m_compliance_mgr;
	dragent_configuration m_configuration;
	shared_ptr<Pipe> m_colog;
	shared_ptr<ProcessHandle> m_cointerface;

	// Maps from task name to all the results that have been received for that task
	std::map<std::string, std::vector<draiosproto::comp_result>> m_results;

	// All the unique metrics that have ever been received by the fake statsd server
	std::set<std::string> m_metrics;
	std::mutex m_metrics_mutex;

	std::thread m_statsd_server, m_result_reader;
	int m_statsd_sock;
	atomic<bool> m_done;
};

static std::vector<task_defs_t> no_tasks;
static std::vector<task_defs_t> one_task = {{"PT1H", 1, "my-task-1", "test-module", "1", "0"}};
static std::vector<task_defs_t> frequent_task = {{"PT10S", 1, "my-task-1", "test-module", "1", "0"}};
static std::vector<task_defs_t> task_slow = {{"PT1H", 1, "my-task-1", "test-module", "1", "5"}};
static std::vector<task_defs_t> one_task_alt_output = {{"PT1H", 3, "my-task-3", "test-module", "2", "0"}};
static std::vector<task_defs_t> task_two = {{"PT1H", 2, "my-task-2", "test-module", "2", "0"}};
static std::vector<task_defs_t> two_tasks = {{"PT1H", 1, "my-task-1", "test-module", "1", "0"}, {"PT1H", 2, "my-task-2", "test-module", "2", "0"}};
static std::vector<task_defs_t> two_tasks_alt_output = {{"PT1H", 3, "my-task-3", "test-module", "3", "0"}, {"PT1H", 4, "my-task-4", "test-module", "4", "0"}};
static std::vector<task_defs_t> one_task_twice = {{"R2/PT1S", 1, "my-task-1", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule = {{"not-a-real-schedule", 1, "bad-schedule-task", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule_2 = {{"PT1K1M", 1, "bad-schedule-task-2", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule_leading_junk = {{"junkPT1H", 1, "bad-schedule-task-leading-junk", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_schedule_trailing_junk = {{"PT-1H", 1, "bad-schedule-task-trailing-junk", "test-module", "1", "5"}};
static std::vector<task_defs_t> bad_module = {{"PT1H", 1, "bad-module-task", "not-a-real-module", "1", "0"}};
static std::vector<task_defs_t> exit_failure = {{"PT1H", 1, "exit-failure-task-1", "test-module", "1", "0", "1", false, "^module test-module via {Path=.*test/resources/modules_dir/test-module/run.sh Args=\\[.*/test/resources/modules_dir/test-module/run.sh 0 1\\] Env=\\[.*\\] Dir=.*/test/resources/modules_dir/test-module} exited with error \\(exit status 1\\) Stdout: \"This is to stdout\\n\" Stderr: \"This is to stderr\\n\""}};

// This module is defined, but its command line doesn't exist, meaning it will fail every time it is run.
static std::vector<task_defs_t> fail_module = {{"PT1H", 1, "fail-task-1", "fail-module", "1", "0", "1", false, "^Could not start module fail-module via {Path=.*/test/resources/modules_dir/fail-module/not-runnable Args=\\[.*/test/resources/modules_dir/fail-module/not-runnable 0 1\\] Env=\\[.*\\] Dir=.*/test/resources/modules_dir/fail-module} \\(fork/exec .*/test/resources/modules_dir/fail-module/not-runnable: permission denied\\)"}};

static std::vector<task_defs_t> multiple_intervals = {{"[R1/PT1S, PT1H]", 1, "multiple-intervals", "test-module", "1", "0"}};

static std::vector<task_defs_t> multiple_intervals_2 = {{"[R1/PT1S, R1/PT2S]", 1, "multiple-intervals-2", "test-module", "1", "0"}};

// The current time will be added to the interval
static std::vector<task_defs_t> explicit_start_time = {{"/P1D", 1, "my-task-1", "test-module", "1", "0"}};

static std::vector<task_defs_t> future_runs_twice_daily = {{"06:00:00Z/PT12H", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T06:00:00Z", "2018-11-14T18:00:00Z", "2018-11-15T06:00:00Z", "2018-11-15T18:00:00Z", "2018-11-16T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_once_daily_6am = {{"06:00:00Z/P1D", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T06:00:00Z", "2018-11-15T06:00:00Z", "2018-11-16T06:00:00Z", "2018-11-17T06:00:00Z", "2018-11-18T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_once_daily_6pm = {{"18:00:00Z/P1D", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T18:00:00Z", "2018-11-15T18:00:00Z", "2018-11-16T18:00:00Z", "2018-11-17T18:00:00Z", "2018-11-18T18:00:00Z"}}};
static std::vector<task_defs_t> future_runs_weekly_monday_6am = {{"2018-11-12T06:00:00Z/P1W", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-19T06:00:00Z", "2018-11-26T06:00:00Z", "2018-12-03T06:00:00Z", "2018-12-10T06:00:00Z", "2018-12-17T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_weekly_monday_6pm = {{"2018-11-12T18:00:00Z/P1W", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-19T18:00:00Z", "2018-11-26T18:00:00Z", "2018-12-03T18:00:00Z", "2018-12-10T18:00:00Z", "2018-12-17T18:00:00Z"}}};
static std::vector<task_defs_t> future_runs_weekly_wednesday_6am = {{"2018-11-14T06:00:00Z/P1W", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T06:00:00Z", "2018-11-21T06:00:00Z", "2018-11-28T06:00:00Z", "2018-12-05T06:00:00Z", "2018-12-12T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_weekly_wednesday_6pm = {{"2018-11-14T18:00:00Z/P1W", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T18:00:00Z", "2018-11-21T18:00:00Z", "2018-11-28T18:00:00Z", "2018-12-05T18:00:00Z", "2018-12-12T18:00:00Z"}}};
static std::vector<task_defs_t> future_runs_weekly_friday_6am = {{"2018-11-16T06:00:00Z/P1W", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-16T06:00:00Z", "2018-11-23T06:00:00Z", "2018-11-30T06:00:00Z", "2018-12-07T06:00:00Z", "2018-12-14T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_weekly_friday_6pm = {{"2018-11-16T18:00:00Z/P1W", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-16T18:00:00Z", "2018-11-23T18:00:00Z", "2018-11-30T18:00:00Z", "2018-12-07T18:00:00Z", "2018-12-14T18:00:00Z"}}};
static std::vector<task_defs_t> future_runs_twice_monthly_6am = {{"[2018-11-01T06:00:00Z/P1M, 2018-11-14T06:00:00Z/P1M]", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T06:00:00Z", "2018-12-01T06:00:00Z", "2018-12-14T06:00:00Z", "2019-01-01T06:00:00Z", "2019-01-14T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_twice_monthly_6pm = {{"[2018-11-01T18:00:00Z/P1M, 2018-11-14T18:00:00Z/P1M]", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T18:00:00Z", "2018-12-01T18:00:00Z", "2018-12-14T18:00:00Z", "2019-01-01T18:00:00Z", "2019-01-14T18:00:00Z"}}};
static std::vector<task_defs_t> future_runs_once_monthly_1st_6am = {{"2018-11-01T06:00:00Z/P1M", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-12-01T06:00:00Z", "2019-01-01T06:00:00Z", "2019-02-01T06:00:00Z", "2019-03-01T06:00:00Z", "2019-04-01T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_once_monthly_1st_6pm = {{"2018-11-01T18:00:00Z/P1M", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-12-01T18:00:00Z", "2019-01-01T18:00:00Z", "2019-02-01T18:00:00Z", "2019-03-01T18:00:00Z", "2019-04-01T18:00:00Z"}}};
static std::vector<task_defs_t> future_runs_once_monthly_14th_6am = {{"2018-11-14T06:00:00Z/P1M", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T06:00:00Z", "2018-12-14T06:00:00Z", "2019-01-14T06:00:00Z", "2019-02-14T06:00:00Z", "2019-03-14T06:00:00Z"}}};
static std::vector<task_defs_t> future_runs_once_monthly_14th_6pm = {{"2018-11-14T18:00:00Z/P1M", 1, "next-run-1", "test-module", "1", "0", "2018-11-14T00:00:00Z", {"2018-11-14T18:00:00Z", "2018-12-14T18:00:00Z", "2019-01-14T18:00:00Z", "2019-02-14T18:00:00Z", "2019-03-14T18:00:00Z"}}};


// Test cases:
//   - DONE A single task with multiple intervals
//   - A task with an explicit start time + interval
//   - Add some endpoint/method that returns a list of the next 10 or so times each task will run, and use that in tests.

TEST_F(compliance_test, start)
{
	start_tasks(one_task);
	verify_task_result(one_task[0]);
	verify_metric(one_task[0]);

	stop_tasks();
}

TEST_F(compliance_test, start_frequent)
{
	start_tasks(frequent_task);
	verify_task_result(frequent_task[0]);
	verify_metric(frequent_task[0]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_start)
{
	start_tasks(one_task);
	verify_task_result(one_task[0]);
	verify_metric(one_task[0]);
	clear_results();

	start_tasks(one_task_alt_output);
	verify_task_result(one_task_alt_output[0]);
	verify_metric(one_task_alt_output[0]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_start_empty_calendar)
{
	start_tasks(one_task);
	verify_task_result(one_task[0]);
	verify_metric(one_task[0]);
	clear_results();

	start_tasks(no_tasks);

	for(uint32_t i=0; i < 30; i++)
	{
		Poco::Thread::sleep(100);

		m_compliance_mgr->check_tasks();
	}

	ASSERT_TRUE(m_results.size() == 0);
}

TEST_F(compliance_test, start_after_stop)
{
	start_tasks(one_task);
	verify_task_result(one_task[0]);
	verify_metric(one_task[0]);
	stop_tasks();
	clear_results();

	start_tasks(one_task_alt_output);
	verify_task_result(one_task_alt_output[0]);
	verify_metric(one_task_alt_output[0]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_tasks_same_module)
{
	start_tasks(two_tasks);
	verify_task_result(two_tasks[0]);
	verify_metric(two_tasks[0]);

	verify_task_result(two_tasks[1]);
	verify_metric(two_tasks[1]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_tasks_multiple_start)
{
	start_tasks(two_tasks);
	verify_task_result(two_tasks[0]);
	verify_metric(two_tasks[0]);

	verify_task_result(two_tasks[1]);
	verify_metric(two_tasks[1]);

	clear_results();

	start_tasks(two_tasks_alt_output);
	verify_task_result(two_tasks_alt_output[0]);
	verify_metric(two_tasks_alt_output[0]);

	verify_task_result(two_tasks_alt_output[1]);
	verify_metric(two_tasks_alt_output[1]);

	stop_tasks();
}

TEST_F(compliance_test, start_cancels)
{
	start_tasks(task_slow);

	sleep(1);

	start_tasks(task_two);

	verify_task_result(task_two[0]);
	verify_metric(task_two[0]);

	sleep(10);
	ASSERT_TRUE(m_results.find(task_slow[0].name) == m_results.end());
	ASSERT_TRUE(m_metrics.find(task_slow[0].name) == m_metrics.end());

	stop_tasks();
}

TEST_F(compliance_test, overlapping_tasks)
{
	start_tasks(one_task_twice);

	verify_task_result(one_task_twice[0]);
	verify_metric(one_task_twice[0]);

	// Ensure that there is only a single result. The first
	// task runs for 5 seconds, so the second invocation
	// should have been skipped.

	sleep(10);

	ASSERT_EQ(m_results[one_task_twice[0].name].size(), 1U);

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

TEST_F(compliance_test, exit_failure)
{
	start_tasks(exit_failure);

	verify_task_result(exit_failure[0]);

	stop_tasks();
}

TEST_F(compliance_test, fail_module)
{
	start_tasks(fail_module);

	verify_task_result(fail_module[0]);

	stop_tasks();
}

TEST_F(compliance_test, multiple_intervals)
{
	start_tasks(multiple_intervals);

	// Should be 1 result from the "run now" task, and one for the first interval.
	verify_task_result(multiple_intervals[0], 2);

	stop_tasks();
}


TEST_F(compliance_test, multiple_intervals_2)
{
	start_tasks(multiple_intervals_2);

	// Should be 1 result from the "run now" task, and one for each interval
	verify_task_result(multiple_intervals_2[0], 3);

	stop_tasks();
}

TEST_F(compliance_test, run_tasks)
{
	start_tasks(one_task);

	verify_task_result(one_task[0]);
	verify_metric(one_task[0]);

	clear_results();

	run_tasks(one_task);

	// Normally this would fail other than the fact that we
	// triggered running the task out-of-band.
	verify_task_result(one_task[0]);
	verify_metric(one_task[0]);

	stop_tasks();
}

TEST_F(compliance_test, explicit_start_time)
{
	char timestr[32];
	time_t now;

	time(&now);

	now += 10;

	strftime(timestr, sizeof(timestr), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

	explicit_start_time[0].schedule = string(timestr) + explicit_start_time[0].schedule;

	start_tasks(explicit_start_time);

	for(uint32_t i=0; i < 50; i++)
	{
		Poco::Thread::sleep(100);
		m_compliance_mgr->check_tasks();
	}

	// There should be only a single result so far, which reflects
	// the initial "run now" task.
	ASSERT_EQ(m_results[explicit_start_time[0].name].size(), 1U);

	for(uint32_t i=0; i < 100; i++)
	{
		Poco::Thread::sleep(100);
		m_compliance_mgr->check_tasks();
	}

	// Now there should be 2 results, as the start time for the schedule has occurred
	ASSERT_EQ(m_results[explicit_start_time[0].name].size(), 2U);

	stop_tasks();
}

TEST_F(compliance_test, future_runs_twice_daily)
{
	get_future_runs(future_runs_twice_daily[0]);
}

TEST_F(compliance_test, future_runs_once_daily_6am)
{
	get_future_runs(future_runs_once_daily_6am[0]);
}

TEST_F(compliance_test, future_runs_once_daily_6pm)
{
	get_future_runs(future_runs_once_daily_6pm[0]);
}

TEST_F(compliance_test, future_runs_weekly_monday_6am)
{
	get_future_runs(future_runs_weekly_monday_6am[0]);
}

TEST_F(compliance_test, future_runs_weekly_monday_6pm)
{
	get_future_runs(future_runs_weekly_monday_6pm[0]);
}

TEST_F(compliance_test, future_runs_weekly_wednesday_6am)
{
	get_future_runs(future_runs_weekly_wednesday_6am[0]);
}

TEST_F(compliance_test, future_runs_weekly_wednesday_6pm)
{
	get_future_runs(future_runs_weekly_wednesday_6pm[0]);
}

TEST_F(compliance_test, future_runs_weekly_friday_6am)
{
	get_future_runs(future_runs_weekly_friday_6am[0]);
}

TEST_F(compliance_test, future_runs_weekly_friday_6pm)
{
	get_future_runs(future_runs_weekly_friday_6pm[0]);
}

TEST_F(compliance_test, future_runs_twice_monthly_6am)
{
	get_future_runs(future_runs_twice_monthly_6am[0]);
}

TEST_F(compliance_test, future_runs_twice_monthly_6pm)
{
	get_future_runs(future_runs_twice_monthly_6pm[0]);
}

TEST_F(compliance_test, future_runs_once_monthly_1st_6am)
{
	get_future_runs(future_runs_once_monthly_1st_6am[0]);
}

TEST_F(compliance_test, future_runs_once_monthly_1st_6pm)
{
	get_future_runs(future_runs_once_monthly_1st_6pm[0]);
}

TEST_F(compliance_test, future_runs_once_monthly_14th_6am)
{
	get_future_runs(future_runs_once_monthly_14th_6am[0]);
}

TEST_F(compliance_test, future_runs_once_monthly_14th_6pm)
{
	get_future_runs(future_runs_once_monthly_14th_6pm[0]);
}

