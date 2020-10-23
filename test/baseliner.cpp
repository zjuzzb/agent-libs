#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/NullChannel.h>

#include <baseliner.h>
#include <configuration.h>
#include <dirent.h>
#include <fcntl.h>
#include <gtest.h>
#include <protocol.h>
#include <running_state.h>
#include <sinsp.h>
#include <sinsp_worker.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;

class test_error_handler : public Poco::ErrorHandler
{
public:
	test_error_handler(){};

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

namespace
{
class test_sinsp_worker : public Runnable
{
public:
	test_sinsp_worker(sinsp* inspector, sinsp_baseliner* baseliner, __pid_t tid)
	    : m_ready(false),
	      m_inspector(inspector),
	      m_baseliner(baseliner),
	      m_tid(tid)
	{
		m_inspector->set_log_callback(common_logger::sinsp_logger_callback);
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

			if (ev->get_tid() == m_tid)
			{
				m_baseliner->process_event(ev);
			}

			if (!m_ready)
			{
				g_log->information("test_sinsp_worker: ready");
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
	sinsp* m_inspector;
	sinsp_baseliner* m_baseliner;
	__pid_t m_tid;
};
}  // namespace

namespace
{
sinsp_analyzer::flush_queue g_queue(1000);
audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_audit_handler;
null_secure_profiling_handler g_secure_profiling_handler;
null_secure_netsec_handler g_secure_netsec_handler;
}  // namespace

class baseliner_test : public testing::Test
{
protected:
	virtual void SetUp()
	{
		m_configuration.init(NULL, false);

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
		internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
		m_analyzer = new sinsp_analyzer(m_inspector,
		                                "/opt/draios",
		                                int_metrics,
		                                g_audit_handler,
		                                g_secure_audit_handler,
		                                g_secure_profiling_handler,
		                                g_secure_netsec_handler,
		                                &g_queue,
		                                []() -> bool { return true; });
		m_inspector->register_external_event_processor(*m_analyzer);

		m_inspector->set_debug_mode(true);
		m_inspector->set_hostname_and_port_resolution_mode(false);

		m_inspector->open("");

		Poco::ErrorHandler::set(&m_error_handler);

		m_baseliner = new sinsp_baseliner(*m_analyzer, m_inspector);
		m_baseliner->init();
		m_baseliner->start_baseline_calculation();

		m_sinsp_worker = new test_sinsp_worker(m_inspector, m_baseliner, getpid());
		ThreadPool::defaultPool().start(*m_sinsp_worker, "test_sinsp_worker");

		// Wait for the test_sinsp_worker to be ready.
		while (!m_sinsp_worker->m_ready)
		{
			Poco::Thread::sleep(100);
		}
	}

	virtual void TearDown()
	{
		dragent::running_state::instance().shut_down();

		ThreadPool::defaultPool().joinAll();
		ThreadPool::defaultPool().stopAll();

		delete m_sinsp_worker;
		delete m_baseliner;
		delete m_inspector;
		delete m_analyzer;

		dragent::running_state::instance().reset_for_test();
	}

	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	sinsp_baseliner* m_baseliner;
	test_sinsp_worker* m_sinsp_worker;
	dragent_configuration m_configuration;
	test_error_handler m_error_handler;
};

TEST_F(baseliner_test, nofd_ops)
{
	char tmpl[] = "/tmp/test_baseliner_nofd_ops.XXXXXX";
	char *tmpdir = mkdtemp(tmpl);
	ASSERT_TRUE(tmpdir != NULL) << "Could not create temporary directory: " << strerror(errno);

	std::string temp_dir_slash = string(tmpdir) + "/";
	std::string one_dir = string(tmpdir) + "/one";
	std::string two_dir = string(tmpdir) + "/two";
	std::string three_dir = string(tmpdir) + "/three";
	std::string four_dir = string(tmpdir) + "/four";
	std::string touch_file = string(tmpdir) + "/file";
	std::string touch_cmd = string("touch ") + touch_file;

	DIR* dirp = opendir(tmpdir);

	ASSERT_TRUE(dirp != NULL) << "Could not open local directory: " << strerror(errno);

	mkdirat(dirfd(dirp), "./one", 0777);
	mkdirat(dirfd(dirp), "./two", 0777);

	unlinkat(dirfd(dirp), "./one", AT_REMOVEDIR);

	renameat(dirfd(dirp), "./two", dirfd(dirp), "./three");

	rename(three_dir.c_str(), four_dir.c_str());

	ASSERT_TRUE(system(touch_cmd.c_str()) == 0);

	unlink(touch_file.c_str());

	closedir(dirp);
	rmdir(four_dir.c_str());
	rmdir(tmpdir);

	sleep(1);

	const secure::profiling::fingerprint* result;
	m_baseliner->serialize_protobuf();
	result = m_baseliner->get_fingerprint(0);

	std::set<std::string> expected_files = {touch_file.c_str()};
	std::set<std::string> expected_dirs = {temp_dir_slash.c_str(),
	                                       one_dir.c_str(),
	                                       two_dir.c_str(),
	                                       three_dir.c_str(),
	                                       four_dir.c_str()};

	for (const auto& prog : result->progs())
	{
		if (prog.comm() != "tests")
		{
			continue;
		}

		for (const auto& cats : prog.cats())
		{
			if (cats.name() == "files" || cats.name() == "dirs")
			{
				auto& expected = cats.name() == "files" ? expected_files : expected_dirs;
				for (const auto& cat : cats.startup_subcats())
				{
					for (const auto& subcat : cat.subcats())
					{
						for (const auto& name : subcat.d())
						{
							if (expected.find(name) != expected.end())
							{
								expected.erase(name);
							}
						}
					}
				}
				for (const auto& cat : cats.regular_subcats())
				{
					for (const auto& subcat : cat.subcats())
					{
						for (const auto& name : subcat.d())
						{
							if (expected.find(name) != expected.end())
							{
								expected.erase(name);
							}
						}
					}
				}
			}
		}
	}
	EXPECT_EQ(expected_files.size(), 0u);
	EXPECT_EQ(expected_dirs.size(), 0u);
}
