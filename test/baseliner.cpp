#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#include <gtest.h>

#include <Poco/NullChannel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>

#include <sinsp.h>
#include <sinsp_worker.h>
#include <configuration.h>
#include <protocol.h>
#include <baseliner.h>

using namespace std;

class test_error_handler : public Poco::ErrorHandler
{
public:
	test_error_handler() {};

	void exception(const Poco::Exception& exc) {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got Poco::Exception " << exc.displayText();
	}

	void exception(const std::exception& exc) {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got std::exception " << exc.what();
	}

	void exception() {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got unknown exception";
	}
};

namespace {
class test_sinsp_worker : public Runnable
{
public:
	test_sinsp_worker(sinsp *inspector, sinsp_baseliner *baseliner, __pid_t tid)
		: m_ready(false),
		  m_inspector(inspector),
		  m_baseliner(baseliner),
		  m_tid(tid)
	{
		m_inspector->set_log_callback(dragent_logger::sinsp_logger_callback);
	}

	~test_sinsp_worker()
	{
		m_inspector->set_log_callback(0);
	}

	void run()
	{
		g_log->information("test_sinsp_worker: Starting");

		while(!dragent_configuration::m_terminate)
		{
			int32_t res;
			sinsp_evt* ev;

			res = m_inspector->next(&ev);

			if(res == SCAP_TIMEOUT)
			{
				continue;
			}
			else if(res == SCAP_EOF)
			{
				break;
			}
			else if(res != SCAP_SUCCESS)
			{
				cerr << "res = " << res << endl;
				throw sinsp_exception(m_inspector->getlasterr().c_str());
			}

			if(ev->get_tid() == m_tid)
			{
				m_baseliner->process_event(ev);
			}

			if(!m_ready)
			{
				g_log->information("test_sinsp_worker: ready");
				m_ready = true;
			}
		}

		scap_stats st;
		m_inspector->get_capture_stats(&st);

		g_log->information("sinsp_worker: Terminating. events=" + to_string(st.n_evts) + " dropped=" + to_string(st.n_drops + st.n_drops_buffer));
	}

	atomic<bool> m_ready;
private:
	sinsp *m_inspector;
	sinsp_baseliner *m_baseliner;
	__pid_t m_tid;
};
}

class baseliner_test : public testing::Test
{
protected:

	virtual void SetUp()
	{
		m_configuration.init(NULL, false);
		dragent_configuration::m_terminate = false;

		m_configuration.m_autodrop_enabled = false;

		if(!g_log)
		{
			AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));

			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));

			// To enable debug logging, change the tailing -1 to Message::Priority::PRIO_DEBUG
			Logger &loggerc = Logger::create("DraiosLogC", formatting_channel_console, -1);

			AutoPtr<Channel> null_channel(new Poco::NullChannel());
			Logger &nullc = Logger::create("NullC", null_channel, -1);

			g_log = std::unique_ptr<dragent_logger>(new dragent_logger(&nullc, &loggerc));
		}

		m_inspector = new sinsp();
		m_analyzer = new sinsp_analyzer(m_inspector, "/opt/draios");
		m_inspector->m_analyzer = m_analyzer;

		m_analyzer->get_configuration()->set_falco_baselining_enabled(m_configuration.m_falco_baselining_enabled);
		m_inspector->set_debug_mode(true);
		m_inspector->set_hostname_and_port_resolution_mode(false);

		m_inspector->open("");

		Poco::ErrorHandler::set(&m_error_handler);

		m_baseliner = new sinsp_baseliner();
		m_baseliner->init(m_inspector);
		m_baseliner->set_baseline_calculation_enabled(true);

		m_sinsp_worker = new test_sinsp_worker(m_inspector, m_baseliner, getpid());
		ThreadPool::defaultPool().start(*m_sinsp_worker, "test_sinsp_worker");

		// Wait for the test_sinsp_worker to be ready.
		while(!m_sinsp_worker->m_ready)
		{
			Poco::Thread::sleep(100);
		}
	}

	virtual void TearDown()
	{
		dragent_configuration::m_terminate = true;

		ThreadPool::defaultPool().joinAll();
		ThreadPool::defaultPool().stopAll();

		delete m_sinsp_worker;
		delete m_baseliner;
		delete m_inspector;
		delete m_analyzer;
	}

	sinsp *m_inspector;
	sinsp_analyzer *m_analyzer;
	sinsp_baseliner *m_baseliner;
	test_sinsp_worker *m_sinsp_worker;
	dragent_configuration m_configuration;
	test_error_handler m_error_handler;
};

TEST_F(baseliner_test, nofd_ops)
{
	mkdir("/tmp/test_baseliner_nofd_ops/", 0777);
	DIR *dirp = opendir("/tmp/test_baseliner_nofd_ops/");

	mkdirat(dirfd(dirp), "./one", 0777);
	mkdirat(dirfd(dirp), "./two", 0777);

	unlinkat(dirfd(dirp), "./one", AT_REMOVEDIR);

	renameat(dirfd(dirp), "./two", dirfd(dirp), "./three");

	rename("/tmp/test_baseliner_nofd_ops/three", "/tmp/test_baseliner_nofd_ops/four");

	ASSERT_TRUE(system("touch /tmp/test_baseliner_nofd_ops/file") == 0);

	unlink("/tmp/test_baseliner_nofd_ops/file");

	closedir(dirp);
	rmdir("/tmp/test_baseliner_nofd_ops/four");
	rmdir("/tmp/test_baseliner_nofd_ops");

	sleep(1);
	
	draiosproto::falco_baseline result;
	m_baseliner->serialize_protobuf(&result);

	std::set<std::string> expected_files = {
		"/tmp/test_baseliner_nofd_ops/file"
	};
	std::set<std::string> expected_dirs = {
		"/tmp/test_baseliner_nofd_ops/",
		"/tmp/test_baseliner_nofd_ops/one",
		"/tmp/test_baseliner_nofd_ops/two",
		"/tmp/test_baseliner_nofd_ops/three",
		"/tmp/test_baseliner_nofd_ops/four"
	};

	for(const auto &prog : result.progs())
	{
		if(prog.comm() != "tests")
		{
			continue;
		}

		for(const auto &cats: prog.cats())
		{
			if(cats.name() == "files" || cats.name() == "dirs")
			{
				auto &expected = cats.name() == "files" ? expected_files : expected_dirs;
				for(const auto &cat : cats.startup_subcats())
				{
					for(const auto &subcat : cat.subcats())
					{
						for(const auto &name : subcat.d())
						{
							if(expected.find(name) != expected.end())
							{
								expected.erase(name);
							}
						}
					}
				}
				for(const auto &cat : cats.regular_subcats())
				{
					for(const auto &subcat : cat.subcats())
					{
						for(const auto &name : subcat.d())
						{
							if(expected.find(name) != expected.end())
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
