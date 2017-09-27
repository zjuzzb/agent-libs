#include <memory>
#include <thread>

#include <Poco/AutoPtr.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/Logger.h>
#include <Poco/NullChannel.h>
#include <Poco/PatternFormatter.h>
#include <Poco/Pipe.h>
#include <Poco/PipeStream.h>
#include <Poco/Process.h>
#include <Poco/Thread.h>

#include <gtest.h>

#include <sinsp.h>
#include <configuration.h>
#include <coclient.h>

using namespace std;
using namespace Poco;

class coclient_test : public testing::Test
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
			Logger &loggerc = Logger::create("DraiosLogC", formatting_channel_console, -1);

			AutoPtr<Channel> null_channel(new NullChannel());
			Logger &nullc = Logger::create("NullC", null_channel, -1);

			g_log = new dragent_logger(&nullc, &loggerc, &nullc);
		}

		string coclient_sock = "./resources/coclient_test.sock";

		Process::Args args{"-sock", coclient_sock, "-use_json=false"};

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
				g_log->debug(line);
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

		m_coclient.set_domain_sock(coclient_sock);
	}

	virtual void TearDown()
	{
		if(m_cointerface)
		{
			Process::kill(*m_cointerface);
		}
	}

	void test_docker_cmd(sdc_internal::docker_cmd_type cmd)
	{
		bool callback_performed = false;

		coclient::response_cb_t callback = [&callback_performed] (bool successful, google::protobuf::Message *response_msg) {
			sdc_internal::docker_command_result *res = (sdc_internal::docker_command_result *) response_msg;

			callback_performed = true;

			EXPECT_TRUE(successful) << "RPC Not successful";

			EXPECT_TRUE(res->successful()) << "Could not actually perform docker command";
			EXPECT_FALSE(res->has_errstr()) << "Response had error string: " << res->errstr();
		};

		// Remove any existing container
		system("docker unpause coclient_test > /dev/null 2>&1");
		system("docker rm -f coclient_test > /dev/null 2>&1");

		ASSERT_EQ(system("docker run -d --name coclient_test busybox sleep 6000 > /dev/null 2>&1"), 0) << "Could not start test container";

		m_coclient.perform_docker_cmd(cmd, "coclient_test", callback);

		for(uint32_t i=0; !callback_performed && i < 500; i++)
		{
			Thread::sleep(100);
			m_coclient.next();
		}

		EXPECT_TRUE(callback_performed) << "Did not receive docker command response message after 10 seconds";

		if(cmd == sdc_internal::PAUSE)
		{
			ASSERT_EQ(system("docker unpause coclient_test > /dev/null 2>&1"), 0);
		}

		ASSERT_EQ(system("docker rm -f coclient_test > /dev/null 2>&1"), 0);
	}

	shared_ptr<Pipe> m_colog;
	shared_ptr<ProcessHandle> m_cointerface;
	coclient m_coclient;
};

static bool check_docker_service()
{
	if(system("service docker status > /dev/null 2>&1") != 0)
	{
		printf("Docker not running, skipping test\n");
		return false;
	}

	return true;
}

TEST_F(coclient_test, DISABLED_perform_ping)
{
	int64_t token = 828271;
	bool callback_performed = false;

	if (!check_docker_service())
	{
		return;
	}

	coclient::response_cb_t callback = [&callback_performed, token] (bool successful, google::protobuf::Message *response_msg) {
		sdc_internal::pong *pong = (sdc_internal::pong *) response_msg;

		g_log->debug("Got pong: successful=" + to_string(successful) + " token=" + to_string(pong->token()));

		callback_performed = true;

		EXPECT_TRUE(successful);
		if (successful) {
			EXPECT_EQ(token, pong->token());
		}
	};

	m_coclient.ping(token, callback);

	for(uint32_t i=0; !callback_performed && i < 100; i++)
	{
		Thread::sleep(100);
		m_coclient.next();
	}

	EXPECT_TRUE(callback_performed) << "Did not receive pong message after 10 seconds";
}

TEST_F(coclient_test, DISABLED_docker_pause)
{
	if (!check_docker_service())
	{
		return;
	}

	test_docker_cmd(sdc_internal::PAUSE);
}

TEST_F(coclient_test, DISABLED_docker_stop)
{
	if (!check_docker_service())
	{
		return;
	}

	test_docker_cmd(sdc_internal::STOP);
}
