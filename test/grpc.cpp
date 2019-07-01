#include <string>
#include <gtest.h>
#include <unistd.h>
#include <sys/time.h>
#include <Poco/Process.h>

#include "grpc_channel_registry.h"
#include "coclient.h"
#include "sdc_internal.pb.h"
#include "sdc_internal.grpc.pb.h"

class TestGRPCClient {
public:
	void connect(const std::string& socket)
	{
		ASSERT_EQ(nullptr, m_grpc_conn);
		m_grpc_conn = grpc_connect<sdc_internal::CoInterface::Stub>("unix:" + socket);
	}

	void ping(uint64_t token)
	{
		ASSERT_NE(nullptr, m_grpc_conn);
		ASSERT_EQ(nullptr, m_grpc_ping);

		m_grpc_ping = make_shared<unary_grpc_client(&sdc_internal::CoInterface::Stub::AsyncPerformPing)>(m_grpc_conn);

		sdc_internal::ping ping_req;
		ping_req.set_token(token);

		auto callback =
			[&](bool successful, sdc_internal::pong &res)
			{
				ASSERT_TRUE(successful);
				m_ping_resp = res.token();
			};

		m_ping_resp = ~0UL;
		m_grpc_ping->do_rpc(ping_req, callback);
	}

	void tick()
	{
		ASSERT_NE(nullptr, m_grpc_ping);
		m_grpc_ping->process_queue();
	}

	std::shared_ptr<sdc_internal::CoInterface::Stub> m_grpc_conn;
	std::shared_ptr<unary_grpc_client(&sdc_internal::CoInterface::Stub::AsyncPerformPing)> m_grpc_ping;
	uint64_t m_ping_resp = ~0UL;
};

sdc_internal::orchestrator_events_stream_command stream_request()
{
	sdc_internal::orchestrator_events_stream_command req;
	req.set_url("");
	req.set_ca_cert("");
	req.set_client_cert("");
	req.set_client_key("");
	req.set_queue_len(0);
	req.set_startup_gc(0);
	req.set_startup_inf_wait_time_s(0);
	req.set_startup_tick_interval_ms(0);
	req.set_startup_low_ticks_needed(0);
	req.set_startup_low_evt_threshold(0);
	req.set_filter_empty(true);
	req.set_ssl_verify_certificate(false);
	req.set_auth_token("");
	req.set_event_counts_log_time(0);
	req.set_batch_msgs_queue_len(0);
	req.set_batch_msgs_tick_interval_ms(0);
	req.set_collect_events(false);
	req.set_user_event_queue_len(0);

	return req;
}

class TestGRPCStreamingClient {
public:
	void connect(const std::string& socket)
	{
		ASSERT_EQ(nullptr, m_grpc_conn);
		m_grpc_conn = grpc_connect<sdc_internal::CoInterface::Stub>("unix:" + socket);
	}

	void call()
	{
		ASSERT_NE(nullptr, m_grpc_conn);
		ASSERT_EQ(nullptr, m_grpc_stream);

		m_grpc_stream = make_shared<streaming_grpc_client(&sdc_internal::CoInterface::Stub::AsyncPerformOrchestratorEventsStream)>(m_grpc_conn);

		auto req = stream_request();

		auto callback =
			[&](streaming_grpc::Status status, sdc_internal::array_congroup_update_event &res)
			{
				if(status == streaming_grpc::OK)
				{
					++m_resp_count;
				}
			};

		m_resp_count = 0;
		m_grpc_stream->do_rpc(req, callback);
	}

	void tick()
	{
		ASSERT_NE(nullptr, m_grpc_stream);
		m_grpc_stream->process_queue();
	}

	std::shared_ptr<sdc_internal::CoInterface::Stub> m_grpc_conn;
	std::shared_ptr<streaming_grpc_client(&sdc_internal::CoInterface::Stub::AsyncPerformOrchestratorEventsStream)> m_grpc_stream;
	uint64_t m_resp_count = ~0UL;
};

static const std::string grpc_socket = "/tmp/grpc-test.sock";

class grpc_test : public testing::Test {};

TEST_F(grpc_test, sync_grpc_stream) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });
	sleep(1);

	auto channel = libsinsp::grpc_channel_registry::get_channel("unix://" + grpc_socket);
	auto cointerface = sdc_internal::CoInterface::NewStub(channel);

	auto req = stream_request();
	sdc_internal::array_congroup_update_event event;

	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(20000);
	context.set_deadline(deadline);

	int received = 0;
	unique_ptr<grpc::ClientReader<sdc_internal::array_congroup_update_event>> reader = cointerface->PerformOrchestratorEventsStream(&context, req);
	while (reader->Read(&event))
	{
		++received;
	}
	grpc::Status status = reader->Finish();

	EXPECT_EQ(10, received);

	Poco::Process::kill(grpc_handle);

	if (!status.ok())
	{
		FAIL() << "sync gRPC request failed: " + status.error_message();
	}
}

TEST_F(grpc_test, sync_grpc) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });
	sleep(1);

	auto channel = libsinsp::grpc_channel_registry::get_channel("unix://" + grpc_socket);
	auto cointerface = sdc_internal::CoInterface::NewStub(channel);

	sdc_internal::ping ping_req;
	sdc_internal::pong ping_resp;
	ping_req.set_token(0);

	grpc::ClientContext context;
	auto deadline = std::chrono::system_clock::now() + std::chrono::milliseconds(2000);
	context.set_deadline(deadline);
	grpc::Status status = cointerface->PerformPing(&context, ping_req, &ping_resp);
	Poco::Process::kill(grpc_handle);

	if (!status.ok())
	{
		FAIL() << "sync gRPC request failed: " + status.error_message();
	}

	ASSERT_EQ(0, ping_resp.token());
}

uint64_t grpc_ping(TestGRPCClient& tc, uint64_t token)
{
	tc.m_grpc_ping = nullptr;
	tc.ping(token);
	for (int i=0; i<10; ++i)
	{
		if(tc.m_ping_resp != ~0UL)
		{
			break;
		}
		sleep(1);
		tc.tick();
	}

	EXPECT_EQ(token, tc.m_ping_resp);
	return tc.m_ping_resp;
}

TEST_F(grpc_test, sequential_grpc) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });

	TestGRPCClient tc;

	sleep(1);

	tc.connect(grpc_socket);

	grpc_ping(tc, 0);
	EXPECT_EQ(0, tc.m_ping_resp);

	grpc_ping(tc, 0);
	EXPECT_EQ(0, tc.m_ping_resp);

	Poco::Process::kill(grpc_handle);
}

TEST_F(grpc_test, slow_grpc) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });

	TestGRPCClient tc;

	sleep(1);

	time_t start = time(NULL);
	tc.connect(grpc_socket);
	grpc_ping(tc, 3 << 16);
	time_t elapsed = time(NULL) - start;

	EXPECT_GE(elapsed, 3);
	EXPECT_LE(elapsed, 4);

	Poco::Process::kill(grpc_handle);
}

TEST_F(grpc_test, simple_grpc) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });

	TestGRPCClient tc;

	sleep(1);

	tc.connect(grpc_socket);
	grpc_ping(tc, 0);

	Poco::Process::kill(grpc_handle);
}

TEST_F(grpc_test, overlapping_grpc_reuse_conn) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });

	TestGRPCClient tc;

	sleep(1);

	tc.connect(grpc_socket);
	tc.ping(3 << 16);
	sleep(1);
	tc.tick();

	// NOTE: here we kill the call object (unary_grpc_client, tc.m_grpc_ping) before the response comes
	// and gRPC complains about this:
	// E0315 10:34:32.965738824  681463 backup_poller.cc:105]       run_poller: {"created":"@1552642472.958808382","description":"Shutting down timer system","file":"src/core/lib/iomgr/timer_generic.cc","file_line":630}

	grpc_ping(tc, 4 << 16);

	Poco::Process::kill(grpc_handle);
}

TEST_F(grpc_test, overlapping_grpc) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });

	TestGRPCClient tc;

	sleep(1);

	tc.connect(grpc_socket);
	tc.ping(3 << 16);
	sleep(1);
	tc.tick();

	tc.m_grpc_ping = nullptr;
	tc.m_grpc_conn = nullptr;
	tc.connect(grpc_socket);

	grpc_ping(tc, 4 << 16);

	Poco::Process::kill(grpc_handle);
}

TEST_F(grpc_test, streaming_grpc) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });

	TestGRPCStreamingClient tc;

	sleep(1);

	tc.connect(grpc_socket);
	tc.call();

	for(int i=0; i<10; ++i)
	{
		tc.tick();
		if(tc.m_resp_count == 10)
		{
			break;
		}
		sleep(1);
	}

	EXPECT_EQ(10, tc.m_resp_count);

	Poco::Process::kill(grpc_handle);
}

TEST_F(grpc_test, streaming_grpc_sequential) {
	unlink(grpc_socket.c_str());
	auto grpc_handle = Poco::Process::launch("./resources/grpc_test_server", { "unix:" + grpc_socket });

	TestGRPCStreamingClient tc;

	sleep(1);

	tc.connect(grpc_socket);

	tc.call();
	for(int i=0; i<10; ++i)
	{
		tc.tick();
		if(tc.m_resp_count == 10)
		{
			break;
		}
		sleep(1);
	}
	EXPECT_EQ(10, tc.m_resp_count);

	tc.m_grpc_stream = nullptr;

	tc.call();
	for(int i=0; i<10; ++i)
	{
		tc.tick();
		if(tc.m_resp_count == 10)
		{
			break;
		}
		sleep(1);
	}
	EXPECT_EQ(10, tc.m_resp_count);

	Poco::Process::kill(grpc_handle);
}
