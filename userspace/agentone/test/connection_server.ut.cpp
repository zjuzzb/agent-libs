#include "agentino_manager.h"  // for connection_context. could use something else if
#include "connection_message.h"
#include "connection_server.h"
#include "scoped_config.h"
// we want to break this dependency. it's just for conveninece
#include "fake_agentino.h"  // just conveninence. could probably be renamed "fake connector" or something

#include <gtest.h>

using namespace agentone;
using namespace test_helpers;
using namespace dragent;

class connection_server_owner_dummy : public connection_server_owner
{
public:
	connection_server_owner_dummy(uint32_t expected_ts, uint32_t port)
	    : cs(*this, port, false),
	      m_expected_ts(expected_ts)
	{
		cs.start();
	}

	virtual ~connection_server_owner_dummy() { cs.stop(); }

	virtual connection::result handle_handshake(
	    std::shared_ptr<connection>& conn,
	    const raw_message& message,
	    std::unique_ptr<google::protobuf::MessageLite>& response,
	    draiosproto::message_type& response_type) override
	{
		got_handshake = true;
		auto request_context = new agentino_handshake_connection_context();
		dragent_protocol::buffer_to_protobuf(message.bytes,
		                                     message.payload_length(),
		                                     &request_context->request);
		handshake_valid = (request_context->request.timestamp_ns() == m_expected_ts);
		conn->set_context(request_context);
		if (handshake_valid)
		{
			response.reset(new draiosproto::agentino_handshake_response);
			response_type = draiosproto::message_type::AGENTINO_HANDSHAKE_RESPONSE;
		}

		return handshake_valid ? connection::SUCCESS : connection::FATAL_ERROR;
	}
	void new_connection(std::shared_ptr<connection>& conn) override
	{
		connected = true;
		m_conn = conn;
	}
	void delete_connection(std::shared_ptr<connection>& conn) override { disconnected = true; }
	void get_pollable_connections(std::list<std::shared_ptr<connection>>& out) const override
	{
		if (!disconnected && m_conn)
		{
			out.emplace_back(m_conn);
		}
	}

	bool handle_message(draiosproto::message_type type,
	                    const uint8_t* buffer,
	                    size_t buffer_size) override
	{
		return true;
	}

	connection_server cs;
	bool connected = false;
	bool disconnected = false;
	bool got_handshake = false;
	bool handshake_valid = false;
	uint32_t m_expected_ts;
	std::shared_ptr<connection> m_conn = nullptr;
};

TEST(connection_server, handshake_success)
{
	scoped_config<uint64_t> sleepytime("connection_server.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	fake_agentino fa(true, false, 1001, true);

	connection_server_owner_dummy csod(1001, 7357);

	// Now actually fire up the fake agentino
	fa.start(7357);

	for (uint32_t loops = 0; !csod.connected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(csod.got_handshake);
	ASSERT_TRUE(csod.handshake_valid);
	ASSERT_TRUE(csod.connected);

	fa.stop();
	for (uint32_t loops = 0; !csod.disconnected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(csod.disconnected);
}

TEST(connection_server, get_handshake_data)
{
	scoped_config<uint64_t> sleepytime("connection_server.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	fake_agentino fa(true, false, 1002, true);
	connection_server_owner_dummy csod(1002, 7358);

	// Now actually fire up the fake agentino
	fa.start(7358);

	for (uint32_t loops = 0; !csod.connected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(csod.got_handshake);
	ASSERT_TRUE(csod.handshake_valid);
	ASSERT_TRUE(csod.connected);
	auto typed_context =
	    dynamic_cast<const agentino_handshake_connection_context*>(csod.m_conn->get_context());
	ASSERT_NE(typed_context, nullptr);
	ASSERT_EQ(typed_context->request.timestamp_ns(), 1002);

	fa.stop();
	for (uint32_t loops = 0; !csod.disconnected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(csod.disconnected);
}

TEST(connection_server, handshake_fail)
{
	scoped_config<uint64_t> sleepytime("connection_server.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	fake_agentino fa(true, false, 1003, true);
	connection_server_owner_dummy csod(1002, 7359);  // note the timestamps don't equal!

	// Now actually fire up the agentino
	fa.start(7359);

	for (uint32_t loops = 0; !csod.got_handshake && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(csod.got_handshake);

	for (uint32_t loops = 0; !csod.disconnected && loops < 3000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(csod.disconnected);

	fa.stop();
}

class dump_connector_during_handshake_server_owner_dummy : public connection_server_owner_dummy
{
public:
	dump_connector_during_handshake_server_owner_dummy(uint32_t expected_ts,
	                                                   uint32_t port,
	                                                   fake_agentino* fa)
	    : connection_server_owner_dummy(expected_ts, port),
	      m_fake_agent(fa)
	{
	}

	~dump_connector_during_handshake_server_owner_dummy() {}

	virtual connection::result handle_handshake(
	    std::shared_ptr<connection>& conn,
	    const raw_message& message,
	    std::unique_ptr<google::protobuf::MessageLite>& response,
	    draiosproto::message_type& response_type) override
	{
		got_handshake = true;
		m_fake_agent->drop_connection();
		for (uint32_t loops = 0;
		     m_fake_agent->get_status() != fake_agentino::server_status::SHUTDOWN && loops < 2000;
		     ++loops)
		{
			usleep(1000);
		}
		response.reset(new draiosproto::agentino_handshake_response);
		response_type = draiosproto::message_type::AGENTINO_HANDSHAKE_RESPONSE;
		return connection::SUCCESS; // this succeeded from our PoV. It will fail on the send
								   // from the server infra
	}

	fake_agentino* m_fake_agent;
};

TEST(connection_server, handshake_disconnect)
{
	scoped_config<uint64_t> sleepytime("connection_server.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	fake_agentino fa(true, false, 1004, true);
	dump_connector_during_handshake_server_owner_dummy csod(1004, 7360, &fa);

	// Now actually fire up the fake agentino
	fa.start(7360);

	for (uint32_t loops = 0; !csod.disconnected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, fa.get_num_disconnects());
	ASSERT_FALSE(csod.connected);
	ASSERT_TRUE(csod.got_handshake);
	ASSERT_TRUE(csod.disconnected);

	fa.stop();
}
