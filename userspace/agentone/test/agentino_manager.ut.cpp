#include "agentino_manager.h"
#include "common_logger.h"
#include "connection_manager.h"
#include "fake_agentino.h"
#include "protobuf_compression.h"
#include "running_state.h"
#include "running_state_fixture.h"
#include "scoped_config.h"

#include <gtest.h>
#include <unistd.h>

using namespace agentone;
using namespace test_helpers;
using namespace dragent;

namespace
{
class am_cm_integration_fixture : public running_state_fixture
{
public:
	am_cm_integration_fixture() {}
};

cm_config base_config = {".",                   // root dir
                         "",                    // server addr
                         6443,                  // server port
                         true,                  // ssl enabled
                         {},                    // cert paths
                         "",                    // cert
                         false,                 // promex enabled
                         "sysdig-agent-bozos",  // promex url
                         "nathanb-dev"};        // customer ID

security_result_handler_dummy dummy_handler;

class test_handler : public security_result_handler
{
public:
	uint32_t m_num_policy_events = 0;
	uint32_t m_num_throttled_events = 0;
	uint32_t m_total_throttled_count = 0;
	uint32_t m_num_comp_results = 0;

	virtual void security_mgr_policy_events_ready(uint64_t ts_ns,
	                                              draiosproto::policy_events* events) override
	{
		++m_num_policy_events;
	}

	virtual void security_mgr_throttled_events_ready(uint64_t ts_ns,
	                                                 draiosproto::throttled_policy_events* events,
	                                                 uint32_t total_throttled_count) override
	{
		++m_num_throttled_events;
		m_total_throttled_count += total_throttled_count;
	}

	virtual void security_mgr_comp_results_ready(uint64_t ts_ns,
	                                             const draiosproto::comp_results* results) override
	{
		++m_num_comp_results;
	}
};

bool null_handshake_callback(agentino_manager* am,
                             void* ctx,
                             const draiosproto::agentino_handshake& hs_data,
                             draiosproto::agentino_handshake_response& hs_resp)
{
	return true;
}

connection::ptr get_bogus_connection()
{
	return std::make_shared<connection>(nullptr, nullptr, 0, null_handshake_callback);
}

// a dummy agentino that overrides the send method so we can ensure things
// get sent right. Even dumber than the fake_agentino, hence the name.
class agentino_dummy : public agentino
{
public:
	agentino_dummy(agentino_manager* manager) : agentino(manager) {}

	void send_policies(draiosproto::policies_v2 policies) override
	{
		if (policies.policy_list().size() == 0)
		{
			m_last_policies_received = 0;
		}
		else
		{
			m_last_policies_received = policies.policy_list()[0].id();
		}
	}

	int32_t m_last_policies_received = -1;
};

// a dummy agentino manager that overrides build_agentino to produce whatever agentino you
// want
template<typename AGENTINO>
class agentino_manager_dummy : public agentino_manager
{
public:
	agentino_manager_dummy(security_result_handler& events_handler,
	                       protocol_queue* pqueue,
	                       container_manager& container_manager_in,
	                       const std::string& machine_id,
	                       const std::string& customer_id)
	    : agentino_manager(events_handler, pqueue, container_manager_in, machine_id, customer_id)
	{
	}

	agentino::ptr build_agentino(connection::ptr connection_in,
	                             const std::map<agentino_metadata_property, std::string>& fixed_metadata,
	                             const std::map<std::string, std::string>& arbitrary_metadata) override
	{
		return std::make_shared<AGENTINO>(this);
	}
};

}  // namespace

namespace agentone
{
class test_helper
{
public:
	static void set_handshake_data(std::shared_ptr<agentone::connection> c,
	                               draiosproto::agentino_handshake ah)
	{
		c->m_hs_data = ah;
		// the connection won't give us the data unless we make it connected
		c->m_state = connection::FULLY_CONNECTED;
	}

	static draiosproto::policies_v2 get_cached_policies(agentino_manager& am)
	{
		return am.m_cached_policies;
	}
};
}  // namespace agentone

TEST(agentino, get_add_metadata)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	agentino a(&m);

	EXPECT_EQ(a.get_metadata_property(CONTAINER_ID), "");
	a.add_metadata_property(CONTAINER_ID, "id");
	EXPECT_EQ(a.get_metadata_property(CONTAINER_ID), "id");
	a.add_metadata_property(CONTAINER_ID, "id2");
	EXPECT_EQ(a.get_metadata_property(CONTAINER_ID), "id2");
	a.add_metadata_property("key", "value");
	EXPECT_EQ(a.get_metadata_property("key"), "value");
}

TEST(agentino, get_add_remove_connection)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	agentino a(&m);

	EXPECT_EQ(a.get_connection_info(), nullptr);
	auto connection_in = get_bogus_connection();
	a.add_connection_info(connection_in);
	EXPECT_EQ(&*a.get_connection_info(), &*connection_in);
	connection_in = get_bogus_connection();
	a.add_connection_info(connection_in);
	EXPECT_EQ(&*a.get_connection_info(), &*connection_in);
	a.remove_connection_info();
	EXPECT_EQ(a.get_connection_info(), nullptr);
}

TEST(agentino, allocator_with_metadata)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	auto connection_in = get_bogus_connection();
	std::map<agentino_metadata_property, std::string> metadata_in;
	metadata_in[CONTAINER_ID] = "id";

	agentino a(&m, connection_in, metadata_in, {{"key", "value"}});
	EXPECT_EQ(a.get_metadata_property(CONTAINER_ID), "id");
	EXPECT_EQ(a.get_metadata_property("key"), "value");
	EXPECT_EQ(&*a.get_connection_info(), &*connection_in);
}

TEST(agentino, build_agentino)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	auto connection_in = get_bogus_connection();
	std::map<agentino_metadata_property, std::string> metadata_in;
	auto a = agentino::build_agentino(&m, connection_in, metadata_in, {});
	EXPECT_EQ(a->get_container_list().size(), 0);
}

TEST(agentino, build_ecs_agentino)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	auto connection_in = get_bogus_connection();
	std::map<agentino_metadata_property, std::string> metadata_in;
	metadata_in[CONTAINER_ID] = "id";
	metadata_in[CONTAINER_IMAGE] = "image";
	metadata_in[CONTAINER_NAME] = "name";
	auto a = agentino::build_agentino(&m, connection_in, metadata_in, {{"key", "value"}});
	auto cs = a->get_container_list();
	ASSERT_EQ(a->get_container_list().size(), 1);
	ASSERT_NE(cs.find("id"), cs.end());
	auto c = cs.find("id");
	EXPECT_EQ(c->second->get_id(), "id");
	EXPECT_EQ(c->second->get_image(), "image");
	EXPECT_EQ(c->second->get_name(), "name");
	EXPECT_EQ(c->second->get_labels().find("key")->second, "value");

	// check that the container in container manager is the same one in the agentino's
	// list of containers
	EXPECT_EQ(&*c_m.get_container("id"), &*c->second);
}

TEST(agentino, build_ecs_agentino_missing_data)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	auto connection_in = get_bogus_connection();
	std::map<agentino_metadata_property, std::string> metadata_in;
	metadata_in[CONTAINER_ID] = "id";
	auto a = agentino::build_agentino(&m, connection_in, metadata_in, {});
	auto cs = a->get_container_list();
	ASSERT_EQ(a->get_container_list().size(), 1);
	ASSERT_NE(cs.find("id"), cs.end());
	auto c = cs.find("id");
	EXPECT_EQ(c->second->get_id(), "id");
	EXPECT_EQ(c->second->get_image(), "");
	EXPECT_EQ(c->second->get_name(), "");
}

// Need to check that the container is successfully deleted when an ecs agentino goes away
TEST(agentino, delete_ecs_agentino)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	EXPECT_EQ(c_m.get_container_list().size(), 0);

	auto connection_in = get_bogus_connection();
	std::map<agentino_metadata_property, std::string> metadata_in;
	metadata_in[CONTAINER_ID] = "id";
	metadata_in[CONTAINER_IMAGE] = "image";
	metadata_in[CONTAINER_NAME] = "name";
	auto a = agentino::build_agentino(&m, connection_in, metadata_in, {{"key", "value"}});
	EXPECT_EQ(c_m.get_container_list().size(), 1);

	a = nullptr;
	EXPECT_EQ(c_m.get_container_list().size(), 0);
}

TEST(agentino, handshake_success)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	uint16_t port = 7357;
	fake_agentino fa(true, false, true);
	bool got_handshake = false;
	bool handshake_valid = false;
	bool connected = false;
	bool disconnected = false;

	// Simple connect handler
	connection::connection_cb ccb = [&connected](agentino_manager* am,
	                                             std::shared_ptr<connection> conn,
	                                             void* ctx) { connected = true; };

	// Simple disconnect handler
	connection::connection_cb dcb = [&disconnected](agentino_manager* am,
	                                                std::shared_ptr<connection> conn,
	                                                void* ctx) { disconnected = true; };

	// Simple handshake handler
	connection::handshake_cb hcb = [&](agentino_manager* am,
	                                   void* ctx,
	                                   const draiosproto::agentino_handshake& hs,
	                                   draiosproto::agentino_handshake_response& hr) -> bool {
		got_handshake = true;

		// Validate handshake (note that gtest limitations do not allow
		// ASSERT_whatever statements in a function with a return type, so
		// use EXPECT statements and then ASSERT after the fact.
		EXPECT_EQ(1001, hs.timestamp_ns());
		if (hs.timestamp_ns() == 1001)
		{
			handshake_valid = true;
		}

		// TODO insert the rest of handshake validation logic in here

		// Build handshake response
		hr.set_timestamp_ns(1002);

		return true;
	};

	// Normally we would connect through an agentino_manager's listen loop,
	// but this unit test is JUST testing the connection and handshake.
	auto new_conn_cb = [&ccb, &hcb, &dcb, &got_handshake](cm_socket* sock, void* ctx) {
		auto* pfa = (fake_agentino*)ctx;

		connection::ptr connp = std::make_shared<connection>(sock, nullptr, 0, hcb, ccb, dcb);
		connp->start(&connp);
		for (uint32_t loops = 0;
		     pfa->get_status() != fake_agentino::server_status::RUNNING && loops < 5000;
		     ++loops)
		{
			usleep(1000);
		}
		ASSERT_EQ(fake_agentino::server_status::RUNNING, pfa->get_status());
		// Once this lambda terminates the FA will report conn drop and
		// everything will go sideways, so don't depend on FA state after
		// this point
	};

	auto conn_error_cb = [](cm_socket::error_type et, int error, void* ctx) {
		ASSERT_EQ(cm_socket::error_type::ERR_NONE, et);
	};

	// Use a CM socket to listen for the agentino connection
	bool r = cm_socket::listen({port, false}, new_conn_cb, conn_error_cb, &fa);
	ASSERT_TRUE(r);

	// Now actually fire up the fake agentino
	fa.start(port);

	for (uint32_t loops = 0; !connected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(got_handshake);
	ASSERT_TRUE(handshake_valid);
	ASSERT_TRUE(connected);

	cm_socket::stop_listening(true);
	fa.stop();
	for (uint32_t loops = 0; !disconnected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(disconnected);
}

TEST(agentino, get_handshake_data)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	uint16_t port = 7359;
	fake_agentino fa(true, false, true);
	bool got_handshake = false;
	bool handshake_valid = false;
	bool connected = false;
	bool disconnected = false;
	struct
	{
		std::string id;
		std::string image;
		std::string name;
	} cb_data;

	// Simple connect handler
	connection::connection_cb ccb = [&connected](agentino_manager* am,
	                                             std::shared_ptr<connection> conn,
	                                             void* ctx) { connected = true; };

	// Simple disconnect handler
	connection::connection_cb dcb = [&disconnected](agentino_manager* am,
	                                                std::shared_ptr<connection> conn,
	                                                void* ctx) { disconnected = true; };

	// Simple handshake handler
	connection::handshake_cb hcb = [&](agentino_manager* am,
	                                   void* ctx,
	                                   const draiosproto::agentino_handshake& hs,
	                                   draiosproto::agentino_handshake_response& hr) -> bool {
		got_handshake = true;

		// Validate handshake (note that gtest limitations do not allow
		// ASSERT_whatever statements in a function with a return type, so
		// use EXPECT statements and then ASSERT after the fact.
		EXPECT_EQ(1002, hs.timestamp_ns());
		if (hs.timestamp_ns() == 1002)
		{
			handshake_valid = true;
		}

		cb_data.id = hs.metadata().container_id();
		cb_data.image = hs.metadata().container_image();
		cb_data.name = hs.metadata().container_name();

		// Build handshake response
		hr.set_timestamp_ns(1002);

		return true;
	};

	// Normally we would connect through an agentino_manager's listen loop,
	// but this unit test is JUST testing the connection and handshake.
	auto new_conn_cb = [&](cm_socket* sock, void* ctx) {
		auto* pfa = (fake_agentino*)ctx;

		connection::ptr connp = std::make_shared<connection>(sock, nullptr, 0, hcb, ccb, dcb);
		connp->start(&connp);
		for (uint32_t loops = 0;
		     pfa->get_status() != fake_agentino::server_status::RUNNING && loops < 5000;
		     ++loops)
		{
			usleep(1000);
		}
		ASSERT_EQ(fake_agentino::server_status::RUNNING, pfa->get_status());

		for (uint32_t loops = 0; !connected && loops < 5000; ++loops)
		{
			usleep(1000);
		}
		ASSERT_TRUE(got_handshake);
		ASSERT_TRUE(handshake_valid);
		ASSERT_TRUE(connected);

		// OK, now that we're connected...
		draiosproto::agentino_handshake hs;
		bool ret = connp->get_handshake_data(&hs);
		ASSERT_TRUE(ret);
		ASSERT_EQ(cb_data.id, hs.metadata().container_id());
		ASSERT_EQ(cb_data.image, hs.metadata().container_image());
		ASSERT_EQ(cb_data.name, hs.metadata().container_name());

		// Once this lambda terminates the FA will report conn drop and
		// everything will go sideways, so don't depend on FA state after
		// this point
	};

	auto conn_error_cb = [](cm_socket::error_type et, int error, void* ctx) {
		ASSERT_EQ(cm_socket::error_type::ERR_NONE, et);
	};

	// Use a CM socket to listen for the agentino connection
	bool r = cm_socket::listen({port, false}, new_conn_cb, conn_error_cb, &fa);
	ASSERT_TRUE(r);

	// Now actually fire up the fake agentino
	fa.start(port);

	for (uint32_t loops = 0; !connected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(got_handshake);
	ASSERT_TRUE(handshake_valid);
	ASSERT_TRUE(connected);

	cm_socket::stop_listening(true);
	fa.stop();
	for (uint32_t loops = 0; !disconnected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(disconnected);
}

TEST(agentino, handshake_fail)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	uint16_t port = 7358;
	fake_agentino fa(true, false, true);
	bool got_handshake = false;
	bool disconnected = false;

	// Simple disconnect handler
	connection::connection_cb dcb = [&disconnected](agentino_manager* am,
	                                                std::shared_ptr<connection> conn,
	                                                void* ctx) { disconnected = true; };

	// The most minimal handshake handler
	connection::handshake_cb hcb = [&got_handshake](
	                                   agentino_manager* am,
	                                   void* ctx,
	                                   const draiosproto::agentino_handshake&,
	                                   draiosproto::agentino_handshake_response& resp) -> bool {
		got_handshake = true;

		return false;
	};

	// Normally we would connect through an agentino_manager's listen loop,
	// but this unit test is JUST testing the connection.
	auto new_conn_cb = [&dcb, &hcb, &got_handshake, &fa](cm_socket* sock, void* ctx) {
		// auto* fa = (fake_agentino*)ctx;

		connection::ptr connp =
		    std::make_shared<connection>(sock, nullptr, 0, hcb, connection::empty_callback, dcb);
		connp->start(ctx);
		for (uint32_t loops = 0; !got_handshake && loops < 5000; ++loops)
		{
			usleep(1000);
		}
		ASSERT_TRUE(got_handshake);

		for (uint32_t loops = 0; fa.connected() && loops < 5000; ++loops)
		{
			usleep(1000);
		}
		ASSERT_FALSE(fa.connected());
	};

	auto conn_error_cb = [](cm_socket::error_type et, int error, void* ctx) {
		ASSERT_EQ(cm_socket::error_type::ERR_NONE, et);
	};

	// Use a CM socket to listen for the agentino connection
	cm_socket::listen({port, false}, new_conn_cb, conn_error_cb, &fa);

	// Now actually fire up the agentino
	fa.start(port);

	for (uint32_t loops = 0; !got_handshake && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(got_handshake);

	for (uint32_t loops = 0; !disconnected && loops < 3000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_TRUE(disconnected);

	fa.stop();
	cm_socket::stop_listening(true);
}

TEST(agentino, handshake_disconnect)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	// Create (but don't start) fake agentino
	fake_agentino fa(true, false, true);
	bool got_handshake = false;
	bool disconnect_on_handshake = true;
	bool connected = false;
	bool disconnected = false;
	connection::ptr connp;

	// Simple connect handler
	connection::connection_cb ccb = [&connected](agentino_manager* am,
	                                             std::shared_ptr<connection> conn,
	                                             void* ctx) { connected = true; };

	// Simple disconnect handler
	connection::connection_cb dcb = [&disconnected](agentino_manager* am,
	                                                std::shared_ptr<connection> conn,
	                                                void* ctx) { disconnected = true; };

	// Simple handshake handler
	connection::handshake_cb hcb = [&](agentino_manager* am,
	                                   void* ctx,
	                                   const draiosproto::agentino_handshake& hs,
	                                   draiosproto::agentino_handshake_response& hr) -> bool {
		auto* pfa = (fake_agentino*)ctx;

		if (disconnect_on_handshake)
		{
			pfa->drop_connection();
			for (uint32_t loops = 0;
			     fa.get_status() != fake_agentino::server_status::SHUTDOWN && loops < 2000;
			     ++loops)
			{
				usleep(1000);
			}
		}
		hr.set_timestamp_ns(1002);

		got_handshake = true;
		return true;
	};

	// Normally we would connect through an agentino_manager's listen loop,
	// but this unit test is JUST testing the connection and handshake.
	auto new_conn_cb = [&ccb, &dcb, &hcb, &connp, &disconnected](cm_socket* sock, void* ctx) {
		connp = std::make_shared<connection>(sock, nullptr, 0, hcb, ccb, dcb);
		connp->start(ctx);

		for (uint32_t loops = 0; !disconnected && loops < 3000; ++loops)
		{
			usleep(1000);
		}
		ASSERT_TRUE(disconnected);
	};

	auto conn_error_cb = [](cm_socket::error_type et, int error, void* ctx) {
		ASSERT_EQ(cm_socket::error_type::ERR_NONE, et);
	};

	// Use a CM socket to listen for the agentino connection
	cm_socket::listen({7357, false}, new_conn_cb, conn_error_cb, &fa);

	// Now actually fire up the fake agentino
	fa.start(7357);

	for (uint32_t loops = 0; !disconnected && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, fa.get_num_disconnects());
	ASSERT_FALSE(connected);
	ASSERT_TRUE(got_handshake);
	ASSERT_TRUE(disconnected);

	fa.stop();
	cm_socket::stop_listening(true);
}

TEST(agentino_manager, basic)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager am(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	EXPECT_EQ(am.get_agentino_list().size(), 0);
	std::shared_ptr<connection> c = get_bogus_connection();
	EXPECT_EQ(am.get_agentino(c), nullptr);
}

TEST(agentino_manager, build_metadata)
{
	draiosproto::agentino_handshake data;
	data.mutable_metadata()->set_container_id("id");
	data.mutable_metadata()->set_container_image("image");
	data.mutable_metadata()->set_container_name("name");
	(*data.mutable_metadata()->mutable_other_metadata())["key"] = "value";

	std::map<agentino_metadata_property, std::string> fixed_metadata;
	std::map<std::string, std::string> arbitrary_metadata;
	agentino_manager::build_metadata(data, fixed_metadata, arbitrary_metadata);

	EXPECT_EQ(fixed_metadata.find(CONTAINER_ID)->second, "id");
	EXPECT_EQ(fixed_metadata.find(CONTAINER_NAME)->second, "name");
	EXPECT_EQ(fixed_metadata.find(CONTAINER_IMAGE)->second, "image");
	EXPECT_EQ(arbitrary_metadata.find("key")->second, "value");
}

TEST(agentino_manager, add_delete_connection)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager am(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	std::shared_ptr<connection> c = get_bogus_connection();
	draiosproto::agentino_handshake data;
	data.mutable_metadata()->set_container_id("id");
	data.mutable_metadata()->set_container_image("image");
	data.mutable_metadata()->set_container_name("name");
	test_helper::set_handshake_data(c, data);

	am.new_agentino_connection(c);
	auto a = am.get_agentino(c);
	ASSERT_NE(a, nullptr);
	EXPECT_NE(a->get_container_list().find("id"), a->get_container_list().end());
	EXPECT_EQ(a->get_connection_info(), c);
	EXPECT_EQ(am.get_agentino_list().size(), 1);

	am.delete_agentino_connection(c);
	EXPECT_EQ(am.get_agentino_list().size(), 0);
	EXPECT_EQ(am.get_agentino(c), nullptr);
}

// Here we check that if a second "version" of the same agentino is created, potentially
// after say a disconnect/reconnect, that there is no issue even if the first one is not
// destroyed
TEST(agentino_manager, ecs_agentino_overlap)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	agentino_manager m(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	EXPECT_EQ(c_m.get_container_list().size(), 0);

	auto connection_in = get_bogus_connection();
	draiosproto::agentino_handshake data;
	data.mutable_metadata()->set_container_id("id");
	test_helper::set_handshake_data(connection_in, data);

	m.new_agentino_connection(connection_in);
	ASSERT_NE(c_m.get_container("id"), nullptr);
	EXPECT_EQ(c_m.get_container("id")->get_ref(), 1);
	EXPECT_EQ(m.get_agentino_list().size(), 1);
	std::shared_ptr<agentino> a = m.get_agentino(connection_in);
	ASSERT_EQ(a->get_metadata_property(CONTAINER_ID), "id");

	// now "delete" the connection, causing it to be removed from the agentino manager,
	// but we still have a pointer to it (a)
	m.delete_agentino_connection(connection_in);
	EXPECT_EQ(m.get_agentino_list().size(), 0);               // gone from aganetino manager
	EXPECT_EQ(a->get_metadata_property(CONTAINER_ID), "id");  // still exists!
	EXPECT_EQ(c_m.get_container("id")->get_ref(), 1);         // container there too!

	// Now create a second identical agentino
	m.new_agentino_connection(connection_in);
	EXPECT_EQ(m.get_agentino_list().size(), 1);        // Now we have agentino
	EXPECT_EQ(c_m.get_container("id")->get_ref(), 2);  // double ref on the container!

	// Now delete the first agentino.
	// The agentino might still live on the new_agentino_list until the next
	// time the loop runs. This is not a bug.
	a = nullptr;
	for (uint32_t loops = 0; c_m.get_container("id")->get_ref() > 1 && loops < 4000; ++loops)
	{
		usleep(100);
	}
	EXPECT_EQ(m.get_agentino_list().size(), 1);        // Still have agentino
	EXPECT_EQ(c_m.get_container("id")->get_ref(), 1);  // and just a single ref on container

	// Now delete everything.
	// Again, must wait for the list to synchronize.
	m.delete_agentino_connection(connection_in);
	for (uint32_t loops = 0; c_m.get_container("id") != nullptr && loops < 4000; ++loops)
	{
		usleep(100);
	}
	EXPECT_EQ(m.get_agentino_list().size(), 0);   // nothing
	EXPECT_EQ(c_m.get_container("id"), nullptr);  // nothing
}

TEST(agentino_manager, basic_connection)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	scoped_config<uint16_t> agentino_port("agentino_port", 6767);
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	container_manager c_m;
	agentino_manager am(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	fake_agentino fa(true, false, true);

	// Now fire up the fake agentino
	fa.start(6767);

	for (uint32_t loops = 0;
	     fa.get_status() != fake_agentino::server_status::RUNNING && loops < 5000;
	     ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(fake_agentino::server_status::RUNNING, fa.get_status());

	for (uint32_t loops = 0; am.get_num_connections() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, am.get_num_connections());

	fa.stop();

	// Make sure disconnect is detected
	for (uint32_t loops = 0; am.get_num_connections() > 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(0, am.get_num_connections());
}

TEST(agentino_manager, multi_connection)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	const uint32_t num_fas = 3;
	const uint16_t port = 6767;
	scoped_config<uint16_t> agentino_port("agentino_port", port);
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	container_manager c_m;
	agentino_manager am(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	std::list<fake_agentino*> fas;

	// Build and start the fake agentinos
	for (uint32_t i = 0; i < num_fas; ++i)
	{
		std::stringstream ss;
		ss << i << i << i << "-" << num_fas - i;
		auto* fa = new fake_agentino(true, false, false, ss.str());
		fas.push_back(fa);

		fa->start(port);

		for (uint32_t loops = 0;
		     fa->get_status() != fake_agentino::server_status::RUNNING && loops < 5000;
		     ++loops)
		{
			usleep(1000);
		}
		ASSERT_EQ(fake_agentino::server_status::RUNNING, fa->get_status());
	}

	for (uint32_t loops = 0; am.get_num_connections() < num_fas && loops < 10000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(num_fas, am.get_num_connections());

	for (auto* fa : fas)
	{
		fa->pause(false);
		fa->stop();
		delete fa;
	}
	fas.clear();

	// Make sure disconnect is detected
	for (uint32_t loops = 0; am.get_num_connections() > 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(0, am.get_num_connections());
}

TEST(agentino_manager, agentino_heartbeat)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	const uint16_t port = 6768;
	scoped_config<uint16_t> agentino_port("agentino_port", port);
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	container_manager c_m;
	agentino_manager am(dummy_handler, nullptr, c_m, "machineid", "de:ad:be:ef");
	fake_agentino fa(true, false, true);
	fa.turn_on_heartbeats();

	// Now fire up the fake agentino
	fa.start(port);

	for (uint32_t loops = 0;
	     fa.get_status() != fake_agentino::server_status::RUNNING && loops < 5000;
	     ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(fake_agentino::server_status::RUNNING, fa.get_status());

	for (uint32_t loops = 0; am.get_num_connections() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, am.get_num_connections());

	for (uint32_t loops = 0; fa.get_num_sent_heartbeats() < 2 && loops < 2000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_LE(2, fa.get_num_sent_heartbeats());

	fa.stop();

	// Make sure disconnect is detected
	for (uint32_t loops = 0; am.get_num_connections() > 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(0, am.get_num_connections());
}

TEST(agentino_manager, agentino_message)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	uint16_t port = 7237;
	scoped_config<uint16_t> agentino_port("agentino_port", port);
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	test_handler th;
	container_manager c_m;
	agentino_manager am(th, nullptr, c_m, "machineid", "de:ad:be:ef");
	fake_agentino fa(true, false, true);

	// Now fire up the fake agentino
	fa.start(port);

	// Make sure both sides are connected
	for (uint32_t loops = 0;
	     fa.get_status() != fake_agentino::server_status::RUNNING && loops < 5000;
	     ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(fake_agentino::server_status::RUNNING, fa.get_status());

	for (uint32_t loops = 0; am.get_num_connections() == 0 && loops < 5000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, am.get_num_connections());

	// Build and send a POLICY_EVENTS message
	draiosproto::policy_events events;
	events.set_machine_id("de:ad:be:ef");
	events.set_customer_id("zippercorp");
	draiosproto::policy_event* new_event = events.add_events();
	new_event->set_timestamp_ns(1);
	new_event->set_policy_id(0xB17EFACE);
	new_event->set_container_id("pianocat");

	fake_agentino::buf b = fa.build_buf(draiosproto::message_type::POLICY_EVENTS,
	                                    dragent_protocol::PROTOCOL_VERSION_NUMBER_10S_FLUSH,
	                                    events);

	bool res = fa.enqueue_agentone_message(b);
	ASSERT_TRUE(res);
	for (uint32_t loops = 0; fa.get_num_sent_messages() == 0 && loops < 3000; ++loops)
	{
		usleep(1000);
	}

	// Validate that the AM received it
	for (uint32_t loops = 0; th.m_num_policy_events == 0 && loops < 3000; ++loops)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, th.m_num_policy_events);

	delete[] b.ptr;
	fa.stop();
}

TEST(agentino_manager, DISABLED_add_connection_to_extant_agentino)
{
	// We currently do not support lookup of agentinos by metadata, so this won't work
}

class tracking_security_result_handler : public security_result_handler_dummy
{
public:
	void security_mgr_policy_events_ready(uint64_t ts_ns,
	                                      draiosproto::policy_events* events) override
	{
		m_events = *events;
		++m_num_events;
	}

	void security_mgr_throttled_events_ready(uint64_t ts_ns,
	                                         draiosproto::throttled_policy_events *events,
	                                         uint32_t total_throttled_count) override
	{
		m_tevents = *events;
		++m_num_throttled;
	}

	draiosproto::policy_events m_events;
	draiosproto::throttled_policy_events m_tevents;

	uint32_t m_num_events = 0;
	uint32_t m_num_throttled = 0;
};

TEST(agentino_manager, handle_events_message)
{
	// Save a little bit of time per test by not setting up ssl
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	tracking_security_result_handler tsrh;
	agentino_manager am(tsrh, nullptr, c_m, "machineid", "de:ad:be:ef");

	draiosproto::policy_events pe;
	pe.set_machine_id("toby-box");
	pe.set_customer_id("toby");

	std::shared_ptr<protobuf_compressor> compressor =
	    protobuf_compressor_factory::get(protocol_compression_method::GZIP);
	std::shared_ptr<serialized_buffer> buffer =
	    dragent_protocol::message_to_buffer(0,
	                                        draiosproto::message_type::POLICY_EVENTS,
	                                        pe,
	                                        compressor);

	am.handle_message(draiosproto::message_type::POLICY_EVENTS,
	                  (const uint8_t*)buffer->buffer.c_str(),
	                  buffer->buffer.size());
	EXPECT_EQ(tsrh.m_events.machine_id(), "machineid");
	EXPECT_EQ(tsrh.m_events.customer_id(), "de:ad:be:ef");
	EXPECT_EQ(1, tsrh.m_num_events);
	EXPECT_EQ(0, tsrh.m_num_throttled);
}

TEST(agentino_manager, handle_throttled_events_message)
{
	// Save a little bit of time per test by not setting up ssl
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	container_manager c_m;
	tracking_security_result_handler tsrh;
	agentino_manager am(tsrh, nullptr, c_m, "machineid", "b1:7e:fa:ce");

	auto type = draiosproto::message_type::THROTTLED_POLICY_EVENTS;
	draiosproto::throttled_policy_events tpe;
	tpe.set_machine_id("kiwi-box");
	tpe.set_customer_id("kiwi");

	std::shared_ptr<protobuf_compressor> compressor =
	    protobuf_compressor_factory::get(protocol_compression_method::GZIP);
	std::shared_ptr<serialized_buffer> buffer =
	    dragent_protocol::message_to_buffer(0,
	                                        type,
	                                        tpe,
	                                        compressor);

	am.handle_message(type,
	                  (const uint8_t*)buffer->buffer.c_str(),
	                  buffer->buffer.size());
	EXPECT_EQ("machineid", tsrh.m_tevents.machine_id());
	EXPECT_EQ("b1:7e:fa:ce", tsrh.m_tevents.customer_id());
	EXPECT_EQ(0, tsrh.m_num_events);
	EXPECT_EQ(1, tsrh.m_num_throttled);
}

TEST(agentino_manager, handle_policies_message)
{
	// Save a little bit of time per test by not setting up ssl
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	tracking_security_result_handler tsrh;
	agentino_manager am(tsrh, nullptr, c_m, "machineid", "de:ad:be:ef");

	draiosproto::policies_v2 p;
	p.mutable_fastengine_files()->set_tag("some tag");

	std::shared_ptr<protobuf_compressor> compressor =
	    protobuf_compressor_factory::get(protocol_compression_method::GZIP);
	std::shared_ptr<serialized_buffer> buffer =
	    dragent_protocol::message_to_buffer(0,
	                                        draiosproto::message_type::POLICIES_V2,
	                                        p,
	                                        compressor);

	am.handle_message(draiosproto::message_type::POLICIES_V2,
	                  (const uint8_t*)buffer->buffer.c_str(),
	                  buffer->buffer.size());
	for (int i = 0;
	     i < 100 && test_helper::get_cached_policies(am).fastengine_files().tag() != "some tag";
	     i++)
	{
		usleep(100000);
	}
	EXPECT_EQ(test_helper::get_cached_policies(am).fastengine_files().tag(), "some tag");
}

TEST(agentino_manager, existing_policies_to_new_agentinos)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	security_result_handler_dummy tsrh;
	agentino_manager_dummy<agentino_dummy> am(tsrh, nullptr, c_m, "toby's_piano", "toby");

	draiosproto::policies_v2 p;

	auto ps = p.add_policy_list();
	ps->set_id(1);
	ps->set_name("zipper");
	ps->set_enabled(true);
	std::shared_ptr<protobuf_compressor> compressor =
	    protobuf_compressor_factory::get(protocol_compression_method::GZIP);
	std::shared_ptr<serialized_buffer> buffer =
	    dragent_protocol::message_to_buffer(0,
	                                        draiosproto::message_type::POLICIES_V2,
	                                        p,
	                                        compressor);
	am.handle_message(draiosproto::message_type::POLICIES_V2,
	                  (const uint8_t*)buffer->buffer.c_str(),
	                  buffer->buffer.size());
	ASSERT_EQ(am.get_cached_policies().policy_list()[0].id(), 1);

	// Could probably abstract away creating agentinos with a helper oh well
	auto connection_in = get_bogus_connection();
	draiosproto::agentino_handshake data;
	test_helper::set_handshake_data(connection_in, data);
	am.new_agentino_connection(connection_in);
	auto a = std::dynamic_pointer_cast<agentino_dummy>(am.get_agentino(connection_in));

	for (int i = 0; i < 100 && a->m_last_policies_received == -1; i++)
	{
		usleep(1000);
	}

	// agentino got the policies! yay!
	EXPECT_EQ(a->m_last_policies_received, 1);
}

TEST(agentino_manager, no_policies_to_new_agentinos)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	security_result_handler_dummy tsrh;
	agentino_manager_dummy<agentino_dummy> am(tsrh, nullptr, c_m, "toby's_piano", "toby");

	auto connection_in = get_bogus_connection();
	draiosproto::agentino_handshake data;
	test_helper::set_handshake_data(connection_in, data);
	am.new_agentino_connection(connection_in);
	auto a = std::dynamic_pointer_cast<agentino_dummy>(am.get_agentino(connection_in));

	for (int i = 0; i < 100 && a->m_last_policies_received == -1; i++)
	{
		usleep(1000);
	}

	// agentino got empty policies
	EXPECT_EQ(a->m_last_policies_received, 0);
}

TEST(agentino_manager, new_policies_to_existing_agentinos)
{
	scoped_config<uint64_t> sleepytime("agentino_manager.socket_poll_timeout_ms", 5);
	scoped_config<uint32_t> sleepytime2("socket.poll_timeout", 5);
	container_manager c_m;
	security_result_handler_dummy tsrh;
	agentino_manager_dummy<agentino_dummy> am(tsrh, nullptr, c_m, "toby's_piano", "toby");

	draiosproto::policies_v2 p;

	auto connection_in = get_bogus_connection();
	draiosproto::agentino_handshake data;
	test_helper::set_handshake_data(connection_in, data);
	am.new_agentino_connection(connection_in);
	auto a = std::dynamic_pointer_cast<agentino_dummy>(am.get_agentino(connection_in));

	for (int i = 0; i < 100 && a->m_last_policies_received == -1; i++)
	{
		usleep(100000);
	}

	// agentino got the policies! yay!
	EXPECT_EQ(a->m_last_policies_received, 0);

	auto ps = p.add_policy_list();
	ps->set_id(1);
	ps->set_name("zipper");
	ps->set_enabled(true);
	std::shared_ptr<protobuf_compressor> compressor =
	    protobuf_compressor_factory::get(protocol_compression_method::GZIP);
	std::shared_ptr<serialized_buffer> buffer =
	    dragent_protocol::message_to_buffer(0,
	                                        draiosproto::message_type::POLICIES_V2,
	                                        p,
	                                        compressor);
	am.handle_message(draiosproto::message_type::POLICIES_V2,
	                  (const uint8_t*)buffer->buffer.c_str(),
	                  buffer->buffer.size());
	for (int i = 0; i < 100 && a->m_last_policies_received != 1; i++)
	{
		usleep(1000);
	}

	// agentino got the policies! yay!
	EXPECT_EQ(a->m_last_policies_received, 1);
}

/****************************************************************************
 * The following tests are more like integration tests, with a CM in agentino
 * mode talking with an agentino manager
 ****************************************************************************/
TEST_F(am_cm_integration_fixture, end_to_end_connection)
{
	const uint16_t port = 7357;
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	cm_config config = base_config;

	// Create the shared blocking queue
	protocol_queue pqueue(MAX_QUEUE_LEN);

	// Create and spin up the agentino manager
	scoped_config<uint16_t> agentino_port("agentino_port", port);
	scoped_config<bool> agentino_ssl("agentino_ssl", false);
	test_handler th;
	container_manager c_m;
	agentino_manager am(th, nullptr, c_m, "machineid", "de:ad:be:ef");  // This starts the AM

	// Set the config for the CM
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = port;
	config.m_ssl_enabled = false;

	// Create the connection manager in agentino mode
	connection_manager cm(config, &pqueue, {5}, {}, true);

	std::thread t([&cm]() { cm.test_run(); });

	// Wait for CM to connect to AM
	for (uint32_t i = 0; !cm.is_connected() && i < 10000; ++i)
	{
		usleep(1000);
	}
	ASSERT_TRUE(cm.is_connected());
	for (uint32_t i = 0; am.get_num_connections() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, am.get_num_connections());

	// Tear down all the things
	am.stop_listening();
	running_state::instance().shut_down();
	t.join();
}

TEST_F(am_cm_integration_fixture, end_to_end_ssl_connection)
{
	const uint16_t port = 6443;
	const size_t MAX_QUEUE_LEN = 64;
	// Build some boilerplate stuff that's needed to build a CM object
	cm_config config = base_config;

	// Create the shared blocking queue
	protocol_queue pqueue(MAX_QUEUE_LEN);

	// Create and spin up the agentino manager
	scoped_config<uint16_t> agentino_port("agentino_port", port);
	scoped_config<bool> agentino_ssl("agentino_ssl", true);
	test_handler th;
	container_manager c_m;
	agentino_manager am(th, nullptr, c_m, "machineid", "de:ad:be:ef");  // This starts the AM

	// Set the config for the CM
	scoped_config<bool> ssl_verify("ssl_verify_certificate", false);
	config.m_server_addr = "127.0.0.1";
	config.m_server_port = port;
	config.m_ssl_enabled = true;

	// Create the connection manager in agentino mode
	connection_manager cm(config, &pqueue, {5}, {}, true);

	std::thread t([&cm]() { cm.test_run(); });

	// Wait for CM to connect to AM
	for (uint32_t i = 0; !cm.is_connected() && i < 10000; ++i)
	{
		usleep(1000);
	}
	ASSERT_TRUE(cm.is_connected());
	for (uint32_t i = 0; am.get_num_connections() == 0 && i < 5000; ++i)
	{
		usleep(1000);
	}
	ASSERT_EQ(1, am.get_num_connections());

	// Tear down all the things
	am.stop_listening();
	running_state::instance().shut_down();
	t.join();
}
