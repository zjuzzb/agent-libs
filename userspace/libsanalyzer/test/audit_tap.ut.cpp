#include <gtest.h>
#include <memory>
#include <Poco/RegularExpression.h>
#include <audit_tap.h>
#include <analyzer.h>
#include <sinsp_mock.h>
#include <scoped_config.h>
#include <connectinfo.h>
#include <env_hash.h>
#include <tap.pb.h>
#include <arpa/inet.h>
#include "unique_ptr_resetter.h"

using namespace test_helpers;

namespace {

const std::string MACHINE_ID_FOR_TEST = "deadbeef";

const uint32_t DEFAULT_PID = 22;
const uint32_t DEFAULT_SOURCE_IP = 0x12345678;
const uint16_t DEFAULT_SOURCE_PORT = 888;
const uint32_t DEFAULT_DEST_IP = 0x44000044;
const uint16_t DEFAULT_DEST_PORT = 999;
const uint32_t DEFAULT_BYTES_IN = 42;
const uint32_t DEFAULT_BYTES_OUT = 16;
const uint32_t DEFAULT_BYTES_TOTAL = DEFAULT_BYTES_IN + DEFAULT_BYTES_OUT;
const uint32_t DEFAULT_COUNT_IN = 11;
const uint32_t DEFAULT_COUNT_OUT = 182;
const uint32_t DEFAULT_COUNT_TOTAL = DEFAULT_COUNT_IN + DEFAULT_COUNT_OUT;
const uint32_t DEFAULT_ERROR_COUNT = 2;

audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_handler;
sinsp_analyzer::flush_queue g_queue(1000);

env_hash_config *default_hash_config()
{
	static std::unique_ptr<env_hash_config> config;

	if (!config)
	{
		config.reset(new env_hash_config);
		config->m_envs_per_flush = 10;
		config->m_env_blacklist.reset(new env_hash::regex_list_t());
		config->m_send_metrics = true;
		config->m_send_audit_tap = true;
	}

	return config.get();
}

void add_connection(sinsp& inspector,
                    audit_tap& tap,
                    const sinsp_threadinfo* const thread1,
                    const int transition_count,
                    const bool is_client = true,
                    const uint32_t bytes_in = DEFAULT_BYTES_IN,
                    const uint32_t bytes_out = DEFAULT_BYTES_OUT,
                    const uint32_t count_in = DEFAULT_COUNT_IN,
                    const uint32_t count_out = DEFAULT_COUNT_OUT,
                    const uint32_t error_count = DEFAULT_ERROR_COUNT)
{
	sinsp_ipv4_connection_manager mgr(&inspector);
	_ipv4tuple ipv4;

	memset(ipv4.m_all, 0, sizeof ipv4.m_all);

	ipv4.m_fields.m_sip = DEFAULT_SOURCE_IP;
	ipv4.m_fields.m_sport = DEFAULT_SOURCE_PORT;
	ipv4.m_fields.m_dip = DEFAULT_DEST_IP;
	ipv4.m_fields.m_dport = DEFAULT_DEST_PORT;

	// These argument values were chosen arbitrarily
	const int fd = 6;
	const uint64_t timestamp = 12345678;
	const uint8_t flags = sinsp_connection::AF_NONE;
	const int32_t error_code = 99;

	sinsp_connection* const connection =
		mgr.add_connection(ipv4,
				   const_cast<std::string *>(&thread1->m_comm),
				   thread1->m_pid,
				   thread1->m_tid,
				   fd,
				   is_client,
				   timestamp,
				   flags,
				   error_code);

	ASSERT_NE(connection, nullptr);
	// This is fundamental to audit_tap so make sure it is happening
	ASSERT_TRUE(connection->m_record_state_history);

	sinsp_counter_bytes* counters = nullptr;
	if(is_client)
	{
		counters = &connection->m_metrics.m_client;
	}
	else
	{
		counters = &connection->m_metrics.m_server;
	}

	counters->m_count_in = count_in;
	counters->m_count_out = count_out;
	counters->m_bytes_in = bytes_in;
	counters->m_bytes_out = bytes_out;

	for(int i = 0; i < error_count; ++i)
	{
		connection->m_metrics.increment_error_count();
	}

	auto two_seconds_ago = sinsp_utils::get_current_time_ns() - 2000000000;

	for(int i = 0; i < transition_count; ++i)
	{
		connection->record_state_transition(two_seconds_ago + i * 10000000);
	}

	userdb db;
	tap.emit_connections(&mgr, &db);
}

void arg_length_test(const int limit)
{
	scoped_config<unsigned int> config("audit_tap.max_command_arg_length", limit);

	const std::string arg_150(150, 'x');

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
	                        "/" /*root dir*/,
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);

	analyzer.enable_audit_tap(true /*emit local connections*/);
	inspector->m_analyzer = &analyzer;

	const sinsp_threadinfo *thread1 = inspector->build_thread()
					  .pid(DEFAULT_PID)
					  .comm("dragent")
					  .arg(arg_150).commit();
	inspector->open();

	audit_tap tap(default_hash_config(),
		      MACHINE_ID_FOR_TEST,
		      true /*emit local connections*/);

	add_connection(*inspector, tap, thread1, 2);

	const tap::AuditLog *log = tap.get_events();
	int expected_length = std::min(static_cast<int>(arg_150.length()), limit);
	std::string expected_arg(expected_length, 'x');
	ASSERT_EQ(expected_arg, log->newprocessevents(0) .commandline(0));
}

} // end namespace

// Ensure basic functionality of audit tap. Note that this was written long
// after audit_tap was created so it should not be considered exhaustive.
//
// This isn't ideal since we're having to create the whole world to test
// a small piece of code. This can be improved by pulling apart analyzer,
// analyzer_thread, sinsp_threadinfo, sinsp_ipv4_connection_manager and
// audit_tap.
TEST(audit_tap_test, basic)
{
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	// The ipv4_connection_manager relies on the circular dependency to the
	// analyzer so we need to set up inspector->m_analyzer to add connections.
	// Also audit_tap uses tinfo->m_ainfo which is collected by the
	// analyzer_thread.
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();

	sinsp_analyzer analyzer(inspector.get(),
	                        "/" /*root dir*/,
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);

	// For this test, we don't use the audit_tap in the analyzer, but if
	// we don't enable it the the ipv4_connection_manager won't record the
	// correct data.
	analyzer.enable_audit_tap(true /*emit local connections*/);
	inspector->m_analyzer = &analyzer;

	// Build some threads that we'll add connections to.
	(void)inspector->build_thread().commit();
	const sinsp_threadinfo *thread1 = inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3).commit();
	(void)inspector->build_thread().pid(expected_pid).tid(1234).commit();
	(void)inspector->build_thread().commit();
	inspector->open();

	// Sanity checks
	ASSERT_EQ(expected_pid, thread1->m_pid);
	ASSERT_EQ(expected_pid, thread1->m_tid);
	ASSERT_EQ(expected_name, thread1->m_exe);

	// Even though the analyzer has it's own tap, let's make our own
	// and it can pull data from sinsp and the analyzer thread.
	audit_tap tap(default_hash_config(),
		      MACHINE_ID_FOR_TEST,
		      true /*emit local connections*/);


	const int TRANSITION_COUNT = 5;
	add_connection(*inspector, tap, thread1, TRANSITION_COUNT);

	const tap::AuditLog *log = tap.get_events();

	// Validate newprocessevents
	ASSERT_EQ(1, log->newprocessevents_size() );
	ASSERT_EQ(expected_pid, log->newprocessevents(0) .pid());
	ASSERT_EQ(expected_name, log->newprocessevents(0).name());
	ASSERT_EQ(3, log->newprocessevents(0).commandline_size());
	ASSERT_EQ(expected_arg_1, log->newprocessevents(0).commandline(0));
	ASSERT_EQ(expected_arg_2, log->newprocessevents(0).commandline(1));
	ASSERT_EQ(expected_arg_3, log->newprocessevents(0).commandline(2));

	// Validate the connectionevents
	ASSERT_EQ(TRANSITION_COUNT + 1, log->connectionevents_size());
}

TEST(audit_tap_test, max_command_arg_config_default)
{
	ASSERT_EQ(100, audit_tap::max_command_argument_length());
}

TEST(audit_tap_test, max_command_arg_configured)
{
	const int LIMIT = 24400;
	scoped_config<unsigned int> config("audit_tap.max_command_arg_length", LIMIT);
	ASSERT_EQ(LIMIT, audit_tap::max_command_argument_length());
}

TEST(audit_tap_test, configurable_command_length_10)
{
	arg_length_test(10);
}

TEST(audit_tap_test, configurable_command_length_99)
{
	arg_length_test(99);
}

TEST(audit_tap_test, configurable_command_length_149)
{
	arg_length_test(149);
}

TEST(audit_tap_test, configurable_command_length_150)
{
	arg_length_test(150);
}

TEST(audit_tap_test, configurable_command_length_151)
{
	arg_length_test(151);
}

TEST(audit_tap_test, configurable_command_length_200)
{
	arg_length_test(200);
}

/**
 * Ensure that audit_tap will emit client connections.
 */
TEST(audit_tap_test, connection_audit_one_client_connection)
{
	const char* const root_dir = "/";
	const bool emit_local_connections = false;
	const std::string arg(5, 'x');

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
	                        root_dir,
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);

	analyzer.enable_audit_tap(emit_local_connections);
	inspector->m_analyzer = &analyzer;

	const sinsp_threadinfo* const thread = inspector->build_thread()
			.pid(DEFAULT_PID)
			.comm("client_application")
			.arg(arg)
			.commit();

	inspector->open();

	audit_tap tap(default_hash_config(),
	              MACHINE_ID_FOR_TEST,
	              emit_local_connections);

	add_connection(*inspector, tap, thread, 2);

	const tap::AuditLog* const log = tap.get_events();

	ASSERT_TRUE(log->has_connectionaudit());
	const auto& conn_audit = log->connectionaudit();

	// Ensure that the connection counts are correct
	ASSERT_EQ(1, conn_audit.connectioncounttotal());
	ASSERT_EQ(1, conn_audit.connectioncountout());
	ASSERT_EQ(0, conn_audit.connectioncountin());

	// Ensure that the single connection is present
	ASSERT_EQ(1, conn_audit.connections_size());

	const auto& conn = conn_audit.connections(0);

	const uint32_t source_ip_nbo = htonl(DEFAULT_SOURCE_IP);
	ASSERT_EQ(source_ip_nbo, conn.clientipv4());
	ASSERT_EQ(DEFAULT_SOURCE_PORT, conn.clientport());
	ASSERT_EQ(DEFAULT_PID, conn.clientpid());

	const uint32_t dest_ip_nbo = htonl(DEFAULT_DEST_IP);
	ASSERT_EQ(dest_ip_nbo, conn.serveripv4());
	ASSERT_EQ(DEFAULT_DEST_PORT, conn.serverport());
	ASSERT_EQ(0, conn.serverpid());
	ASSERT_EQ(DEFAULT_ERROR_COUNT, conn.errorcount());

	const auto& request_counts = conn.requestcounts();

	ASSERT_EQ(DEFAULT_COUNT_TOTAL, request_counts.total());
	ASSERT_EQ(DEFAULT_COUNT_IN, request_counts.in());
	ASSERT_EQ(DEFAULT_COUNT_OUT, request_counts.out());

	const auto& byte_counts = conn.bytecounts();

	ASSERT_EQ(DEFAULT_BYTES_TOTAL, byte_counts.total());
	ASSERT_EQ(DEFAULT_BYTES_IN, byte_counts.in());
	ASSERT_EQ(DEFAULT_BYTES_OUT, byte_counts.out());
}

/**
 * Ensure that audit_tap will emit server connections.
 */
TEST(audit_tap_test, connection_audit_one_server_connection)
{
	const char* const root_dir = "/";
	const bool emit_local_connections = false;
	const std::string arg(5, 'x');

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
	                        root_dir,
	                        int_metrics,
	                        g_audit_handler,
	                        g_secure_handler,
	                        &g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);

	analyzer.enable_audit_tap(emit_local_connections);
	inspector->m_analyzer = &analyzer;

	const sinsp_threadinfo* const thread = inspector->build_thread()
			.pid(DEFAULT_PID)
			.comm("server_application")
			.arg(arg)
			.commit();

	inspector->open();

	audit_tap tap(default_hash_config(),
	              MACHINE_ID_FOR_TEST,
	              emit_local_connections);

	const bool is_client = false;
	add_connection(*inspector, tap, thread, 2, is_client);

	const tap::AuditLog* const log = tap.get_events();

	ASSERT_TRUE(log->has_connectionaudit());
	const auto& conn_audit = log->connectionaudit();

	// Ensure that the connection counts are correct
	ASSERT_EQ(1, conn_audit.connectioncounttotal());
	ASSERT_EQ(0, conn_audit.connectioncountout());
	ASSERT_EQ(1, conn_audit.connectioncountin());

	// Ensure that the single connection is present
	ASSERT_EQ(1, conn_audit.connections_size());

	const auto& conn = conn_audit.connections(0);

	const uint32_t source_ip_nbo = htonl(DEFAULT_SOURCE_IP);
	ASSERT_EQ(source_ip_nbo, conn.clientipv4());
	ASSERT_EQ(DEFAULT_SOURCE_PORT, conn.clientport());
	ASSERT_EQ(0, conn.clientpid());

	const uint32_t dest_ip_nbo = htonl(DEFAULT_DEST_IP);
	ASSERT_EQ(dest_ip_nbo, conn.serveripv4());
	ASSERT_EQ(DEFAULT_DEST_PORT, conn.serverport());
	ASSERT_EQ(DEFAULT_PID, conn.serverpid());
	ASSERT_EQ(DEFAULT_ERROR_COUNT, conn.errorcount());

	const auto& request_counts = conn.requestcounts();

	ASSERT_EQ(DEFAULT_COUNT_TOTAL, request_counts.total());
	ASSERT_EQ(DEFAULT_COUNT_IN, request_counts.in());
	ASSERT_EQ(DEFAULT_COUNT_OUT, request_counts.out());

	const auto& byte_counts = conn.bytecounts();

	ASSERT_EQ(DEFAULT_BYTES_TOTAL, byte_counts.total());
	ASSERT_EQ(DEFAULT_BYTES_IN, byte_counts.in());
	ASSERT_EQ(DEFAULT_BYTES_OUT, byte_counts.out());
}
