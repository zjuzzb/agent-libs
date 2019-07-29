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

using namespace test_helpers;

namespace {

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

const std::string MACHINE_ID_FOR_TEST = "deadbeef";

}

namespace {

void add_connection(sinsp &inspector,
		    audit_tap &tap,
		    const sinsp_threadinfo *thread1,
		    int transition_count)
{
	sinsp_ipv4_connection_manager mgr(&inspector);

	_ipv4tuple ipv4;
	ipv4.m_fields.m_sip = 0x12345678;
	ipv4.m_fields.m_sport = 888;
	ipv4.m_fields.m_dip = 0x44000044;
	ipv4.m_fields.m_dport = 999;

	sinsp_connection *connection =
		mgr.add_connection(ipv4,
				   const_cast<std::string *>(&thread1->m_comm),
				   thread1->m_pid,
				   thread1->m_tid,
				   // the rest of the arguments were chosen arbitrarily
				   6 /*fd*/,
				   true /*isclient*/,
				   12345678 /*timestamp*/,
				   sinsp_connection::AF_NONE /*flags*/,
				   99 /*error_code*/);

	ASSERT_NE(connection, nullptr);
	// This is fundamental to audit_tap so make sure it is happening
	ASSERT_TRUE(connection->m_record_state_history);

	auto two_seconds_ago = sinsp_utils::get_current_time_ns() - 2000000000;


	for(int i = 0; i < transition_count; ++i)
	{
		connection->record_state_transition(two_seconds_ago + i * 10000000);

	}

	userdb db;
	tap.emit_connections(&mgr, &db);
}

}

// Ensure basic functionality of audit tap. Note that this was written long
// after audit_tap was created so it should not be considered exhaustive.
//
// This isn't ideal since we're having to create the whole world to test
// a small piece of code. This can be improved by pulling apart analyzer,
// analyzer_thread, sinsp_threadinfo, sinsp_ipv4_connection_manager and
// audit_tap.
TEST(audit_tap_test, DISABLED_basic)
{
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	sinsp_mock inspector;
	// The ipv4_connection_manager relies on the circular dependency to the
	// analyzer so we need to set up inspector.m_analyzer to add connections.
	// Also audit_tap uses tinfo->m_ainfo which is collected by the
	// analyzer_thread.
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(&inspector, "/" /*root dir*/, int_metrics);
	// For this test, we don't use the audit_tap in the analyzer, but if
	// we don't enable it the the ipv4_connection_manager won't record the
	// correct data.
	analyzer.enable_audit_tap(true /*emit local connections*/);
	inspector.m_analyzer = &analyzer;

	// Build some threads that we'll add connections to.
	(void)inspector.build_thread().commit();
	const sinsp_threadinfo *thread1 = inspector.build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3).commit();
	(void)inspector.build_thread().pid(expected_pid).tid(1234).commit();
	(void)inspector.build_thread().commit();
	inspector.open();

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
	add_connection(inspector, tap, thread1, TRANSITION_COUNT);

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

#define ARG_LENGTH_TEST(__limit)                                               \
{                                                                              \
	scoped_config<unsigned int> config("process_emitter.max_command_arg_length", __limit);\
									       \
	const std::string arg_150(150, 'x');                                   \
									       \
	sinsp_mock inspector;                                                  \
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();\
	sinsp_analyzer analyzer(& inspector, "/" /*root dir*/, int_metrics);   \
	analyzer.enable_audit_tap(true /*emit local connections*/);            \
	inspector.m_analyzer = &analyzer;                                      \
									       \
	const sinsp_threadinfo *thread1 = inspector.build_thread()             \
					  .pid(22)                             \
					  .comm("dragent")                     \
					  .arg(arg_150).commit();              \
	inspector.open();                                                      \
									       \
	audit_tap tap(default_hash_config(),                                   \
		      MACHINE_ID_FOR_TEST,                                     \
		      true /*emit local connections*/);                        \
                                                                               \
	add_connection(inspector, tap, thread1, 2);                            \
                                                                               \
	const tap::AuditLog *log = tap.get_events();                           \
	int expected_length = std::min(static_cast<int>(arg_150.length()), __limit);\
	std::string expected_arg(expected_length, 'x');                        \
	ASSERT_EQ(expected_arg, log->newprocessevents(0) .commandline(0));     \
}


TEST(audit_tap_test, DISABLED_configurable_command_length)
{
   ARG_LENGTH_TEST(10);
   ARG_LENGTH_TEST(99);
   ARG_LENGTH_TEST(149);
   ARG_LENGTH_TEST(150);
   ARG_LENGTH_TEST(151);
   ARG_LENGTH_TEST(200);
}
