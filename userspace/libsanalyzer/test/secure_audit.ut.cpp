#include <gtest.h>
#include <memory>
#include <secure_audit.h>
#include <analyzer.h>
#include <sinsp_mock.h>
#include <scoped_config.h>
#include <connectinfo.h>
#include "unique_ptr_resetter.h"

using namespace test_helpers;

namespace
{
const int N_DIFFERENT_EXE = 5;
const int N_DIFFERENT_CMDLINES = 50;

const std::vector<std::string> exe = {"cat", "ls", "ps", "df", "ll"};

audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_handler;
sinsp_analyzer::flush_queue g_queue(1000);

void add_executed_commands_helper(std::unordered_map<std::string, std::vector<sinsp_executed_command>>& executed_commands,
				  int n_cmd_per_container,
				  std::vector<std::string>& containers,
				  std::vector<sinsp_executed_command>& commands)
{
	int j = 0;
	int jmax = commands.size();

	if(jmax == 0)
	{
		return;
	}

	for(auto container : containers)
	{
		for(int i = 0; i < n_cmd_per_container; i++)
		{
			executed_commands[container].push_back(commands[j]);
			j++;
			if(j == jmax)
			{
				j = 0;
			}
		}
	}
}

// Generic test for executed commands
void check_executed_commands_helper(const secure::Audit* audit_pb,
				    secure_audit* audit,
				    int n_cmd_per_container,
				    std::vector<std::string>& containers,
				    std::vector<sinsp_executed_command>& commands)
{
	// Test number of executed commands
	int n_cmd_tot = 0;

	int executed_commands_per_container_limit = audit->c_secure_audit_executed_commands_per_container_limit.get_value();

	// Secure audit - Executed commands
	// Try to limit to N_DIFFERENT_CMDLINES
	// Try to limit to N_DIFFERENT_EXE

	// We have a limit on executed commands
	if(executed_commands_per_container_limit != 0)
	{
		// If we exeed the limit
		if(n_cmd_per_container > executed_commands_per_container_limit)
		{
			// try to group by cmdline
			if(executed_commands_per_container_limit < N_DIFFERENT_CMDLINES)
			{
				// try to group by exe
				if(executed_commands_per_container_limit < N_DIFFERENT_EXE)
				{
					if(executed_commands_per_container_limit < n_cmd_per_container)
					{
						n_cmd_per_container = executed_commands_per_container_limit;
					}
				}
				else
				{
					n_cmd_per_container = N_DIFFERENT_EXE;
				}
			}
			else
			{
				n_cmd_per_container = N_DIFFERENT_CMDLINES;
			}
		}
	}

	n_cmd_tot = n_cmd_per_container * containers.size();

	if(!audit->c_secure_audit_executed_commands_enabled.get_value() ||
	   !audit->c_secure_audit_enabled.get_value())
	{
		n_cmd_tot = 0;
	}

	if(commands.size() == 0)
	{
		n_cmd_tot = 0;
	}

	if(n_cmd_tot == 0)
	{
		ASSERT_EQ(audit_pb, nullptr);
	}
	else
	{
		ASSERT_NE(audit_pb, nullptr);
		ASSERT_EQ(audit_pb->executed_commands_size(), n_cmd_tot);

		for(int i = 0; i < audit_pb->executed_commands_size(); i++)
		{
			// Check some fields to be correctly populated
			const secure::ExecutedCommand& c = audit_pb->executed_commands(i);
			uint64_t delta_seconds = 100000000000; // 100 s
			ASSERT_TRUE(c.timestamp() > (sinsp_utils::get_current_time_ns() - delta_seconds));
			ASSERT_TRUE(c.timestamp() < (sinsp_utils::get_current_time_ns() + delta_seconds));

			ASSERT_TRUE(std::find(exe.begin(), exe.end(), c.comm()) != exe.end());
		}
	}
}

void executed_commands_build_and_test_generic(
	secure_audit* audit,
	int n_commands_per_container,
	int n_containers,
	int n_commands)
{
	// Initialize needed stuff
	std::unordered_map<std::string, std::vector<sinsp_executed_command>> m_executed_commands_local;
	std::vector<std::string> containers;
	std::vector<sinsp_executed_command> commands;

	// Build containers
	for(int i = 0; i < n_containers; i++)
	{
		if(i == 0)
		{
			containers.push_back(""); // root namespace
		}
		else
		{
			char buffer[10];
			sprintf(buffer, "%3d", i);
			containers.push_back("s1sdygc0n" + std::string(buffer));
		}
	}

	// Build command(s)
	sinsp_executed_command c;

	for(int i = 0; i < n_commands; i++)
	{
		c.m_ts = sinsp_utils::get_current_time_ns();
		c.m_count = 1 + (i % 4);
		c.m_shell_id = 14000 + i;
		c.m_login_shell_distance = 1 + (i % 3);
		c.m_comm = exe[i % 5];
		// N_DIFFERENT_EXE = 5
		c.m_exe = exe[i % 5];
		c.m_pid = 15000 + i * 2;
		c.m_ppid = 16000 + i * 3;
		c.m_uid = 5;
		c.m_cwd = "/home/ubuntu/test/";
		c.m_tty = 12;
		// N_DIFFERENT_CMDLINES = 50
		c.m_cmdline = exe[i % 5] + " compile | tail -n " + std::to_string(((i % 50) * 5) + 1);

		c.m_category = draiosproto::CAT_NONE;

		commands.push_back(c);
	}

	// Test empty protobuf
	const secure::Audit* audit_pb = audit->get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	// Build protobuf
	add_executed_commands_helper(m_executed_commands_local, n_commands_per_container, containers, commands);
	audit->emit_commands_audit(&m_executed_commands_local);
	// Get pb
	audit_pb = audit->get_events(sinsp_utils::get_current_time_ns());
	if(((n_commands_per_container * n_containers * n_commands) != 0) &&
	   audit->c_secure_audit_executed_commands_enabled.get_value() &&
	   audit->c_secure_audit_enabled.get_value())
	{
		ASSERT_NE(nullptr, audit_pb);
	}
	else
	{
		ASSERT_EQ(nullptr, audit_pb);
	}
	// Basic tests on generated pb
	check_executed_commands_helper(audit_pb, audit, n_commands_per_container, containers, commands);
	audit->clear();
}

// Network byte order is defined to always be big-endian
uint32_t ip_string_to_be(std::string ip_str)
{
	struct sockaddr_in sa;

	// store this IP address in sa:
	inet_pton(AF_INET, ip_str.c_str(), &(sa.sin_addr));

	return sa.sin_addr.s_addr;
}

uint32_t ip_string_to_le(std::string ip_str)
{
	return ntohl(ip_string_to_be(ip_str));
}

enum ip_proto_l4
{
	IP_PROTO_INVALID = 0,
	IP_PROTO_ICMP = 1,
	IP_PROTO_TCP = 6,
	IP_PROTO_UDP = 17
};
} // end namespace

TEST(secure_audit_test, executed_commands_per_container_limit_default)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	// c_secure_audit_executed_commands_per_container_limit is 30 by default

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 10, 1, 10);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 29, 20, 600);
	executed_commands_build_and_test_generic(&audit, 30, 20, 600);
	executed_commands_build_and_test_generic(&audit, 31, 20, 620);
	executed_commands_build_and_test_generic(&audit, 500, 10, 5000);
}

TEST(secure_audit_test, executed_commands_per_container_limit_unlimited)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	audit.c_secure_audit_executed_commands_per_container_limit.set(0);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 10, 1, 10);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 500, 10, 5000);
	executed_commands_build_and_test_generic(&audit, 1000, 100, 5000);
}

TEST(secure_audit_test, executed_commands_per_container_limit_2)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	// 2 < 5 (# different commands)
	audit.c_secure_audit_executed_commands_per_container_limit.set(2);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 1, 2, 2);
	executed_commands_build_and_test_generic(&audit, 2, 2, 10);
	executed_commands_build_and_test_generic(&audit, 3, 2, 10);
	executed_commands_build_and_test_generic(&audit, 10, 1, 10);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 30, 20, 600);
	executed_commands_build_and_test_generic(&audit, 500, 10, 5000);
}

TEST(secure_audit_test, executed_commands_per_container_limit_5)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	// 5 == 5 (# of different commands)
	audit.c_secure_audit_executed_commands_per_container_limit.set(5);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 4, 2, 20);
	executed_commands_build_and_test_generic(&audit, 5, 2, 20);
	executed_commands_build_and_test_generic(&audit, 6, 2, 20);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 30, 20, 600);
	executed_commands_build_and_test_generic(&audit, 500, 10, 5000);
}

TEST(secure_audit_test, executed_commands_per_container_limit_7)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	// 5 (# different commands) < 7 < 50 (# different cmdlines)
	audit.c_secure_audit_executed_commands_per_container_limit.set(7);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 1, 2, 20);
	executed_commands_build_and_test_generic(&audit, 5, 2, 20);
	executed_commands_build_and_test_generic(&audit, 6, 2, 20);
	executed_commands_build_and_test_generic(&audit, 7, 2, 20);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 30, 20, 600);
	executed_commands_build_and_test_generic(&audit, 500, 10, 5000);
}

TEST(secure_audit_test, executed_commands_per_container_limit_50)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	// 50 == 50 (# different cmlines)
	audit.c_secure_audit_executed_commands_per_container_limit.set(50);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 1, 2, 20);
	executed_commands_build_and_test_generic(&audit, 5, 2, 20);
	executed_commands_build_and_test_generic(&audit, 6, 2, 20);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 30, 20, 600);
	executed_commands_build_and_test_generic(&audit, 49, 10, 1500);
	executed_commands_build_and_test_generic(&audit, 50, 10, 1500);
	executed_commands_build_and_test_generic(&audit, 51, 10, 1500);
	executed_commands_build_and_test_generic(&audit, 500, 10, 5000);
}

TEST(secure_audit_test, executed_commands_per_container_limit_70)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	// 70 > 50 (# different cmlines)
	audit.c_secure_audit_executed_commands_per_container_limit.set(70);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 1, 2, 20);
	executed_commands_build_and_test_generic(&audit, 5, 2, 20);
	executed_commands_build_and_test_generic(&audit, 6, 2, 20);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
	executed_commands_build_and_test_generic(&audit, 30, 20, 600);
	executed_commands_build_and_test_generic(&audit, 50, 10, 1000);
	executed_commands_build_and_test_generic(&audit, 69, 10, 1000);
	executed_commands_build_and_test_generic(&audit, 70, 10, 1000);
	executed_commands_build_and_test_generic(&audit, 71, 10, 1000);
	executed_commands_build_and_test_generic(&audit, 500, 10, 5000);
}

TEST(secure_audit_test, executed_commands_disabled)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_executed_commands_enabled.set(false);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 10, 1, 10);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
}

TEST(secure_audit_test, audit_disabled)
{
	// Instantiate secure_audit
	secure_audit audit;

	audit.c_secure_audit_enabled.set(false);
	audit.c_secure_audit_executed_commands_enabled.set(true);

	executed_commands_build_and_test_generic(&audit, 0, 0, 0);
	executed_commands_build_and_test_generic(&audit, 1, 1, 1);
	executed_commands_build_and_test_generic(&audit, 10, 1, 10);
	executed_commands_build_and_test_generic(&audit, 10, 10, 100);
}

TEST(secure_audit_test, connections_base_client)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_enabled.set(true);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	const int expected_connections_size = 1;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c = audit_pb->connections(0);

	// checking is_client_only connection
	ASSERT_EQ(c.client_port(), expected_sport);
	ASSERT_EQ(c.server_port(), expected_dport);
	ASSERT_EQ(c.client_ipv4(), ip_string_to_le(expected_sip));
	ASSERT_EQ(c.server_ipv4(), ip_string_to_le(expected_dip));
	ASSERT_EQ(c.l4_protocol(), IP_PROTO_TCP);

	if(expected_error_code == 0)
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_ESTABLISHED);
	}
	else
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_FAILED);
	}

	ASSERT_EQ(c.error_code(), expected_error_code);
	ASSERT_EQ(c.timestamp(), ts);
	ASSERT_EQ(c.client_pid(), expected_pid);
	ASSERT_EQ(c.comm(), expected_comm);
	ASSERT_EQ(c.container_id(), expected_container_id);
	ASSERT_EQ(c.cmdline(), "");
}

TEST(secure_audit_test, connections_base_server)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_enabled.set(true);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	const int expected_connections_size = 1;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_dpid = expected_pid;
	conn.m_dtid = expected_pid;
	conn.m_dfd = 1234;

	conn.m_spid = 0;
	conn.m_stid = 0;
	conn.m_sfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_dproc = proc;
	conn.m_sproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c = audit_pb->connections(0);

	// checking is_client_only connection
	ASSERT_EQ(c.client_port(), expected_sport);
	ASSERT_EQ(c.server_port(), expected_dport);
	ASSERT_EQ(c.client_ipv4(), ip_string_to_le(expected_sip));
	ASSERT_EQ(c.server_ipv4(), ip_string_to_le(expected_dip));
	ASSERT_EQ(c.l4_protocol(), IP_PROTO_TCP);

	if(expected_error_code == 0)
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_ESTABLISHED);
	}
	else
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_FAILED);
	}

	ASSERT_EQ(c.error_code(), expected_error_code);
	ASSERT_EQ(c.timestamp(), ts);
	ASSERT_EQ(c.server_pid(), expected_pid);
	ASSERT_EQ(c.comm(), expected_comm);
	ASSERT_EQ(c.container_id(), expected_container_id);
	ASSERT_EQ(c.cmdline(), "");
}

TEST(secure_audit_test, connections_base_client_server)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_enabled.set(true);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	const int expected_connections_size = 1;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_dpid = expected_pid;
	conn.m_dtid = expected_pid;
	conn.m_dfd = 1234;

	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_dproc = proc;
	conn.m_sproc = proc;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c = audit_pb->connections(0);

	// checking is_client_only connection
	ASSERT_EQ(c.client_port(), expected_sport);
	ASSERT_EQ(c.server_port(), expected_dport);
	ASSERT_EQ(c.client_ipv4(), ip_string_to_le(expected_sip));
	ASSERT_EQ(c.server_ipv4(), ip_string_to_le(expected_dip));
	ASSERT_EQ(c.l4_protocol(), IP_PROTO_TCP);

	if(expected_error_code == 0)
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_ESTABLISHED);
	}
	else
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_FAILED);
	}

	ASSERT_EQ(c.error_code(), expected_error_code);
	ASSERT_EQ(c.timestamp(), ts);
	ASSERT_EQ(c.server_pid(), expected_pid);
	ASSERT_EQ(c.comm(), expected_comm);
	ASSERT_EQ(c.container_id(), expected_container_id);
	ASSERT_EQ(c.cmdline(), "");
}

TEST(secure_audit_test, connections_enabled_disabled)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_enabled.set(false);
	audit.c_secure_audit_connections_enabled.set(true);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(nullptr, audit_pb);

	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_enabled.set(false);

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(nullptr, audit_pb);

	audit.c_secure_audit_enabled.set(false);
	audit.c_secure_audit_connections_enabled.set(false);

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(nullptr, audit_pb);
}

TEST(secure_audit_test, connections_local)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_enabled.set(true);
	audit.c_secure_audit_connections_local.set(true);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "127.0.0.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	const int expected_connections_size = 2;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));
	tuple.m_fields.m_dip = ip_string_to_be(expected_sip);
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c = audit_pb->connections(0);

	// checking is_client_only connection
	ASSERT_EQ(c.client_port(), expected_sport);
	ASSERT_EQ(c.server_port(), expected_dport);
	ASSERT_EQ(c.client_ipv4(), ip_string_to_le(expected_sip));
	ASSERT_EQ(c.server_ipv4(), ip_string_to_le(expected_dip));
	ASSERT_EQ(c.l4_protocol(), IP_PROTO_TCP);

	if(expected_error_code == 0)
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_ESTABLISHED);
	}
	else
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_FAILED);
	}

	ASSERT_EQ(c.error_code(), expected_error_code);
	ASSERT_EQ(c.timestamp(), ts);
	ASSERT_EQ(c.client_pid(), expected_pid);
	ASSERT_EQ(c.comm(), expected_comm);
	ASSERT_EQ(c.container_id(), expected_container_id);
	ASSERT_EQ(c.cmdline(), "");

	audit.clear();

	audit.c_secure_audit_connections_local.set(false);
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(nullptr, audit_pb);
}

TEST(secure_audit_test, connections_cmdline)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_connections_enabled.set(true);
	audit.c_secure_audit_connections_cmdline.set(true);
	audit.c_secure_audit_connections_cmdline_maxlen.set(0);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_cmdline = "gcc -o a.out hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	const int expected_connections_size = 1;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c = audit_pb->connections(0);

	// checking is_client_only connection
	ASSERT_EQ(c.client_port(), expected_sport);
	ASSERT_EQ(c.server_port(), expected_dport);
	ASSERT_EQ(c.client_ipv4(), ip_string_to_le(expected_sip));
	ASSERT_EQ(c.server_ipv4(), ip_string_to_le(expected_dip));
	ASSERT_EQ(c.l4_protocol(), IP_PROTO_TCP);

	if(expected_error_code == 0)
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_ESTABLISHED);
	}
	else
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_FAILED);
	}

	ASSERT_EQ(c.error_code(), expected_error_code);
	ASSERT_EQ(c.timestamp(), ts);
	ASSERT_EQ(c.client_pid(), expected_pid);
	ASSERT_EQ(c.comm(), expected_comm);
	ASSERT_EQ(c.container_id(), expected_container_id);
	ASSERT_EQ(c.cmdline(), expected_cmdline);
}

TEST(secure_audit_test, connections_cmdline_maxlen)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_connections_enabled.set(true);
	audit.c_secure_audit_connections_cmdline.set(true);
	audit.c_secure_audit_connections_cmdline_maxlen.set(0);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";
	const std::string expected_arg_4 = "i_am_a_very_very_long_parameter";
	const std::string expected_arg_5 = "Lorem_ipsum_dolor_sit_amet,_consectetur_adipiscing_elit,_sed_do_eiusmod_tempor_incididunt_ut_labore_et_dolore_magna_aliqua._Pellentesque_habitant_morbi_tristique_senectus._Egestas_maecenas_pharetra_convallis_posuere_morbi._Mi_tempus_imperdiet_nulla_malesuada_pellentesque_elit_eget._Maecenas_accumsan_lacus_vel_facilisis_volutpat_est_velit_egestas_dui._Sapien_faucibus_et_molestie_ac_feugiat_sed_lectus_vestibulum._Dis_parturient_montes_nascetur_ridiculus_mus_mauris_vitae._Praesent_elementum_facilisis_leo_vel._Lorem_ipsum_dolor_sit_amet_consectetur_adipiscing_elit_duis_tristique._Risus_nullam_eget_felis_eget_nunc._Sollicitudin_nibh_sit_amet_commodo._Posuere_ac_ut_consequat_semper_viverra_nam_libero_justo._Tincidunt_arcu_non_sodales_neque._Gravida_dictum_fusce_ut_placerat._Eu_feugiat_pretium_nibh_ipsum_consequat_nisl_vel_pretium_lectus._Consectetur_purus_ut_faucibus_pulvinar_elementum._Dictumst_vestibulum_rhoncus_est_pellentesque_elit._Amet_facilisis_magna_etiam_tempor._Cursus_sit_amet_dictum_sit_amet_justo.__Nibh_praesent_tristique_magna_sit_amet_purus_gravida_quis._In_hendrerit_gravida_rutrum_quisque_non_tellus_orci._Mauris_sit_amet_massa_vitae._Semper_viverra_nam_libero_justo_laoreet_sit_amet_cursus._Purus_non_enim_praesent_elementum_facilisis_leo_vel_fringilla._Euismod_nisi_porta_lorem_mollis._Commodo_nulla_facilisi_nullam_vehicula_ipsum_a_arcu._In_vitae_turpis_massa_sed_elementum_tempus._Amet_tellus_cras_adipiscing_enim_eu_turpis_egestas_pretium_aenean._Tortor_at_risus_viverra_adipiscing_at_in._Tempus_imperdiet_nulla_malesuada_pellentesque_elit_eget._Amet_tellus_cras_adipiscing_enim_eu_turpis_egestas_pretium._Vulputate_eu_scelerisque_felis_imperdiet_proin_fermentum_leo._Nulla_posuere_sollicitudin_aliquam_ultrices_sagittis_orci_a._Aliquet_nec_ullamcorper_sit_amet_risus._Sed_risus_pretium_quam_vulputate_dignissim_suspendisse_in_est._Sit_amet_volutpat_consequat_mauris_nunc_congue_nisi_vitae_suscipit._Dui_faucibus_in_ornare_quam_viverra_orci_sagittis.__Eget_nullam_non_nisi_est_sit_amet_facilisis._Velit_euismod_in_pellentesque_massa._Diam_sit_amet_nisl_suscipit_adipiscing_bibendum_est_ultricies._Dignissim_diam_quis_enim_lobortis_scelerisque_fermentum_dui_faucibus_in._Magna_fermentum_iaculis_eu_non_diam._Sit_amet_nisl_suscipit_adipiscing_bibendum_est_ultricies._Elementum_pulvinar_etiam_non_quam_lacus_suspendisse_faucibus_interdum._Interdum_velit_euismod_in_pellentesque_massa_placerat_duis_ultricies._Tellus_cras_adipiscing_enim_eu._Pellentesque_habitant_morbi_tristique_senectus_et_netus._Odio_ut_enim_blandit_volutpat_maecenas._Ut_lectus_arcu_bibendum_at_varius_vel_pharetra_vel_turpis._Tempor_orci_eu_lobortis_elementum_nibh_tellus._Orci_ac_auctor_augue_mauris._Vestibulum_lorem_sed_risus_ultricies_tristique_nulla_aliquet_enim_tortor._Tristique_senectus_et_netus_et_malesuada_fames_ac_turpis._Sapien_eget_mi_proin_sed_libero_enim._Dolor_sit_amet_consectetur_adipiscing_elit_pellentesque_habitant_morbi_tristique._Aliquam_sem_et_tortor_consequat_id_porta.__Leo_urna_molestie_at_elementum._Semper_risus_in_hendrerit_gravida_rutrum_quisque_non._Facilisi_etiam_dignissim_diam_quis_enim._Et_magnis_dis_parturient_montes_nascetur_ridiculus_mus_mauris._Placerat_in_egestas_erat_imperdiet_sed_euismod_nisi_porta_lorem._Integer_quis_auctor_elit_sed_vulputate_mi_sit_amet._Sem_integer_vitae_justo_eget._Eros_donec_ac_odio_tempor_orci_dapibus_ultrices_in._Massa_enim_nec_dui_nunc_mattis_enim._Elit_pellentesque_habitant_morbi_tristique_senectus_et_netus_et._Id_leo_in_vitae_turpis_massa_sed_elementum_tempus_egestas._Hendrerit_dolor_magna_eget_est._Accumsan_in_nisl_nisi_scelerisque_eu._Turpis_egestas_integer_eget_aliquet_nibh_praesent_tristique_magna_sit._Commodo_ullamcorper_a_lacus_vestibulum._Nascetur_ridiculus_mus_mauris_vitae_ultricies_leo_integer._Consequat_semper_viverra_nam_libero.__Sem_et_tortor_consequat_id_porta_nibh_venenatis_cras_sed._Ornare_lectus_sit_amet_est_placerat_in_egestas_erat._Ultrices_neque_ornare_aenean_euismod_elementum_nisi_quis._Augue_lacus_viverra_vitae_congue_eu_consequat_ac_felis._Erat_imperdiet_sed_euismod_nisi_porta_lorem._Proin_fermentum_leo_vel_orci._Pellentesque_diam_volutpat_commodo_sed_egestas_egestas_fringilla._Praesent_elementum_facilisis_leo_vel_fringilla_est_ullamcorper_eget._Adipiscing_commodo_elit_at_imperdiet_dui._Adipiscing_elit_pellentesque_habitant_morbi_tristique_senectus_et_netus._Sit_amet_venenatis_urna_cursus_eget_nunc._Egestas_integer_eget_aliquet_nibh._Facilisis_magna_etiam_tempor_orci_eu_lobortis_elementum_nibh_tellus.";

	std::string expected_cmdline = expected_comm + " " +
				       expected_arg_1 + " " +
				       expected_arg_2 + " " +
				       expected_arg_3 + " " +
				       expected_arg_4 + " " +
				       expected_arg_5;

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	const int expected_connections_size = 1;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.arg(expected_arg_4)
		.arg(expected_arg_5)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c = audit_pb->connections(0);

	// checking is_client_only connection
	ASSERT_EQ(c.client_port(), expected_sport);
	ASSERT_EQ(c.server_port(), expected_dport);
	ASSERT_EQ(c.client_ipv4(), ip_string_to_le(expected_sip));
	ASSERT_EQ(c.server_ipv4(), ip_string_to_le(expected_dip));
	ASSERT_EQ(c.l4_protocol(), IP_PROTO_TCP);

	if(expected_error_code == 0)
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_ESTABLISHED);
	}
	else
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_FAILED);
	}

	ASSERT_EQ(c.error_code(), expected_error_code);
	ASSERT_EQ(c.timestamp(), ts);
	ASSERT_EQ(c.client_pid(), expected_pid);
	ASSERT_EQ(c.comm(), expected_comm);
	ASSERT_EQ(c.container_id(), expected_container_id);
	ASSERT_EQ(c.cmdline(), expected_cmdline);

	// maxlen - 20
	std::string expected_cmdline_substring;

	audit.clear();
	audit.c_secure_audit_connections_cmdline_maxlen.set(20);
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c20 = audit_pb->connections(0);

	expected_cmdline_substring = expected_cmdline.substr(0, 20);
	ASSERT_EQ(c20.cmdline(), expected_cmdline_substring);

	// maxlen - 150
	audit.clear();
	audit.c_secure_audit_connections_cmdline_maxlen.set(150);
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c150 = audit_pb->connections(0);

	expected_cmdline_substring = expected_cmdline.substr(0, 150);
	ASSERT_EQ(c150.cmdline(), expected_cmdline_substring);

	// maxlen - len+50
	audit.clear();

	int cmdline_len = expected_cmdline.length();

	audit.c_secure_audit_connections_cmdline_maxlen.set(cmdline_len + 50);
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& cp50 = audit_pb->connections(0);

	//expected_cmdline_substring = expected_cmdline.substr (0,150);
	ASSERT_EQ(cp50.cmdline(), expected_cmdline);
}

TEST(secure_audit_test, k8s_audit_base)
{
	// Instantiate secure_audit
	secure_audit audit;

	// Dummy k8s audit events
	std::string exec_1_str = R"EOF(
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "f330b164-7758-40e5-a930-910aba3b62f1",
  "stage": "ResponseStarted",
  "requestURI": "/api/v1/namespaces/sysdigcloud/pods/sysdigcloud-elasticsearch-0/exec?command=bash&container=elasticsearch&container=elasticsearch&stdin=true&stdout=true&tty=true",
  "verb": "create",
  "user": {
    "username": "kubernetes-admin",
    "groups": [
      "system:masters",
      "system:authenticated"
    ]
  },
  "sourceIPs": [
    "172.31.76.57"
  ],
  "userAgent": "kubectl/v1.13.5 (linux/amd64) kubernetes/2166946",
  "objectRef": {
    "resource": "pods",
    "namespace": "sysdigcloud",
    "name": "sysdigcloud-elasticsearch-0",
    "apiVersion": "v1",
    "subresource": "exec"
  },
  "responseStatus": {
    "metadata": {},
    "code": 101
  },
  "requestReceivedTimestamp": "2019-10-09T09:27:23.963881Z",
  "stageTimestamp": "2019-10-09T09:27:23.983028Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": ""
  }
}
)EOF";

	std::string exec_2_str = R"EOF(
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "f330b164-7758-40e5-a930-910aba3b62f1",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/sysdigcloud/pods/sysdigcloud-elasticsearch-0/exec?command=bash&container=elasticsearch&container=elasticsearch&stdin=true&stdout=true&tty=true",
  "verb": "create",
  "user": {
    "username": "kubernetes-admin",
    "groups": [
      "system:masters",
      "system:authenticated"
    ]
  },
  "sourceIPs": [
    "172.31.76.57"
  ],
  "userAgent": "kubectl/v1.13.5 (linux/amd64) kubernetes/2166946",
  "objectRef": {
    "resource": "pods",
    "namespace": "sysdigcloud",
    "name": "sysdigcloud-elasticsearch-0",
    "apiVersion": "v1",
    "subresource": "exec"
  },
  "responseStatus": {
    "metadata": {},
    "code": 101
  },
  "requestReceivedTimestamp": "2019-10-09T09:27:23.963881Z",
  "stageTimestamp": "2019-10-09T09:27:29.677189Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": ""
  }
}
)EOF";

	std::string audit_1_str = R"EOF(
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "a5e4aeb1-0e94-4a64-a855-d8078da69b14",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/services?resourceVersion=1646487&timeout=8m5s&timeoutSeconds=485&watch=true",
  "verb": "watch",
  "user": {
    "username": "system:apiserver",
    "uid": "a7eabae4-bdae-43e3-bff3-372ac588bae0",
    "groups": [
      "system:masters"
    ]
  },
  "sourceIPs": [
    "::1"
  ],
  "userAgent": "kube-apiserver/v1.13.10 (linux/amd64) kubernetes/37d1693",
  "objectRef": {
    "resource": "services",
    "apiVersion": "v1"
  },
  "responseStatus": {
    "metadata": {},
    "code": 200
  },
  "requestReceivedTimestamp": "2019-10-09T09:19:19.234150Z",
  "stageTimestamp": "2019-10-09T09:27:24.234636Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": ""
  }
}
)EOF";

	std::string audit_2_str = R"EOF(
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "e1b258d4-aa58-4ae1-b2ca-e86af8ce7d03",
  "stage": "ResponseStarted",
  "requestURI": "/api/v1/services?resourceVersion=1646487&timeout=7m50s&timeoutSeconds=470&watch=true",
  "verb": "watch",
  "user": {
    "username": "system:apiserver",
    "uid": "a7eabae4-bdae-43e3-bff3-372ac588bae0",
    "groups": [
      "system:masters"
    ]
  },
  "sourceIPs": [
    "::1"
  ],
  "userAgent": "kube-apiserver/v1.13.10 (linux/amd64) kubernetes/37d1693",
  "objectRef": {
    "resource": "services",
    "apiVersion": "v1"
  },
  "responseStatus": {
    "metadata": {},
    "code": 200
  },
  "requestReceivedTimestamp": "2019-10-09T09:27:24.235190Z",
  "stageTimestamp": "2019-10-09T09:27:24.235427Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": ""
  }
}
)EOF";

	json json_exec_1 = json::parse(exec_1_str);
	json json_exec_2 = json::parse(exec_2_str);

	json json_audit_1 = json::parse(audit_1_str);
	json json_audit_2 = json::parse(audit_2_str);

	// Enable k8s_audit
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_k8s_audit_enabled.set(true);

	// Create configuration with exec filter
	std::vector<std::string> m_secure_audit_k8s_active_filters;
	std::unordered_map<std::string, std::unordered_map<std::string, std::string>> m_secure_audit_k8s_filters;

	m_secure_audit_k8s_active_filters.push_back("exec");

	std::unordered_map<std::string, std::string> map_tmp({{"/verb", "create"},
							      {"/objectRef/resource", "pods"},
							      {"/objectRef/subresource", "exec"}});

	m_secure_audit_k8s_filters["exec"] = map_tmp;

	ASSERT_EQ(m_secure_audit_k8s_active_filters[0], "exec");
	ASSERT_EQ(m_secure_audit_k8s_filters.find("exec")->second["/verb"], "create");
	ASSERT_EQ(m_secure_audit_k8s_filters.find("exec")->second["/objectRef/resource"], "pods");
	ASSERT_EQ(m_secure_audit_k8s_filters.find("exec")->second["/objectRef/subresource"], "exec");

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	// add add events
	audit.filter_and_append_k8s_audit(json_audit_1, m_secure_audit_k8s_active_filters, m_secure_audit_k8s_filters);
	audit.filter_and_append_k8s_audit(json_audit_2, m_secure_audit_k8s_active_filters, m_secure_audit_k8s_filters);

	audit.filter_and_append_k8s_audit(json_exec_1, m_secure_audit_k8s_active_filters, m_secure_audit_k8s_filters);
	audit.filter_and_append_k8s_audit(json_exec_2, m_secure_audit_k8s_active_filters, m_secure_audit_k8s_filters);

	audit.emit_k8s_exec_audit();

	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->k8s_audits_size(), 2);

	const secure::K8sAudit& k1 = audit_pb->k8s_audits(0);
	const secure::K8sAudit& k2 = audit_pb->k8s_audits(1);

	ASSERT_EQ(k1.blob(), json_exec_1.dump());
	ASSERT_EQ(k2.blob(), json_exec_2.dump());

	audit.clear();
}

TEST(secure_audit_test, k8s_audit_disabled)
{
	// Instantiate secure_audit
	secure_audit audit;

	// Dummy k8s audit events
	std::string exec_1_str = R"EOF(
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "f330b164-7758-40e5-a930-910aba3b62f1",
  "stage": "ResponseStarted",
  "requestURI": "/api/v1/namespaces/sysdigcloud/pods/sysdigcloud-elasticsearch-0/exec?command=bash&container=elasticsearch&container=elasticsearch&stdin=true&stdout=true&tty=true",
  "verb": "create",
  "user": {
    "username": "kubernetes-admin",
    "groups": [
      "system:masters",
      "system:authenticated"
    ]
  },
  "sourceIPs": [
    "172.31.76.57"
  ],
  "userAgent": "kubectl/v1.13.5 (linux/amd64) kubernetes/2166946",
  "objectRef": {
    "resource": "pods",
    "namespace": "sysdigcloud",
    "name": "sysdigcloud-elasticsearch-0",
    "apiVersion": "v1",
    "subresource": "exec"
  },
  "responseStatus": {
    "metadata": {},
    "code": 101
  },
  "requestReceivedTimestamp": "2019-10-09T09:27:23.963881Z",
  "stageTimestamp": "2019-10-09T09:27:23.983028Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": ""
  }
}
)EOF";
	json json_exec_1 = json::parse(exec_1_str);

	// Create configuration with exec filter
	std::vector<std::string> m_secure_audit_k8s_active_filters;
	std::unordered_map<std::string, std::unordered_map<std::string, std::string>> m_secure_audit_k8s_filters;

	m_secure_audit_k8s_active_filters.push_back("exec");

	std::unordered_map<std::string, std::string> map_tmp({{"/verb", "create"},
							      {"/objectRef/resource", "pods"},
							      {"/objectRef/subresource", "exec"}});

	m_secure_audit_k8s_filters["exec"] = map_tmp;

	// Disable k8s_audit
	audit.c_secure_audit_enabled.set(false);
	audit.c_secure_audit_k8s_audit_enabled.set(true);

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.filter_and_append_k8s_audit(json_exec_1, m_secure_audit_k8s_active_filters, m_secure_audit_k8s_filters);
	audit.emit_k8s_exec_audit();

	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(nullptr, audit_pb);

	// Disable k8s_audit
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_k8s_audit_enabled.set(false);

	audit.filter_and_append_k8s_audit(json_exec_1, m_secure_audit_k8s_active_filters, m_secure_audit_k8s_filters);
	audit.emit_k8s_exec_audit();

	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(nullptr, audit_pb);

	// Disable k8s_audit
	audit.c_secure_audit_enabled.set(false);
	audit.c_secure_audit_k8s_audit_enabled.set(false);

	audit.filter_and_append_k8s_audit(json_exec_1, m_secure_audit_k8s_active_filters, m_secure_audit_k8s_filters);
	audit.emit_k8s_exec_audit();

	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(nullptr, audit_pb);
}

class test_helper
{
public:
	static internal_metrics::sptr_t get_internal_metrics(sinsp_analyzer* analyzer)
	{
		return analyzer->m_internal_metrics;
	}
};

TEST(secure_audit_test, audit_frequency_default)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_only_interactive.set(false);
	// frequency set to 10 by default
	//audit.c_secure_audit_frequency->set(10);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	// Building inspector and analyzer
	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	// Building threadinfo
	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	// Set analyzer
	audit.set_data_handler(&analyzer);
	audit.set_internal_metrics(&analyzer);
	// We don't need connection manager for this test
	audit.init(nullptr);

	// Flush with no data -> no protobuf emitted
	audit.flush(ts);
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// put a connection into secure audit buffer
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush before frequency
	audit.flush(ts + (uint64_t)5000000000); // ts + 5 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// Try to flush few ms before frequency -> test threshold of 100ms
	audit.flush(ts + (uint64_t)10000000000 - (uint64_t)90000000); // ts + 10 s - 90ms
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);
}

TEST(secure_audit_test, audit_frequency_5)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_only_interactive.set(false);
	audit.c_secure_audit_frequency->set(5);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	// Building inspector and analyzer
	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	// Building threadinfo
	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	// Set analyzer
	audit.set_data_handler(&analyzer);
	audit.set_internal_metrics(&analyzer);
	// We don't need connection manager for this test
	audit.init(nullptr);

	// Flush with no data -> no protobuf emitted
	audit.flush(ts);
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// put a connection into secure audit buffer
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush before frequency
	audit.flush(ts + (uint64_t)4000000000); // ts + 4 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// Try to flush few ms before frequency -> test threshold of 100ms
	audit.flush(ts + (uint64_t)5000000000 - (uint64_t)90000000); // ts + 5 s - 90ms
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush few seconds after frequency
	audit.flush(ts + (uint64_t)6000000000); // ts + 6 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// Try to flush ~2 times freq
	audit.flush(ts + (uint64_t)10000000000); // ts + 10 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);
}

TEST(secure_audit_test, audit_frequency_out_of_limits_lower)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_only_interactive.set(false);

	std::string yaml_config_str = R"EOF(
secure_audit_streams:
  frequency: -1
)EOF";

	yaml_configuration yaml_conf(yaml_config_str);
	audit.c_secure_audit_frequency->init(yaml_conf);

	// Check the min to be applied
	ASSERT_EQ(audit.c_secure_audit_frequency->get_value(), 1);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	// Building inspector and analyzer
	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	// Building threadinfo
	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	// Set analyzer
	audit.set_data_handler(&analyzer);
	audit.set_internal_metrics(&analyzer);
	// We don't need connection manager for this test
	audit.init(nullptr);

	// Flush with no data -> no protobuf emitted
	audit.flush(ts);
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// put a connection into secure audit buffer
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush before frequency
	audit.flush(ts + (uint64_t)500000000); // ts + 0.5 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// Try to flush few ms before frequency -> test threshold of 100ms
	audit.flush(ts + (uint64_t)1000000000 - (uint64_t)90000000); // ts + 1 s - 90ms
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush few seconds after frequency
	audit.flush(ts + (uint64_t)1500000000); // ts + 1.5 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// Try to flush ~2 times freq
	audit.flush(ts + (uint64_t)2000000000); // ts + 2 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);
}

TEST(secure_audit_test, audit_frequency_out_of_limits_upper)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_enabled.set(true);

	// 90 * 60 = 5400
	// 30 * 60 = 1800
	std::string yaml_config_str = R"EOF(
secure_audit_streams:
  frequency: 5400
)EOF";

	yaml_configuration yaml_conf(yaml_config_str);
	audit.c_secure_audit_frequency->init(yaml_conf);

	// Check the max limit to be applied
	ASSERT_EQ(audit.c_secure_audit_frequency->get_value(), 1800);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	// Building inspector and analyzer
	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	// Building threadinfo
	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	// Set analyzer
	audit.set_data_handler(&analyzer);
	audit.set_internal_metrics(&analyzer);
	// We don't need connection manager for this test
	audit.init(nullptr);

	// Flush with no data -> no protobuf emitted
	audit.flush(ts);
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// put a connection into secure audit buffer
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush before frequency
	audit.flush(ts + (uint64_t)20000000000); // ts + 20 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// Try to flush few ms before frequency -> test threshold of 100ms
	// Upperbound limit is 30 min -> 30 * 60
	audit.flush(ts + (uint64_t)1000000000 * (uint64_t)(30 * 60) - (uint64_t)90000000); // ts + 30 min - 90ms
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush few seconds after frequency
	audit.flush(ts + (uint64_t)1000000000 * (uint64_t)(31 * 60)); // ts + 31 min
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);

	// Try to flush ~2 times freq
	audit.flush(ts + (uint64_t)1000000000 * (uint64_t)(60 * 60)); // ts + 60 min
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);
}

TEST(secure_audit_test, audit_internal_metrics)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_only_interactive.set(false);
	// frequency set to 10 by default
	audit.c_secure_audit_frequency->set(10);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	// Building inspector and analyzer
	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	// Building threadinfo
	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_spid = expected_pid;
	conn.m_stid = expected_pid;
	conn.m_sfd = 1234;

	conn.m_dpid = 0;
	conn.m_dtid = 0;
	conn.m_dfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_sproc = proc;
	conn.m_dproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	// Set analyzer
	audit.set_data_handler(&analyzer);
	audit.set_internal_metrics(&analyzer);
	// We don't need connection manager for this test
	audit.init(nullptr);

	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), -1);
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_fl_ms(), -1);
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_emit_ms(), -1);

	// Flush with no data -> no protobuf emitted
	audit.flush(ts);
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);
	ASSERT_NE(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_fl_ms(), -1);

	// put a connection into secure audit buffer
	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Try to flush before frequency
	audit.flush(ts + (uint64_t)5000000000); // ts + 5 s
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 0);
	ASSERT_NE(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_fl_ms(), -1);

	// Try to flush few ms before frequency -> test threshold of 100ms
	audit.flush(ts + (uint64_t)11000000000 - (uint64_t)90000000); // ts + 10 s - 90ms
	ASSERT_EQ(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_n_sent_protobufs(), 1);
	ASSERT_NE(test_helper::get_internal_metrics(&analyzer)->get_secure_audit_fl_ms(), -1);
}

TEST(secure_audit_test, connections_base_server_only_interactive)
{
	// Secure Audit
	secure_audit audit;
	audit.c_secure_audit_connections_only_interactive.set(true);
	audit.c_secure_audit_enabled.set(true);
	audit.c_secure_audit_connections_enabled.set(true);
	audit.c_secure_audit_connections_cmdline.set(false);

	// Build Thread Info
	const int64_t expected_pid = 4;
	const std::string expected_name = "/usr/bin/gcc";
	const std::string expected_comm = "gcc";
	const std::string expected_arg_1 = "-o";
	const std::string expected_arg_2 = "a.out";
	const std::string expected_arg_3 = "hello_world.cpp";

	const std::string expected_sip = "192.168.1.1";
	const std::string expected_dip = "192.168.1.2";
	const uint16_t expected_sport = 80;
	const uint16_t expected_dport = 90;
	const uint8_t expected_l4proto = SCAP_L4_TCP;

	const uint32_t expected_error_code = 0;
	const std::string expected_container_id = "sysd1gcl0ud1";

	const int expected_connections_size = 1;

	std::unique_ptr<sinsp_mock> inspector(new sinsp_mock);
	internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
	sinsp_analyzer analyzer(inspector.get(),
				"/" /*root dir*/,
				int_metrics,
				g_audit_handler,
				g_secure_handler,
				&g_queue);
	unique_ptr_resetter<sinsp_mock> resetter(inspector);
	inspector->m_analyzer = &analyzer;

	(void)inspector->build_thread().commit();
	inspector->build_thread()
		.pid(expected_pid)
		.comm("gcc")
		.exe(expected_name)
		.arg(expected_arg_1)
		.arg(expected_arg_2)
		.arg(expected_arg_3)
		.commit();

	inspector->open();

	std::shared_ptr<sinsp_threadinfo> proc = nullptr;
	proc = inspector->get_thread_ref(expected_pid,
					 false /*don't query the os if not found*/,
					 true /*lookup only*/);

	proc->m_container_id = expected_container_id;

	// Set process as interactive
	sinsp_threadinfo* main_thread = proc->get_main_thread();
	ASSERT_NE(main_thread, nullptr);
	ASSERT_NE(main_thread->m_ainfo, nullptr);
	main_thread->m_ainfo->m_th_analysis_flags |= thread_analyzer_info::flags::AF_IS_INTERACTIVE_COMMAND;

	// Sanity checks for Thread Info
	ASSERT_EQ(expected_pid, proc->m_pid);
	ASSERT_EQ(expected_pid, proc->m_tid);
	ASSERT_EQ(expected_name, proc->m_exe);
	ASSERT_EQ(expected_comm, proc->get_comm());
	ASSERT_EQ(expected_container_id, proc->m_container_id);

	_ipv4tuple tuple;
	sinsp_connection conn;
	uint64_t ts = sinsp_utils::get_current_time_ns();

	// Build Tuple
	tuple.m_fields.m_sip = ip_string_to_be(expected_sip);
	tuple.m_fields.m_sport = expected_sport;
	tuple.m_fields.m_dip = ip_string_to_be(expected_dip);
	tuple.m_fields.m_dport = expected_dport;
	tuple.m_fields.m_l4proto = expected_l4proto;

	// Build Connection
	conn.m_dpid = expected_pid;
	conn.m_dtid = expected_pid;
	conn.m_dfd = 1234;

	conn.m_spid = 0;
	conn.m_stid = 0;
	conn.m_sfd = 0;

	conn.m_timestamp = ts;
	conn.m_refcount = 1;

	conn.m_analysis_flags = sinsp_connection::AF_NONE;
	conn.m_error_code = expected_error_code;

	conn.m_dproc = proc;
	conn.m_sproc = nullptr;

	// Test empty protobuf
	const secure::Audit* audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());
	ASSERT_EQ(audit_pb, nullptr);

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_NE(nullptr, audit_pb);

	ASSERT_EQ(audit_pb->connections_size(), expected_connections_size);
	const secure::Connection& c = audit_pb->connections(0);

	// checking is_client_only connection
	ASSERT_EQ(c.client_port(), expected_sport);
	ASSERT_EQ(c.server_port(), expected_dport);
	ASSERT_EQ(c.client_ipv4(), ip_string_to_le(expected_sip));
	ASSERT_EQ(c.server_ipv4(), ip_string_to_le(expected_dip));
	ASSERT_EQ(c.l4_protocol(), IP_PROTO_TCP);

	if(expected_error_code == 0)
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_ESTABLISHED);
	}
	else
	{
		ASSERT_EQ(c.status(), secure::ConnectionStatus::CONNECTION_STATUS_FAILED);
	}

	ASSERT_EQ(c.error_code(), expected_error_code);
	ASSERT_EQ(c.timestamp(), ts);
	ASSERT_EQ(c.server_pid(), expected_pid);
	ASSERT_EQ(c.comm(), expected_comm);
	ASSERT_EQ(c.container_id(), expected_container_id);
	ASSERT_EQ(c.cmdline(), "");

	audit.clear();

	// send a connection with no INTERACTIVE tinfo commands
	main_thread->m_ainfo->m_th_analysis_flags &= ~thread_analyzer_info::flags::AF_IS_INTERACTIVE_COMMAND;

	audit.emit_connection_async(tuple, conn, std::move(sinsp_connection::state_transition(ts, conn.m_analysis_flags, conn.m_error_code)));

	// Get pb
	audit_pb = audit.get_events(sinsp_utils::get_current_time_ns());

	ASSERT_EQ(nullptr, audit_pb);
}
