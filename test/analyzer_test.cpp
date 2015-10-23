#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define VISIBILITY_PRIVATE

#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <list>
#include <cassert>
#include <event.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/inotify.h>

#include <sinsp.h>
#include <sinsp_int.h>
#include <sinsp_errno.h>
#include "sinsp.h"
#include "sinsp_int.h"
#include "parsers.h"
#include "connectinfo.h"
#include "metrics.h"
#include "analyzer.h"
#include "delays.h"
#include "analyzer_thread.h"
#include "analyzer_fd.h"
#include <sys/prctl.h>
#include <signal.h>

using namespace std;

using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;

TEST_F(sys_call_test, analyzer_errors)
{
//	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		char* const* pnt1 = NULL;
		char* pnt2 = NULL;

		FILE* f = fopen("/nonexistent", "r");	// generates ENOENT
		f = fopen("/nonexistent", "r");
		f = fopen("/nonexistent", "r");
		f = fopen("/nonexistent", "r");
		f = fopen("/nonexistent", "r");
		EXPECT_EQ(NULL, f);	// just to avoid the compiler from emitting a warning
		close(3333); // generates EBADF
		close(3333);
		close(3333);
		execve(pnt2, pnt1, pnt1); // generates EFAULT
		execve(pnt2, pnt1, pnt1);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if(e->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(e->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				sinsp_error_counters* ec = &param.m_inspector->m_analyzer->m_host_metrics.m_syscall_errors;

				EXPECT_LE((size_t)10, ec->m_count);
				EXPECT_LE((size_t)5, ec->m_count_file);
				EXPECT_LE((size_t)5, ec->m_count_file_open);
				EXPECT_LE((size_t)0, ec->m_count_net);

				sinsp_threadinfo* tinfo = param.m_inspector->find_thread_test(getpid(), true);
				ec = &tinfo->m_ainfo->m_dynstate->m_syscall_errors;

				EXPECT_LE((size_t)10, ec->m_count);
				EXPECT_LE((size_t)5, ec->m_count_file);
				EXPECT_LE((size_t)5, ec->m_count_file_open);
				EXPECT_LE((size_t)0, ec->m_count_net);
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

//	EXPECT_EQ(7, callnum);
}

TEST_F(sys_call_test, analyzer_procrename)
{

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	int child_pid = 0;

	child_pid = fork();

	if (child_pid == 0)
	{
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		// We need another executable to change both procname and cmdline
		// Also we have a clean environment without gtest, analyzer etc stuff loaded
		execl("./resources/chname", "chname", NULL);
	}

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		// Wait a bit so the first flush will be executed
		usleep(1500*1000);
		getuid();
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if(e->get_type() == PPME_SYSCALL_GETUID_X)
		{
			auto* thread_table = param.m_inspector->m_thread_manager->get_threads();
			ASSERT_NE(thread_table->end(), thread_table->find(child_pid));
			const auto& tinfo = thread_table->find(child_pid)->second;
			EXPECT_EQ("savonarola", tinfo.m_comm);
			EXPECT_EQ("sysdig", tinfo.m_exe);
			EXPECT_FALSE(tinfo.m_args.empty());
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	kill(child_pid, SIGTERM);
	waitpid(child_pid, NULL, 0);
}

TEST_F(sys_call_test, analyzer_fdstats)
{
	bool found = false;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int fd;
		ssize_t res;

		inspector->m_sysdig_pid = 0;

		fd = open("/tmp/nonexistent", O_RDONLY);
		EXPECT_EQ(-1, fd);

		for(uint32_t j = 0; j < 10; ++j)
		{
			fd = open("/tmp/testfile_opencount", O_RDWR | O_CREAT, 0666);
			EXPECT_LT(0, fd);
			close(fd);
		}

		fd = open("/tmp/testfile_rdwr", O_RDWR | O_CREAT, 0666);
		EXPECT_LT(0, fd);
		res = write(fd, "token1", sizeof("token1"));
		EXPECT_EQ(sizeof("token1"), (uint64_t) res);
		res = write(fd, "token1", sizeof("token1"));
		EXPECT_EQ(sizeof("token1"), (uint64_t) res);
		res = write(fd, "token1", sizeof("token1"));
		EXPECT_EQ(sizeof("token1"), (uint64_t) res);
		res = write(fd, "token1", sizeof("token1"));
		EXPECT_EQ(sizeof("token1"), (uint64_t) res);
		res = write(fd, "token1", sizeof("token1"));
		EXPECT_EQ(sizeof("token1"), (uint64_t) res);
		close(fd);

		fd = open("/tmp/testfile_rdwr", O_RDONLY);
		EXPECT_LT(0, fd);
		char buf[512];
		res = read(fd, buf, sizeof(buf));
		EXPECT_EQ(5 * sizeof("token1"), (uint64_t) res);
		close(fd);

		res = renameat(0, "/tmp/testfile_rdwr", 0, "/tmp/testfile_rdonly");
		EXPECT_EQ(0, res);

		fd = open("/tmp/testfile_rdonly", O_RDONLY);
		EXPECT_LT(0, fd);
		res = write(fd, "token1", sizeof("token1"));
		EXPECT_EQ(-1, res);
		close(fd);

		// We use a random call to tee to signal that we're done
		tee(-1, -1, 0, 0);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;

		if(e->get_type() == PPME_GENERIC_E)
		{
			if(NumberParser::parse(e->get_param_value_str("ID", false)) == PPM_SC_TEE)
			{
				found = true;

				unordered_map<string, analyzer_file_stat>* files_stat = 
					&param.m_inspector->m_analyzer->m_fd_listener->m_files_stat;

				EXPECT_NE((uint64_t) 0, files_stat->size());

				unordered_map<string, analyzer_file_stat>::const_iterator it;

				it = files_stat->find("/tmp/nonexistent");
				EXPECT_NE(files_stat->end(), it);
				EXPECT_EQ((uint64_t) 0, it->second.m_time_ns);
				EXPECT_EQ((uint64_t) 0, it->second.m_bytes);
				EXPECT_EQ((uint64_t) 1, it->second.m_errors);
				EXPECT_EQ((uint64_t) 0, it->second.m_open_count);

				it = files_stat->find("/tmp/testfile_opencount");
				EXPECT_NE(files_stat->end(), it);
				EXPECT_EQ((uint64_t) 0, it->second.m_time_ns);
				EXPECT_EQ((uint64_t) 0, it->second.m_bytes);
				EXPECT_EQ((uint64_t) 0, it->second.m_errors);
				EXPECT_EQ((uint64_t) 10, it->second.m_open_count);

				it = files_stat->find("/tmp/testfile_rdwr");
				EXPECT_NE(files_stat->end(), it);
				EXPECT_NE((uint64_t) 0, it->second.m_time_ns);
				EXPECT_EQ(10 * sizeof("token1"), it->second.m_bytes);
				EXPECT_EQ((uint64_t) 0, it->second.m_errors);
				EXPECT_EQ((uint64_t) 2, it->second.m_open_count);

				it = files_stat->find("/tmp/testfile_rdonly");
				EXPECT_NE(files_stat->end(), it);
				EXPECT_EQ((uint64_t) 0, it->second.m_time_ns);
				EXPECT_EQ((uint64_t) 0, it->second.m_bytes);
				EXPECT_EQ((uint64_t) 1, it->second.m_errors);
				EXPECT_EQ((uint64_t) 1, it->second.m_open_count);
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_TRUE(found);
}

TEST_F(sys_call_test, client_transaction_pruning1)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(2200, 2300, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning2)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1200, 1300, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning3)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(2200, 2300, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1200, 1300, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][0].m_flags);
	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][1].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning4)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning5)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1000, 1100, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning6)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1100, 2000, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning7)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(500, 700, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning8)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(4100, 4500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning9)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(4000, 4500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning10)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(3900, 4500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning11)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(900, 1500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning12)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1500, 3500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

///////////////////////////////////////

TEST_F(sys_call_test, client_transaction_pruning13)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(2200, 2300, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning14)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1200, 1300, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning15)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(2200, 2300, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1200, 1300, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][0].m_flags);
	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][1].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning16)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning17)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1000, 1100, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning18)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1100, 2000, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning19)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(500, 700, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning20)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(4100, 4500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning21)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(4000, 4500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning22)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(3900, 4500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning23)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(900, 1500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning24)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(1000, 2000, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(3000, 4000, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(1500, 3500, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning25)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(30, 40, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(10, 50, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(5, 7, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning26)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(30, 40, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(10, 50, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(5, 15, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning27)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(30, 40, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(10, 50, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(5, 60, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning28)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[1].push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(30, 40, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(10, 50, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(25, 27, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(43, 47, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(5, 15, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][1].m_flags);
	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][2].m_flags);
}

TEST_F(sys_call_test, client_transaction_pruning29)
{
	vector<vector<sinsp_trlist_entry>> client_tr = vector<vector<sinsp_trlist_entry>>(2);
	vector<vector<sinsp_trlist_entry>> server_tr = vector<vector<sinsp_trlist_entry>>(2);

	server_tr[0].push_back(sinsp_trlist_entry(10, 50, sinsp_trlist_entry::FL_NONE));
	server_tr[1].push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	server_tr[0].push_back(sinsp_trlist_entry(30, 40, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(25, 27, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(43, 47, sinsp_trlist_entry::FL_NONE));
	client_tr[0].push_back(sinsp_trlist_entry(5, 15, sinsp_trlist_entry::FL_NONE));

	sinsp_delays::prune_client_transactions(&client_tr, &server_tr);

	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_FILTERED_OUT, client_tr[0][0].m_flags);
	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][1].m_flags);
	EXPECT_EQ((int32_t)sinsp_trlist_entry::FL_NONE, client_tr[0][2].m_flags);
}

TEST_F(sys_call_test, transaction_merging1)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(20, 30, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)20, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)30, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging2)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 25, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(20, 30, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)20, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)30, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging3)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 30, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)20, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)30, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging4)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(9, 30, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)21, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)9, result[0].m_stime);
	EXPECT_EQ((uint64_t)30, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging5)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(20, 30, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(30, 40, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(40, 50, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)40, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)50, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging6)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 19, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(20, 29, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(30, 39, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(40, 49, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)36, sum);
	EXPECT_EQ((uint64_t)4, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)19, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging7)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(40, 49, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(20, 29, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 19, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(30, 39, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)36, sum);
	EXPECT_EQ((uint64_t)4, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)19, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging8)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)10, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)20, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging9)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 30, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 40, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 50, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)40, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)50, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging10)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(15, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 30, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 40, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(20, 50, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)40, sum);
	EXPECT_EQ((uint64_t)1, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)50, result[0].m_etime);
}

TEST_F(sys_call_test, transaction_merging11)
{
	vector<sinsp_trlist_entry> tr;
	vector<sinsp_trlist_entry> result;

	tr.push_back(sinsp_trlist_entry(10, 20, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(10, 25, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(30, 40, sinsp_trlist_entry::FL_NONE));
	tr.push_back(sinsp_trlist_entry(27, 50, sinsp_trlist_entry::FL_NONE));

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result, true);

	EXPECT_EQ((uint64_t)38, sum);
	EXPECT_EQ((uint64_t)2, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)25, result[0].m_etime);
}
