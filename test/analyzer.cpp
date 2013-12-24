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

				EXPECT_NE((size_t)0, ec->m_table.size());

				EXPECT_LE((uint32_t)5, ec->m_table[SE_ENOENT].m_count);
				EXPECT_LE((uint32_t)3, ec->m_table[SE_EBADF].m_count);
				EXPECT_LE((uint32_t)2, ec->m_table[SE_EFAULT].m_count);

				sinsp_threadinfo* tinfo = param.m_inspector->m_thread_manager->get_thread(getpid());
				ec = &tinfo->m_ainfo->m_procinfo->m_syscall_errors;

				EXPECT_NE((size_t)0, ec->m_table.size());

				EXPECT_LE((uint32_t)5, ec->m_table[SE_ENOENT].m_count);
				EXPECT_LE((uint32_t)3, ec->m_table[SE_EBADF].m_count);
				EXPECT_LE((uint32_t)2, ec->m_table[SE_EFAULT].m_count);

				map<int32_t, sinsp_counter_cnt>::iterator it;
				uint32_t j = 0;
				for(it = ec->m_table.begin(); it != ec->m_table.end(); ++it, j++)
				{
					if(j == 0)
					{
						EXPECT_EQ((int32_t)SE_ENOENT, it->first);
					}
					else if(j == 1)
					{
						EXPECT_EQ((int32_t)SE_EBADF, it->first);
					}
					else if(j == 2)
					{
						EXPECT_EQ((int32_t)SE_EFAULT, it->first);
					}
					else
					{
						break;
					}
				}

				EXPECT_LE((uint32_t)3, j);
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

//	EXPECT_EQ(7, callnum);
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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

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

	uint64_t sum = sinsp_delays::merge_transactions(&tr, &result);

	EXPECT_EQ((uint64_t)38, sum);
	EXPECT_EQ((uint64_t)2, result.size());
	EXPECT_EQ((uint64_t)10, result[0].m_stime);
	EXPECT_EQ((uint64_t)25, result[0].m_etime);
}
