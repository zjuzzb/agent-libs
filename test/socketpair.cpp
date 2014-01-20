#define VISIBILITY_PRIVATE

#include <sinsp.h>
#include <sinsp_int.h>
#include <analyzer.h>
#include <connectinfo.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <list>
#include <cassert>
#include <sys/sem.h>

using namespace std;
using Poco::StringTokenizer;
using Poco::NumberFormatter;


#define DATA1 "vincenzino"
#define DATA2 "josefina"

TEST_F(sys_call_test, socketpair)
{
//	int callnum = 0;

	int ptid = 0;	// parent tid
	int ctid = 0;	// child tid
	bool connection_established = false;
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return ((evt->get_tid() == ctid) || (evt->get_tid() == ptid));
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int sockets[2];
		char buf[1024];
		int mutex;
		
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) 
		{
			perror("opening stream socket pair");
			return;
		}

		mutex = semget(1234, 1, IPC_CREAT | 0666);
		semctl(mutex, 0, SETVAL, 0);

		if((ctid = fork()) == -1)
		{
			perror("fork");
			return;
		}
		else if(ctid) 
		{     
			/* This is the parent. */
			ptid = getpid();

			close(sockets[0]);
			if(read(sockets[1], buf, 1024) < 0)
			{
				perror("reading stream message");
			}

			if (write(sockets[1], DATA2, sizeof(DATA2)) < 0)
			{
				perror("writing stream message");
			}

			usleep(200);
			close(sockets[1]);

			while (semctl(mutex, 0, GETVAL) == 0) ;
		} 
		else 
		{     

			close(sockets[1]);
			if (write(sockets[0], DATA1, sizeof(DATA1)) < 0)
			{
				perror("writing stream message");
			}
			if (read(sockets[0], buf, 1024) < 0)
			{
				perror("reading stream message");
			}

			usleep(200);
			close(sockets[0]);

			semctl(mutex, 0, SETVAL, 1);

			_exit(0);
		}
    };

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_unix_connection_manager::iterator_t it = param.m_inspector->m_analyzer->m_unix_connections->m_connections.begin();
		sinsp_unix_connection_manager::iterator_t end = param.m_inspector->m_analyzer->m_unix_connections->m_connections.end();
		while(it != end)
		{
			if(it->second.m_dtid == ptid && it->second.m_stid == ctid)
			{
				connection_established = true;
			}
			it++;
		}

	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(connection_established);
}
