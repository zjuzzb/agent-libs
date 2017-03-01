#define VISIBILITY_PRIVATE

#include <iostream>

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <sinsp.h>
#include <sinsp_int.h>

#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <sys/uio.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <Poco/Path.h>
#include <list>
#include <cassert>

using namespace std;
using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;
using Poco::Path;

#define DATA "josephine"

#define FILENAME "test_tmpfile"
#define DIRNAME "test_tmpdir"
#define UNEXISTENT_DIRNAME "/unexistent/pippo"

/////////////////////////////////////////////////////////////////////////////////////
// creat/unlink
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_creat_ulink)
{
	int callnum = 0;
	char bcwd[1024];

	if(getcwd(bcwd, 1024));
	string cwd(bcwd);
	cwd += "/";


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
		int fd = creat(FILENAME, O_WRONLY);

		if(fd < 0)
		{
			FAIL();
		}

		if(write(fd, "fica", sizeof("fica")));
		close(fd);
		unlink(FILENAME);
		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_CREAT_E)
		{
			callnum++;
		}
		else if(type == PPME_SYSCALL_CREAT_X)
		{
			if(callnum == 1)
			{
				string fname = e->get_param_value_str("name", false);
				if(fname == FILENAME)
				{
					EXPECT_EQ("0", e->get_param_value_str("mode"));
				}

				EXPECT_LT(0, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_UNLINK_E)
		{
			if(callnum == 2 || callnum == 4)
			{
				EXPECT_EQ(FILENAME, e->get_param_value_str("path", false));
				EXPECT_EQ(cwd + FILENAME, e->get_param_value_str("path"));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_UNLINK_X)
		{
			if(callnum == 3)
			{
				EXPECT_LE(0, NumberParser::parse(e->get_param_value_str("res", false)));
				callnum++;
			}
			else if(callnum == 5)
			{
				EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(6, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// link/linkat/unlinkat
/////////////////////////////////////////////////////////////////////////////////////
#define FILENAME1 FILENAME "1"
#define FILENAME2 FILENAME "2"

TEST_F(sys_call_test, fs_link)
{
	int callnum = 0;
	char bcwd[1024];
	int dirfd;

	getcwd(bcwd, 1024);
	string cwd(bcwd);
	cwd += "/";


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
		int fd = creat(FILENAME, O_WRONLY);

		if(fd < 0)
		{
			FAIL();
		}

		if(write(fd, "fica", sizeof("fica")));
		close(fd);

		if(link(FILENAME, FILENAME1) != 0)
		{
			FAIL();
		}

		dirfd = open(".", O_DIRECTORY);
		if(dirfd <= 0)
		{
			FAIL();
		}
		
		if(linkat(dirfd, FILENAME, dirfd, FILENAME2, 0) != 0)
		{
			FAIL();
		}

		if(unlinkat(dirfd, FILENAME, 0) != 0)
		{
			FAIL();
		}

		if(unlinkat(dirfd, FILENAME, 0) == 0)
		{
			FAIL();
		}

		if(unlinkat(dirfd, FILENAME1, 0) != 0)
		{
			FAIL();
		}

		if(unlinkat(dirfd, FILENAME2, 0) != 0)
		{
			FAIL();
		}

		close(dirfd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_LINK_E)
		{
			EXPECT_EQ(FILENAME, e->get_param_value_str("oldpath", false));
			EXPECT_EQ(FILENAME1, e->get_param_value_str("newpath", false));
			callnum++;
		}
		else if(type == PPME_SYSCALL_LINK_X)
		{
			if(callnum == 1)
			{
				EXPECT_EQ("0", e->get_param_value_str("res"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_LINKAT_E)
		{
			if(callnum == 2)
			{
				EXPECT_EQ(dirfd, NumberParser::parse(e->get_param_value_str("olddir", false)));
				EXPECT_EQ(string("<d>") + bcwd, e->get_param_value_str("olddir"));				
				EXPECT_EQ(FILENAME, e->get_param_value_str("oldpath"));

				EXPECT_EQ(dirfd, NumberParser::parse(e->get_param_value_str("newdir", false)));
				EXPECT_EQ(string("<d>") + bcwd, e->get_param_value_str("newdir"));				
				EXPECT_EQ(FILENAME2, e->get_param_value_str("newpath"));

				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_LINKAT_X)
		{
			if(callnum == 3)
			{
				EXPECT_EQ("0", e->get_param_value_str("res"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_UNLINKAT_E)
		{
			if(callnum == 4)
			{
				EXPECT_EQ(dirfd, NumberParser::parse(e->get_param_value_str("dirfd", false)));
				EXPECT_EQ(string("<d>") + bcwd, e->get_param_value_str("dirfd"));				
				EXPECT_EQ(FILENAME, e->get_param_value_str("name"));

				callnum++;
			}
			else if(callnum == 6)
			{
				EXPECT_EQ(dirfd, NumberParser::parse(e->get_param_value_str("dirfd", false)));
				EXPECT_EQ(string("<d>") + bcwd, e->get_param_value_str("dirfd"));				
				EXPECT_EQ(FILENAME, e->get_param_value_str("name"));

				callnum++;
			}
			else if(callnum == 8)
			{
				EXPECT_EQ(dirfd, NumberParser::parse(e->get_param_value_str("dirfd", false)));
				EXPECT_EQ(string("<d>") + bcwd, e->get_param_value_str("dirfd"));				
				EXPECT_EQ(FILENAME1, e->get_param_value_str("name"));

				callnum++;
			}
			else if(callnum == 10)
			{
				EXPECT_EQ(dirfd, NumberParser::parse(e->get_param_value_str("dirfd", false)));
				EXPECT_EQ(string("<d>") + bcwd, e->get_param_value_str("dirfd"));				
				EXPECT_EQ(FILENAME2, e->get_param_value_str("name"));

				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_UNLINKAT_X)
		{
			if(callnum == 5 || callnum == 9 || callnum == 11)
			{
				EXPECT_EQ("0", e->get_param_value_str("res"));
				callnum++;
			}
			else if(callnum == 7)
			{
				EXPECT_NE("0", e->get_param_value_str("res"));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(12, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// mkdir/rmdir
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_mkdir_rmdir)
{
	int callnum = 0;
	char bcwd[1024];

	getcwd(bcwd, 1024);
	string cwd(bcwd);
	cwd += "/";


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
		mkdir(UNEXISTENT_DIRNAME, 0);
		
		if(mkdir(DIRNAME, 0) != 0)
		{
			FAIL();
		}

		if(rmdir(DIRNAME) != 0)
		{
			FAIL();
		}

		if(rmdir(DIRNAME) == 0)
		{
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_MKDIR_2_E)
		{
			if(callnum == 0)
			{
				EXPECT_EQ("0", e->get_param_value_str("mode"));
				callnum++;
			}
			else
			{
				if(callnum == 2)
				{
					EXPECT_EQ("0", e->get_param_value_str("mode"));
					callnum++;
				}
			}
		}
		else if(type == PPME_SYSCALL_MKDIR_2_X)
		{
			if(callnum == 1)
			{
			        EXPECT_NE("0", e->get_param_value_str("res"));
				EXPECT_EQ(UNEXISTENT_DIRNAME, e->get_param_value_str("path"));
				EXPECT_EQ(UNEXISTENT_DIRNAME, e->get_param_value_str("path", false));
				callnum++;
			}
			else if(callnum == 3)
			{
			        EXPECT_EQ("0", e->get_param_value_str("res"));
			        EXPECT_EQ(cwd + DIRNAME, e->get_param_value_str("path"));
				EXPECT_EQ(DIRNAME, e->get_param_value_str("path", false));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_RMDIR_2_E)
		{
			if(callnum == 4 || callnum == 6)
			{
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_RMDIR_2_X)
		{
			if(callnum == 5)
			{
				EXPECT_LE(0, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ(DIRNAME, e->get_param_value_str("path", false));
				EXPECT_EQ(cwd + DIRNAME, e->get_param_value_str("path"));
				callnum++;
			}
			else if(callnum == 7)
			{
				EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ(DIRNAME, e->get_param_value_str("path", false));
				EXPECT_EQ(cwd + DIRNAME, e->get_param_value_str("path"));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(8, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// openat
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_openat)
{
	int callnum = 0;
	char bcwd[1024];
	int dirfd;
	int fd1;
	int fd2;

	getcwd(bcwd, 1024);
	string cwd(bcwd);
	cwd += "/";

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
		dirfd = open(".", O_DIRECTORY);
		if(dirfd <= 0)
		{
			FAIL();
		}
		
		//
		// Generate a pagefault to make sure openat_enter doesn't
		// get dropped because FILENAME is not available in memory
		//
		string s = FILENAME;
		fd1 = openat(dirfd, FILENAME, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
		if(fd1 <= 0)
		{
			FAIL();
		}

		write(fd1, DATA, sizeof(DATA));

		close(fd1);
		close(dirfd);

		unlink(FILENAME);

		fd2 = openat(AT_FDCWD, FILENAME, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
		if(fd2 <= 0)
		{
			FAIL();
		}

		close(fd2);
		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_OPENAT_E)
		{
			if(callnum == 0)
			{
				EXPECT_EQ(dirfd, NumberParser::parse(e->get_param_value_str("dirfd", false)));
				EXPECT_EQ(string("<d>") + bcwd, e->get_param_value_str("dirfd"));			
				callnum++;
			}
			else if(callnum == 2)
			{
				EXPECT_EQ(-100, NumberParser::parse(e->get_param_value_str("dirfd", false)));
				callnum++;
			}

			EXPECT_EQ(FILENAME, e->get_param_value_str("name"));
		}
		else if(type == PPME_SYSCALL_OPENAT_X)
		{
			if(callnum == 1)
			{
				EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
			else if(callnum == 3)
			{
				EXPECT_EQ(fd2, NumberParser::parse(e->get_param_value_str("fd", false)));				
				callnum++;
			}

			EXPECT_EQ(string("<f>") + cwd + FILENAME, e->get_param_value_str("fd"));
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// pread/pwrite
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_pread)
{
	int callnum = 0;
	char buf[32];
	int fd;
	int fd1;
	bool pwrite64_succeeded;

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
		fd = creat(FILENAME, S_IRWXU);
		if(fd < 0)
		{
			FAIL();
		}

		write(fd, "ficafica", sizeof("ficafica") - 1);
		pwrite(fd, "cazo", sizeof("cazo") - 1, 4);
		ssize_t bytes_sent = pwrite64(fd, "cazo", sizeof("cazo") - 1, 987654321987654);
		//
		// On NFS, pwrite64 succeeds, so the test must evaluate the return
		// code in the proper way
		//
		pwrite64_succeeded = bytes_sent > 0;

		pread64(fd, buf, 32, 1234567891234);
		close(fd);

		fd1 = open(FILENAME, O_RDONLY);
		if(fd1 < 0)
		{
			FAIL();
		}

		pread(fd1, buf, 4, 4);

		close(fd1);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_WRITE_E)
		{
			if(NumberParser::parse(e->get_param_value_str("fd", false)) == fd)
			{
				EXPECT_EQ((int)sizeof("ficafica") - 1, NumberParser::parse(e->get_param_value_str("size", false)));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_WRITE_X)
		{
			if(callnum == 1)
			{
				EXPECT_EQ((int)sizeof("ficafica") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("ficafica", e->get_param_value_str("data"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_PWRITE_E)
		{
			if(NumberParser::parse(e->get_param_value_str("fd", false)) == fd)
			{
				if(callnum == 2)
				{
					EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("size", false)));
					EXPECT_EQ("4", e->get_param_value_str("pos"));
					callnum++;
				}
				else
				{
					EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("size", false)));
					EXPECT_EQ("987654321987654", e->get_param_value_str("pos"));
					callnum++;
				}
			}
		}
		else if(type == PPME_SYSCALL_PWRITE_X)
		{
			if(callnum == 3)
			{
				EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("cazo", e->get_param_value_str("data"));
				callnum++;
			}
			else
			{
				if(pwrite64_succeeded)
				{
					EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				}
				else
				{
					EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
				}
				EXPECT_EQ("cazo", e->get_param_value_str("data"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_PREAD_E)
		{
			if(callnum == 6)
			{
				EXPECT_EQ("32", e->get_param_value_str("size"));
				EXPECT_EQ("1234567891234", e->get_param_value_str("pos"));
				callnum++;
			}
			else if(callnum == 8)
			{
				EXPECT_EQ("4", e->get_param_value_str("size"));
				EXPECT_EQ("4", e->get_param_value_str("pos"));
				callnum++;
			}
			else
			{
				FAIL();
			}
		}
		else if(type == PPME_SYSCALL_PREAD_X)
		{
			if(callnum == 7)
			{
				EXPECT_NE("0", e->get_param_value_str("res", false));
				callnum++;
			}
			else if(callnum == 9)
			{
				EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(10, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// writev/readv
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_readv)
{
	int callnum = 0;
	int fd;
	int fd1;
	int bytes_sent;

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
		int wv_count;
		char msg1[10] = "aaaaa";
		char msg2[10] = "bbbbb";
		char msg3[10] = "ccccc";
		struct iovec wv[3];
		int rres;

		fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);

		wv[0].iov_base = msg1;
		wv[1].iov_base = msg2;
		wv[2].iov_base = msg3;
		wv[0].iov_len  = strlen(msg1);
		wv[1].iov_len  = strlen(msg2);
		wv[2].iov_len  = strlen(msg3);
		wv_count = 3;
		
		bytes_sent = writev(fd, wv, wv_count);
		if(bytes_sent <= 0)
		{
			FAIL();
		}

		close(fd);

		fd1 = open(FILENAME, O_CREAT | O_RDONLY, S_IRWXU);

		wv[0].iov_len  = sizeof(msg1);
		wv[1].iov_len  = sizeof(msg2);
		wv[2].iov_len  = sizeof(msg3);

		rres = readv(fd1, wv, wv_count);
		if(rres <= 0)
		{
			FAIL();
		}

		close(fd1);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_WRITEV_E)
		{
			EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
			EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("size")));
			callnum++;
		}
		else if(type == PPME_SYSCALL_WRITEV_X)
		{
			if(callnum == 1)
			{
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_READV_E)
		{
			EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("fd", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_READV_X)
		{
			if(callnum == 3)
			{
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbbccccc", (e->get_param_value_str("data")).substr(0, 15));
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("size")));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// pwritev/preadv
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_preadv)
{
	int callnum = 0;
	int fd;
	int fd1;
	int bytes_sent;
	bool pwritev64_succeeded;

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
		int wv_count;
		char msg1[10] = "aaaaa";
		char msg2[10] = "bbbbb";
		char msg3[10] = "ccccc";
		struct iovec wv[3];
		int rres;
		fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);

		write(fd, "123456789012345678901234567890", sizeof("ficafica") - 1);

		wv[0].iov_base = msg1;
		wv[1].iov_base = msg2;
		wv[2].iov_base = msg3;
		wv[0].iov_len  = strlen(msg1);
		wv[1].iov_len  = strlen(msg2);
		wv[2].iov_len  = strlen(msg3);
		wv_count = 3;

		bytes_sent = pwritev64(fd, wv, wv_count, 132456789012345LL);
		//
		// On NFS, pwritev64 succeeds, so the test must evaluate the return
		// code in the proper way
		//
		pwritev64_succeeded = bytes_sent > 0;
		
		bytes_sent = pwritev(fd, wv, wv_count, 10);
		if(bytes_sent <= 0)
		{
			FAIL();
		}

		close(fd);

		fd1 = open(FILENAME, O_CREAT | O_RDONLY, S_IRWXU);

		wv[0].iov_len  = sizeof(msg1);
		wv[1].iov_len  = sizeof(msg2);
		wv[2].iov_len  = sizeof(msg3);

		rres = preadv64(fd1, wv, wv_count, 987654321098);

		rres = preadv(fd1, wv, wv_count, 10);
		if(rres <= 0)
		{
			FAIL();
		}

		close(fd1);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_PWRITEV_E)
		{
			if(callnum == 0)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("size")));
				EXPECT_EQ(132456789012345LL, NumberParser::parse64(e->get_param_value_str("pos")));
				callnum++;
			}
			else
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, NumberParser::parse(e->get_param_value_str("pos")));
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("size")));
				callnum++;				
			}
		}
		else if(type == PPME_SYSCALL_PWRITEV_X)
		{
			if(callnum == 1)
			{
				if(pwritev64_succeeded)
				{
					EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("res", false)));
				}
				else
				{
					EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
				}

				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				callnum++;
			}
			else
			{
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				callnum++;				
			}
		}
		else if(type == PPME_SYSCALL_PREADV_E)
		{
			if(callnum == 4)
			{
				EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(987654321098, NumberParser::parse64(e->get_param_value_str("pos")));
				callnum++;
			}
			else
			{
				EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, NumberParser::parse64(e->get_param_value_str("pos")));
				callnum++;				
			}
		}
		else if(type == PPME_SYSCALL_PREADV_X)
		{
			if(callnum == 3)
			{
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbb", e->get_param_value_str("data"));
				EXPECT_EQ(30, NumberParser::parse(e->get_param_value_str("size")));
				callnum++;
			}
		}

	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

//	EXPECT_EQ(4, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// dup
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_dup)
{
	int callnum = 0;
	int fd;
	int fd1;
	int fd2;
	int fd3;
	int fd4;
	int fd5;
	int fd6;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt) &&
				(evt->get_type() == PPME_SYSCALL_DUP_E || evt->get_type() == PPME_SYSCALL_DUP_X);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		fd = open(FILENAME, O_CREAT | O_WRONLY, 0);
		fd1 = dup(fd);
		fd2 = dup2(fd, 333);
		EXPECT_EQ(333, fd2);
		fd3 = dup2(fd, fd1);
		EXPECT_EQ(fd3, fd1);
		fd4 = dup3(fd3, 444, O_CLOEXEC);
		EXPECT_EQ(444, fd4);
		fd5 = dup2(-1, 33);
		EXPECT_EQ(-1, fd5);
		fd6 = dup2(fd, fd);
		EXPECT_EQ(fd6, fd);

		close(fd);
		close(fd1);
		close(fd2);
		close(fd3);
		close(fd4);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if(type == PPME_SYSCALL_DUP_E)
		{
			if(callnum == 0)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
			else if(callnum == 2)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;				
			}
			else if(callnum == 4)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;				
			}
			else if(callnum == 6)
			{
				EXPECT_EQ(fd3, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;				
			}
			else if(callnum == 8)
			{
#ifdef __x86_64__
				EXPECT_EQ("4294967295", e->get_param_value_str("fd", false));
#else
				EXPECT_EQ("-1", e->get_param_value_str("fd", false));
#endif
				callnum++;				
			}
			else if(callnum == 10)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;				
			}
		}
		else if(type == PPME_SYSCALL_DUP_X)
		{
			if(callnum == 1)
			{
				EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL, (sinsp_threadinfo*)param.m_inspector->get_thread(e->get_tid(), false, true)->get_fd(fd1));
				callnum++;
			}
			else if(callnum == 3)
			{
				EXPECT_EQ(fd2, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL, (sinsp_threadinfo*)param.m_inspector->get_thread(e->get_tid(), false, true)->get_fd(fd2));
				callnum++;
			}
			else if(callnum == 5)
			{
				EXPECT_EQ(fd3, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL, (sinsp_threadinfo*)param.m_inspector->get_thread(e->get_tid(), false, true)->get_fd(fd3));
				callnum++;
			}
			else if(callnum == 7)
			{
				EXPECT_EQ(fd4, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL, (sinsp_threadinfo*)param.m_inspector->get_thread(e->get_tid(), false, true)->get_fd(fd4));
				callnum++;
			}
			else if(callnum == 9)
			{
				EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ((sinsp_threadinfo*)NULL, (sinsp_threadinfo*)param.m_inspector->get_thread(e->get_tid(), false, true)->get_fd(fd5));
				callnum++;
			}
			else if(callnum == 11)
			{
				EXPECT_EQ(fd6, NumberParser::parse(e->get_param_value_str("res", false)));
				callnum++;				
			}
		}

	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(12, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// fcntl
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_fcntl)
{
	int callnum = 0;
	int fd;
	int fd1;
	int fd2;

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
		fd = open(FILENAME, O_CREAT | O_WRONLY, 0);
		fd1 = fcntl(fd, F_DUPFD);
		fd2 = fcntl(fd, F_DUPFD_CLOEXEC);

		close(fd);
		close(fd1);
		close(fd2);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_FCNTL_E)
		{
			if(callnum == 0)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
			else if(callnum == 2)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_FCNTL_X)
		{
			if(callnum == 1)
			{
				EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL, (sinsp_threadinfo*)param.m_inspector->get_thread(e->get_tid(), false, true)->get_fd(fd1));
				callnum++;
			}
			else if(callnum == 3)
			{
				EXPECT_EQ(fd2, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL, (sinsp_threadinfo*)param.m_inspector->get_thread(e->get_tid(), false, true)->get_fd(fd1));
				callnum++;
			}
		}

	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// sendfile
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_sendfile)
{
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;
	off_t offset = 0;

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
		struct stat stat_buf;

		read_fd = open ("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat (read_fd, &stat_buf);

		write_fd = open ("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = sendfile(write_fd, read_fd, &offset, size);
		EXPECT_LE(0, res);

		close (read_fd);
		close (write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E)
		{
			EXPECT_EQ(write_fd, NumberParser::parse(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, NumberParser::parse(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, NumberParser::parse(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_SENDFILE_X)
		{
			EXPECT_LE(0, NumberParser::parse(e->get_param_value_str("res", false)));
			EXPECT_EQ(offset, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fs_sendfile_nulloff)
{
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;

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
		struct stat stat_buf;

		read_fd = open ("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat (read_fd, &stat_buf);

		write_fd = open ("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = sendfile(write_fd, read_fd, NULL, size);
		EXPECT_LE(0, res);

		close (read_fd);
		close (write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E)
		{
			EXPECT_EQ(write_fd, NumberParser::parse(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, NumberParser::parse(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, NumberParser::parse(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_SENDFILE_X)
		{
			EXPECT_LE(0, NumberParser::parse(e->get_param_value_str("res", false)));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fs_sendfile_failed)
{
	int callnum = 0;
	//int size;

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
		int res = sendfile(-1, -2, NULL, 444);
		EXPECT_GT(0, res);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E)
		{
			EXPECT_NO_THROW({
#ifdef __x86_64__
				EXPECT_EQ("4294967295", e->get_param_value_str("out_fd", false));
				EXPECT_EQ("4294967294", e->get_param_value_str("in_fd", false));
#else
				EXPECT_EQ("-1", e->get_param_value_str("out_fd", false));
				EXPECT_EQ("-2", e->get_param_value_str("in_fd", false));
#endif
				EXPECT_EQ(444, NumberParser::parse(e->get_param_value_str("size", false)));
				EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			});

			callnum++;
		}
		else if(type == PPME_SYSCALL_SENDFILE_X)
		{
			EXPECT_NO_THROW({
				EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			});
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fs_sendfile_invalidoff)
{
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;

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
		struct stat stat_buf;

		read_fd = open ("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat (read_fd, &stat_buf);

		write_fd = open ("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = sendfile(write_fd, read_fd, (off_t*)3333, size);
		EXPECT_GT(0, res);

		close (read_fd);
		close (write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E)
		{
			EXPECT_EQ(write_fd, NumberParser::parse(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, NumberParser::parse(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, NumberParser::parse(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_SENDFILE_X)
		{
			EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(2, callnum);
}

#ifdef __i386__
TEST_F(sys_call_test, fs_sendfile64)
{
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;
	loff_t offset = 0;

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
		struct stat stat_buf;

		read_fd = open ("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat (read_fd, &stat_buf);

		write_fd = open ("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = syscall(SYS_sendfile64, write_fd, read_fd, &offset, size);
		EXPECT_LE(0, res);

		close (read_fd);
		close (write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E)
		{
			EXPECT_EQ(write_fd, NumberParser::parse(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, NumberParser::parse(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, NumberParser::parse(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
		else if(type == PPME_SYSCALL_SENDFILE_X)
		{
			EXPECT_LE(0, NumberParser::parse(e->get_param_value_str("res", false)));
			EXPECT_EQ(offset, NumberParser::parse(e->get_param_value_str("offset", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(2, callnum);
}
#endif

#ifdef __x86_64__
TEST_F(sys_call_test32, fs_pread)
{
	proc_started_filter test_started_filter;
	int callnum = 0;
	int fd = 3;
	bool pwrite64_succeeded = false;
	proc test_proc = proc("./test_helper_32", { "pread_pwrite"});
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		if(tinfo && tinfo->m_comm == "test_helper_32")
		{
			return test_started_filter(evt);
		}
		return false;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		Poco::PipeInputStream istr(*get<1>(handle));
		string buf;
		int bool_n = 0;
		istr >> bool_n;
		pwrite64_succeeded = (bool_n == 1);
		get<0>(handle).wait();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_WRITE_E)
		{
			if(NumberParser::parse(e->get_param_value_str("fd", false)) == fd)
			{
				EXPECT_EQ((int)sizeof("ficafica") - 1, NumberParser::parse(e->get_param_value_str("size", false)));
				callnum++;
			}
		}
		else if(type == PPME_SYSCALL_WRITE_X)
		{
			if(callnum == 1)
			{
				EXPECT_EQ((int)sizeof("ficafica") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("ficafica", e->get_param_value_str("data"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_PWRITE_E)
		{
			if(NumberParser::parse(e->get_param_value_str("fd", false)) == fd)
			{
				if(callnum == 2)
				{
					EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("size", false)));
					EXPECT_EQ("4", e->get_param_value_str("pos"));
					callnum++;
				}
				else
				{
					EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("size", false)));
					EXPECT_EQ("987654321", e->get_param_value_str("pos"));
					callnum++;
				}
			}
		}
		else if(type == PPME_SYSCALL_PWRITE_X)
		{
			if(callnum == 3)
			{
				EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("cazo", e->get_param_value_str("data"));
				callnum++;
			}
			else
			{
				if(pwrite64_succeeded)
				{
					EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				}
				else
				{
					EXPECT_GT(0, NumberParser::parse(e->get_param_value_str("res", false)));
				}
				EXPECT_EQ("cazo", e->get_param_value_str("data"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_PREAD_E)
		{
			if(callnum == 6)
			{
				EXPECT_EQ("32", e->get_param_value_str("size"));
				EXPECT_EQ("987654321", e->get_param_value_str("pos"));
				callnum++;
			}
			else if(callnum == 8)
			{
				EXPECT_EQ("4", e->get_param_value_str("size"));
				EXPECT_EQ("4", e->get_param_value_str("pos"));
				callnum++;
			}
			else
			{
				FAIL();
			}
		}
		else if(type == PPME_SYSCALL_PREAD_X)
		{
			if(callnum == 7)
			{
				EXPECT_NE("0", e->get_param_value_str("res", false));
				callnum++;
			}
			else if(callnum == 9)
			{
				EXPECT_EQ((int)sizeof("cazo") - 1, NumberParser::parse(e->get_param_value_str("res", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(10, callnum);
}

TEST_F(sys_call_test32, fs_preadv)
{
	int callnum = 0;
	int fd = 3;
	int fd1 = 3;
	bool pwritev64_succeeded;
	bool pwritev64_succeeded2;
	proc test_proc = proc("./test_helper_32", { "preadv_pwritev"});
	proc_started_filter test_started_filter;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		if(tinfo && tinfo->m_comm == "test_helper_32")
		{
			return test_started_filter(evt);
		}
		return false;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		Poco::PipeInputStream istr(*get<1>(handle));
		string buf;
		int bool_n = 0;
		istr >> bool_n;
		pwritev64_succeeded = (bool_n == 1);
		bool_n = 0;
		istr >> bool_n;
		pwritev64_succeeded2 = (bool_n == 1);
		get<0>(handle).wait();
	};

	int pwrite1_res, pwrite2_res;
	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_PWRITEV_E)
		{
			if(callnum == 0)
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("size")));
				EXPECT_EQ(987654321, NumberParser::parse64(e->get_param_value_str("pos")));
				callnum++;
			}
			else
			{
				EXPECT_EQ(fd, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, NumberParser::parse(e->get_param_value_str("pos")));
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("size")));
				callnum++;				
			}
		}
		else if(type == PPME_SYSCALL_PWRITEV_X)
		{
			if(callnum == 1)
			{
				pwrite1_res = NumberParser::parse(e->get_param_value_str("res", false));
				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				callnum++;
			}
			else
			{
				pwrite2_res = NumberParser::parse(e->get_param_value_str("res", false));
				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				callnum++;			
			}
		}
		else if(type == PPME_SYSCALL_PREADV_E)
		{
			if(callnum == 4)
			{
				EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(987654321, NumberParser::parse64(e->get_param_value_str("pos")));
				callnum++;
			}
			else
			{
				EXPECT_EQ(fd1, NumberParser::parse(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, NumberParser::parse64(e->get_param_value_str("pos")));
				callnum++;				
			}
		}
		else if(type == PPME_SYSCALL_PREADV_X)
		{
			if(callnum == 3)
			{
				EXPECT_EQ(15, NumberParser::parse(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbb", e->get_param_value_str("data"));
				EXPECT_EQ(30, NumberParser::parse(e->get_param_value_str("size")));
				callnum++;
			}
		}

	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	if(pwritev64_succeeded)
	{
		EXPECT_EQ(15, pwrite1_res);
	}
	else
	{
		EXPECT_GT(0, pwrite1_res);
	}
	if(pwritev64_succeeded2)
	{
		EXPECT_EQ(15, pwrite2_res);
	}
	else
	{
		EXPECT_EQ(-22, pwrite2_res);
	}
//	EXPECT_EQ(4, callnum);
}
#endif
