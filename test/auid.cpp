#include <istream>
#include <string>
#include <memory>

#include <sys/types.h>
#include <pwd.h>
#include <sys/syscall.h>

#include <sinsp.h>
#include <sinsp_int.h>
#include "sys_call_test.h"

using namespace std;

TEST_F(sys_call_test, auid)
{
	shared_ptr<sinsp_evt_formatter> userinfo_fmt;
	string expected_userinfo;
	int64_t loginuid;
	uid_t uid;
	struct passwd *user;
	bool saw_socket_event = false;

	// Get uid and name
	uid = getuid();
	expected_userinfo = to_string(uid);
	user = getpwuid(uid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += string(" ") + user->pw_name;

	// Separately find out loginuid
	ifstream lfile("/proc/self/loginuid");
	ASSERT_TRUE(lfile.is_open());
	lfile >> loginuid;

	expected_userinfo += string(" ") + to_string(loginuid);
	user = getpwuid(loginuid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += string(" ") +  user->pw_name;

	// FILTER
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	// TEST CODE
	run_callback_t test = [&](sinsp* inspector)
	{
		if(!userinfo_fmt)
		{
			userinfo_fmt = make_shared<sinsp_evt_formatter>(inspector, string("%user.uid %user.name %user.loginuid %user.loginname"));
		}

		int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
		close(fd);
	};

	// OUTPUT VALDATION
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		string actual_userinfo;
		sinsp_evt* evt = param.m_evt;

		if(strcmp(evt->get_name(), "socket") == 0)
		{
			userinfo_fmt->tostring(evt, &actual_userinfo);
			ASSERT_STREQ(expected_userinfo.c_str(), actual_userinfo.c_str());
			saw_socket_event=true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	ASSERT_TRUE(saw_socket_event);
};

TEST_F(sys_call_test, auid_through_exec)
{
	shared_ptr<sinsp_evt_formatter> userinfo_fmt;
	string expected_userinfo;
	int64_t loginuid;
	uid_t uid;
	struct passwd *user;
	sinsp_filter_compiler compiler(NULL, string("evt.type=execve and evt.dir=< and proc.name=ls and proc.apid=") + to_string(getpid()));
	shared_ptr<sinsp_filter> spawned_by_test(compiler.compile());
	bool saw_execve = false;

	// Get uid and name
	uid = getuid();
	expected_userinfo = to_string(uid);
	user = getpwuid(uid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += string(" ") + user->pw_name;

	// Separately find out loginuid
	ifstream lfile("/proc/self/loginuid");
	ASSERT_TRUE(lfile.is_open());
	lfile >> loginuid;

	expected_userinfo += string(" ") + to_string(loginuid);
	user = getpwuid(loginuid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += string(" ") +  user->pw_name;

	// FILTER
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return spawned_by_test->run(evt);
	};

	// TEST CODE
	run_callback_t test = [&](sinsp* inspector)
	{
		if(!userinfo_fmt)
		{
			userinfo_fmt = make_shared<sinsp_evt_formatter>(inspector, string("%user.uid %user.name %user.loginuid %user.loginname"));
		}

		ASSERT_EQ(system("ls > /dev/null 2>&1"), 0);
	};

	// OUTPUT VALDATION
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		string actual_userinfo;
		sinsp_evt* evt = param.m_evt;

		if(strcmp(evt->get_name(), "execve") == 0)
		{
			userinfo_fmt->tostring(evt, &actual_userinfo);
			ASSERT_STREQ(expected_userinfo.c_str(), actual_userinfo.c_str());
			saw_execve = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	ASSERT_TRUE(saw_execve);
};

TEST_F(sys_call_test, auid_sudo_nobody)
{
	shared_ptr<sinsp_evt_formatter> userinfo_fmt;
	string expected_userinfo;
	int64_t loginuid;
	uid_t uid;
	struct passwd *user;
	sinsp_filter_compiler compiler(NULL, string("evt.type=execve and evt.dir=< and proc.name=ls and proc.apid=") + to_string(getpid()));
	shared_ptr<sinsp_filter> spawned_by_test(compiler.compile());
	bool saw_execve = false;

	// This depends on a user "nobody" existing.
	user = getpwnam("nobody");

	if(user == NULL)
	{
		printf("Skipping test, user \"nobody\" does not exist.\n");
		return;
	}

	// Get uid and name
	uid = user->pw_uid;
	expected_userinfo = to_string(uid);
	expected_userinfo += string(" ") + user->pw_name;

	// Separately find out loginuid
	ifstream lfile("/proc/self/loginuid");
	ASSERT_TRUE(lfile.is_open());
	lfile >> loginuid;

	expected_userinfo += string(" ") + to_string(loginuid);
	user = getpwuid(loginuid);
	ASSERT_TRUE(user != NULL);
	expected_userinfo += string(" ") +  user->pw_name;

	// FILTER
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return spawned_by_test->run(evt);
	};

	// TEST CODE
	run_callback_t test = [&](sinsp* inspector)
	{
		if(!userinfo_fmt)
		{
			userinfo_fmt = make_shared<sinsp_evt_formatter>(inspector, string("%user.uid %user.name %user.loginuid %user.loginname"));
		}

		ASSERT_EQ(system("sudo -u nobody ls > /dev/null 2>&1"), 0);
	};

	// OUTPUT VALDATION
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		string actual_userinfo;
		sinsp_evt* evt = param.m_evt;

		if(strcmp(evt->get_name(), "execve") == 0)
		{
			userinfo_fmt->tostring(evt, &actual_userinfo);
			ASSERT_STREQ(expected_userinfo.c_str(), actual_userinfo.c_str());
			saw_execve = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	ASSERT_TRUE(saw_execve);
};
