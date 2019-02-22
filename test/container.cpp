#define VISIBILITY_PRIVATE

#include <sys/syscall.h>
#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <thread>
#include <list>
#include <fstream>
#include <sstream>
#include <cassert>
#include <memory>
#include <atomic>
#include "scap-int.h"
#include "docker_utils.h"

TEST_F(sys_call_test, container_cgroups)
{
	int ctid;
	bool done = false;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return evt->get_tid() == ctid;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		ctid = fork();

		if(ctid >= 0)
		{
			if(ctid == 0)
			{
				sleep(1);
				exit(0);
			}
			else
			{
				wait(NULL);
			}
		}
		else
		{
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if(param.m_evt->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			struct scap_threadinfo scap_tinfo;
			sinsp_threadinfo sinsp_tinfo;
			char buf[100];

			sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
			ASSERT_TRUE(tinfo != NULL);
			ASSERT_TRUE(tinfo->m_cgroups.size() > 0);

			snprintf(buf, sizeof(buf), "/proc/%d/", ctid);
			int32_t res = scap_proc_fill_cgroups(param.m_inspector->m_h, &scap_tinfo, buf);
			ASSERT_TRUE(res == SCAP_SUCCESS);

			sinsp_tinfo.set_cgroups(scap_tinfo.cgroups, scap_tinfo.cgroups_len);
			if(scap_tinfo.cgroups_len)
			{
				ASSERT_TRUE(sinsp_tinfo.m_cgroups.size() > 0);
			}

			map<string, string> cgroups_kernel;
			for(uint32_t j = 0; j < tinfo->m_cgroups.size(); ++j)
			{
				cgroups_kernel.insert(pair<string, string>(tinfo->m_cgroups[j].first, tinfo->m_cgroups[j].second));
			}

			map<string, string> cgroups_proc;
			for(uint32_t j = 0; j < sinsp_tinfo.m_cgroups.size(); ++j)
			{
				cgroups_proc.insert(pair<string, string>(sinsp_tinfo.m_cgroups[j].first, sinsp_tinfo.m_cgroups[j].second));
			}

			ASSERT_TRUE(cgroups_kernel.size() > 0);
			ASSERT_TRUE(cgroups_proc.size() > 0);

			for(auto& it_proc : cgroups_proc)
			{
				auto it_kernel = cgroups_kernel.find(it_proc.first);
				if(it_kernel != cgroups_kernel.end())
				{
					EXPECT_EQ(it_kernel->first, it_proc.first);
					EXPECT_EQ(it_kernel->second, it_proc.second);
				}
			}

			done = true;
		} else {
			printf("event type: %d != %d\n", param.m_evt->get_type(), PPME_SYSCALL_CLONE_20_X);
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

static int clone_callback_3(void *arg)
{
	sleep(1);
	sleep(1);
	sleep(1);
	sleep(1);
	sleep(1);
	return 0;
}

TEST_F(sys_call_test, container_clone_nspid)
{
	int ctid;
	int flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD | CLONE_NEWPID;
	bool done = false;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == ctid;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		const int STACK_SIZE = 65536;       /* Stack size for cloned child */
		char *stack;                        /* Start of stack buffer area */
		char *stack_top;                     /* End of stack buffer area */

		stack = (char*)malloc(STACK_SIZE);
		if(stack == NULL)
		{
		    FAIL();
		}
		stack_top = stack + STACK_SIZE;

		ctid = clone(clone_callback_3, stack_top, flags, NULL);
		if(ctid == -1)
		{
		    FAIL();
		}

		wait(NULL);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(e->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
			ASSERT_TRUE(tinfo != NULL);
			ASSERT_TRUE(tinfo->m_vtid == 1);
			ASSERT_TRUE(tinfo->m_vpid == 1);

			done = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_clone_nspid_ioctl)
{
	int ctid;
	int flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD | CLONE_NEWPID;
	bool done = false;

	const int STACK_SIZE = 65536;
	char *stack;
	char *stack_top;

	stack = (char*)malloc(STACK_SIZE);
	if(stack == NULL)
	{
	    FAIL();
	}
	stack_top = stack + STACK_SIZE;

	ctid = clone(clone_callback_3, stack_top, flags, NULL);
	if(ctid == -1)
	{
	    FAIL();
	}

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_tid() == ctid;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		wait(NULL);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		if(tinfo)
		{
			EXPECT_EQ(1, tinfo->m_vtid);
			EXPECT_EQ(1, tinfo->m_vpid);

			done = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_docker_netns_ioctl)
{
	bool done = false;
	bool first = true;

	if(system("service docker status > /dev/null 2>&1") != 0)
	{
		printf("Docker not running, skipping test\n");
		return;
	}

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return !tinfo->m_container_id.empty();
		}

		return false;
	};

	ASSERT_TRUE(system("docker kill ilovesysdig_docker > /dev/null 2>&1 || true") == 0);
	ASSERT_TRUE(system("docker rm -v ilovesysdig_docker > /dev/null 2>&1 || true") == 0);

#ifdef __s390x__
	if(system("docker run -d --name ilovesysdig_docker s390x/busybox ping -w 10 127.0.0.1") != 0)
#else
	if(system("docker run -d --name ilovesysdig_docker busybox ping -w 10 127.0.0.1") != 0)
#endif
	{
		ASSERT_TRUE(false);
	}

	sleep(2);

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		sleep(5);

		ASSERT_TRUE(system("docker kill ilovesysdig_docker > /dev/null 2>&1") == 0);
		ASSERT_TRUE(system("docker rm -v ilovesysdig_docker > /dev/null 2>&1") == 0);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if(e->get_type() == PPME_SOCKET_SENDTO_E)
		{
			string tuple = e->get_param_value_str("tuple");

			EXPECT_TRUE(tuple == "0.0.0.0:1->127.0.0.1:0");

			//
			// The first one doesn't have fd set
			//
			if(first)
			{
				first = false;
				return;
			}

			string fd = e->get_param_value_str("fd");
			EXPECT_TRUE(fd == "<4r>127.0.0.1->127.0.0.1");

			done = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_docker)
{
	bool done = false;

	if(system("service docker status > /dev/null 2>&1") != 0)
	{
		printf("Docker not running, skipping test\n");
		return;
	}

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return !tinfo->m_container_id.empty() &&
				tinfo->m_exe != "docker-runc" &&
				tinfo->m_exe != "runc";
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		ASSERT_TRUE(system("docker kill ilovesysdig_docker > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("docker rm -v ilovesysdig_docker > /dev/null 2>&1 || true") == 0);

#ifdef __s390x__
		if(system("docker run -d --name ilovesysdig_docker s390x/busybox") != 0)
#else
		if(system("docker run -d --name ilovesysdig_docker busybox") != 0)
#endif
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		ASSERT_TRUE(system("docker kill ilovesysdig_docker > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("docker rm -v ilovesysdig_docker > /dev/null 2>&1") == 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		ASSERT_TRUE(tinfo->m_container_id.length() == 12);

		const sinsp_container_info *container_info =
		        param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != NULL);

		EXPECT_EQ(sinsp_container_type::CT_DOCKER, container_info->m_type);
		EXPECT_EQ("ilovesysdig_docker", container_info->m_name);
#ifdef __s390x__
		EXPECT_EQ("s390x/busybox", container_info->m_image);
#else
		EXPECT_EQ("busybox", container_info->m_image);
#endif

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_custom)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container"});

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_exe == "/bin/echo" && !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_custom_env_match)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container"});

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_exe == "/bin/echo" && !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
			{ "CUSTOM_CONTAINER_NAME",  "custom_(.*)" },
		});
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_custom_env_match_last)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container"});

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_exe == "/bin/echo" && !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
			{ "CUSTOM_CONTAINER_IMAGE",  "custom_(.*)" },
		});
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_custom_env_match_all)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container"});

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_exe == "/bin/echo" && !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
			{ "CUSTOM_CONTAINER_NAME",  "custom_(.*)" },
			{ "CUSTOM_CONTAINER_IMAGE",  "custom_(.*)" }
		});
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_custom_env_match_flipped)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container"});

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_exe == "/bin/echo" && !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
			{ "CUSTOM_CONTAINER_IMAGE",  "custom_(.*)" },
			{ "CUSTOM_CONTAINER_NAME",  "custom_(.*)" }
		});
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_custom_halfnhalf)
{
	bool done = false;
	string container_name, container_image;
	proc test_proc = proc("./test_helper", { "custom_container", "halfnhalf" });

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_container_id == "foo";
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		container_name = container_info->m_name;
		container_image = container_info->m_image;

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_incremental_metadata(true);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});

	// we're building the metadata process by process, so we can only expect it to be complete at the end
	EXPECT_EQ("custom_name", container_name);
	EXPECT_EQ("custom_image", container_image);
	ASSERT_TRUE(done);
}

/// Test the happy path for large environment support
/// Loading the environment from /proc is racy but this process is a "sleep 1" so we should have plenty
/// of time to do it
TEST_F(sys_call_test, container_custom_huge_env)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container", "huge_env" });

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_container_id == "foo";
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
					      { "CUSTOM_CONTAINER_IMAGE",  "custom_(.*)" },
					      { "CUSTOM_CONTAINER_NAME",  "custom_(.*)" }
				      });
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));

		// enable reading environments from /proc
		inspector->set_large_envs(true);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

/// Run a fast process with a large environment, where the interesting variables are at the beginning
/// We don't read the environment from /proc in this test but we still should have the initial 4K available
TEST_F(sys_call_test, container_custom_huge_env_echo)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container", "huge_env_echo" });

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_container_id == "foo";
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
					      { "CUSTOM_CONTAINER_IMAGE",  "custom_(.*)" },
					      { "CUSTOM_CONTAINER_NAME",  "custom_(.*)" }
				      });
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

/// Run a fast process with a large environment, where the interesting variables are at the beginning
/// We'll (probably) fail to read the environment from /proc before the process exits
/// but we still should have the initial 4K available
TEST_F(sys_call_test, container_custom_huge_env_echo_proc)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container", "huge_env_echo" });

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_container_id == "foo";
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
					      { "CUSTOM_CONTAINER_IMAGE",  "custom_(.*)" },
					      { "CUSTOM_CONTAINER_NAME",  "custom_(.*)" }
				      });
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));

		// enable reading environments from /proc
		inspector->set_large_envs(true);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

/// Test that loading the environment from /proc actually works
/// Loading the environment from /proc is racy but this process is a "sleep 1" so we should have plenty
/// of time to do it. This test will fail if we only use the initial 4K of the environment
/// (the interesting variables are at the end of the environment)
/// An analogous test with a short-lived process (e.g. echo) will most probably fail
/// (we won't be able to read the environment before the process exits)
TEST_F(sys_call_test, container_custom_huge_env_at_end)
{
	bool done = false;
	proc test_proc = proc("./test_helper", { "custom_container", "huge_env_at_end" });

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return tinfo->m_container_id == "foo";
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ("foo", tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CUSTOM, container_info->m_type);
		EXPECT_EQ("custom_name", container_info->m_name);
		EXPECT_EQ("custom_image", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		custom_container::resolver res;
		res.set_cgroup_match("^/custom_container_(.*)");
		res.set_environ_match({
					      { "CUSTOM_CONTAINER_IMAGE",  "custom_(.*)" },
					      { "CUSTOM_CONTAINER_NAME",  "custom_(.*)" }
				      });
		res.set_id_pattern("<cgroup:1>");
		res.set_name_pattern("<CUSTOM_CONTAINER_NAME>");
		res.set_image_pattern("<CUSTOM_CONTAINER_IMAGE>");
		res.set_max(50);
		res.set_max_id_length(50);
		res.set_enabled(true);
		inspector->m_analyzer->set_custom_container_conf(move(res));

		// enable reading environments from /proc
		inspector->set_large_envs(true);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_rkt_after)
{
	bool done = false;

	if(system("rkt version > /dev/null 2>&1") != 0)
	{
		printf("rkt not installed, skipping test\n");
		return;
	}

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		if (std::ifstream("/tmp/myrkt"))
		{
			ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt stop > /dev/null") == 0);
			ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt rm > /dev/null") == 0);
		}

		int rc = system("rkt fetch --insecure-options=image docker://busybox");
		if (rc != 0)
		{
			ASSERT_TRUE(false);
		}

		rc = system("systemd-run rkt run --uuid-file-save=/tmp/myrkt docker://busybox --name=myrkt --exec=sleep -- 5");
		if (rc != 0)
		{
			ASSERT_TRUE(false);
		}

		sleep(10);

		ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt stop > /dev/null") == 0);
		ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt rm > /dev/null") == 0);
		remove("/tmp/myrkt");
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		if (tinfo->m_comm != "init")
		{
			ASSERT_NE(tinfo->m_vtid, tinfo->m_tid);
			ASSERT_NE(tinfo->m_vpid, tinfo->m_pid);
		}

		ASSERT_EQ(42u, tinfo->m_container_id.length()) << "container_id is " << tinfo->m_container_id;

		const sinsp_container_info *container_info =
		        param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != NULL);

		EXPECT_EQ(sinsp_container_type::CT_RKT, container_info->m_type);
		EXPECT_EQ("myrkt", container_info->m_name);
		EXPECT_EQ("registry-1.docker.io/library/busybox:latest", container_info->m_image);

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_rkt_before)
{
	bool done = false;

	if(system("rkt version > /dev/null 2>&1") != 0)
	{
		printf("rkt not installed, skipping test\n");
		return;
	}

	if (std::ifstream("/tmp/myrkt"))
	{
		ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt stop > /dev/null") == 0);
		ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt rm > /dev/null") == 0);
	}

	// start rkt before sysdig

	int rc = system("rkt fetch --insecure-options=image docker://busybox");
	if (rc != 0)
	{
		ASSERT_TRUE(false);
	}

	rc = system("systemd-run rkt run --uuid-file-save=/tmp/myrkt docker://busybox --name=myrkt --exec=sleep -- 5");
	if (rc != 0)
	{
		ASSERT_TRUE(false);
	}

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		// wait to be sure that rkt container is started and verified by the callback below
		sleep(10);

		ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt stop > /dev/null") == 0);
		ASSERT_TRUE(system("xargs -a /tmp/myrkt rkt rm > /dev/null") == 0);
		remove("/tmp/myrkt");
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		if (tinfo->m_comm != "init")
		{
			ASSERT_NE(tinfo->m_vtid, tinfo->m_tid);
			ASSERT_NE(tinfo->m_vpid, tinfo->m_pid);
		}

		ASSERT_EQ(42u, tinfo->m_container_id.length()) << "container_id is " << tinfo->m_container_id;

		const sinsp_container_info *container_info =
		        param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != NULL);

		EXPECT_EQ(sinsp_container_type::CT_RKT, container_info->m_type);
		EXPECT_EQ("myrkt", container_info->m_name);
		EXPECT_EQ("registry-1.docker.io/library/busybox:latest", container_info->m_image);

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, DISABLED_container_lxc)
{
	bool done = false;

	if(system("lxc-create --help > /dev/null 2>&1") != 0)
	{
		printf("LXC not installed, skipping test\n");
		return;
	}

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		ASSERT_TRUE(system("lxc-stop --name ilovesysdig_lxc > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("lxc-destroy --name ilovesysdig_lxc > /dev/null 2>&1 || true") == 0);

#ifdef __s390x__
		if(system("lxc-create -n ilovesysdig_lxc -t s390x/busybox") != 0)
#else
		if(system("lxc-create -n ilovesysdig_lxc -t busybox") != 0)
#endif
		{
			ASSERT_TRUE(false);
		}

		if(system("lxc-start -n ilovesysdig_lxc -d") != 0)
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		ASSERT_TRUE(system("lxc-stop --name ilovesysdig_lxc > /dev/null 2>&1") == 0);
		ASSERT_TRUE(system("lxc-destroy --name ilovesysdig_lxc > /dev/null 2>&1") == 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		ASSERT_TRUE(tinfo->m_container_id == "ilovesysdig_lxc");

		const sinsp_container_info *container_info =
		        param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != NULL);

		ASSERT_TRUE(container_info->m_type == sinsp_container_type::CT_LXC);
		ASSERT_TRUE(container_info->m_name == "ilovesysdig_lxc");
		ASSERT_TRUE(container_info->m_image.empty());

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_libvirt)
{
	bool done = false;

	if(system("virsh --help > /dev/null 2>&1") != 0)
	{
		printf("libvirt not installed, skipping test\n");
		return;
	}

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;
		if(tinfo)
		{
			return !tinfo->m_container_id.empty() && tinfo->m_comm == "sh";
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		FILE* f = fopen("/tmp/conf.xml", "w");
		ASSERT_TRUE(f != NULL);
		fprintf(f,
			"<domain type='lxc'>\n"
			"   <name>libvirt-container</name>\n"
			"   <memory>128000</memory>\n"
			"   <os>\n"
			"      <type>exe</type>\n"
			"      <init>/bin/sh</init>\n"
			"   </os>\n"
			"   <devices>\n"
			"      <console type='pty'/>\n"
			"   </devices>\n"
			"</domain>");
		fclose(f);

		ASSERT_TRUE(system("virsh -c lxc:/// undefine libvirt-container > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("virsh -c lxc:/// destroy libvirt-container > /dev/null 2>&1 || true") == 0);

		if(system("virsh -c lxc:/// define /tmp/conf.xml") != 0)
		{
			ASSERT_TRUE(false);
		}

		if(system("virsh -c lxc:/// start libvirt-container") != 0)
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		ASSERT_TRUE(system("virsh -c lxc:/// undefine libvirt-container > /dev/null 2>&1") == 0);
		ASSERT_TRUE(system("virsh -c lxc:/// destroy libvirt-container > /dev/null 2>&1") == 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		unsigned int lxc_id;
		ASSERT_TRUE(tinfo->m_container_id.find("libvirt\\x2dcontainer") != string::npos ||
		            sscanf(tinfo->m_container_id.c_str(), "lxc-%u-libvirt-container", &lxc_id) == 1);

		const sinsp_container_info *container_info =
		        param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != NULL);

		ASSERT_TRUE(container_info->m_type == sinsp_container_type::CT_LIBVIRT_LXC);
		ASSERT_TRUE(container_info->m_name == tinfo->m_container_id);
		ASSERT_TRUE(container_info->m_image.empty());

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, nsenterok)
{
	unsigned evtcount = 0;

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt) && (evt->get_type() == PPME_SYSCALL_SETNS_E || evt->get_type() == PPME_SYSCALL_SETNS_X);
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		nsenter enter(1, "net");
		try
		{
			nsenter enter(1, "uts");
			throw exception();
		} catch (const exception& ex)
		{
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		auto evt = param.m_evt;
		auto type = evt->get_type();
		switch(type)
		{
		case PPME_SYSCALL_SETNS_E:
			switch(evtcount)
			{
				case 0:
					EXPECT_EQ("<f>/proc/1/ns/net", evt->get_param_value_str("fd"));
					break;
				case 2:
					EXPECT_EQ("<f>/proc/1/ns/uts", evt->get_param_value_str("fd"));
					break;
				case 4:
					EXPECT_EQ(string("<f>/proc/") + to_string(getpid()) +"/ns/uts", evt->get_param_value_str("fd"));
					break;
				case 6:
					EXPECT_EQ(string("<f>/proc/") + to_string(getpid()) + "/ns/net", evt->get_param_value_str("fd"));
					break;
			}
			break;
		case PPME_SYSCALL_SETNS_X:
			switch(evtcount)
			{
				case 1:
					EXPECT_EQ("0", evt->get_param_value_str("res"));
					break;
				case 3:
					EXPECT_EQ("0", evt->get_param_value_str("res"));
					break;
				case 5:
					EXPECT_EQ("0", evt->get_param_value_str("res"));
					break;
				case 7:
					EXPECT_EQ("0", evt->get_param_value_str("res"));
					break;
			}
			break;
		}
		evtcount += 1;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_EQ(8u, evtcount);
}

TEST_F(sys_call_test, nsenter_fail)
{
	unsigned evtcount = 0;

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt) && (evt->get_type() == PPME_SYSCALL_SETNS_E || evt->get_type() == PPME_SYSCALL_SETNS_X);
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		EXPECT_THROW(nsenter enter(-1, "net"), sinsp_exception);
		EXPECT_THROW(nsenter enter(-1, "zzz"), sinsp_exception);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		evtcount += 1;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_EQ(0u, evtcount);
}

class container_state {
public:
	container_state() :
		container_w_healthcheck(false),
		root_cmd_seen(false),
		second_cmd_seen(false),
		healthcheck_seen(false) {};
	virtual ~container_state() {};

	bool container_w_healthcheck;
	bool root_cmd_seen;
	bool second_cmd_seen;
	bool healthcheck_seen;
};

static std::string capture_stats(sinsp *inspector)
{
	scap_stats st;
	inspector->get_capture_stats(&st);

	std::stringstream ss;

	ss << "capture stats: dropped=" << st.n_drops <<
		" buf=" << st.n_drops_buffer <<
		" pf=" << st.n_drops_pf <<
		" bug=" << st.n_drops_bug;

	return ss.str();
}

static void update_container_state(sinsp *inspector, sinsp_evt *evt, container_state &cstate)
{
	sinsp_threadinfo* tinfo = evt->m_tinfo;

	if(tinfo == NULL)
	{
		return;
	}

	const sinsp_container_info *container_info =
		inspector->m_container_manager.get_container(tinfo->m_container_id);

	if(container_info)
	{
		std::string cmdline;

		sinsp_threadinfo::populate_cmdline(cmdline, tinfo);

		if(container_info->m_has_healthcheck)
		{
			cstate.container_w_healthcheck = true;
		}

		// This is the container's initial command. In the test case
		// where the health check is the same command, we will see this
		// command twice--the first time it should not be identifieed as
		// a health check, and the second time it should.
		if(cmdline == "sh -c /bin/sleep 1")
		{
			if(!cstate.root_cmd_seen)
			{
				cstate.root_cmd_seen = true;
				ASSERT_FALSE(tinfo->m_is_container_healthcheck) << capture_stats(inspector);
			}
			else
			{
				ASSERT_TRUE(tinfo->m_is_container_healthcheck) << capture_stats(inspector);
				cstate.healthcheck_seen = true;
			}
		}

		// Child process of the above sh command. Same handling as above,
		// will see twice only when health check is same as root command.
		if(cmdline == "sleep 1")
		{
			if(!cstate.second_cmd_seen)
			{
				cstate.second_cmd_seen = true;
				ASSERT_FALSE(tinfo->m_is_container_healthcheck) << capture_stats(inspector);
			}
			else
			{
				// Should inherit container healthcheck property from parent.
				ASSERT_TRUE(tinfo->m_is_container_healthcheck) << capture_stats(inspector);
			}
		}

		// Commandline for the health check of the healthcheck containers,
		// in direct exec and shell formats.
		if(cmdline == "sysdig-ut-healt" || cmdline == "sh -c /bin/sysdig-ut-health-check")
		{
			cstate.healthcheck_seen = true;

			ASSERT_TRUE(tinfo->m_is_container_healthcheck) << capture_stats(inspector);
		}
	}

}

// Start up a container with the provided dockerfile, and track the
// state of the initial command for the container, a child proces of
// that initial command, and a health check (if one is configured).
static void healthcheck_helper(const char *dockerfile,
			       bool expect_healthcheck)
{
	container_state cstate;
	bool exited_early;

	if(!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("cont_health_ut");
	dutils_kill_image("cont_health_ut_img");

	std::string build_cmdline = string("cd resources/health_dockerfiles && docker build -t cont_health_ut_img -f ") +
		dockerfile +
		" . > /dev/null 2>&1";

	ASSERT_TRUE(system(build_cmdline.c_str()) == 0);

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;

		return (strcmp(evt->get_name(), "execve")==0 && evt->get_direction() == SCAP_ED_OUT && tinfo->m_container_id != "");
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		// Setting dropping mode preserves the execs but
		// reduces the chances that we'll drop events during
		// the docker fetch.
		inspector->start_dropping_mode(1);

		// --network=none speeds up the container setup a bit.
		int rc = system("docker run --rm --network=none --name cont_health_ut cont_health_ut_img /bin/sh -c '/bin/sleep 1' > /dev/null 2>&1");

		ASSERT_TRUE(exited_early || (rc == 0));
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		update_container_state(param.m_inspector, param.m_evt, cstate);

		// Exit as soon as we've seen all the initial commands
		// and the health check (if expecting one)
		if(!exited_early &&
		   cstate.root_cmd_seen &&
		   cstate.second_cmd_seen &&
		   (cstate.healthcheck_seen || !expect_healthcheck))
		{
			exited_early=true;
			dutils_kill_container("cont_health_ut");
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(cstate.root_cmd_seen);
	ASSERT_TRUE(cstate.second_cmd_seen);
	ASSERT_EQ(cstate.container_w_healthcheck, expect_healthcheck);
	ASSERT_EQ(cstate.healthcheck_seen, expect_healthcheck);
}

static void healthcheck_tracefile_helper(const char *dockerfile,
					 bool expect_healthcheck)
{
	container_state cstate;
	std::unique_ptr<sinsp> inspector;
	char dumpfile[20] = "/tmp/captureXXXXXX";
	int dumpfile_fd;

        inspector.reset(new sinsp());
	inspector->set_hostname_and_port_resolution_mode(false);

	ASSERT_GE(dumpfile_fd = mkstemp(dumpfile), 0);

	inspector->open();
	inspector->autodump_start(string(dumpfile), true);
	inspector->start_dropping_mode(1);

	// We can close our fd for the file, the inspector has its own copy.
	ASSERT_EQ(close(dumpfile_fd), 0u);

	std::atomic_bool done;

	done = false;
	std::thread dump_thread = std::thread([&] ()
	{
		while(!done)
		{
			sinsp_evt *ev;
			int32_t res = inspector->next(&ev);

			if(res == SCAP_TIMEOUT)
			{
				continue;
			}

			ASSERT_EQ(SCAP_SUCCESS, res);
		}

		inspector->stop_capture();
		inspector->close();
	});

	std::string build_cmdline = string("cd resources/health_dockerfiles && docker build -t cont_health_ut_img -f ") +
		dockerfile +
		" . > /dev/null 2>&1";
	ASSERT_TRUE(system(build_cmdline.c_str()) == 0);

	// --network=none speeds up the container setup a bit.
	ASSERT_TRUE((system("docker run --rm --network=none --name cont_health_ut cont_health_ut_img /bin/sh -c '/bin/sleep 1' > /dev/null 2>&1")) == 0);

	done=true;
	dump_thread.join();

	// Now reread the file we just wrote and pass it through
	// update_container_state.

	inspector.reset(new sinsp());
	inspector->set_hostname_and_port_resolution_mode(false);
	inspector->set_filter("evt.type=execve and evt.dir=<");
	inspector->open(dumpfile);

	while(1)
	{
		sinsp_evt *ev;
		int32_t res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		ASSERT_TRUE(res == SCAP_SUCCESS);

		update_container_state(inspector.get(), ev, cstate);
	}

	inspector->close();

	ASSERT_TRUE(cstate.root_cmd_seen);
	ASSERT_TRUE(cstate.second_cmd_seen);
	ASSERT_EQ(cstate.container_w_healthcheck, expect_healthcheck);
	ASSERT_EQ(cstate.healthcheck_seen, expect_healthcheck);

	unlink(dumpfile);
}

//  Run container w/o health check, should not find any health check
//  for the container. Should not identify either the entrypoint
//  or a second process spawned after as a health check process.
TEST_F(sys_call_test, docker_container_no_healthcheck)
{
	healthcheck_helper("Dockerfile.no_healthcheck",
			   false);
}

// A container with HEALTHCHECK=none should behave identically to one
// without any container at all.
TEST_F(sys_call_test, docker_container_none_healthcheck)
{
	healthcheck_helper("Dockerfile.none_healthcheck",
			   false);
}

//  Run container w/ health check. Should find health check for
//  container but not identify entrypoint or second process after as
//  a health check process. Should identify at least one health
//  check executed for container.
TEST_F(sys_call_test, docker_container_healthcheck)
{
	healthcheck_helper("Dockerfile.healthcheck",
			   true);
}

//  Run container w/ health check and entrypoint having identical
//  cmdlines. Should identify healthcheck but not entrypoint as a
//  health check process.
TEST_F(sys_call_test, docker_container_healthcheck_cmd_overlap)
{
	healthcheck_helper("Dockerfile.healthcheck_cmd_overlap",
			   true);
}

// A health check using shell exec instead of direct exec.
TEST_F(sys_call_test, docker_container_healthcheck_shell)
{
	healthcheck_helper("Dockerfile.healthcheck_shell",
			   true);
}

// Identical to above tests, but read events from a trace file instead
// of live. Only doing selected cases.
TEST_F(sys_call_test, docker_container_healthcheck_trace)
{
	healthcheck_tracefile_helper("Dockerfile.healthcheck",
				     true);
}

TEST_F(sys_call_test, docker_container_healthcheck_cmd_overlap_trace)
{
	healthcheck_tracefile_helper("Dockerfile.healthcheck_cmd_overlap",
				     true);
}



