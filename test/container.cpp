#define VISIBILITY_PRIVATE

#include <sys/syscall.h>
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
#include <Poco/NumberParser.h>
#include <list>
#include <cassert>
#include "scap-int.h"

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
			int32_t res = scap_proc_fill_cgroups(&scap_tinfo, buf);
			ASSERT_TRUE(res == SCAP_SUCCESS);

			sinsp_tinfo.set_cgroups(scap_tinfo.cgroups, scap_tinfo.cgroups_len);
			if(scap_tinfo.cgroups_len)
			{
				ASSERT_TRUE(sinsp_tinfo.m_cgroups.size() > 0);
			}

			//
			// This tests that the cgroups in /proc/PID/cgroup are always a subset of the ones that came through clone(), checking
			// the matching. This happens because the kernel by default hides some
			//
			map<string, string> cgroups1;
			for(uint32_t j = 0; j < tinfo->m_cgroups.size(); ++j)
			{
				cgroups1.insert(pair<string, string>(tinfo->m_cgroups[j].first, tinfo->m_cgroups[j].second));
			}

			map<string, string> cgroups2;
			for(uint32_t j = 0; j < sinsp_tinfo.m_cgroups.size(); ++j)
			{
				cgroups2.insert(pair<string, string>(sinsp_tinfo.m_cgroups[j].first, sinsp_tinfo.m_cgroups[j].second));
			}

			ASSERT_TRUE(cgroups1.size() >= cgroups2.size());
			for(map<string, string>::iterator it2 = cgroups2.begin(); it2 != cgroups2.end(); ++it2)
			{
				map<string, string>::iterator it1 = cgroups1.find(it2->first);
				ASSERT_TRUE(it1 != cgroups1.end());
				ASSERT_TRUE(it1->first == it2->first);
				ASSERT_TRUE(it1->second == it2->second);
			}

			done = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

static int clone_callback_3(void *arg)
{
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
			ASSERT_TRUE(tinfo->m_vtid == 1);
			ASSERT_TRUE(tinfo->m_vpid == 1);

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
			return !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		system("docker kill ilovesysdig_docker > /dev/null 2>&1");
		system("docker rm ilovesysdig_docker > /dev/null 2>&1");

		if(system("docker run -d --name ilovesysdig_docker nginx") != 0)
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		system("docker kill ilovesysdig_docker > /dev/null 2>&1");
		system("docker rm ilovesysdig_docker > /dev/null 2>&1");
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		ASSERT_TRUE(tinfo->m_container_id.length() == 12);

		sinsp_container_info container_info;
		bool found = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id, &container_info);
		ASSERT_TRUE(found);

		ASSERT_TRUE(container_info.m_type == sinsp_container_type::CT_DOCKER);
		ASSERT_TRUE(container_info.m_name == "ilovesysdig_docker");
		ASSERT_TRUE(container_info.m_image == "nginx");

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_lxc)
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
		system("lxc-stop --name ilovesysdig_lxc > /dev/null 2>&1");
		system("lxc-destroy --name ilovesysdig_lxc > /dev/null 2>&1");

		if(system("lxc-create -n ilovesysdig_lxc -t busybox") != 0)
		{
			ASSERT_TRUE(false);
		}

		if(system("lxc-start -n ilovesysdig_lxc -d") != 0)
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		system("lxc-stop --name ilovesysdig_lxc > /dev/null 2>&1");
		system("lxc-destroy --name ilovesysdig_lxc > /dev/null 2>&1");
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		ASSERT_TRUE(tinfo->m_container_id == "ilovesysdig_lxc");

		sinsp_container_info container_info;
		bool found = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id, &container_info);
		ASSERT_TRUE(found);

		ASSERT_TRUE(container_info.m_type == sinsp_container_type::CT_LXC);
		ASSERT_TRUE(container_info.m_name == "ilovesysdig_lxc");
		ASSERT_TRUE(container_info.m_image.empty());

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

		system("virsh -c lxc:/// undefine libvirt-container > /dev/null 2>&1");
		system("virsh -c lxc:/// destroy libvirt-container > /dev/null 2>&1");

		if(system("virsh -c lxc:/// define /tmp/conf.xml") != 0)
		{
			ASSERT_TRUE(false);
		}

		if(system("virsh -c lxc:/// start libvirt-container") != 0)
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		system("virsh -c lxc:/// undefine libvirt-container > /dev/null 2>&1");
		system("virsh -c lxc:/// destroy libvirt-container > /dev/null 2>&1");
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		ASSERT_TRUE(tinfo->m_container_id == "libvirt\\x2dcontainer");

		sinsp_container_info container_info;
		bool found = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id, &container_info);
		ASSERT_TRUE(found);

		ASSERT_TRUE(container_info.m_type == sinsp_container_type::CT_LIBVIRT_LXC);
		ASSERT_TRUE(container_info.m_name == "libvirt\\x2dcontainer");
		ASSERT_TRUE(container_info.m_image.empty());

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);
}
