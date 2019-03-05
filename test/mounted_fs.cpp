#include <gtest.h>

// for evt->tinfo
#define VISIBILITY_PRIVATE
#define EXPOSE_INTERNALS_MOUNTED_FS_H

#include "sdc_internal.pb.h"
#include "mounted_fs.h"
#include "sys_call_test.h"
#include "docker_utils.h"

class mounted_fs_reader_test : public sys_call_test {};

TEST_F(mounted_fs_reader_test, container_mounts)
{
	bool done = false;
	mount_points_filter_vec filters({{"*|autofs|*", false}, {"*|proc|*", false}, {"*|subfs|*", false}, {"*|debugfs|*", false},
					 {"*|devpts|*", false}, {"*|fusectl|*", false}, {"*|mqueue|*", false}, {"*|rpc_pipefs|*", false},
					 {"*|sysfs|*", false}, {"*|devfs|*", false}, {"*|devtmpfs|*", false}, {"*|kernfs|*", false},
					 {"*|ignore|*", false}, {"*|rootfs|*", false}, {"*|none|*", false}, {"*|*|*", true}});

	mounted_fs_reader reader(false, filters, 15);
	int home_fd = mounted_fs_reader::open_ns_fd(getpid());

	char root_dir[PATH_MAX];
	string root_dir_link = "/proc/" + to_string(getppid()) + "/root";
	ssize_t root_dir_sz = readlink(root_dir_link.c_str(), root_dir, PATH_MAX - 1);
	ASSERT_GT(root_dir_sz, 0);
	root_dir[root_dir_sz] = '\0';

	const std::string runc = "runc";
	if(!dutils_check_docker())
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
				tinfo->m_comm.find(runc) == std::string::npos;
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		ASSERT_TRUE(system("docker kill ilovesysdig_docker > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("docker rm -v ilovesysdig_docker > /dev/null 2>&1 || true") == 0);

#ifdef __s390x__
		if(system("docker run -d --name ilovesysdig_docker s390x/busybox sleep 10") != 0)
#else
		if(system("docker run -d --name ilovesysdig_docker busybox sleep 10") != 0)
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
		ASSERT_TRUE(tinfo != nullptr);
		const sinsp_container_info *container_info =
			param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != nullptr);

		if(done || container_info->m_name != "ilovesysdig_docker")
		{
			return;
		}

		// We can't call setns(CLONE_NEWNS) from a multithreaded process, so do the actual read
		// in a subprocess. It returns one of:
		//  0: tests passed
		//  2: tests failed
		//
		// Note: we can't really use GTEST ASSERT/EXPECT macros as they don't play nice
		// with the fork (the subprocess crashes with a failed assertion in libpthread when a test fails)
		//
		// Note: the actual test is pretty light (only checking for tmpfs on /dev) to avoid depending
		// on too many Docker internals
		pid_t pid = fork();
		switch(pid) {
		case 0: {
			int ret = 2;

			sdc_internal::mounted_fs_request req;
			sdc_internal::mounted_fs_response resp;
			auto container = req.add_containers();
			container->set_id(tinfo->m_container_id);
			container->set_pid(tinfo->m_pid);
			container->set_vpid(tinfo->m_vpid);
			container->set_root(tinfo->m_root);

			if(reader.handle_mounted_fs_request(root_dir, home_fd, req, resp) != 0)
			{
				fprintf(stderr, "failed to get mounted fs stats for container %s\n", tinfo->m_container_id.c_str());
				_exit(2);
			}

			for (const auto& fs_container : resp.containers())
			{
				for (const auto& container_mount : fs_container.mounts())
				{
					if (container_mount.mount_dir() == "/dev" && container_mount.type() != "tmpfs")
					{
						fprintf(stderr, "got fs type %s for container /dev\n", container_mount.type().c_str());
						_exit(2);
					}
				}
				ret = 0;
			}
			_exit(ret);
		}
		default: {
			int status;
			ASSERT_NE(-1, pid);

			waitpid(pid, &status, 0);
			ASSERT_TRUE(WIFEXITED(status));
			switch(WEXITSTATUS(status)) {
			case 0:
				done = true;
				break;
			case 1:
				break;
			default:
				ASSERT_EQ(0, status);
				break;
			}
		}
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	ASSERT_TRUE(done);

	close(home_fd);
}
