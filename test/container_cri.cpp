#define VISIBILITY_PRIVATE

#include <gtest.h>
#include "sys_call_test.h"

static const std::string cri_container_id = "575371e74864";
static const std::string fake_cri_socket = "/tmp/fake-cri.sock";

class container_cri : public sys_call_test {};

TEST_F(container_cri, fake_cri_no_server) {
	bool done = false;
	proc test_proc = proc("./test_helper", { "cri_container" });

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

		EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CRI, container_info->m_type);
		EXPECT_EQ("", container_info->m_name);
		EXPECT_EQ("", container_info->m_image);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->set_cri_socket_path(fake_cri_socket);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);

}

TEST_F(container_cri, fake_cri) {
	bool done = false;
	proc test_proc = proc("./test_helper", { "cri_container" });
	unlink(fake_cri_socket.c_str());
	auto fake_cri_handle = Poco::Process::launch("./resources/fake_cri", { "unix://" + fake_cri_socket, "resources/fake_cri_agent" });

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

		EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CONTAINERD, container_info->m_type);
		EXPECT_EQ("sysdig-agent", container_info->m_name);
		EXPECT_EQ("docker.io/sysdig/agent:latest", container_info->m_image);
		EXPECT_EQ("sha256:8d0619a4da278dfe2772f75aa3cc74df0a250385de56085766035db5c9a062ed", container_info->m_imagedigest);
		EXPECT_EQ("4bc0e14060f4263acf658387e76715bd836a13b9ba44f48465bd0633a412dbd0", container_info->m_imageid);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->set_cri_socket_path(fake_cri_socket);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);

	Poco::Process::kill(fake_cri_handle);
}

TEST_F(container_cri, fake_cri_unknown_runtime) {
	bool done = false;
	proc test_proc = proc("./test_helper", { "cri_container" });
	unlink(fake_cri_socket.c_str());
	auto fake_cri_handle = Poco::Process::launch("./resources/fake_cri", { "unix://" + fake_cri_socket, "resources/fake_cri_agent", "unknown-runtime" });

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

		EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CRI, container_info->m_type);
		EXPECT_EQ("sysdig-agent", container_info->m_name);
		EXPECT_EQ("docker.io/sysdig/agent:latest", container_info->m_image);
		EXPECT_EQ("sha256:8d0619a4da278dfe2772f75aa3cc74df0a250385de56085766035db5c9a062ed", container_info->m_imagedigest);
		EXPECT_EQ("4bc0e14060f4263acf658387e76715bd836a13b9ba44f48465bd0633a412dbd0", container_info->m_imageid);

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->set_cri_socket_path(fake_cri_socket);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);

	Poco::Process::kill(fake_cri_handle);
}
