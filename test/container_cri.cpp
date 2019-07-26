#define VISIBILITY_PRIVATE

#include "common_logger.h"
#include "sys_call_test.h"
#include <gtest.h>

static const std::string cri_container_id = "575371e74864";
static const std::string fake_cri_socket = "/tmp/fake-cri.sock";
static const std::string fake_docker_socket = "/tmp/fake-docker.sock";
static const std::string default_docker_socket = "/var/run/docker.sock";

class container_cri : public sys_call_test {
protected:
	void fake_cri_test(
		const std::string& pb_prefix,
		const std::string& runtime,
		const std::function<void(const callback_param& param, std::atomic<bool>& done)>& callback,
		bool extra_queries=true);

	void fake_cri_test_timing(
		const std::string& pb_prefix,
		const std::string& delay_arg,
		const std::string& runtime,
		float docker_delay,
		const std::function<void(const callback_param& param, std::atomic<bool>& done)>& callback,
		const std::function<void(const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done)>& new_cb,
		bool want_events=true,
		bool async=true);
};

TEST_F(container_cri, fake_cri_no_server) {
	std::atomic<bool> done(false);
	proc test_proc = proc("./test_helper", { "cri_container" });

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		// we never get the PPME_CONTAINER_JSON_E event if the lookup fails
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
		std::get<0>(handle).wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);

		// This can either be null or a container reporting a failed lookup
		EXPECT_TRUE((container_info == nullptr || !container_info->m_successful));

		done = true;
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->set_cri_socket_path(fake_cri_socket);
		inspector->set_log_callback(common_logger::sinsp_logger_callback);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter, setup);});
	ASSERT_TRUE(done);

}

void container_cri::fake_cri_test(const std::string& pb_prefix, const std::string& runtime, const std::function<void(const callback_param& param, std::atomic<bool>& done)>& callback, bool extra_queries)
{
	std::atomic<bool> done(false);
	proc test_proc = proc("./test_helper", { "cri_container" });
	unlink(fake_cri_socket.c_str());
	auto fake_cri_handle = Poco::Process::launch("./resources/fake_cri", { "unix://" + fake_cri_socket, pb_prefix, runtime });
	auto start_time = time(NULL);

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_type() == PPME_CONTAINER_JSON_E;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		std::get<0>(handle).wait();
		while(!done && time(NULL) < start_time + 10)
		{
			usleep(100000);
		}
	};

	captured_event_callback_t cri_callback = [&](const callback_param& param)
	{
		callback(param, done);
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->set_cri_socket_path(fake_cri_socket);
		inspector->set_cri_extra_queries(extra_queries);
		inspector->set_log_callback(common_logger::sinsp_logger_callback);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, cri_callback, filter, setup);});
	ASSERT_TRUE(done);

	Poco::Process::kill(fake_cri_handle);

}

TEST_F(container_cri, fake_cri) {
	fake_cri_test("resources/fake_cri_agent", "containerd", [&](const callback_param& param, std::atomic<bool>& done) {
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
		EXPECT_EQ(1073741824, container_info->m_memory_limit);
		EXPECT_EQ(102, container_info->m_cpu_shares);
		EXPECT_EQ(0, container_info->m_cpu_quota);
		EXPECT_EQ(100000, container_info->m_cpu_period);

		done = true;
	});
}

TEST_F(container_cri, fake_cri_crio_extra_queries) {
	fake_cri_test("resources/fake_cri_crio", "cri-o", [&](const callback_param& param, std::atomic<bool>& done) {
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CRIO, container_info->m_type);
		EXPECT_EQ("sysdig-agent", container_info->m_name);
		EXPECT_EQ("docker.io/gnosek/agent:crio", container_info->m_image);
		EXPECT_EQ("sha256:5241704b37e01f7bbca0ef6a90f5034731eba85320afd2eb9e4bce7ab09165a2", container_info->m_imagedigest);
		EXPECT_EQ("4e01602047d456fa783025a26b4b4c59b6527d304f9983fbd63b8d9a3bec53dc", container_info->m_imageid);

		done = true;
	});
}

TEST_F(container_cri, fake_cri_crio) {
	fake_cri_test("resources/fake_cri_crio", "cri-o", [&](const callback_param& param, std::atomic<bool>& done) {
		sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
		ASSERT_TRUE(tinfo != NULL);

		EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_NE(container_info, nullptr);

		EXPECT_EQ(sinsp_container_type::CT_CRIO, container_info->m_type);
		EXPECT_EQ("sysdig-agent", container_info->m_name);
		EXPECT_EQ("docker.io/gnosek/agent:crio", container_info->m_image);
		EXPECT_EQ("sha256:5241704b37e01f7bbca0ef6a90f5034731eba85320afd2eb9e4bce7ab09165a2", container_info->m_imagedigest);
		EXPECT_EQ("", container_info->m_imageid); // no extra queries -> no image id

		done = true;
	}, false);
}

TEST_F(container_cri, fake_cri_unknown_runtime) {
	fake_cri_test("resources/fake_cri_agent", "unknown-runtime", [&](const callback_param& param, std::atomic<bool>& done) {
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
	});
}

void container_cri::fake_cri_test_timing(
	const std::string& pb_prefix,
	const std::string& delay_arg,
	const std::string& runtime,
	float docker_delay,
	const std::function<void(const callback_param& param, std::atomic<bool>& done)>& callback,
	const std::function<void(const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done)>& new_cb,
	bool want_events,
	bool async)
{
	std::atomic<bool> done_events(!want_events);
	std::atomic<bool> done_callbacks(false);
	proc test_proc = proc("./test_helper", { "cri_container" });
	unlink(fake_cri_socket.c_str());
	auto fake_cri_handle = Poco::Process::launch("./resources/fake_cri", { delay_arg, "unix://" + fake_cri_socket, pb_prefix, runtime });
	auto fake_docker_handle = Poco::Process::launch("/usr/bin/env", { "python", "./resources/fake_docker.py", to_string(docker_delay), fake_docker_socket });
	auto start_time = time(NULL);

	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return evt->get_type() == PPME_CONTAINER_JSON_E;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
		while((!done_events || !done_callbacks) && time(NULL) < start_time + 5)
		{
			usleep(100000);
		}
	};

	captured_event_callback_t cri_callback = [&](const callback_param& param)
	{
		callback(param, done_events);
	};

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->set_docker_socket_path(fake_docker_socket);
		inspector->set_cri_async(async);
		inspector->set_cri_async_limits(async);
		inspector->set_cri_socket_path(fake_cri_socket);
		inspector->set_cri_extra_queries(false);
		inspector->set_log_callback(common_logger::sinsp_logger_callback);
		inspector->m_container_manager.subscribe_on_new_container(
			[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo) {
			new_cb(container, tinfo, done_callbacks);
		});
	};

	before_close_t cleanup = [&](sinsp* inspector)
	{
		inspector->set_docker_socket_path(default_docker_socket);
		inspector->set_cri_async(true);
		inspector->set_cri_async_limits(false);
	};

	EXPECT_NO_FATAL_FAILURE({event_capture::run(test, cri_callback, filter, setup, cleanup);});
	EXPECT_TRUE(done_events);
	EXPECT_TRUE(done_callbacks);

	Poco::Process::kill(fake_cri_handle);
	Poco::Process::kill(fake_docker_handle);

}

namespace {
void expect_cri_container(const callback_param& param, std::atomic<bool>& done)
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
	EXPECT_EQ(1073741824, container_info->m_memory_limit);
	EXPECT_EQ(102, container_info->m_cpu_shares);
	EXPECT_EQ(0, container_info->m_cpu_quota);
	EXPECT_EQ(100000, container_info->m_cpu_period);

	done = true;
}

void expect_docker_container(const callback_param& param, std::atomic<bool>& done)
{
	sinsp_threadinfo* tinfo = param.m_evt->m_tinfo;
	ASSERT_TRUE(tinfo != NULL);

	EXPECT_EQ(cri_container_id, tinfo->m_container_id);

	const sinsp_container_info* container_info = param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
	ASSERT_NE(container_info, nullptr);

	EXPECT_EQ(sinsp_container_type::CT_DOCKER, container_info->m_type);
	EXPECT_EQ("nginx", container_info->m_name);
	EXPECT_EQ("568c4670fa800978e08e4a51132b995a54f8d5ae83ca133ef5546d092b864acf", container_info->m_imageid);

	done = true;
}

void expect_no_container(const callback_param& param, std::atomic<bool>& done)
{
	FAIL();
}

struct callback_params {
	sinsp_container_type type;
	bool complete;
	bool successful;
};

void expect_callbacks(std::vector<callback_params>& params, const sinsp_container_info& container, std::atomic<bool>& done)
{
	ASSERT(!params.empty());

	auto exp = params[0];
	EXPECT_EQ(exp.type, container.m_type);
	EXPECT_EQ(exp.complete, container.m_metadata_complete);
	EXPECT_EQ(exp.successful, container.m_successful);

	params.erase(params.begin());
	if(params.empty())
	{
		done = true;
	}
}

}

TEST_F(container_cri, fake_cri_then_docker) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--nodelay",
		"containerd",
		0.5,
		expect_cri_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		});

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_then_cri) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--slow",
		"containerd",
		0.0,
		expect_docker_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		});

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_cri_fail_then_docker) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, false},
		{CT_DOCKER, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		2.0,
		expect_docker_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		});

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_then_cri_fail) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		0.0,
		expect_docker_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		});

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_cri_then_docker_fail) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--nodelay",
		"containerd",
		-0.5,
		expect_cri_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		});

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_fail_then_cri) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, false},
		{CT_CONTAINERD, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--slow",
		"containerd",
		-0.1,
		expect_cri_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		});

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_cri_fail_then_docker_fail) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, false},
		{CT_DOCKER, true, false}
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		-2.0,
		expect_no_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_fail_then_cri_fail) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, false},
		{CT_CONTAINERD, true, false}
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		-0.1,
		expect_no_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}


TEST_F(container_cri, fake_cri_then_docker_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--nodelay",
		"containerd",
		0.5,
		expect_cri_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		true,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_then_cri_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--slow",
		"containerd",
		0.0,
		expect_docker_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		true,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_cri_fail_then_docker_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, false},
		{CT_DOCKER, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		2.0,
		expect_docker_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		true,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_then_cri_fail_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		0.0,
		expect_docker_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		true,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_cri_then_docker_fail_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--nodelay",
		"containerd",
		-0.5,
		expect_cri_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		true,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_fail_then_cri_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, false},
		{CT_CONTAINERD, true, true},
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--slow",
		"containerd",
		-0.1,
		expect_cri_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		true,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_cri_fail_then_docker_fail_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_CONTAINERD, true, false},
		{CT_DOCKER, true, false}
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		-2.0,
		expect_no_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		false,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}

TEST_F(container_cri, fake_docker_fail_then_cri_fail_sync) {
	std::vector<callback_params> exp_callbacks = {
		{CT_DOCKER, false, false},
		{CT_DOCKER, true, false},
		{CT_CONTAINERD, true, false}
	};

	fake_cri_test_timing(
		"resources/fake_cri_agent",
		"--veryslow",
		"containerd",
		-0.1,
		expect_no_container,
		[&](const sinsp_container_info& container, sinsp_threadinfo* tinfo, std::atomic<bool>& done) {
			expect_callbacks(exp_callbacks, container, done);
		},
		false,
		false);

	ASSERT_TRUE(exp_callbacks.empty());
}
