#include <gtest.h>
#include "sys_call_test.h"

#include <runc.cpp>

using namespace libsinsp::runc;

constexpr const cgroup_layout CRI_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd containerd
	{"/crio-", ""}, // non-systemd cri-o
	{"/containerd-", ".scope"}, // systemd containerd (?)
	{"/crio-", ".scope"}, // systemd cri-o
	{nullptr, nullptr}
};

constexpr const cgroup_layout DOCKER_CGROUP_LAYOUT[] = {
	{"/", ""}, // non-systemd docker
	{"/docker-", ".scope"}, // systemd docker
	{nullptr, nullptr}
};

class container_cgroup : public testing::Test {};

TEST_F(container_cgroup, containerd_cgroupfs)
{
	std::string container_id;
	const std::string cgroup = "/kubepods/besteffort/podac04f3f2-1f2c-11e9-b015-1ebee232acfa/605439acbd4fb18c145069289094b17f17e0cfa938f78012d4960bc797305f22";
	const std::string expected_container_id = "605439acbd4f";

	EXPECT_EQ(true, match_container_id(cgroup, CRI_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, crio_cgroupfs)
{
	std::string container_id;
	const std::string cgroup = "/kubepods/besteffort/pod63b3ebfc-2890-11e9-8154-16bf8ef8d9dc/crio-73bfe475650de66df8e2affdc98d440dcbe84f8df83b6f75a68a82eb7026136a";
	const std::string expected_container_id = "73bfe475650d";

	EXPECT_EQ(true, match_container_id(cgroup, CRI_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, crio_systemd)
{
	std::string container_id;
	const std::string cgroup = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod63b3ebfc_2890_11e9_8154_16bf8ef8d9dc.slice/crio-17d8c9eacc629f9945f304d89e9708c0c619649a484a215b240628319548a09f.scope";
	const std::string expected_container_id = "17d8c9eacc62";

	EXPECT_EQ(true, match_container_id(cgroup, CRI_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, docker_cgroupfs)
{
	std::string container_id;
	const std::string cgroup = "/docker/7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe5392991e3b12251e6b8";
	const std::string expected_container_id = "7951fb549ab9";

	EXPECT_EQ(true, match_container_id(cgroup, DOCKER_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, docker_systemd)
{
	std::string container_id;
	const std::string cgroup = "/docker.slice/docker-7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe5392991e3b12251e6b8.scope";
	const std::string expected_container_id = "7951fb549ab9";

	EXPECT_EQ(true, match_container_id(cgroup, DOCKER_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}