#include <gtest.h>
#include "../src/process_helpers.h"

#include <sstream>

namespace {

const std::string PROC_SELF_CGROUP = R"cg(12:cpuset:/
11:memory:/user.slice/user-0.slice/session-5844.scope
10:cpu,cpuacct:/user.slice/user-0.slice/session-5844.scope
9:hugetlb:/
8:devices:/user.slice/user-0.slice/session-5844.scope
7:pids:/user.slice/user-0.slice/session-5844.scope
6:freezer:/
5:net_cls,net_prio:/
4:perf_event:/
3:rdma:/
2:blkio:/user.slice/user-0.slice/session-5844.scope
1:name=systemd:/user.slice/user-0.slice/session-5844.scope)cg";
}

TEST(process_helpers_test, parse_cgroups_cpu)
{
	std::istringstream ss(PROC_SELF_CGROUP);
	auto cgroup = process_helpers::subprocess_cgroup::parse_cgroup(ss, "cpu");
	ASSERT_EQ("/user.slice/user-0.slice/session-5844.scope", cgroup);
}

TEST(process_helpers_test, parse_cgroups_cpuacct)
{
	std::istringstream ss(PROC_SELF_CGROUP);
	auto cgroup = process_helpers::subprocess_cgroup::parse_cgroup(ss, "cpuacct");
	ASSERT_EQ("/user.slice/user-0.slice/session-5844.scope", cgroup);
}

TEST(process_helpers_test, parse_cgroups_rdma)
{
	std::istringstream ss(PROC_SELF_CGROUP);
	auto cgroup = process_helpers::subprocess_cgroup::parse_cgroup(ss, "rdma");
	ASSERT_EQ("/", cgroup);
}

TEST(process_helpers_test, parse_cgroups_invalid)
{
	std::istringstream ss(PROC_SELF_CGROUP);
	auto cgroup = process_helpers::subprocess_cgroup::parse_cgroup(ss, "invalid");
	ASSERT_EQ("", cgroup);
}