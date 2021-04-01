#include "../process_helpers.h"
#include <fstream>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utils.h>
#include <sinsp.h>

type_config<int64_t> c_default_cpu_shares(
	-1,
	"CPU shares for the default cgroup (-1 to disable)",
	"subprocess_resource_limits",
	"default",
	"cpu_shares"
);

type_config<int64_t> c_default_cpu_quota(
	-1,
	"CPU quota for the default cgroup (-1 to disable, 100 = 1 full core)",
	"subprocess_resource_limits",
	"default",
	"cpu_quota"
);

type_config<int64_t> c_cointerface_cpu_shares(
	-1,
	"CPU shares for the cointerface cgroup (-1 to disable)",
	"subprocess_resource_limits",
	"cointerface",
	"cpu_shares"
);

type_config<int64_t> c_cointerface_cpu_quota(
	-1,
	"CPU quota for the cointerface cgroup (-1 to disable, 100 = 1 full core)",
	"subprocess_resource_limits",
	"cointerface",
	"cpu_quota"
);

type_config<int64_t> c_coldstart_manager_cpu_shares(
	-1,
	"CPU shares for the coldstart_manager cgroup (-1 to disable)",
	"subprocess_resource_limits",
	"coldstart",
	"cpu_shares"
);

type_config<int64_t> c_coldstart_manager_cpu_quota(
	-1,
	"CPU quota for the coldstart_manager cgroup (-1 to disable, 100 = 1 full core)",
	"subprocess_resource_limits",
	"coldstart",
	"cpu_quota"
);

type_config<int64_t> c_cgroup_cleanup_timeout_ms(
	10000,
	"Timeout for cleaning up subprocess cgroups (in ms)",
	"subprocess_resource_limits",
	"cgroup_cleanup_timeout"
);


namespace process_helpers
{

bool change_priority(int pid, int prio)
{
	const int result = setpriority(PRIO_PROCESS, pid, prio);
	return result == 0;
}

subprocess_cgroup::subprocess_cgroup(const std::string &subsys, const std::string &name)
{
	auto current_cgroup = get_current_cgroup(subsys);
	if(!current_cgroup.empty())
	{
		m_full_path = current_cgroup + name;
	}

	m_created = false;
}

void subprocess_cgroup::create()
{
	if(m_full_path.empty() || m_created)
	{
		return;
	}

	if(mkdir(m_full_path.c_str(), 0700) == 0 || errno == EEXIST)
	{
		m_created = true;
	}
}

bool subprocess_cgroup::remove(int timeout_ms) const
{
	if(!m_created)
	{
		return true;
	}

	auto deadline = sinsp_utils::get_current_time_ns() + (timeout_ms * 1000000);

	while(sinsp_utils::get_current_time_ns() < deadline)
	{
		if(rmdir(m_full_path.c_str()) == 0)
		{
			return true;
		}

		switch(errno)
		{
		case EBUSY:
			usleep(100000);
			break;
		case ENOENT:
			return true;
		default:
		{
			auto msg = "Removing cgroup " + m_full_path;
			perror(msg.c_str());
			return false;
		}
		}
	}

	return false;
}

void subprocess_cgroup::enter() const
{
	if(!m_created)
	{
		return;
	}
	std::ofstream tasks(m_full_path + "/tasks");
	tasks << 0;
}

void subprocess_cgroup::set_value(const std::string &name, int64_t value)
{
	if(!m_created)
	{
		return;
	}
	std::ofstream cg_value(m_full_path + "/" + name);
	cg_value << value;
}

std::string subprocess_cgroup::parse_cgroup(std::istream &s, const std::string& subsys)
{
	char buf[1024];
	while(true)
	{
		s.getline(buf, sizeof(buf));
		if(!*buf)
		{
			return "";
		}

		// the lines in /proc/self/cgroup look like this:
		// 10:cpu,cpuacct:/user.slice/user-0.slice/session-5832.scope
		// first, we skip the cgroup id
		char *p = strchr(buf, ':');
		if(!p)
		{
			continue;
		}
		p++;

		// and remember the pointer to the end of the subsys list
		char *cgroup = strchr(p, ':');
		if(!cgroup)
		{
			continue;
		}
		*cgroup = 0;
		cgroup++;

		// then, try to find the matching subsys (separated by commas);
		char *found_subsys;
		char *save;
		bool found = false;

		while((found_subsys = strtok_r(p, ",", &save)) != nullptr)
		{
			if(!strcmp(found_subsys, subsys.c_str()))
			{
				found = true;
				break;
			}
			p = nullptr;
		}
		if(!found)
		{
			continue;
		}

		return cgroup;
	}

}

std::string subprocess_cgroup::get_current_cgroup(const std::string& subsys)
{
	std::ifstream cgroups("/proc/self/cgroup");
	auto cgroup = parse_cgroup(cgroups, subsys);
	if(!cgroup.empty())
	{
		auto subsys_path = sinsp::lookup_cgroup_dir(subsys);

		if(!subsys_path->empty())
		{
			return *subsys_path + cgroup;
		}
	}

	return "";
}


void subprocess_cpu_cgroup::create()
{
	if(m_shares > 0)
	{
		subprocess_cgroup::create();
		set_value("cpu.shares", m_shares);
	}
	if(m_quota > 0)
	{
		subprocess_cgroup::create();
		int64_t quota = m_quota * CPU_QUOTA_PERIOD / 100;
		set_value("cpu.cfs_quota_us", quota);
		set_value("cpu.cfs_period_us", CPU_QUOTA_PERIOD);
	}
}

}
