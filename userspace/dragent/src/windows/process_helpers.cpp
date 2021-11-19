#include "../process_helpers.h"
#include "../logger.h"

COMMON_LOGGER("dragent");

namespace process_helpers
{

bool change_priority(int pid, int prio)
{
	LOG_INFO("Changing process priority is not supported on windows");
	return false;
}

subprocess_cgroup::subprocess_cgroup(const std::string &subsys, const std::string &name):
	m_full_path(""),
	m_created(false)
{
}

void subprocess_cgroup::create()
{
}

bool subprocess_cgroup::remove(int timeout_ms) const
{
	return false;
}

void subprocess_cgroup::enter() const
{
}

void subprocess_cgroup::set_value(const std::string &name, int64_t value)
{
}

std::string subprocess_cgroup::parse_cgroup(std::istream& s, const std::string& subsys)
{
	return "";
}

std::string get_current_cgroup(const std::string& subsys)
{
	return "";
}

void subprocess_cpu_cgroup::create_if_needed()
{
	if(m_shares > 0 || m_quota > 0)
	{
		LOG_INFO("Subprocess resource limits are not supported on windows");
	}
}

}
