#pragma once

#include <string>
#include "type_config.h"

extern type_config<int64_t> c_default_cpu_shares;
extern type_config<int64_t> c_cointerface_cpu_shares;
extern type_config<int64_t> c_cgroup_cleanup_timeout_ms;

namespace process_helpers
{

/**
 * Change the priority of a process
 *
 * @param pid process identifier
 * @param prio the priority to set the process to
 *
 * @return true if successful
 */
bool change_priority(int pid, int prio);

// TODO stub windows impl
class subprocess_cgroup {
public:
	/**
	 * An object to manage cgroups and membership
	 *
	 * It manages a child cgroup of the current process (i.e. name is the suffix
	 * to add to the current cgroup for subsystem subsys).
	 *
	 * @param subsys the subsystem to manage the cgroup (e.g. cpu, memory)
	 * @param name the name of the subgroup inside the current process's cgroup; *must* have a leading "/"
	 */
	explicit subprocess_cgroup(const std::string& subsys, const std::string& name);

	/**
	 * Destructor; since the object may be accessed from different processes,
	 * do _not_ call remove() from here
	 */
	virtual ~subprocess_cgroup() = default;

	/**
	 * Create the cgroup, setting m_created to true if it succeeds
	 * or the cgroup has existed before
	 */
	virtual void create();

	/**
	 * Remove the cgroup, waiting up to the specified timeout for the removal
	 * to succeed
	 *
	 * @param timeout_ms timeout to wait (in milliseconds)
	 * @return true if the cgroup was removed successfully
	 */
	virtual bool remove(int timeout_ms) const;

	/**
	 * Move the current thread (and only the thread, not the whole process) to the cgroup
	 */
	virtual void enter() const;

protected:
	virtual void set_value(const std::string& name, int64_t value);

private:
	std::string m_full_path;
	bool m_created;
};

class subprocess_cpu_cgroup : public subprocess_cgroup {
public:
	/**
	 * an object to manage cpu cgroup resource limits
	 * @param name
	 * @param shares
	 */
	explicit subprocess_cpu_cgroup(const std::string& name, int64_t shares):
		subprocess_cgroup("cpu", name),
		m_shares(shares)
	{}

	void create() override;

private:
	int64_t m_shares;
};


}
