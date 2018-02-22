#pragma once

#include "posix_queue.h"
#ifndef CYGWING_AGENT
#include "sdc_internal.pb.h"
#endif
#include "mount_points_limits.h"

typedef struct wh_t wh_t;

class mounted_fs
{
public:
	mounted_fs():
			size_bytes(0),
			used_bytes(0),
			available_bytes(0)
	{
	}
	explicit mounted_fs(const draiosproto::mounted_fs& proto);
	mounted_fs(mounted_fs&&) = default;
	mounted_fs& operator=(mounted_fs&&) = default;

	void to_protobuf(draiosproto::mounted_fs* proto) const;

private:
	string device;
	string mount_dir;
	string type;
	uint64_t size_bytes;
	uint64_t used_bytes;
	uint64_t available_bytes;
	uint64_t total_inodes;
	uint64_t used_inodes;

	friend class sinsp_procfs_parser;
};

struct sinsp_proc_stat
{
	vector<double> m_user;
	vector<double> m_nice;
	vector<double> m_system;
	vector<double> m_idle;
	vector<double> m_iowait;
	vector<double> m_irq;
	vector<double> m_softirq;
	vector<double> m_steal;
	vector<double> m_loads;
	uint64_t m_btime = 0;
	uint64_t m_uptime = 0;
};

struct sinsp_proc_file_stats {
	uint32_t m_syscr = 0;
	uint32_t m_syscw = 0;
	uint32_t m_read_bytes = 0;
	uint32_t m_write_bytes = 0;

	bool has_values() const
	{
		return m_syscr > 0 ||
				m_syscw > 0 ||
				m_read_bytes > 0 ||
				m_write_bytes > 0;
	}
};

class sinsp_procfs_parser
{
public:
#ifndef CYGWING_AGENT
	sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture);
#else
	sinsp_procfs_parser(sinsp* inspector, uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture);
#endif	
	void read_mount_points(mount_points_limits::sptr_t mount_points);
	void get_proc_stat(OUT sinsp_proc_stat* proc_stat);
	void get_global_mem_usage_kb(int64_t* used_memory, int64_t* free_memory, int64_t* avail_memory, int64_t* used_swap, int64_t* total_swap, int64_t* avail_swap);

	vector<mounted_fs> get_mounted_fs_list(bool remotefs_enabled,
										   const string& mtab="/etc/mtab");

#ifndef CYGWING_AGENT
	void set_global_cpu_jiffies();
#endif

	// must call set_global_cpu_jiffies() before calling this function
	// note that, due to the non-atomic (loop) nature of process CPU times collection,
	// this function produces an inherent error when called in a loop for all processes or
	// threads; additionally, there is an OS inaccuracy in reporting per-thread CPU times
	// in the presence of steal time
	double get_process_cpu_load(uint64_t pid, uint64_t* old_proc_jiffies);

	long get_process_rss_bytes(uint64_t pid);

	// returns the stolen percentage of total cpu usage
	uint64_t global_steal_pct();

	//
	// Scans /proc lightly to retrieve just the list of processes that are alive
	//
	void get_tid_list(OUT set<uint64_t>* tids);

	vector<string> read_process_cmdline(uint64_t pid);
	string read_process_name(uint64_t pid);
	int64_t read_cgroup_used_memory(const string& container_memory_cgroup);
	double read_cgroup_used_cpu(const string& container_cpuacct_cgroup, string& last_cpuacct_cgroup, int64_t *last_cpu_time);
	pair<uint32_t, uint32_t> read_network_interfaces_stats();
	pair<uint32_t, uint32_t> read_proc_network_stats(int64_t pid, uint64_t *old_last_in_bytes,
													 uint64_t *old_last_out_bytes);
	sinsp_proc_file_stats read_proc_file_stats(int64_t pid, sinsp_proc_file_stats* old);
	string read_proc_root(int64_t pid);

private:
#ifndef CYGWING_AGENT
	double get_global_cpu_jiffies(uint64_t* stolen = nullptr) const;
	void lookup_memory_cgroup_dir();
	void lookup_cpuacct_cgroup_dir();
	unique_ptr<string> lookup_cgroup_dir(const string& subsys);
	void assign_jiffies(vector<double>& vec, uint64_t delta_jiffies, uint64_t delta_tot_jiffies);
	bool get_cpus_load(OUT sinsp_proc_stat* proc_stat, char* line, int j);
	bool get_boot_time(OUT sinsp_proc_stat* proc_stat, char* line);
#endif
	pair<uint32_t, uint32_t> read_net_dev(const string& path, uint64_t* old_last_in_bytes, uint64_t* old_last_out_bytes, const vector<const char*>& bad_interface_names = {});

    // Current implementation for read_cgroup_used_memory()
    int64_t read_cgroup_used_memory_vmrss(const string &container_memory_cgroup);
    double read_cgroup_used_cpuacct_cpu_time(const string &container_memory_cgroup, string& last_cpuacct_cgroup, int64_t *last_cpu_time);

	mount_points_limits::sptr_t m_mount_points;

	uint32_t m_ncpus;
	int64_t m_physical_memory_kb;
	bool m_is_live_capture;

	uint64_t m_last_in_bytes;
	uint64_t m_last_out_bytes;
	// nullptr means that lookup have not yet take place
	// "" means that it cannot find cgroup mount point
	unique_ptr<string> m_memory_cgroup_dir;
	unique_ptr<string> m_cpuacct_cgroup_dir;

	vector<uint64_t> m_old_user;
	vector<uint64_t> m_old_nice;
	vector<uint64_t> m_old_system;
	vector<uint64_t> m_old_idle;
	vector<uint64_t> m_old_iowait;
	vector<uint64_t> m_old_irq;
	vector<uint64_t> m_old_softirq;
	vector<uint64_t> m_old_steal;
	vector<uint64_t> m_old_work;
	vector<uint64_t> m_old_total;

#ifdef CYGWING_AGENT
	wh_t* m_whhandle;
#endif

#ifndef CYGWING_AGENT
	// utility class to deal with jiffie counters housekeeping
	class jiffies_t
	{
	public:
		static const uint64_t NO_JIFFIES;

		jiffies_t() = delete;
		jiffies_t(const sinsp_procfs_parser& procfs_parser);

		void set();
		uint64_t delta_total() const;
		uint64_t delta_steal() const;

	private:
		void set_current();

		uint64_t m_current_total = NO_JIFFIES;
		uint64_t m_old_total = NO_JIFFIES;
		uint64_t m_delta_total = NO_JIFFIES;
		uint64_t m_current_steal = NO_JIFFIES;
		uint64_t m_old_steal = NO_JIFFIES;
		uint64_t m_delta_steal = NO_JIFFIES;
		const sinsp_procfs_parser& m_procfs_parser;
	};
	jiffies_t m_global_jiffies;

	friend class jiffies_t;
#endif // CYGWING_AGENT
};

#ifndef CYGWING_AGENT
inline void sinsp_procfs_parser::lookup_memory_cgroup_dir()
{
	m_memory_cgroup_dir = lookup_cgroup_dir("memory");
}

inline void sinsp_procfs_parser::lookup_cpuacct_cgroup_dir()
{
	m_cpuacct_cgroup_dir = lookup_cgroup_dir("cpuacct");
}

inline void sinsp_procfs_parser::assign_jiffies(vector<double>& vec, uint64_t delta_jiffies, uint64_t delta_tot_jiffies)
{
	double val = (double)delta_jiffies * 100 / delta_tot_jiffies;
	vec.push_back(std::min(val, 100.0));
}
#endif

#ifndef CYGWING_AGENT
inline void sinsp_procfs_parser::set_global_cpu_jiffies()
{
	m_global_jiffies.set();
}

inline uint64_t sinsp_procfs_parser::jiffies_t::delta_total() const
{
	return m_delta_total;
}

inline uint64_t sinsp_procfs_parser::jiffies_t::delta_steal() const
{
	return m_delta_steal;
}

inline void sinsp_procfs_parser::jiffies_t::set_current()
{
	m_current_total = m_procfs_parser.get_global_cpu_jiffies(&m_current_steal);
}
#endif // CYGWING_AGENT

class mounted_fs_proxy
{
public:
	explicit mounted_fs_proxy();
	unordered_map<string, vector<mounted_fs>> receive_mounted_fs_list();
	bool send_container_list(const vector<sinsp_threadinfo*>& containers);
private:
	posix_queue m_input;
	posix_queue m_output;
};

class mounted_fs_reader
{
public:
	mounted_fs_reader(sinsp* inspector, bool remotefs, const mount_points_filter_vec& mount_points, unsigned mounts_limit_size);
	int run();
private:
	static const uint16_t ERROR_EXIT = 1;
	static const uint16_t DONT_RESTART_EXIT = 17;
	static bool change_ns(int destpid);
	static int open_ns_fd(int pid);
	posix_queue m_input;
	posix_queue m_output;
	sinsp_procfs_parser m_procfs_parser;
	bool m_remotefs;
};
