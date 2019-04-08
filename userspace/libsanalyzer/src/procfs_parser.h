#pragma once

#include "posix_queue.h"
#ifndef CYGWING_AGENT
#include "sdc_internal.pb.h"
#include "procfs_scanner.h"
#endif
#include "mount_points_limits.h"

typedef struct wh_t wh_t;

struct sinsp_proc_stat
{
	std::vector<double> m_user;
	std::vector<double> m_nice;
	std::vector<double> m_system;
	std::vector<double> m_idle;
	std::vector<double> m_iowait;
	std::vector<double> m_irq;
	std::vector<double> m_softirq;
	std::vector<double> m_steal;
	std::vector<double> m_loads;
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

enum sinsp_cpu
{
	CPU_USER,
	CPU_NICE,
	CPU_SYSTEM,
	CPU_IRQ,
	CPU_SOFTIRQ,
	CPU_STEAL,
	CPU_WORK_MAX = CPU_STEAL, // include all counters up to this point in CPU_WORK
	CPU_IDLE,
	CPU_IOWAIT,
	CPU_WORK,
	CPU_TOTAL,
	CPU_NUM_COUNTERS // must be last
};

class sinsp_procfs_parser
{
public:
#ifndef CYGWING_AGENT
	sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture, uint64_t ttl_s_cpu, uint64_t ttl_s_mem);
#else
	sinsp_procfs_parser(sinsp* inspector, uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture, uint64_t ttl_s_cou, uint64_t ttl_s_mem);
#endif	
	void get_proc_stat(OUT sinsp_proc_stat* proc_stat);
	void get_global_mem_usage_kb(int64_t* used_memory, int64_t* free_memory, int64_t* avail_memory, int64_t* used_swap, int64_t* total_swap, int64_t* avail_swap);

#ifndef CYGWING_AGENT
	void set_global_cpu_jiffies();
	uint64_t get_cpu_jiffies() const {
		return m_global_jiffies.total();
	}

	double get_global_cpu_jiffies(uint64_t* stolen = nullptr) const;
#endif

	// must call set_global_cpu_jiffies() before calling this function
	// note that, due to the non-atomic (loop) nature of process CPU times collection,
	// this function produces an inherent error when called in a loop for all processes or
	// threads; additionally, there is an OS inaccuracy in reporting per-thread CPU times
	// in the presence of steal time

	// the _sync variant reads the cpu usage in the current thread (*old_proc is the
	// user+system value from the previous read, time is maintained using the global
	// jiffie timer
	double get_process_cpu_load_sync(uint64_t pid, uint64_t* old_proc);

	// this variant reads the cpu usage from the data collected by the /proc scan thread
	// (m_procfs_scan_thread must be enabled)
	double get_process_cpu_load(uint64_t pid);

	bool get_process_mem_metrics(pid_t pid, struct proc_metrics::mem_metrics *metrics);

	long get_process_rss_bytes(uint64_t pid);

	// returns the stolen percentage of total cpu usage
	uint64_t global_steal_pct();

	std::vector<std::string> read_process_cmdline(uint64_t pid);
	std::string read_process_name(uint64_t pid);
	int64_t read_cgroup_used_memory(const std::string& container_memory_cgroup);
	double read_cgroup_used_cpu(const std::string& container_cpuacct_cgroup, std::string& last_cpuacct_cgroup, int64_t *last_cpu_time);
	std::pair<uint32_t, uint32_t> read_network_interfaces_stats();
	std::pair<uint32_t, uint32_t> read_proc_network_stats(int64_t pid, uint64_t *old_last_in_bytes,
													 uint64_t *old_last_out_bytes);
	sinsp_proc_file_stats read_proc_file_stats(int64_t pid, sinsp_proc_file_stats* old);
	std::string read_proc_root(int64_t pid);

	static int add_ports_from_proc_fs(std::string fname, const std::set<uint16_t> &oldports, std::set<uint16_t> &ports, const std::set<uint64_t> &inodes);
	static int read_process_serverports(int64_t pid, const std::set<uint16_t> &oldports, std::set<uint16_t> &ports);
private:
#ifndef CYGWING_AGENT
	void lookup_memory_cgroup_dir();
	void lookup_cpuacct_cgroup_dir();
	void assign_jiffies(std::vector<double>& vec, uint64_t delta_jiffies, uint64_t delta_tot_jiffies);
	bool get_cpus_load(OUT sinsp_proc_stat *proc_stat, char *line, int cpu_num);
	bool get_boot_time(OUT sinsp_proc_stat* proc_stat, char* line);
#endif
	std::pair<uint32_t, uint32_t> read_net_dev(const std::string& path, uint64_t* old_last_in_bytes, uint64_t* old_last_out_bytes, const std::vector<const char*>& bad_interface_names = {});

    // Current implementation for read_cgroup_used_memory()
    int64_t read_cgroup_used_memory_vmrss(const std::string &container_memory_cgroup);
    double read_cgroup_used_cpuacct_cpu_time(const std::string &container_memory_cgroup, std::string& last_cpuacct_cgroup, int64_t *last_cpu_time);

	uint32_t m_ncpus = 0;
	int64_t m_physical_memory_kb = 0;
	bool m_is_live_capture = false;

	uint64_t m_last_in_bytes;
	uint64_t m_last_out_bytes;
	// nullptr means that lookup have not yet take place
	// "" means that it cannot find cgroup mount point
	std::shared_ptr<std::string> m_memory_cgroup_dir;
	std::shared_ptr<std::string> m_cpuacct_cgroup_dir;

	static const char* m_cpu_labels[];
	std::vector<uint64_t> m_old_cpu[CPU_NUM_COUNTERS];

#ifdef CYGWING_AGENT
	wh_t* m_whhandle;
#else
	proc_metrics::procfs_scanner_cpu m_procfs_scanner_cpu;
	proc_metrics::procfs_scanner_mem m_procfs_scanner_mem;
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

		uint64_t total() const {
			return m_current_total;
		}

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
	friend class test_helper;
#endif // CYGWING_AGENT
};

#ifndef CYGWING_AGENT
inline void sinsp_procfs_parser::lookup_memory_cgroup_dir()
{
	m_memory_cgroup_dir = sinsp::lookup_cgroup_dir("memory");
	if(!m_memory_cgroup_dir)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Cannot find memory cgroup dir");
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Found memory cgroup dir: %s", m_memory_cgroup_dir->c_str());
	}
}

inline void sinsp_procfs_parser::lookup_cpuacct_cgroup_dir()
{
	m_cpuacct_cgroup_dir = sinsp::lookup_cgroup_dir("cpuacct");
	if(!m_cpuacct_cgroup_dir)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Cannot find cpuacct cgroup dir");
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Found cpuacct cgroup dir: %s", m_cpuacct_cgroup_dir->c_str());
	}
}

inline void sinsp_procfs_parser::assign_jiffies(std::vector<double>& vec, uint64_t delta_jiffies, uint64_t delta_tot_jiffies)
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
