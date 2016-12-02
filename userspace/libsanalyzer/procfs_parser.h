#pragma once

#include "posix_queue.h"
#include "sdc_internal.pb.h"

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

	void to_protobuf(draiosproto::mounted_fs* proto) const;

	uint64_t get_total_bytes() const;
	uint64_t get_total_inodes() const;
	uint64_t get_used_bytes() const;
	void set_used_bytes(uint64_t bytes);
	uint64_t get_used_inodes() const;
	void set_used_inodes(uint64_t inodes);

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

inline uint64_t mounted_fs::get_total_bytes() const
{
	return size_bytes;
}

inline uint64_t mounted_fs::get_total_inodes() const
{
	return total_inodes;
}

inline uint64_t mounted_fs::get_used_bytes() const
{
	return used_bytes;
}

inline void mounted_fs::set_used_bytes(uint64_t bytes)
{
	used_bytes = bytes;
}

inline uint64_t mounted_fs::get_used_inodes() const
{
	return used_inodes;
}

inline void mounted_fs::set_used_inodes(uint64_t inodes)
{
	used_inodes = inodes;
}

struct sinsp_proc_stat
{
	vector<double> m_loads;
	vector<double> m_steals;
	vector<double> m_user;
	vector<double> m_nice;
	vector<double> m_system;
	vector<double> m_idle;
	vector<double> m_iowait;
	uint64_t m_btime = 0;
	uint64_t m_uptime = 0;
};

struct sinsp_proc_pid_stat
{
	uint64_t m_pid;
	char m_status;
	std::string m_container_id;
};

class sinsp_procfs_parser
{
public:
	sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture);
	double get_global_cpu_load(OUT uint64_t* global_total_jiffies = NULL, uint64_t* global_idle_jiffies = NULL, uint64_t* global_steal_jiffies = NULL);
	void get_proc_stat(OUT sinsp_proc_stat* proc_stat);
	const vector<sinsp_proc_pid_stat>& proc_pid_stat() const;
	void get_global_mem_usage_kb(int64_t* used_memory, int64_t* free_memory, int64_t* avail_memory, int64_t* used_swap, int64_t* total_swap);

	vector<mounted_fs> get_mounted_fs_list(bool remotefs_enabled, const string& mtab="/etc/mtab");

	//
	// must call get_total_cpu_load to update the system time before calling this
	//
	double get_process_cpu_load(uint64_t pid, uint64_t* old_proc_jiffies, uint64_t delta_global_total_jiffies);

	//
	// Scans /proc lightly to retrieve just the list of processes that are alive
	//
	void get_tid_list(OUT set<uint64_t>* tids);

	vector<string> read_process_cmdline(uint64_t pid);
	string read_process_name(uint64_t pid);
	int64_t read_cgroup_used_memory(const string& container_memory_cgroup);
	pair<uint32_t, uint32_t> read_network_interfaces_stats();
private:
	void lookup_memory_cgroup_dir();
	void assign_jiffies(vector<double>& vec, uint64_t delta_jiffies, uint64_t delta_tot_jiffies);
	bool get_cpus_load(OUT sinsp_proc_stat* proc_stat, char* line, int j, uint32_t old_array_size);
	bool get_boot_time(OUT sinsp_proc_stat* proc_stat, char* line);
	void get_proc_pid_stat();

	uint32_t m_ncpus;
	int64_t m_physical_memory_kb;
	bool m_is_live_capture;

	uint64_t m_last_in_bytes;
	uint64_t m_last_out_bytes;
	// nullptr means that lookup have not yet take place
	// "" means that it cannot find memory cgroup mount point
	unique_ptr<string> m_memory_cgroup_dir;
	vector<sinsp_proc_pid_stat> m_proc_pid_stat;

	vector<uint64_t> m_old_total;
	vector<uint64_t> m_old_work;
	vector<uint64_t> m_old_steal;
	vector<uint64_t> m_old_user;
	vector<uint64_t> m_old_nice;
	vector<uint64_t> m_old_system;
	vector<uint64_t> m_old_idle;
	vector<uint64_t> m_old_iowait;
	uint64_t m_old_global_total;
	uint64_t m_old_global_work;
};

inline const vector<sinsp_proc_pid_stat>& sinsp_procfs_parser::proc_pid_stat() const
{
	return m_proc_pid_stat;
}

inline void sinsp_procfs_parser::assign_jiffies(vector<double>& vec, uint64_t delta_jiffies, uint64_t delta_tot_jiffies)
{
	double val = (double)delta_jiffies * 100 / delta_tot_jiffies;
	val = MIN(val, 100);
	vec.push_back(val);
}


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
	explicit mounted_fs_reader(bool remotefs);
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