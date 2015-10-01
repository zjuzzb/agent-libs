#pragma once

#include "posix_queue.h"
#include "third-party/jsoncpp/json/json.h"

class mounted_fs
{
public:
	mounted_fs():
			size_bytes(0),
			used_bytes(0),
			available_bytes(0)
	{
	}
	explicit mounted_fs(const Json::Value& json);
	
	Json::Value to_json() const;
	void to_protobuf(draiosproto::mounted_fs* proto);

private:
	string device;
	string mount_dir;
	string type;
	uint64_t size_bytes;
	uint64_t used_bytes;
	uint64_t available_bytes;

	friend class sinsp_procfs_parser;
};

class sinsp_procfs_parser
{
public:
	sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture);
	double get_global_cpu_load(OUT uint64_t* global_total_jiffies = NULL, uint64_t* global_idle_jiffies = NULL, uint64_t* global_steal_jiffies = NULL);
	void get_cpus_load(OUT vector<double>* loads, OUT vector<double>* idles, OUT vector<double>* steals);
	void get_global_mem_usage_kb(int64_t* used_memory, int64_t* used_swap);

	vector<mounted_fs> get_mounted_fs_list(bool remotefs_enabled);

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
private:
	void lookup_memory_cgroup_dir();

	uint32_t m_ncpus;
	int64_t m_physical_memory_kb;
	bool m_is_live_capture;

	// nullptr means that lookup have not yet take place
	// "" means that it cannot find memory cgroup mount point
	unique_ptr<string> m_memory_cgroup_dir;

	vector<uint64_t> m_old_total_jiffies;
	vector<uint64_t> m_old_work_jiffies;
	vector<uint64_t> m_old_idle_jiffies;
	vector<uint64_t> m_old_steal_jiffies;
	uint64_t m_old_global_total_jiffies;
	uint64_t m_old_global_work_jiffies;
};

class mounted_fs_proxy
{
public:
	explicit mounted_fs_proxy();
	unordered_map<string, vector<mounted_fs>> receive_mounted_fs_list();
	bool send_container_list(const vector<pair<string, pid_t>>& containers);
private:
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
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
	Json::Reader m_json_reader;
	Json::FastWriter m_json_writer;
};