#pragma once

#include "posix_queue.h"
#include "third-party/jsoncpp/json/json.h"

class sinsp_procfs_parser
{
public:
	struct mounted_fs
	{
		mounted_fs():
			size_bytes(0),
			used_bytes(0),
			available_bytes(0)
		{
		}

		explicit mounted_fs(const Json::Value& json);
		Json::Value to_json() const;

		static Json::Value vector_to_json(const vector<sinsp_procfs_parser::mounted_fs>&);
		static vector<sinsp_procfs_parser::mounted_fs> vector_from_json(const Json::Value& json);

		string device;
		string mount_dir;
		string type;
		uint64_t size_bytes;
		uint64_t used_bytes;
		uint64_t available_bytes;
	};

	sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture);
	double get_global_cpu_load(OUT uint64_t* global_total_jiffies = NULL, uint64_t* global_idle_jiffies = NULL, uint64_t* global_steal_jiffies = NULL);
	void get_cpus_load(OUT vector<double>* loads, OUT vector<double>* idles, OUT vector<double>* steals);
	void get_global_mem_usage_kb(int64_t* used_memory, int64_t* used_swap);

	vector<sinsp_procfs_parser::mounted_fs> get_mounted_fs_list(bool remotefs_enabled);

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

private:
	uint32_t m_ncpus;
	int64_t m_physical_memory_kb;
	bool m_is_live_capture;

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
	const vector<sinsp_procfs_parser::mounted_fs>& get_mounted_fs_list();
private:
	vector<sinsp_procfs_parser::mounted_fs> fs_list;
	Json::Reader m_json_reader;
	posix_queue m_input;
};

class mounted_fs_reader
{
public:
	explicit mounted_fs_reader(bool remotefs);
	int run();
private:
	posix_queue m_output;
	sinsp_procfs_parser m_procfs_parser;
	bool m_remotefs;
	Json::FastWriter m_json_writer;
};