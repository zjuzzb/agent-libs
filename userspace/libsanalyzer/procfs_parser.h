#pragma once

class sinsp_procfs_parser
{
public:
	sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture);
	uint32_t get_global_cpu_load(OUT uint64_t* global_total_jiffies = NULL);
	void get_cpus_load(OUT vector<uint32_t>* loads, OUT vector<uint32_t>* idles, OUT vector<uint32_t>* steals);
	int64_t get_global_mem_usage_kb();

	//
	// must call get_total_cpu_load to update the system time before calling this
	//
	uint32_t get_process_cpu_load_and_mem(uint64_t pid, uint64_t* old_proc_jiffies, uint64_t delta_global_total_jiffies, OUT int64_t* resident_memory_kb);

private:
//	uint64_t m_last_read_time;
	uint32_t m_ncpus;
	int64_t m_physical_memory_kb;
	bool m_is_live_capture;

	vector<uint64_t> m_old_total_jiffies;
	vector<uint64_t> m_old_work_jiffies;
	vector<uint64_t> m_old_idle_jiffies;
	vector<uint64_t> m_old_steal_jiffies;
	uint64_t m_old_global_total_jiffies;
	uint64_t m_old_global_work_jiffies;
	uint32_t m_page_size;
};
