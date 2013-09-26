#pragma once

class sinsp_procparser
{
public:
	sinsp_procparser();

	void get_cpus_load(OUT vector<uint32_t>* loads);

private:
//	uint64_t m_last_read_time;
	vector<uint64_t> m_old_total_jiffies;
	vector<uint64_t> m_old_work_jiffies;
};
