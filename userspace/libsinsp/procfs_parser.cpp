//
// links:
//   http://stackoverflow.com/questions/3017162/how-to-get-total-cpu-usage-in-linux-c
//   http://stackoverflow.com/questions/1420426/calculating-cpu-usage-of-a-process-in-linux
// 

#include <stdio.h>
#include <stdlib.h>
#include <algorithm>

#include "sinsp.h"
#include "sinsp_int.h"
#include "procfs_parser.h"

sinsp_procfs_parser::sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb)
{
	m_ncpus = ncpus;
	m_physical_memory_kb = physical_memory_kb;
	m_old_global_total_jiffies = 0;
	m_old_global_work_jiffies = 0;
}

uint32_t sinsp_procfs_parser::get_global_cpu_load(OUT uint64_t* global_total_jiffies)
{
	uint32_t res = -1;
	char line[512];
	char tmps[32];

#ifdef _WIN32
	return -1;
#endif

	FILE* f = fopen("/proc/stat", "r");
	if(f == NULL)
	{
		ASSERT(false);
		return -1;
	}

	//
	// Consume the first line which is the global system summary
	//
	if(fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		return -1;
	}

	uint64_t val1, val2, val3, val4, val5, val6, val7;
	uint64_t total_jiffies;
	uint64_t work_jiffies;
	uint64_t delta_total_jiffies;
	uint64_t delta_work_jiffies;

	//
	// Extract the line content
	//
	if(sscanf(line, "%s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
		tmps,
		&val1,
		&val2,
		&val3,
		&val4,
		&val5,
		&val6,
		&val7) != 8)
	{
		ASSERT(false);
		return -1;
	}

	//
	// Calculate the value
	//
	total_jiffies = val1 + val2 + val3 + val4 + val5 + val6 + val7;
	work_jiffies = val1 + val2 + val3;

	if(m_old_global_total_jiffies != 0)
	{
		delta_work_jiffies = work_jiffies - m_old_global_work_jiffies;
		delta_total_jiffies = total_jiffies - m_old_global_total_jiffies;

		res = (uint32_t)((double)delta_work_jiffies * 100 / delta_total_jiffies);

		m_old_global_total_jiffies = total_jiffies;
		m_old_global_work_jiffies = work_jiffies;
	}

	m_old_global_total_jiffies = total_jiffies;
	m_old_global_work_jiffies = work_jiffies;

	//
	// Optionally return the total jiffies to the user
	//
	if(global_total_jiffies)
	{
		*global_total_jiffies = total_jiffies;
	}

	fclose(f);

	return res;
}

//
// See http://stackoverflow.com/questions/3017162/how-to-get-total-cpu-usage-in-linux-c
//
void sinsp_procfs_parser::get_cpus_load(OUT vector<uint32_t>* loads)
{
	char line[512];
	char tmps[32];
	uint32_t j;
	uint32_t old_array_size = m_old_total_jiffies.size();

	//
	// Nothing to do on windows
	//
#ifdef _WIN32
	return;
#endif

	loads->clear();

	FILE* f = fopen("/proc/stat", "r");
	if(f == NULL)
	{
		ASSERT(false);
		return;
	}

	//
	// Consume the first line which is the global system summary
	//
	if(fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		return;
	}

	//
	// Consume the cpu lines
	//
	for(j = 0; fgets(line, sizeof(line), f) != NULL; j++)
	{
		uint64_t val1, val2, val3, val4, val5, val6, val7;
		uint64_t total_jiffies;
		uint64_t work_jiffies;
		uint64_t delta_total_jiffies;
		uint64_t delta_work_jiffies;

		if(strstr(line, "cpu") != line)
		{
			break;
		}

		if(sscanf(line, "%s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
			tmps,
			&val1,
			&val2,
			&val3,
			&val4,
			&val5,
			&val6,
			&val7) != 8)
		{
			ASSERT(false);
			break;
		}

		total_jiffies = val1 + val2 + val3 + val4 + val5 + val6 + val7;
		work_jiffies = val1 + val2 + val3;

		if(old_array_size == 0)
		{
			m_old_total_jiffies.push_back(total_jiffies);
			m_old_work_jiffies.push_back(work_jiffies);
		}
		else
		{
			delta_work_jiffies = work_jiffies - m_old_work_jiffies[j];
			delta_total_jiffies = total_jiffies - m_old_total_jiffies[j];

			uint32_t load = (uint32_t)((double)delta_work_jiffies * 100 / delta_total_jiffies);
			loads->push_back(load);

			m_old_total_jiffies[j] = total_jiffies;
			m_old_work_jiffies[j] = work_jiffies;
		}
	}

	fclose(f);
}

uint32_t sinsp_procfs_parser::get_process_cpu_load(uint64_t pid, uint64_t* old_proc_jiffies, uint64_t delta_global_total_jiffies)
{
	char line[512];
	char tmps[32];
	uint32_t res = -1;
	string path = string("/proc/") + to_string(pid) + "/stat";
	uint64_t tval, val1, val2;

#ifdef _WIN32
	return -1;
#endif

	FILE* f = fopen(path.c_str(), "r");
	if(f == NULL)
	{
		return -1;
	}

	//
	// Consume the line
	//
	if(fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		return -1;
	}

	//
	// Extract the line content
	//
	if(sscanf(line, "%" PRIu64 " %s %s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
		&tval,
		tmps,
		tmps,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		&val1,
		&val2
		) != 15)
	{
		ASSERT(false);
		return -1;
	}

	//
	// Calculate the value
	//
	uint64_t proc_jiffies = val1 + val2;

	if(*old_proc_jiffies != (uint64_t)-1LL)
	{
		uint64_t delta_proc_jiffies = proc_jiffies - *old_proc_jiffies;

		res = (uint32_t)(((double)delta_proc_jiffies * 100 / delta_global_total_jiffies) * m_ncpus);

		res = MIN(res, 100);
	}

	*old_proc_jiffies = proc_jiffies;

	fclose(f);

	return res;	
}

int64_t sinsp_procfs_parser::get_process_resident_memory_kb(uint64_t pid)
{
	uint32_t j;
	char line[512];
	int64_t res = 0;
	string path = string("/proc/") + to_string(pid) + "/smaps";

#ifdef _WIN32
	return -1;
#endif

	FILE* f = fopen(path.c_str(), "r");
	if(f == NULL)
	{
		return -1;
	}

	//
	// Consume the Rss lines
	//
	for(j = 0; fgets(line, sizeof(line), f) != NULL; j++)
	{
		uint64_t val;

		if(strstr(line, "Rss") == line)
		{
			if(sscanf(line, "Rss: %" PRId64, &val) == 1)
			{
				res += val;
			}
			else
			{
				ASSERT(false);
			}
		}
	}

	fclose(f);

	ASSERT(res <= m_physical_memory_kb);

	return res;
}
