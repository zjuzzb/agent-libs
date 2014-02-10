//
// links:
//   http://stackoverflow.com/questions/3017162/how-to-get-total-cpu-usage-in-linux-c
//   http://stackoverflow.com/questions/1420426/calculating-cpu-usage-of-a-process-in-linux
// 

#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#ifndef _WIN32
#include <unistd.h>
#include <dirent.h>
#endif
#include <sys/stat.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "procfs_parser.h"

sinsp_procfs_parser::sinsp_procfs_parser(uint32_t ncpus, int64_t physical_memory_kb, bool is_live_capture)
{
	m_ncpus = ncpus;
	m_physical_memory_kb = physical_memory_kb;
	m_is_live_capture = is_live_capture;

	m_old_global_total_jiffies = 0;
	m_old_global_work_jiffies = 0;
#ifndef _WIN32
	m_page_size = (uint32_t)sysconf(_SC_PAGESIZE);
#endif
}

double sinsp_procfs_parser::get_global_cpu_load(OUT uint64_t* global_total_jiffies)
{
	double res = -1;
	char line[512];
	char tmps[32];

	if(!m_is_live_capture)
	{
		return -1;
	}

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
		fclose(f);
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
		fclose(f);
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

		res = (double)delta_work_jiffies * 100 / delta_total_jiffies;

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
void sinsp_procfs_parser::get_cpus_load(OUT vector<double>* loads, OUT vector<double>* idles, OUT vector<double>* steals)
{
	char line[512];
	char tmps[32];
	uint32_t j;
	uint32_t old_array_size = m_old_total_jiffies.size();

	//
	// Nothing to do on windows
	//
	if(!m_is_live_capture)
	{
		return;
	}

	loads->clear();
	idles->clear();
	steals->clear();

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
		fclose(f);
		return;
	}

	//
	// Consume the cpu lines
	//
	for(j = 0; fgets(line, sizeof(line), f) != NULL; j++)
	{
		uint64_t val1, val2, val3, val5, val6, val7;
		uint64_t total_jiffies;
		uint64_t work_jiffies;
		uint64_t idle_jiffies;
		uint64_t steal_jiffies;
		uint64_t delta_total_jiffies;
		uint64_t delta_work_jiffies;
		uint64_t delta_idle_jiffies;
		uint64_t delta_steal_jiffies;

		if(strstr(line, "cpu") != line)
		{
			break;
		}

		if(sscanf(line, "%s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
			tmps, // cpu name
			&val1, // user
			&val2, // nice
			&val3, // system
			&idle_jiffies, // idle
			&val5, // iowait
			&val6, // irq
			&val7, // softirq
			&steal_jiffies) != 9) // steal
		{
			ASSERT(false);
			fclose(f);
			break;
		}

		total_jiffies = val1 + val2 + val3 + idle_jiffies + val5 + val6 + val7;
		work_jiffies = val1 + val2 + val3 + val5 + val6 + val7;

		if(old_array_size == 0)
		{
			m_old_total_jiffies.push_back(total_jiffies);
			m_old_work_jiffies.push_back(work_jiffies);
			m_old_idle_jiffies.push_back(idle_jiffies);
			m_old_steal_jiffies.push_back(steal_jiffies);
		}
		else
		{
			delta_work_jiffies = work_jiffies - m_old_work_jiffies[j];
			delta_idle_jiffies = idle_jiffies - m_old_idle_jiffies[j];
			delta_steal_jiffies = steal_jiffies - m_old_steal_jiffies[j];
			delta_total_jiffies = total_jiffies - m_old_total_jiffies[j];

			double load = (double)delta_work_jiffies * 100 / delta_total_jiffies;
			loads->push_back(load);

			double idle = (double)delta_idle_jiffies * 100 / delta_total_jiffies;
			idles->push_back(idle);

			double steal = (double)delta_steal_jiffies * 100 / (delta_steal_jiffies + delta_total_jiffies);
			steals->push_back(steal);

			m_old_total_jiffies[j] = total_jiffies;
			m_old_work_jiffies[j] = work_jiffies;
			m_old_idle_jiffies[j] = idle_jiffies;
			m_old_steal_jiffies[j] = steal_jiffies;
		}
	}

	fclose(f);
}

int64_t sinsp_procfs_parser::get_global_mem_usage_kb()
{
	int64_t res = -1;
	char line[512];
	int64_t tmp;

	if(!m_is_live_capture)
	{
		return -1;
	}

	FILE* f = fopen("/proc/meminfo", "r");
	if(f == NULL)
	{
		ASSERT(false);
		return -1;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		//
		// Extract the line content
		//
		if(sscanf(line, "MemFree: %" PRId64, &tmp) == 1)
		{
			res = m_physical_memory_kb - tmp;
		}
		else if(sscanf(line, "Buffers: %" PRId64, &tmp) == 1)
		{
			res -= tmp;
		}
		else if(sscanf(line, "Cached: %" PRId64, &tmp) == 1)
		{
			res -= tmp;
			break;
		}
	}

	fclose(f);

	if(res < 0)
	{
		ASSERT(false);
		res = 0;
	}

	return res;
}

double sinsp_procfs_parser::get_process_cpu_load_and_mem(uint64_t pid, uint64_t* old_proc_jiffies, uint64_t delta_global_total_jiffies, OUT int64_t* resident_memory_kb)
{
	char line[512];
	char tmps[32];
	double res = -1;
	string path = string("/proc/") + to_string(pid) + "/stat";
	uint64_t tval, val1, val2, val3, val4;

	if(!m_is_live_capture)
	{
		return -1;
	}

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
		fclose(f);
		return -1;
	}

	//
	// Extract the line content
	//
	if(sscanf(line, "%" PRIu64 " %s %s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRId64,
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
		&val2,
		&val3,
		&val4,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		&tval,
		resident_memory_kb
		) != 24)
	{
		ASSERT(false);
		fclose(f);
		return -1;
	}

	//
	// Calculate the value
	//
	uint64_t proc_jiffies = val1 + val2 + val3 + val4;

	if(*old_proc_jiffies != (uint64_t)-1LL)
	{
		uint64_t delta_proc_jiffies = proc_jiffies - *old_proc_jiffies;

		res = ((double)delta_proc_jiffies * 100 / delta_global_total_jiffies) * m_ncpus;

		res = MIN(res, double(100 * m_ncpus));
	}

	*old_proc_jiffies = proc_jiffies;

	fclose(f);

	//
	// Before returning, convert the memory size from pages to bytes.
	//
	*resident_memory_kb = (*resident_memory_kb) * (m_page_size / 1024);

	return res;	
}

//
// Scan a directory containing multiple processes under /proc
//
void sinsp_procfs_parser::get_tid_list(OUT set<uint64_t>* tids)
{
#ifdef _WIN32
return;
#else
	DIR *dir_p;
	struct dirent *dir_entry_p;
	uint64_t tid;

	tid = 0;
	dir_p = opendir("/proc");

	if(dir_p == NULL)
	{
		throw sinsp_exception("error opening the /proc directory");
	}

	while((dir_entry_p = readdir(dir_p)) != NULL)
	{
		if(strspn(dir_entry_p->d_name, "0123456789") != strlen(dir_entry_p->d_name))
		{
			continue;
		}

		//
		// Gather the process TID, which is the directory name
		//
		tid = atoi(dir_entry_p->d_name);
		tids->insert(tid);
	}

	closedir(dir_p);
#endif // _WIN32
}
