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
#include <mntent.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#else
#include <time.h>
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
}

double sinsp_procfs_parser::get_global_cpu_load(OUT uint64_t* global_total_jiffies, uint64_t* global_idle_jiffies, uint64_t* global_steal_jiffies)
{
	double res = -1;
	char line[512];
	char tmps[32];

	if(!m_is_live_capture)
	{
		return -1;
	}

	char filename[SCAP_MAX_PATH_SIZE];
	sprintf(filename, "%s/proc/stat", scap_get_host_root());
	FILE* f = fopen(filename, "r");
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

	uint64_t val1, val2, val3, val4, val5, val6, val7, val8;
	uint64_t total_jiffies;
	uint64_t work_jiffies;
	uint64_t delta_total_jiffies;
	uint64_t delta_work_jiffies;

	//
	// Extract the line content
	//
	if(sscanf(line, "%s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
		tmps,
		&val1,
		&val2,
		&val3,
		&val4,
		&val5,
		&val6,
		&val7,
		&val8) != 9)
	{
		ASSERT(false);
		fclose(f);
		return -1;
	}

	//
	// Calculate the value
	//
	total_jiffies = val1 + val2 + val3 + val4 + val5 + val6 + val7 + val8;
	work_jiffies = val1 + val2 + val3 + val8;

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

	if(global_idle_jiffies)
	{
		*global_idle_jiffies = val4;
	}

	if(global_steal_jiffies)
	{
		*global_steal_jiffies = val8;
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
	uint32_t old_array_size = (uint32_t)m_old_total_jiffies.size();

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

	char filename[SCAP_MAX_PATH_SIZE];
	sprintf(filename, "%s/proc/stat", scap_get_host_root());
	FILE* f = fopen(filename, "r");
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

		total_jiffies = val1 + val2 + val3 + idle_jiffies + val5 + val6 + val7 + steal_jiffies;
		work_jiffies = val1 + val2 + val3 + val5 + val6 + val7 + steal_jiffies;

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
			load = MIN(load, 100);
			loads->push_back(load);

			double idle = (double)delta_idle_jiffies * 100 / delta_total_jiffies;
			idle = MIN(idle, 100);
			idles->push_back(idle);

			double steal = (double)delta_steal_jiffies * 100 / delta_total_jiffies;
			steal = MIN(steal, 100);
			steals->push_back(steal);

			m_old_total_jiffies[j] = total_jiffies;
			m_old_work_jiffies[j] = work_jiffies;
			m_old_idle_jiffies[j] = idle_jiffies;
			m_old_steal_jiffies[j] = steal_jiffies;
		}
	}

	fclose(f);
}

void sinsp_procfs_parser::get_global_mem_usage_kb(int64_t* used_memory, int64_t* used_swap)
{
	char line[512];
	int64_t mem_free = 0;
	int64_t buffers = 0;
	int64_t cached = 0;
	int64_t swap_total = 0;
	int64_t swap_free = 0;
	int64_t tmp = 0;

	*used_memory = -1;
	*used_swap = -1;

	if(!m_is_live_capture)
	{
		return;
	}

	char filename[SCAP_MAX_PATH_SIZE];
	sprintf(filename, "%s/proc/meminfo", scap_get_host_root());
	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false);
		return;
	}

	while(fgets(line, sizeof(line), f) != NULL)
	{
		//
		// Extract the line content
		//
		if(sscanf(line, "MemFree: %" PRId64, &tmp) == 1)
		{
			mem_free = tmp;
		}
		else if(sscanf(line, "Buffers: %" PRId64, &tmp) == 1)
		{
			buffers = tmp;
		}
		else if(sscanf(line, "Cached: %" PRId64, &tmp) == 1)
		{
			cached = tmp;
		}
		else if(sscanf(line, "SwapTotal: %" PRId64, &tmp) == 1)
		{
			swap_total = tmp;
		}
		else if(sscanf(line, "SwapFree: %" PRId64, &tmp) == 1)
		{
			swap_free = tmp;
			break;
		}
	}

	fclose(f);

	*used_memory = m_physical_memory_kb - mem_free - buffers - cached;
	if(*used_memory < 0)
	{
		ASSERT(false);
		*used_memory = 0;
	}

	*used_swap = swap_total - swap_free;
	if(*used_swap < 0)
	{
		ASSERT(false);
		*used_swap = 0;
	}
}

double sinsp_procfs_parser::get_process_cpu_load(uint64_t pid, uint64_t* old_proc_jiffies, uint64_t delta_global_total_jiffies)
{
	char line[512];
	char tmps[32];
	double res = -1;

	string path = string(scap_get_host_root()) + string("/proc/") + to_string((long long unsigned int) pid) + "/stat";
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
		&tval
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
	char filename[SCAP_MAX_PATH_SIZE];
	sprintf(filename, "%s/proc", scap_get_host_root());
	dir_p = opendir(filename);

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

void sinsp_procfs_parser::get_mounted_fs_list(vector<mounted_fs>* fs_list, bool remotefs_enabled)
{
#ifdef _WIN32
return;
#else

	string root = scap_get_host_root();
	string mtab = root + "/etc/mtab";

	FILE* fp = setmntent(mtab.c_str(), "r");
	if(fp == NULL)
	{
		throw sinsp_exception(string("error opening ").append(mtab).c_str());
	}

	while(true)
	{
		struct mntent* entry = getmntent(fp);
		if(entry == NULL)
		{
			break;
		}

		//
		// Dummy detection from coreutils
		//
  		if(strcmp(entry->mnt_type, "autofs") == 0 // dummy fs
			|| strcmp(entry->mnt_type, "proc") == 0
			|| strcmp(entry->mnt_type, "subfs") == 0
			|| strcmp(entry->mnt_type, "debugfs") == 0
			|| strcmp(entry->mnt_type, "devpts") == 0
			|| strcmp(entry->mnt_type, "fusectl") == 0
			|| strcmp(entry->mnt_type, "mqueue") == 0
			|| strcmp(entry->mnt_type, "rpc_pipefs") == 0
			|| strcmp(entry->mnt_type, "sysfs") == 0
			|| strcmp(entry->mnt_type, "devfs") == 0
			|| strcmp(entry->mnt_type, "kernfs") == 0
			|| strcmp(entry->mnt_type, "ignore") == 0
			|| strcmp(entry->mnt_type, "rootfs") == 0
			|| strcmp(entry->mnt_type, "none") == 0)
		{
			continue;
		}

		//
		// From coreutils, if dev contains ':', then remote
		//
		if(!remotefs_enabled)
		{
			// if remotefs are disabled, recognize them and skip
			if(strchr(entry->mnt_fsname, ':') != NULL
				|| strcmp(entry->mnt_type, "nfs") == 0 // remote fs
				|| strcmp(entry->mnt_type, "smbfs") == 0
				|| strcmp(entry->mnt_type, "cifs") == 0)
			{
				continue;
			}
		}

		struct statvfs statfs;
		string dir = root + entry->mnt_dir;
		if(statvfs(dir.c_str(), &statfs) < 0)
		{
			g_logger.log("error getting details for " + dir + ": " + strerror(errno), sinsp_logger::SEV_ERROR);
			continue;
		}

		if(statfs.f_blocks == 0)
		{
			continue;
		}

		uint64_t blocksize;
		if(statfs.f_frsize)
		{
			blocksize = statfs.f_frsize;
		}
		else
		{
			blocksize = statfs.f_bsize;
		}

		mounted_fs fs;

		fs.device = entry->mnt_fsname;
		fs.mount_dir = entry->mnt_dir;
		fs.type =  entry->mnt_type;
		fs.available_bytes = blocksize * statfs.f_bavail;
		fs.size_bytes = blocksize * statfs.f_blocks;
		fs.used_bytes = blocksize * (statfs.f_blocks - statfs.f_bfree);

		fs_list->push_back(fs);
	}

	endmntent(fp);
#endif
}

vector<string> sinsp_procfs_parser::read_process_cmdline(uint64_t pid)
{
#ifdef _WIN32
vector<string> res;
return res;
#else
	vector<string> args;
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc/%lu/cmdline", scap_get_host_root(), pid);
	ifstream cmdlineFile(filename);
	while(cmdlineFile.good())
	{
		string strBuf;
		std::getline( cmdlineFile, strBuf, '\0' );
		args.push_back(strBuf);
	}
	return args;
#endif
}

string sinsp_procfs_parser::read_process_name(uint64_t pid)
{
#ifdef _WIN32
return "";
#else
	char name[SCAP_MAX_PATH_SIZE] = "";
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc/%lu/status", scap_get_host_root(), pid);

	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		g_logger.log(string("Cannot open ") + filename, sinsp_logger::SEV_DEBUG);
	}
	else
	{
		char line[SCAP_MAX_ENV_SIZE];
		if(fgets(line, sizeof(line), f) == NULL)
		{
			g_logger.log(string("Cannot read from: ") + filename, sinsp_logger::SEV_WARNING);
		}
		else
		{
			line[sizeof(line) - 1] = 0;
			sscanf(line, "Name:%s", name);
		}
		fclose(f);
	}
	return string(name);
#endif
}
