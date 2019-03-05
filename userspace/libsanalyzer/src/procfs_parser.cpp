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
#include <sys/resource.h>
#else
#include <time.h>
#endif
#include <sys/stat.h>

#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "procfs_parser.h"
#include "Poco/StringTokenizer.h"
#ifdef CYGWING_AGENT
#include "dragent_win_hal_public.h"
#endif

using Poco::StringTokenizer;

#ifndef CYGWING_AGENT
const uint64_t sinsp_procfs_parser::jiffies_t::NO_JIFFIES = ~0;

sinsp_procfs_parser::jiffies_t::jiffies_t(const sinsp_procfs_parser& procfs_parser):
	m_procfs_parser(procfs_parser)
{
	set_current();
}

void sinsp_procfs_parser::jiffies_t::set()
{
	m_old_total = m_current_total;
	m_old_steal = m_current_steal;
	set_current();
	ASSERT(m_current_total >= m_old_total);
	m_delta_total = m_current_total - m_old_total;
	ASSERT(m_current_steal >= m_old_steal);
	m_delta_steal = m_current_steal - m_old_steal;
}
#endif // CYGWING_AGENT

#ifndef CYGWING_AGENT
sinsp_procfs_parser::sinsp_procfs_parser(
#else
sinsp_procfs_parser::sinsp_procfs_parser(sinsp* inspector, 
#endif
					 uint32_t ncpus, 
					 int64_t physical_memory_kb,
					 bool is_live_capture,
					 uint64_t ttl_s_cpu,
					 uint64_t ttl_s_mem):
	m_ncpus(ncpus),
	m_physical_memory_kb(physical_memory_kb),
	m_is_live_capture(is_live_capture),
	m_last_in_bytes(0),
	m_last_out_bytes(0)
#ifndef CYGWING_AGENT
	, m_procfs_scanner_cpu(scap_get_host_root(), ttl_s_cpu, this)
	, m_procfs_scanner_mem(scap_get_host_root(), ttl_s_mem)
	, m_global_jiffies(*this)
#endif
{
#ifdef CYGWING_AGENT
	m_whhandle = inspector->get_wmi_handle();
	if(m_whhandle == NULL)
	{
		throw sinsp_exception("sinsp_procfs_parser::sinsp_procfs_parser initialization error: m_whhandle=NULL");
	} 
#endif
}

void sinsp_procfs_parser::read_mount_points(mount_points_limits::sptr_t mount_points)
{
	m_mount_points = mount_points;
}

#ifndef CYGWING_AGENT
double sinsp_procfs_parser::get_global_cpu_jiffies(uint64_t* stolen) const
{
	char line[512] = {0};

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

	// Consume the first line which is the global system summary
	if(fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false);
		fclose(f);
		return -1;
	}

	char tmps[32];
	uint64_t user, nice, system, idle, iowait, irq, softirq, steal;

	// Extract the cpu line content
	if(sscanf(line, "%s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
		tmps,
		&user,
		&nice,
		&system,
		&idle,
		&iowait,
		&irq,
		&softirq,
		&steal) != 9)
	{
		ASSERT(false);
		fclose(f);
		return -1;
	}
	fclose(f);
	if(stolen) { *stolen = steal; }
	return user + nice + system + idle + iowait + irq + softirq + steal;
}
#endif // CYGWING_AGENT

void sinsp_procfs_parser::get_proc_stat(OUT sinsp_proc_stat* proc_stat)
{
#ifndef CYGWING_AGENT
	ASSERT(proc_stat);

	char line[512];
	proc_stat->m_user.clear();
	proc_stat->m_nice.clear();
	proc_stat->m_system.clear();
	proc_stat->m_idle.clear();
	proc_stat->m_iowait.clear();
	proc_stat->m_irq.clear();
	proc_stat->m_softirq.clear();
	proc_stat->m_steal.clear();
	proc_stat->m_loads.clear();

	if(!m_is_live_capture) { return; }

	char filename[SCAP_MAX_PATH_SIZE];
	sprintf(filename, "%s/proc/stat", scap_get_host_root());
	FILE* f = fopen(filename, "r");
	if(f == NULL)
	{
		ASSERT(false); return;
	}

	//
	// Consume the first line (aggregated cpu values)
	//
	if(fgets(line, sizeof(line), f) == NULL)
	{
		ASSERT(false); fclose(f); return;
	}

	//
	// Consume the cpu lines
	//
	for(int j = 0; fgets(line, sizeof(line), f) != NULL; ++j)
	{
		if(strstr(line, "cpu") == line)
		{
			if(!get_cpus_load(proc_stat, line, j))
			{
				ASSERT(false); break;
			}
		}
		else if(strstr(line, "btime") == line) // boot time
		{
			if(!proc_stat->m_btime)
			{
				if(!get_boot_time(proc_stat, line))
				{
					ASSERT(false); break;
				}
			}
			proc_stat->m_uptime = get_epoch_utc_seconds_now() - proc_stat->m_btime;
			g_logger.log("sinsp_procfs_parser::get_proc_stat() m_btime=" + std::to_string(proc_stat->m_btime) +
				 ", m_uptime=" + std::to_string(proc_stat->m_uptime) , sinsp_logger::SEV_TRACE);
		}
	}
	fclose(f);
	ASSERT(!proc_stat->m_loads.size() || proc_stat->m_loads.size() == m_ncpus);
#else
	proc_stat->m_user.clear();
	proc_stat->m_nice.clear();
	proc_stat->m_system.clear();
	proc_stat->m_idle.clear();
	proc_stat->m_iowait.clear();
	proc_stat->m_irq.clear();
	proc_stat->m_softirq.clear();
	proc_stat->m_steal.clear();
	proc_stat->m_loads.clear();
	proc_stat->m_btime = 0;
	proc_stat->m_uptime = 0;

	wh_cpulist clist = wh_wmi_get_cpus(m_whhandle);
	if(clist.m_result == 0)
	{
		return;
	}

	for(uint32_t j = 0; j < clist.m_count; j++)
	{
		proc_stat->m_user.push_back(clist.m_cpus[j].user * 100);
		proc_stat->m_system.push_back(clist.m_cpus[j].system * 100);
		proc_stat->m_idle.push_back(clist.m_cpus[j].idle * 100);
		proc_stat->m_irq.push_back(clist.m_cpus[j].irq * 100);
		proc_stat->m_softirq.push_back(clist.m_cpus[j].softirq * 100);
		proc_stat->m_loads.push_back(clist.m_cpus[j].load * 100);
	}

	wh_os_times otimes = wh_wmi_get_os_times(m_whhandle);
	if(otimes.m_result == 0)
	{
		return;
	}

	proc_stat->m_btime = otimes.m_boot_time_s_unix;
	proc_stat->m_uptime = otimes.m_uptime_s_unix;
#endif
}

#ifndef CYGWING_AGENT
bool sinsp_procfs_parser::get_boot_time(OUT sinsp_proc_stat* proc_stat, char* line)
{
	ASSERT(proc_stat);
	char tmp[32] = {0};
	proc_stat->m_btime = 0;
	int scanned = sscanf(line, "%s %" PRIu64, tmp, &proc_stat->m_btime);
	if(scanned != 2)
	{
		g_logger.log("get_boot_time() scanned " + std::to_string(scanned) +
					 " values (expected 2), giving up", sinsp_logger::SEV_ERROR);
		return false;
	}
	g_logger.log("sinsp_procfs_parser::get_boot_time() scanned " + std::to_string(scanned) +
				 " values: " + tmp + '=' + std::to_string(proc_stat->m_btime) , sinsp_logger::SEV_TRACE);
	return true;
}

// must align with the order of sinsp_cpu enum values
const char* sinsp_procfs_parser::m_cpu_labels[] = { "user", "nice", "system", "irq", "softirq", "steal", "idle", "iowait" };

static inline uint64_t cpu_diff(int cpu, const char* label, uint64_t curr, uint64_t prev)
{
	if (curr < prev)
	{
		static ratelimit r;
		r.run([&] {
			g_logger.format(sinsp_logger::SEV_WARNING, "CPU#%d %s time going backwards (%" PRIu64 " -> %" PRIu64 ")",
							cpu, label, prev, curr);
		});
		return 0;
	}
	return curr - prev;
}


//
// See http://stackoverflow.com/questions/3017162/how-to-get-total-cpu-usage-in-linux-c
//
bool sinsp_procfs_parser::get_cpus_load(OUT sinsp_proc_stat *proc_stat, char *line, int cpu_num)
{
	ASSERT(proc_stat);

	char cpu[32] = {0};

	if(!m_is_live_capture) { return true; }

	uint64_t current[CPU_NUM_COUNTERS] = { 0 };
	uint64_t delta[CPU_NUM_COUNTERS] = { 0 };

	int scanned = sscanf(line, "%s %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64" %" PRIu64,
	                     cpu,
	                     &current[CPU_USER],
	                     &current[CPU_NICE],
	                     &current[CPU_SYSTEM],
	                     &current[CPU_IDLE],
	                     &current[CPU_IOWAIT],
	                     &current[CPU_IRQ],
	                     &current[CPU_SOFTIRQ],
	                     &current[CPU_STEAL]);

	if(scanned != 9)
	{
		g_logger.log("get_cpus_load() scanned " + std::to_string(scanned) +
					 " values (expected 9), giving up", sinsp_logger::SEV_ERROR);
		return false;
	}

	if (m_old_cpu[CPU_TOTAL].size() < static_cast<size_t>(cpu_num+1))
	{
		for (size_t i = 0; i < CPU_WORK; ++i)
		{
			current[CPU_TOTAL] += current[i];
			if (i <= CPU_WORK_MAX) {
				current[CPU_WORK] += current[i];
			}
		}

		for (size_t i = 0; i < CPU_NUM_COUNTERS; ++i)
		{
			m_old_cpu[i].push_back(current[i]);
		}
	}
	else
	{
		for (size_t i = 0; i < CPU_WORK; ++i)
		{
			uint64_t diff = cpu_diff(cpu_num, m_cpu_labels[i], current[i], m_old_cpu[i][cpu_num]);
			delta[i] = diff;
			delta[CPU_TOTAL] += diff;
			if (i <= CPU_WORK_MAX) {
				delta[CPU_WORK] += diff;
			}
		}

		// heuristics, fixups and sanity checks
		if (delta[CPU_TOTAL] == 0) {
			static ratelimit r;
			r.run([&] {
				g_logger.format(sinsp_logger::SEV_WARNING, "CPU #%d total time standing still (%" PRIu64 ")",
								current[CPU_TOTAL]);
			});
			return false;
		}
		if (current[CPU_STEAL] < m_old_cpu[CPU_STEAL][cpu_num])
		{
			static ratelimit r;
			r.run([&] {
				g_logger.format(sinsp_logger::SEV_WARNING,
								"Unstable stolen CPU counters detected, please upgrade your kernel. "
								"See: https://0xstubs.org/debugging-a-flaky-cpu-steal-time-counter-on-a-paravirtualized-xen-guest/");
			});
		}
		// XXX: this depends on actual wall clock time since the last read, if it's not 1 second, then the (arbitrary)
		// 80 ticks value won't be appropriate
		if (delta[CPU_TOTAL] < 80)
		{
			static ratelimit r;
			r.run([&] {
				g_logger.format(sinsp_logger::SEV_WARNING,
								"Total CPU time below 80%%, assigning the missing %d ticks to steal", 100 - delta[CPU_TOTAL]);
			});
			delta[CPU_STEAL] += 100 - delta[CPU_TOTAL];
			delta[CPU_TOTAL] = 100;
		}
		// back to your regularly scheduled program

		assign_jiffies(proc_stat->m_user, delta[CPU_USER], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_nice, delta[CPU_NICE], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_system, delta[CPU_SYSTEM], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_idle, delta[CPU_IDLE], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_iowait, delta[CPU_IOWAIT], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_irq, delta[CPU_IRQ], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_softirq, delta[CPU_SOFTIRQ], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_steal, delta[CPU_STEAL], delta[CPU_TOTAL]);
		assign_jiffies(proc_stat->m_loads, delta[CPU_WORK], delta[CPU_TOTAL]);

		for (size_t i = 0; i < CPU_NUM_COUNTERS; ++i)
		{
			m_old_cpu[i][cpu_num] = current[i];
		}
	}

	return true;
}
#endif // CYGWING_AGENT

void sinsp_procfs_parser::get_global_mem_usage_kb(int64_t* used_memory, int64_t* free_memory, int64_t* avail_memory, int64_t* used_swap, int64_t* total_swap, int64_t* avail_swap)
{
#ifndef CYGWING_AGENT
	char line[512];
	int64_t mem_free = 0;
	int64_t mem_avail = 0;
	int64_t buffers = 0;
	int64_t cached = 0;
	int64_t swap_total = 0;
	int64_t swap_free = 0;
	int64_t swap_cached = 0;
	int64_t slab_reclaimable = 0;
	int64_t tmp = 0;

	ASSERT(used_memory);
	ASSERT(used_swap);
	ASSERT(total_swap);
	*used_memory = -1;
	*avail_memory = -1;
	*used_swap = -1;
	*total_swap = -1;
	*avail_swap = -1;

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
		else if(sscanf(line, "MemAvailable: %" PRId64, &tmp) == 1)
		{
			mem_avail = tmp;
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
		}
		else if(sscanf(line, "SwapCached: %" PRId64, &tmp) == 1)
		{
			swap_cached = tmp;
		}
		else if(sscanf(line, "SReclaimable: %" PRId64, &tmp) == 1)
		{
			slab_reclaimable = tmp;
		}
	}

	fclose(f);

	*free_memory = mem_free;
	if(*free_memory < 0)
	{
		ASSERT(false);
		*free_memory = 0;
	}

	if(!mem_avail && mem_free > 0 && cached > 0)
	{
		// NOTE: `free` sets mem_avail to mem_free and does not include cached
		mem_avail = mem_free + cached;
	}
	*avail_memory = mem_avail;
	if(*avail_memory < 0)
	{
		ASSERT(false);
		*avail_memory = 0;
	}

	if(slab_reclaimable > 0)
	{
		// `free` accounts for slab_reclaimable as part of cached
		cached += slab_reclaimable;
	}
	*used_memory = m_physical_memory_kb - mem_free - buffers - cached;
	if(*used_memory < 0)
	{
		ASSERT(false);
		*used_memory = 0;
	}

	*total_swap = swap_total;
	if(*total_swap < 0)
	{
		ASSERT(false);
		*total_swap = 0;
	}

	*avail_swap = swap_free + swap_cached;
	if(*avail_swap < 0)
	{
		ASSERT(false);
		*avail_swap = 0;
	}

	*used_swap = swap_total - *avail_swap;
	if(*used_swap < 0)
	{
		ASSERT(false);
		*used_swap = 0;
	}
#else // CYGWING_AGENT
	wh_meminfo minfo = wh_wmi_get_meminfo(m_whhandle);
	if(minfo.m_result == 0)
	{
		throw sinsp_exception(string("error calling wh_wmi_get_mounts:") + wh_getlasterror(m_whhandle));
	}

	*used_memory = minfo.m_used_kb;
	*free_memory = minfo.m_free_kb;
	*avail_memory = minfo.m_free_kb;
	*used_swap = minfo.used_swap_kb;
	*total_swap = minfo.total_swap_kb;
	*avail_swap = minfo.avail_swap_kb;
	return;
#endif // CYGWING_AGENT
}

uint64_t sinsp_procfs_parser::global_steal_pct()
{
#ifndef CYGWING_AGENT
	uint64_t steal_pct = 0;
	uint64_t global_steal_jiffies_delta = m_global_jiffies.delta_steal();
	if(global_steal_jiffies_delta)
	{
		uint64_t global_total_jiffies_delta = m_global_jiffies.delta_total();
		if(global_total_jiffies_delta > 0 && (global_steal_jiffies_delta < global_total_jiffies_delta))
		{
			steal_pct = std::round(((double)global_steal_jiffies_delta / global_total_jiffies_delta) * 100);
		}
	}
	return steal_pct;
#else // CYGWING_AGENT
	//
	// We assume windows is mostly run in the datacenter and therefore this is not relevant.
	// We always return 0. 
	//
	return 0;
#endif // CYGWING_AGENT
}

double sinsp_procfs_parser::get_process_cpu_load(uint64_t pid)
{
#ifndef CYGWING_AGENT
	if(!m_is_live_capture) { return -1; }

	auto cpu_usage = m_procfs_scanner_cpu.get_data();
	auto cpu = cpu_usage->load_map.find(pid);
	if (cpu != cpu_usage->load_map.end())
	{
		return cpu->second.adjusted;
	}
	else // no data, or don't have this pid
	{
		return -1;
	}
#else // CYGWING_AGENT
	wh_proc_perf_info pinfo = wh_wmi_get_proc_perf_info(m_whhandle, pid);
	if(pinfo.m_result != 0)
	{
		return pinfo.m_cpu_percent;
	}
	else
	{
		return 0;
	}
#endif // CYGWING_AGENT
}

bool sinsp_procfs_parser::get_process_mem_metrics(pid_t pid, struct proc_metrics::mem_metrics *metrics)
{
#ifndef CYGWING_AGENT
	auto mem_data = m_procfs_scanner_mem.get_data();
	auto mem = mem_data->find(pid);
	if (mem == mem_data->end())
	{
		return false;
	}

	*metrics = mem->second;
	return true;
#else // CYGWING_AGENT
	// todo: CYGWING_AGENT. for now just return false (not supported)
	return false;
#endif // CYGWING_AGENT
}

double sinsp_procfs_parser::get_process_cpu_load_sync(uint64_t pid, uint64_t* old_proc)
{
#ifndef CYGWING_AGENT
        if(!m_is_live_capture) { return -1; }
        double res = -1;
        uint64_t global_total_jiffies_delta = m_global_jiffies.delta_total();

        if(global_total_jiffies_delta == jiffies_t::NO_JIFFIES) {
        	return -1;
        }

	string path = string(scap_get_host_root()) + string("/proc/") + to_string((long long unsigned int) pid) + "/stat";

	// we are looking for /proc/[PID]/stat entries [(14) utime %lu] and [(15) stime %lu],
	// see http://man7.org/linux/man-pages/man5/proc.5.html
	// the important bit here is that [(2) comm %s] may contain spaces, so sscanf is not bullet-proof;
	// we find the first closing paren (ie. skip the first two entries) and then extract desired values
	// from the rest of the line. so, (14) and (15), after adjustment for shift and zero-base, translates to (11) and (12)
	std::ifstream f(path);
	std::string line;
	if(!std::getline(f, line) || line.empty()) {
		return -1;
	}

	std::string::size_type pos = line.find(')');
	if((pos == std::string::npos) || (pos >= line.size() - 1)) {
		return -1;
	}

	unsigned long utime = 0, stime = 0;
	if(sscanf(line.c_str()+pos+1, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu %lu", &utime, &stime) > 0)
	{
		uint64_t proc = utime + stime;
		if(*old_proc != (uint64_t)-1LL)
		{
			uint64_t delta_proc = proc - *old_proc;
			res = ((double)delta_proc * 100 / global_total_jiffies_delta) * m_ncpus;
			res = std::min(res, 100.0 * m_ncpus);
		}
		*old_proc = proc;
		return res;
	}
        return res;
#else // CYGWING_AGENT
        wh_proc_perf_info pinfo = wh_wmi_get_proc_perf_info(m_whhandle, pid);
        if(pinfo.m_result != 0)
        {
                return pinfo.m_cpu_percent;
        }
        else
        {
                return 0;
        }
#endif // CYGWING_AGENT
}

long sinsp_procfs_parser::get_process_rss_bytes(uint64_t pid)
{
#ifndef CYGWING_AGENT
	long res = -1;
	string path = string(scap_get_host_root()) + string("/proc/") + to_string((long long unsigned int) pid) + "/stat";

	// we are looking for /proc/[PID]/stat entry [(24) rss %ld],
	// see http://man7.org/linux/man-pages/man5/proc.5.html
	// the important bit here is that [(2) comm %s] may contain spaces, so sscanf is not bullet-proof;
	// we find the first closing paren (ie. skip the first two entries) and then extract desired values
	// from the rest of the line. so, (24), after adjustment for shift and zero-base, translates to (21)
	std::ifstream f(path);
	std::string line;

	if(!std::getline(f, line) || line.empty()) {
		return -1;
	}

	std::string::size_type pos = line.find(')');
	if((pos == std::string::npos) || (pos >= line.size() - 1)) {
		return -1;
	}

	StringTokenizer st(line.substr(pos + 1), " ", StringTokenizer::TOK_TRIM | StringTokenizer::TOK_IGNORE_EMPTY);
	if(st.count() >= 22)
	{
		res = strtol(st[21].c_str(), nullptr, 10);
		if(res == LONG_MAX && errno == ERANGE) { ASSERT(false);}
		return sysconf(_SC_PAGESIZE) * res;
	}

	return res;
#else // CYGWING_AGENT
	wh_proc_perf_info pinfo = wh_wmi_get_proc_perf_info(m_whhandle, pid);
	if(pinfo.m_result != 0)
	{
		return pinfo.m_memory_bytes;
	}
	else
	{
		return 0;
	}
#endif // CYGWING_AGENT
}

vector<mounted_fs> sinsp_procfs_parser::get_mounted_fs_list(bool remotefs_enabled, const string& mtab)
{
	map<string, mounted_fs> mount_points;

#if !defined(_WIN32) && !defined(CYGWING_AGENT)
	FILE* fp = setmntent(mtab.c_str(), "r");
	if(fp == NULL)
	{
		throw sinsp_exception("error opening " + mtab);
	}

	m_mount_points->reset();
	while(!m_mount_points->limit_is_reached())	// stops looking for more mount point entries when mount limit is reached
	{
		struct mntent* entry = getmntent(fp);
		if(entry == NULL)
		{
			break;
		}

		// already processed; skips
		if (mount_points.find(entry->mnt_dir) != mount_points.end())
		{
			continue;
		}

		bool colon_found = (strchr(entry->mnt_fsname, ':') != NULL);

		//
		// From coreutils, if dev contains ':', then remote
		//
		if(!remotefs_enabled)
		{
			// if remotefs are disabled, recognize them and skip
			if((colon_found && strstr(entry->mnt_fsname, "docker") == NULL)
				|| strcmp(entry->mnt_type, "nfs") == 0 // remote fs
				|| strcmp(entry->mnt_type, "smbfs") == 0
				|| strcmp(entry->mnt_type, "cifs") == 0)
			{
				continue;
			}
		}

		if (!m_mount_points->allow(entry->mnt_fsname, entry->mnt_type, entry->mnt_dir))
		{
			continue;
		}

		struct statvfs statfs;
		if(statvfs(entry->mnt_dir, &statfs) < 0)
		{
			g_logger.log("unable to get details for " + string(entry->mnt_dir) + ": " + strerror(errno), sinsp_logger::SEV_DEBUG);
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


		m_mount_points->increase();

		mounted_fs fs;
		fs.device = entry->mnt_fsname;
		fs.mount_dir = entry->mnt_dir;
		fs.type =  entry->mnt_type;
		fs.available_bytes = blocksize * statfs.f_bavail;
		fs.size_bytes = blocksize * statfs.f_blocks;
		fs.used_bytes = blocksize * (statfs.f_blocks - statfs.f_bfree);
		fs.total_inodes = statfs.f_files;
		fs.used_inodes = statfs.f_files - statfs.f_ffree;
		mount_points[entry->mnt_dir] = move(fs);
	}

	endmntent(fp);

	m_mount_points->log_if_max_mount_limit_reached();
#else // !defined(_WIN32) && !defined(CYGWING_AGENT)
#ifdef CYGWING_AGENT
	wh_mountlist mtable = wh_wmi_get_mounts(m_whhandle);
	if(mtable.m_result == 0)
	{
		throw sinsp_exception(string("error calling wh_wmi_get_mounts:") + wh_getlasterror(m_whhandle));
	}

	m_mount_points->reset();

	for(uint32_t j = 0; j < mtable.m_count; ++j)
	{
		wh_mounted_fs_info* wmi = &mtable.m_mounts[j];

		mounted_fs fs;
		fs.device = wmi->device;
		fs.mount_dir = wmi->mount_dir;
		fs.type =  wmi->type;
		fs.available_bytes = wmi->available_bytes;
		fs.size_bytes = wmi->size_bytes;
		fs.used_bytes = wmi->used_bytes;
		fs.total_inodes = 0;
		fs.used_inodes = 0;

		mount_points[fs.mount_dir] = move(fs);
	}
#endif // CYGWING_AGENT
#endif // !defined(_WIN32) && !defined(CYGWING_AGENT)
	vector<mounted_fs> ret;
	for (auto& mp : mount_points)
		ret.emplace_back(move(mp.second));
	return ret;
}

vector<string> sinsp_procfs_parser::read_process_cmdline(uint64_t pid)
{
#ifndef CYGWING_AGENT
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
		try
		{
			std::getline( cmdlineFile, strBuf, '\0' );
			if(!strBuf.empty())
			{
				args.push_back(strBuf);
			}
		}
		catch (const exception& ex)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Error while read process_cmdline: %s", ex.what());
			break;
		}
	}
	return args;
#endif
#else // CYGWING_AGENT
	//
	// This should never be called under Windows since Windows only supports nodriver mode.
	//
	ASSERT(false);
	throw sinsp_exception("sinsp_procfs_parser::read_process_cmdline not implemented on Windows");
#endif // CYGWING_AGENT
}

string sinsp_procfs_parser::read_process_name(uint64_t pid)
{
#ifndef CYGWING_AGENT
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
#else // CYGWING_AGENT
	//
	// This should never be called under Windows since Windows only supports nodriver mode.
	//
	ASSERT(false);
	throw sinsp_exception("sinsp_procfs_parser::read_process_name not implemented on Windows");
#endif // CYGWING_AGENT
}

/*
 * We were using the value reported by memory.usage_in_bytes as the amount of
 * memory in use by a cgroup or container. However, usage_in_bytes is a fuzz
 * value as per kernel-src/Documentation. An accurate value is a combination of
 * rss+cache from the memory.stat entry of the cgroup.
 */
int64_t sinsp_procfs_parser::read_cgroup_used_memory(const string &container_memory_cgroup)
{
#ifndef CYGWING_AGENT
    if (!m_is_live_capture) {
        return -1;
    }

    if (!m_memory_cgroup_dir) {
        lookup_memory_cgroup_dir();
    }

    if (!m_memory_cgroup_dir || m_memory_cgroup_dir->empty()) {
        return -1;
    }

    return read_cgroup_used_memory_vmrss(container_memory_cgroup);
#else // CYGWING_AGENT
	//
	// This is not required on windows
	//
	ASSERT(false);
	throw sinsp_exception("sinsp_procfs_parser::read_cgroup_used_memory not implemented on Windows");
#endif // CYGWING_AGENT
}

/*
 * This function calculates VmRss which is what we use to determine mem usage
 * of a process.
 *
 * This function must only be called from read_cgroup_used_memory().
 *
 * In proc(5), VmRss is defined as the following:
 *              * VmRSS: Resident set size.  Note that the value here is the sum
 *                of RssAnon, RssFile, and RssShmem.
 *
 *              * RssAnon:  Size  of  resident  anonymous  memory.  (since Linux
 *                4.5).
 *
 *              * RssFile: Size of resident file mappings.  (since Linux 4.5).
 *
 *              * RssShmem: Size of resident shared memory  (includes  System  V
 *                shared  memory,  mappings  from tmpfs(5), and shared anonymous
 *                mappings).  (since Linux 4.5).
 *
 * For a cgroup, this translates to the following formula:
 *      memory_stat.rss + memory_stat.cache - memory_stat.inactive_file
 *
 * NOTE: This function MUST only be called from read_cgroup_used_memory().
 */
int64_t sinsp_procfs_parser::read_cgroup_used_memory_vmrss(const string &container_memory_cgroup)
{
    int64_t stat_val_cache = -1, stat_val_rss = -1, stat_val_inactive_file = -1;
    unsigned stat_find_count = 0;
    const unsigned num_stats = 3;

    // Using scap_get_host_root() is not necessary here because
    // m_memory_cgroup_dir is taken from /etc/mtab
    char mem_stat_filename[SCAP_MAX_PATH_SIZE];
    snprintf(mem_stat_filename, sizeof(mem_stat_filename),"%s/%s/memory.stat",
             m_memory_cgroup_dir->c_str(), container_memory_cgroup.c_str());

    FILE *fp = fopen(mem_stat_filename, "r");
    if (fp == NULL) {
        g_logger.log(string(__func__) + ": Unable to open file " + mem_stat_filename +
                     ": errno: " + strerror(errno), sinsp_logger::SEV_DEBUG);
        return -1;
    }

    char fp_line[128] = { 0 };
    while(fgets(fp_line, sizeof(fp_line), fp) != NULL) {
        char stat_val_str[64] = { 0 };
        int64_t stat_val = -1;
        if (sscanf(fp_line, "%63s %" PRId64, stat_val_str, &stat_val) != 2) {
            g_logger.log(string(__func__) + ": Unable to parse line '" + fp_line + "'" +
                         " from file " + mem_stat_filename, sinsp_logger::SEV_ERROR);
            fclose(fp);
            return -1;
        }

        if (stat_val_cache == -1 && strcmp(stat_val_str, "cache") == 0) {
            stat_val_cache = stat_val;
            ++stat_find_count;
        } else if (stat_val_rss == -1 && strcmp(stat_val_str, "rss") == 0) {
            stat_val_rss = stat_val;
            ++stat_find_count;
        } else if (stat_val_inactive_file == -1 &&
                   strcmp(stat_val_str, "inactive_file") == 0) {
            stat_val_inactive_file = stat_val;
            ++stat_find_count;
        }

        if (num_stats == stat_find_count) {
            break;
        }
    }

    fclose(fp);

    if (num_stats != stat_find_count) {
        return -1;
    }

    int64_t ret_val = stat_val_rss + stat_val_cache - stat_val_inactive_file;
    if (ret_val < 0) {
        g_logger.format(sinsp_logger::SEV_ERROR, "%s: Calculation failed with values "
                        "%" PRId64 ", %" PRId64 ", %" PRId64 " from file %s", __func__,
                        stat_val_cache, stat_val_rss, stat_val_inactive_file,
                        mem_stat_filename);
        return -1;
    }

    return ret_val;
}

/*
 * Get CPU usage from cpuacct cgroup subsystem
 */
#ifndef CYGWING_AGENT
double sinsp_procfs_parser::read_cgroup_used_cpu(const string &container_cpuacct_cgroup,
		string& last_cpuacct_cgroup, int64_t *last_cpu_time)
{
	if (!m_is_live_capture) {
		return -1;
	}

	if (!m_cpuacct_cgroup_dir) {
		lookup_cpuacct_cgroup_dir();
	}

	if (!m_cpuacct_cgroup_dir || m_cpuacct_cgroup_dir->empty()) {
		return -1;
	}

	return read_cgroup_used_cpuacct_cpu_time(container_cpuacct_cgroup, last_cpuacct_cgroup, last_cpu_time);
}

double sinsp_procfs_parser::read_cgroup_used_cpuacct_cpu_time(
                                        const string &container_cpuacct_cgroup,
					string& last_cpuacct_cgroup,
					int64_t *last_cpu_time)
{
	// Using scap_get_host_root() is not necessary here because
	// m_cpuacct_cgroup_dir is taken from /etc/mtab
	char cpuacct_filename[SCAP_MAX_PATH_SIZE];
	snprintf(cpuacct_filename, sizeof(cpuacct_filename), "%s/%s/cpuacct.usage",
	         m_cpuacct_cgroup_dir->c_str(), container_cpuacct_cgroup.c_str());

	FILE *fp = fopen(cpuacct_filename, "r");
	if (fp == NULL) {
		g_logger.log(string(__func__) + ": Unable to open file " + cpuacct_filename +
		             ": errno: " + strerror(errno), sinsp_logger::SEV_DEBUG);
		return -1;
	}

	char fp_line[128] = { 0 };
	uint64_t delta_jiffies = m_global_jiffies.delta_total();
	if (delta_jiffies > 110)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "%s: cpuacct scan %" PRId64 " ticks apart",
				cpuacct_filename, delta_jiffies);
	}
	if(fgets(fp_line, sizeof(fp_line), fp) != NULL) {
		int64_t stat_val = -1;
		if (sscanf(fp_line, "%" PRId64, &stat_val) != 1) {
			g_logger.log(string(__func__) + ": Unable to parse line '" + fp_line + "'" +
			             " from file " + cpuacct_filename, sinsp_logger::SEV_ERROR);
			fclose(fp);
			return -1;
		}

		fclose(fp);
		int64_t last = *last_cpu_time;
		g_logger.format(sinsp_logger::SEV_DEBUG, "%s: cpuacct values: %" PRId64
				" -> %" PRId64 " in file %s", __func__, last, stat_val,
				cpuacct_filename);

		*last_cpu_time = stat_val;
		if (container_cpuacct_cgroup != last_cpuacct_cgroup)
		{
			if (!last_cpuacct_cgroup.empty())
			{
				// the container moved between cpuacct cgroups (possibly e.g. during k8s container restart)
				// don't report the delta as it's meaningless (we're subtracting values from two
				// different cgroups)
				g_logger.format(sinsp_logger::SEV_WARNING, "%s: detected cpuacct cgroup switch %s -> %s, skipping sample",
						__func__, last_cpuacct_cgroup.c_str(), container_cpuacct_cgroup.c_str());
			}
			// else: it's the first time we're reading from this cgroup. Skip the sample silently.

			// remember the cgroup for future reference
			last_cpuacct_cgroup = container_cpuacct_cgroup;
			return 0;
		}

		if (stat_val >= last)
		{
			/*
			   without scaling, 1 full cpu of time would be 1e9 nsec / 100 ticks, i.e. 1e7
			   scale down by 1e5 to get a floating point value in the range of 0-100.0 per cpu
			*/
			double cpu_usage = ((stat_val - last) / (delta_jiffies * 100000.0)) * m_ncpus;
			return min(cpu_usage, 100.0 * m_ncpus);
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_WARNING, "%s: cpuacct value %" PRId64
					" lower than last %" PRId64 " in file %s, skipping sample",
					__func__, stat_val, last, cpuacct_filename);
			return 0;
		}
	}

	fclose(fp);
	return -1;
}

unique_ptr<string> sinsp_procfs_parser::lookup_cgroup_dir(const string& subsys)
{
	unique_ptr<string> cgroup_dir;

	// Look for mount point of cgroup filesystem
	// It should be already mounted on the host or by
	// our docker-entrypoint.sh script
	if(strcmp(scap_get_host_root(), "") != 0)
	{
		// We are inside our container, so we should use the directory
		// mounted by it
		auto cgroup = string(scap_get_host_root()) + "/cgroup/" + subsys;
		cgroup_dir = make_unique<string>(cgroup);
	}
	else
	{
		FILE* fp = setmntent("/proc/mounts", "r");
		struct mntent* entry = getmntent(fp);
		while(entry != NULL)
		{
			if(strcmp(entry->mnt_type, "cgroup") == 0 &&
			   hasmntopt(entry, subsys.c_str()) != NULL)
			{
				cgroup_dir = make_unique<string>(entry->mnt_dir);
				break;
			}
			entry = getmntent(fp);
		}
		endmntent(fp);
	}
	if(!cgroup_dir)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Cannot find %s cgroup dir", subsys.c_str());
		return make_unique<string>();
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_INFO, "Found %s cgroup dir: %s", subsys.c_str(), cgroup_dir->c_str());
		return cgroup_dir;
	}
}
#endif // CYGWING_AGENT

pair<uint32_t, uint32_t> sinsp_procfs_parser::read_network_interfaces_stats()
{
#ifndef CYGWING_AGENT
	char net_dev_path[100];
	snprintf(net_dev_path, sizeof(net_dev_path), "%s/proc/net/dev", scap_get_host_root());
	static const vector<const char*> BAD_INTERFACE_NAMES = { "lo", "stf", "gif", "dummy", "vmnet", "docker", "veth"};
	return read_net_dev(net_dev_path, &m_last_in_bytes, &m_last_out_bytes, BAD_INTERFACE_NAMES);
#else // CYGWING_AGENT
	wh_machine_bandwidth_info mi = wh_wmi_get_machine_net_totbytes(m_whhandle);
	uint32_t deltain = mi.m_bytes_in - m_last_in_bytes;
	uint32_t deltaout = mi.m_bytes_out - m_last_out_bytes;

	if(m_last_in_bytes == 0 && m_last_out_bytes == 0)
	{
		m_last_in_bytes = mi.m_bytes_in;
		m_last_out_bytes = mi.m_bytes_out;
		return make_pair(0, 0);
	}
	else
	{
		m_last_in_bytes = mi.m_bytes_in;
		m_last_out_bytes = mi.m_bytes_out;
		return make_pair(deltain, deltaout);
	}
#endif // CYGWING_AGENT
}

pair<uint32_t, uint32_t> sinsp_procfs_parser::read_proc_network_stats(int64_t pid, uint64_t *old_last_in_bytes,
																	  uint64_t *old_last_out_bytes)
{
#ifndef CYGWING_AGENT
	char net_dev_path[100];
	snprintf(net_dev_path, sizeof(net_dev_path), "%s/proc/%ld/net/dev", scap_get_host_root(), pid);
	return read_net_dev(net_dev_path, old_last_in_bytes, old_last_out_bytes);
#else // CYGWING_AGENT
	//
	// There is no way in windows to get per process network utilization.
	//
	pair<uint32_t, uint32_t> ret;
	return ret;
#endif // CYGWING_AGENT
}

pair<uint32_t, uint32_t> sinsp_procfs_parser::read_net_dev(const string& path, uint64_t* old_last_in_bytes, uint64_t* old_last_out_bytes, const vector<const char*>& bad_interface_names)
{
#ifndef CYGWING_AGENT
	pair<uint32_t, uint32_t> ret;

	if(!m_is_live_capture)
	{
		// Reading this data does not makes sense if it's not a live capture
		return ret;
	}

	auto net_dev = fopen(path.c_str(), "r");
	if(net_dev == NULL)
	{
		return ret;
	}

	// Skip first two lines as they are column headers
	char skip_buffer[1024];
	if(fgets(skip_buffer, sizeof(skip_buffer), net_dev) == NULL)
	{
		fclose(net_dev);
		return ret;
	}
	if(fgets(skip_buffer, sizeof(skip_buffer), net_dev) == NULL)
	{
		fclose(net_dev);
		return ret;
	}

	char interface_name[30];
	uint64_t in_bytes, out_bytes;
	uint64_t tot_in_bytes = 0;
	uint64_t tot_out_bytes = 0;

	while(fscanf(net_dev, "%s %lu %*u %*u %*u %*u %*u %*u %*u %lu %*u %*u %*u %*u %*u %*u %*u",
				 interface_name, &in_bytes, &out_bytes) > 0)
	{
		if(find_if(bad_interface_names.begin(), bad_interface_names.end(), [&interface_name](const char* bad_interface) {
			return strcasestr(interface_name, bad_interface) == interface_name;
		}) == bad_interface_names.end())
		{
			// g_logger.format(sinsp_logger::SEV_INFO, "Selected interface %s %u, %u", interface_name, in_bytes, out_bytes);
			tot_in_bytes += in_bytes;
			tot_out_bytes += out_bytes;
		}
	}
	fclose(net_dev);

	// Calculate delta, no delta if it is the first time we read
	if(*old_last_in_bytes > 0 || *old_last_out_bytes > 0)
	{
		// Network metrics use uint32_t on protobuf, so we use the same
		// for deltas
		ret.first = static_cast<uint32_t>(tot_in_bytes - *old_last_in_bytes);
		ret.second = static_cast<uint32_t>(tot_out_bytes - *old_last_out_bytes);
	}
	*old_last_in_bytes = tot_in_bytes;
	*old_last_out_bytes = tot_out_bytes;

	return ret;
#else // CYGWING_AGENT
	//
	// This should never be called on Windows.
	//
	ASSERT(false);
	throw sinsp_exception("sinsp_procfs_parser::read_net_dev not implemented on Windows");
#endif // CYGWING_AGENT
}

sinsp_proc_file_stats sinsp_procfs_parser::read_proc_file_stats(int64_t pid, sinsp_proc_file_stats *old)
{
#ifndef CYGWING_AGENT
	char filepath[SCAP_MAX_PATH_SIZE];
	snprintf(filepath, SCAP_MAX_PATH_SIZE, "%s/proc/%ld/io", scap_get_host_root(), pid);

	sinsp_proc_file_stats ret, last;

	if(!m_is_live_capture)
	{
		// Reading this data does not makes sense if it's not a live capture
		return ret;
	}

	auto io_file = fopen(filepath, "r");
	if(io_file == NULL)
	{
		return ret;
	}

	char field[20];
	uint32_t value;
	while(fscanf(io_file, "%s %u", field, &value) > 0)
	{
		string field_s(field);
		if (field_s == "rchar:")
		{
			last.m_read_bytes = value;
		}
		else if (field_s == "wchar:")
		{
			last.m_write_bytes = value;
		}
		else if(field_s == "syscr:")
		{
			last.m_syscr = value;
		}
		else if (field_s == "syscw:")
		{
			last.m_syscw = value;
			// no need to read more
			break;
		}
	}

	fclose(io_file);

	// Calculate delta, no delta if it is the first time we read
	if(old->has_values())
	{
		ret.m_syscr = last.m_syscr - old->m_syscr;
		ret.m_syscw = last.m_syscw - old->m_syscw;
		ret.m_read_bytes = last.m_read_bytes - old->m_read_bytes;
		ret.m_write_bytes = last.m_write_bytes - old->m_write_bytes;
	}
	*old = last;

	return ret;
#else // CYGWING_AGENT
	//
	// There is no way in windows to get per process file utilization.
	//
	sinsp_proc_file_stats ret;
	return ret;
#endif // CYGWING_AGENT
}

string sinsp_procfs_parser::read_proc_root(int64_t pid)
{
#ifndef CYGWING_AGENT
	char path[SCAP_MAX_PATH_SIZE];
	string root_link = string(scap_get_host_root()) + "/proc/" + to_string(pid) + "/root";
	ssize_t len = readlink(root_link.c_str(), path, SCAP_MAX_PATH_SIZE - 1);
	if (len > 0)
	{
		path[len] = '\0';
		return path;
	}
	else
	{
		g_logger.log("Cannot read root link.", sinsp_logger::SEV_WARNING);
		return "/";
	}
#else // CYGWING_AGENT
	return "/";
#endif // CYGWING_AGENT
}

mounted_fs::mounted_fs(const draiosproto::mounted_fs& proto):
	device(proto.device()),
	mount_dir(proto.mount_dir()),
	type(proto.type()),
	size_bytes(proto.size_bytes()),
	used_bytes(proto.used_bytes()),
	available_bytes(proto.available_bytes()),
	total_inodes(proto.total_inodes()),
	used_inodes(proto.used_inodes())
{

}

void mounted_fs::to_protobuf(draiosproto::mounted_fs *fs) const
{
	fs->set_device(device);
	fs->set_mount_dir(mount_dir);
	fs->set_type(type);
	fs->set_size_bytes(size_bytes);
	fs->set_used_bytes(used_bytes);
	fs->set_available_bytes(available_bytes);
	fs->set_total_inodes(total_inodes);
	fs->set_used_inodes(used_inodes);
}

mounted_fs_proxy::mounted_fs_proxy():
	m_input("/sdc_mounted_fs_reader_out", posix_queue::direction_t::RECEIVE),
	m_output("/sdc_mounted_fs_reader_in", posix_queue::direction_t::SEND)
{

}

unordered_map<string, vector<mounted_fs>> mounted_fs_proxy::receive_mounted_fs_list()
{
#ifndef CYGWING_AGENT
	unordered_map<string, vector<mounted_fs>> fs_map;
	auto last_msg = m_input.receive();
	decltype(last_msg) msg;
	while(!last_msg.empty())
	{
		msg = move(last_msg);
		last_msg = m_input.receive();
	}
	if(!msg.empty())
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Received from mounted_fs_reader: %lu bytes", msg.size());
		sdc_internal::mounted_fs_response response_proto;
		if(response_proto.ParseFromString(msg))
		{
			fs_map.clear();
			for(const auto& c : response_proto.containers())
			{
				vector<mounted_fs> fslist;
				for( const auto& m : c.mounts())
				{
					fslist.emplace_back(m);
				}
				fs_map.emplace(c.container_id(), move(fslist));
			}
		}
	}
	return fs_map;
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_proxy::receive_mounted_fs_list not implemented on Windows");
#endif
}

bool mounted_fs_proxy::send_container_list(const vector<sinsp_threadinfo*> &containers)
{
#ifndef CYGWING_AGENT
	sdc_internal::mounted_fs_request req;
	for(const auto& item : containers)
	{
		// Safety check, it should never happen
		if(item->m_root.empty())
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "Process root of pid %ld is empty, skipping ", item->m_pid);
			continue;
		}

		auto container = req.add_containers();
		container->set_id(item->m_container_id);
		container->set_pid(item->m_pid);
		container->set_vpid(item->m_vpid);
		container->set_root(item->m_root);
	}

	// Add host
	auto host = req.add_containers();
	host->set_id("host");
	host->set_pid(1U);
	host->set_vpid(1U);
	host->set_root("/");

	auto req_s = req.SerializeAsString();
	return m_output.send(req_s);
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_proxy::send_container_list not implemented on Windows");
#endif
}

mounted_fs_reader::mounted_fs_reader(sinsp* inspector, bool remotefs, const mount_points_filter_vec& filters, unsigned mounts_limit_size):
	m_input("/sdc_mounted_fs_reader_in", posix_queue::direction_t::RECEIVE),
	m_output("/sdc_mounted_fs_reader_out", posix_queue::direction_t::SEND),
	// for genric fs reader, fetch new data any time it's requested
#ifndef CYGWING_AGENT
	m_procfs_parser(0, 0, true, 0, 0),
#else
	m_procfs_parser(inspector, 0, 0, true, 0, 0),
#endif
	m_remotefs(remotefs)
{
	g_logger.add_stderr_log();
	m_procfs_parser.read_mount_points(make_shared<mount_points_limits>(filters, mounts_limit_size));
}

int mounted_fs_reader::open_ns_fd(int pid)
{
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, sizeof(filename), "%s/proc/%d/ns/mnt", scap_get_host_root(), pid);
	return open(filename, O_RDONLY);
}

bool mounted_fs_reader::change_ns(int destpid)
{
#ifndef CYGWING_AGENT
	g_logger.format(sinsp_logger::SEV_DEBUG, "Set to ns pid %d", destpid);
	// Go to container mnt ns
	auto fd = open_ns_fd(destpid);
	if(fd <= 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Cannot open namespace fd for pid=%d", destpid);
		return false;
	}
	if(setns(fd, CLONE_NEWNS) != 0)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "Cannot setns to pid=%d", destpid);
		close(fd);
		return false;
	}
	close(fd);
	return true;
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_reader::change_ns not implemented on Windows");
#endif
}

int mounted_fs_reader::run()
{
#ifndef CYGWING_AGENT
	auto pid = getpid();
	g_logger.format(sinsp_logger::SEV_INFO, "Starting mounted_fs_reader with pid %u", pid);
	int home_fd = 0;
	if(getppid() == 1)
	{
		// If `--pid host` is not used, we take the mnt from /proc
		// as we don't know our hostpid
		char filename[SCAP_MAX_PATH_SIZE];
		snprintf(filename, sizeof(filename), "/proc/%d/ns/mnt", pid);
		home_fd = open(filename, O_RDONLY);
	}
	else
	{
		home_fd = open_ns_fd(pid);
	}

	if(home_fd <= 0)
	{
		return DONT_RESTART_EXIT;
	}

	// The procedure of traversing containers and their mounted file systems (the loop below) requires changing
	// namespace (and perhaps the root directory) of the agent/mounted_fs_reader to the one of a container. When examining
	// of a mounted file system is over, a step back to the home namespace and it's root directory is performed.
	// Executing `setns` to the home namespace together with `chroot` to the original root directory and then `chdir` is
	// sufficient in most cases to switch back.
	// However, there are situations like in case of Rkt containers when this is not good enough to break the root jail
	// (made by Rkt). To force jail break, there is an initial `setns` to the home namespace (which resets the root
	// directory) and then subsequent calls to `chroot` and `chdir` to set the real root directory. Since the purpose of
	// this trick is not obvious, it should be considered for refactoring in the future.

	if (setns(home_fd, CLONE_NEWNS) != 0)
	{
		g_logger.log("Error on setns home, exiting", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	};

	char root_dir[PATH_MAX];
	string root_dir_link = "/proc/" + to_string(getppid()) + "/root";
	ssize_t root_dir_sz = readlink(root_dir_link.c_str(), root_dir, PATH_MAX - 1);
	if (root_dir_sz <= 0)
	{
		g_logger.log("Cannot read root directory.", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	}
	else
		root_dir[root_dir_sz] = '\0';

	if (chroot(root_dir) < 0)
	{
		g_logger.log("Cannot set root directory.", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	}
	if (chdir("/") < 0)
	{
		g_logger.log("Cannot change to root directory.", sinsp_logger::SEV_ERROR);
		return ERROR_EXIT;
	}

	while(true)
	{
		// Send heartbeat
		send_subprocess_heartbeat();
		auto request_s = m_input.receive(1);
		if(!request_s.empty())
		{
			sdc_internal::mounted_fs_request request_proto;
			if(request_proto.ParseFromString(request_s))
			{
				sdc_internal::mounted_fs_response response_proto;
				g_logger.format(sinsp_logger::SEV_DEBUG, "Look mounted_fs for %d containers", request_proto.containers_size());
				// g_logger.format(sinsp_logger::SEV_DEBUG, "Receive from dragent; %s", request_proto.DebugString().c_str());
				for(const auto& container_proto : request_proto.containers())
				{
					// Go to container mnt ns
					auto changed = change_ns(container_proto.pid());

					if(changed)
					{
						try
						{
							if(container_proto.root() != "/")
							{
								g_logger.format(sinsp_logger::SEV_DEBUG, "chroot to: %s", container_proto.root().c_str());
								auto res = chroot(container_proto.root().c_str());
								if(res != 0)
								{
									throw sinsp_exception(string("chroot on ") + container_proto.root() + " failed: " + strerror(errno));
								}
							}
							char filename[SCAP_MAX_PATH_SIZE];
							// Use mtab if it's not a symlink to /proc/self/mounts
							// Because when entering a mount namespace, we don't have
							// a self entry on /proc
							struct stat mtab_stat;
							if(lstat("/etc/mtab", &mtab_stat) == 0 && !S_ISLNK(mtab_stat.st_mode))
							{
								snprintf(filename, sizeof(filename), "/etc/mtab");
							}
							else
							{
								snprintf(filename, sizeof(filename), "/proc/%lu/mounts", container_proto.vpid());
							}
							auto fs_list = m_procfs_parser.get_mounted_fs_list(m_remotefs, filename);
							auto container_mounts_proto = response_proto.add_containers();
							container_mounts_proto->set_container_id(container_proto.id());
							for(const auto& fs : fs_list)
							{
								auto fsinfo = container_mounts_proto->add_mounts();
								fs.to_protobuf(fsinfo);
							}
						}
						catch (const sinsp_exception& ex)
						{
							g_logger.format(sinsp_logger::SEV_WARNING, "Exception for container=%s pid=%d: %s, vpid=%d", container_proto.id().c_str(), container_proto.pid(), ex.what(), container_proto.vpid());
						}
						// Back home
						if(setns(home_fd, CLONE_NEWNS) != 0)
						{
							g_logger.log("Error on setns home, exiting", sinsp_logger::SEV_ERROR);
							return ERROR_EXIT;
						};

						if (chroot(root_dir) < 0)
						{
							g_logger.log("Cannot set root directory.", sinsp_logger::SEV_ERROR);
							return ERROR_EXIT;
						}
						if (chdir("/") < 0)
						{
							g_logger.log("Cannot change to root directory.", sinsp_logger::SEV_ERROR);
							return ERROR_EXIT;
						}
					}
				}
				auto response_s = response_proto.SerializeAsString();
				m_output.send(response_s);
			}
		}
	}
#else
	ASSERT(false);
	throw sinsp_exception("mounted_fs_reader::run not implemented on Windows");
#endif
}
