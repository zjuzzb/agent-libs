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
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

using namespace std;
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

// If we end up scanning multiple processes within a namespace we may want
// to start caching port info per namespace like sysdig does
int sinsp_procfs_parser::add_ports_from_proc_fs(string fname, const set<uint16_t> &oldports, set<uint16_t> &ports, const std::set<uint64_t> &inodes)
{
	int added = 0;
	const int max_socks = 1000;
	FILE *fp;
	char buf[1024];

	fp = fopen(fname.c_str(), "r");
	if (!fp)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "procfs port scan: Failed to open %s for server port scan", fname.c_str());
		return 0;
	}
	g_logger.format(sinsp_logger::SEV_TRACE, "procfs port scan: scanning %s", fname.c_str());

	int socks = 0;

	for (; socks < max_socks && fgets(buf, sizeof(buf), fp); socks++)
	{
		char *token[10];
		char *tokptr, *nextptr;
		uint64_t inode;

		// Skip first line (table header)
		if (!socks)
			continue;

		// Tokenize the first 10 tokens (last should be inode)
		int ti;
		tokptr = strtok_r(buf, " ", &nextptr);
		for (ti = 0; ti < 10 && tokptr; ti++, tokptr = strtok_r(NULL, " ", &nextptr))
		{
			token[ti] = tokptr;
		}
		if (ti < 10)
		{
			g_logger.format(sinsp_logger::SEV_DEBUG, "procfs port scan: %s: Only found %d tokens", fname.c_str(), ti);
			// Didn't find inode
			continue;
		}

		char *end;
		inode = (uint64_t)strtoull(token[9], &end, 10);
		if (end == token[9])
		{
			// token[9] didn't contain digits.
			g_logger.format(sinsp_logger::SEV_DEBUG, "procfs port scan: %s: token %s has no digits", fname.c_str(), token[9]);
			continue;
		}

		if (inodes.find(inode) == inodes.end())
		{
			// Inode isn't in the set of inodes we're looking for
			continue;
		}

		// Get remote address, should end at ':' delimiting the port number
		uint64_t addr = (uint64_t)strtoull(token[2], &end, 16);

		if (addr != 0)
		{
			// Skip sockets with a remote address, we're only interested in
			// ports we're just listening on.
			continue;
		}

		// Get local address, should end at ':' delimiting the port number
		addr = (uint64_t)strtoull(token[1], &end, 16);

		if (!end || *end != ':')
		{
			// Address didn't end on ':', shouldn't happen
			g_logger.format(sinsp_logger::SEV_DEBUG, "procfs port scan: %s: address %s ends on %c", fname.c_str(), token[2], *end);
			continue;
		}

		uint32_t port = (uint32_t)strtoul(end+1, NULL, 16);
		if (!port)
		{
			// Local port is 0, shouldn't happen
			g_logger.format(sinsp_logger::SEV_DEBUG, "procfs port scan: %s: local port is %d, parsed from %s", fname.c_str(), port, end ? end+1 : "NULL");
			continue;
		}
		if (oldports.find(port) == oldports.end())
		{
			ports.emplace(port);
			g_logger.format(sinsp_logger::SEV_DEBUG, "procfs port scan: Added port %d from %s", port, fname.c_str());
			added++;
		}
	}

	fclose(fp);

	if (socks == max_socks) {
		g_logger.format(sinsp_logger::SEV_INFO, "procfs port scan: Stopped reading sockets from %s after %d lines", fname.c_str(), socks);
	}
	return added;
}

int sinsp_procfs_parser::read_process_serverports(int64_t pid, const set<uint16_t> &oldports, set<uint16_t> &ports)
{
	int added = 0;
	string proc_dir = string(scap_get_host_root()) + "/proc/" + to_string(pid);
	string fd_dir = proc_dir + "/fd";
	string ns_link = proc_dir + "/ns/net";
	char link_name[SCAP_MAX_PATH_SIZE];
	DIR *dir_p = nullptr;
	struct dirent *dir_entry_p = nullptr;
	uint64_t net_ns = 0;

	// Get set of inodes from /proc/<pid>/fd/*
	dir_p = opendir(fd_dir.c_str());
	if(dir_p == NULL)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "procfs port scan: Failed to open %s for server port scan", fd_dir.c_str());
		return added;
	}

	std::set<uint64_t> inodes;
	while((dir_entry_p = readdir(dir_p)) != NULL)
	{
		uint64_t inode;
		string f_name = fd_dir + "/" + dir_entry_p->d_name;

		ssize_t r = readlink(f_name.c_str(), link_name, sizeof(link_name));
		if ((r > 0) && (sscanf(link_name, "socket:[%" PRIi64 "]", &inode) == 1))
		{
			inodes.emplace(inode);
		}
	}
	closedir(dir_p);

	// Get the network namespace of the process
	ssize_t r = readlink(ns_link.c_str(), link_name, sizeof(link_name));
	if(r <= 0)
	{
		// No network namespace available. Assume global
		net_ns = 0;
	}
	else
	{
		link_name[r] = '\0';
		if (sscanf(link_name, "net:[%" PRIi64 "]", &net_ns) != 1)
		{
			g_logger.format(sinsp_logger::SEV_INFO, "procfs port scan: Malformed net namespace %s for pid %" PRIi64 ", assuming host namespace", link_name, pid);
		}
	}

	// If namespaces are supported look in /proc/<pid>/net/
	// if not look in /proc/net/
	string netdir = net_ns ? proc_dir + "/net" : string(scap_get_host_root()) + "/proc/net";

	// Only looking for tcp sockets for now
	added += add_ports_from_proc_fs(netdir + "/tcp", oldports, ports, inodes);
	added += add_ports_from_proc_fs(netdir + "/tcp6", oldports, ports, inodes);

	return added;
}
