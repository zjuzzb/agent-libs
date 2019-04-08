#include "sinsp.h"
#include "sinsp_int.h"
#include "procfs_scanner.h"
#include "procfs_parser.h"

using namespace proc_metrics;

bool procfs_scanner_utils::get_procfs_status(const char *text, const char *name, uint32_t *val) {
	const char *pch = ::strstr(text, name);
	if (pch) {
		// assuming KB for value of name
		return (sscanf(pch + ::strlen(name), "%u", val) == 1);
	}

	return false;
}

bool procfs_scanner_utils::get_procfs_status_metrics(const string &path, mem_metrics *mem)
{
	std::ifstream f(path);
	if (!f)
	{
		return false;
	}

	std::stringstream sstream;
	sstream << f.rdbuf();
	string content = sstream.str();

	return
		get_procfs_status(content.c_str(), "VmSize:", &mem->vmsize_kb) &&
		get_procfs_status(content.c_str(), "VmRSS:", &mem->vmrss_kb) &&
		get_procfs_status(content.c_str(), "VmSwap:", &mem->vmswap_kb);
}

bool procfs_scanner_utils::get_procfs_stat_metrics(const string &path, jiffies_t *cpu_load, mem_metrics *mem)
{
	// we are looking for /proc/[PID]/stat entries [(14) utime %lu] and [(15) stime %lu],
	// see http://man7.org/linux/man-pages/man5/proc.5.html
	// the important bit here is that [(2) comm %s] may contain spaces, so sscanf is not bullet-proof;
	// we find the first closing paren (ie. skip the first two entries) and then extract desired values
	// from the rest of the line. so, (14) and (15), after adjustment for shift and zero-base, translates to (11) and (12)
	std::ifstream f(path);
	std::string line;

	if(!std::getline(f, line) || line.empty()) {
		return false;
	}

	std::string::size_type pos = line.find(')');
	if((pos == std::string::npos) || (pos >= line.size() - 1)) {
		return false;
	}

	unsigned long utime = 0, stime = 0;
	if(sscanf(line.c_str()+pos+1,
		// 3   4   5   6   7   8   9  10   11   12  13  14  15
		"%*s %*s %*s %*s %*s %*s %*s %llu %*s %llu %*s %lu %lu",
		&mem->pfminor,
		&mem->pfmajor,
		&utime,
		&stime) == 4)
	{
		*cpu_load = utime + stime;
		return true;
	}

	return false;
}

void procfs_scanner_cpu::scan_process(load_map_t* load_map, uint64_t pid)
{
	load_map_value_t values;

	string pathStat = m_proc_root + to_string((long long unsigned int) pid) + "/stat";
	if (!procfs_scanner_utils::get_procfs_stat_metrics(pathStat, &values.raw, &values.mem))
	{
		return;
	}

	load_map->insert({pid, values});
}

void procfs_scanner_cpu::scan_all_processes(cpu_load_data_t* load_data)
{
	load_data->fetch_time = m_parser->get_cpu_jiffies();

	// proc/pid/stat scanned every iteration;
	// proc/pid/status (for mem) may or may not be scanned.
	scoped_dir proc(m_proc_root.c_str());
	if (proc.m_directory == nullptr)
	{
		return; //shrug
	}

	struct dirent* de;

	while ((de = readdir(proc.m_directory)) != nullptr)
	{
		if (!isdigit(de->d_name[0]))
		{
			continue;
		}

		scan_process(&load_data->load_map, stoull(de->d_name));

	}
}

void procfs_scanner_cpu::run_impl()
{
	std::string key;
	while(dequeue_next_key(key))
	{
		ASSERT(key == m_kv_key);

		shared_ptr<cpu_load_data_t> new_data = make_shared<cpu_load_data_t>();
		scan_all_processes(&*new_data);

		jiffies_t delta = new_data->fetch_time - m_prev_data->fetch_time;

		for (auto& new_pid : new_data->load_map)
		{
			const auto& old_pid = m_prev_data->load_map.find(new_pid.first);
			if (old_pid != m_prev_data->load_map.end())
			{
				jiffies_t cpu_diff = (new_pid.second.raw - old_pid->second.raw) /  delta;
				if (cpu_diff >= 0) { //this probably won't happen?
					new_pid.second.adjusted = std::min(cpu_diff, 1.0) * 100 * m_nprocs;
				}
			}
		}


		// raw value of all procs stored
		// adjusted value stored for all procs that we had data for in consecutive fetches
		// fetch time stored
		store_value(m_kv_key, new_data);
	}
}

shared_ptr<cpu_load_data_t> procfs_scanner_cpu::get_data()
{
	// not too much time has passed, just return old data
	if (m_last_fetch_time + m_ttl_s > sinsp_utils::get_current_time_ns() / ONE_SECOND_IN_NS)
	{
		return m_prev_data;
	}

	// tried to fetch data, but no data yet
	shared_ptr<cpu_load_data_t> data;
	if (lookup(m_kv_key, data))
	{
		// got some
		m_prev_data = data;
		m_last_fetch_time = sinsp_utils::get_current_time_ns() / ONE_SECOND_IN_NS;
	}

	// in cases where lookup fails, we'll return old data
	return m_prev_data;

}

void procfs_scanner_mem::scan_process(mem_map_t* mem_map, uint64_t pid)
{
	mem_metrics mem;
	jiffies_t cputime;

	string pathStat = m_proc_root + to_string((long long unsigned int) pid) + "/stat";
	if (!procfs_scanner_utils::get_procfs_stat_metrics(pathStat, &cputime, &mem))
	{
		return;
	}

	string pathStatus = m_proc_root + to_string((long long unsigned int) pid) + "/status";
	if (!procfs_scanner_utils::get_procfs_status_metrics(pathStatus, &mem))
	{
		return;
	}

	mem_map->insert({pid, mem});
}

void procfs_scanner_mem::scan_all_processes(mem_map_t* mem_map)
{
	// proc/pid/stat scanned every iteration;
	// proc/pid/status (for mem) may or may not be scanned.
	scoped_dir proc(m_proc_root.c_str());
	if (proc.m_directory == nullptr)
	{
		return; // shrug.
	}

	struct dirent* de;

	while ((de = readdir(proc.m_directory)) != nullptr)
	{
		if (!isdigit(de->d_name[0]))
		{
			continue;
		}

		scan_process(mem_map, stoull(de->d_name));

	}
}

void procfs_scanner_mem::run_impl()
{
	std::string key;
	while(dequeue_next_key(key))
	{
		ASSERT(key == m_kv_key);

		shared_ptr<mem_map_t> new_data = make_shared<mem_map_t>();
		scan_all_processes(new_data.get());

		store_value(m_kv_key, new_data);
	}
}


shared_ptr<mem_map_t> procfs_scanner_mem::get_data()
{
	// not too much time has passed, just return old data
	if (m_last_fetch_time + m_ttl_s > sinsp_utils::get_current_time_ns() / ONE_SECOND_IN_NS)
	{
		return m_prev_data;
	}

	// tried to fetch data, but no data yet
	shared_ptr<mem_map_t> data;
	if (lookup(m_kv_key, data))
	{
		// got some
		m_prev_data = data;
		m_last_fetch_time = sinsp_utils::get_current_time_ns() / ONE_SECOND_IN_NS;
	}

	// in cases where lookup fails, we'll return old data
	return m_prev_data;
}

