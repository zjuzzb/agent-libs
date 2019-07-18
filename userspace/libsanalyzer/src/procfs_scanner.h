#pragma once

#include <Poco/Mutex.h>
#include <Poco/RWLock.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wextra"
#include <Poco/Timer.h>
#pragma GCC diagnostic pop

#include <unordered_map>
#include <set>
#include <atomic>

#include <unistd.h>
#include <stdio.h>

#include "async_key_value_source.h"
#include "utils/scoped_dir.h"

class sinsp_procfs_parser;

namespace proc_metrics {
struct mem_metrics {
	uint32_t vmsize_kb;
	uint32_t vmrss_kb;
	uint32_t vmswap_kb;
	unsigned long long pfmajor;
	unsigned long long pfminor;
};

typedef uint64_t pid_t;
typedef double jiffies_t;

namespace procfs_scanner_utils
{
	bool get_procfs_status(const char *text, const char *name, uint32_t *val);
	bool get_procfs_status_metrics(const std::string &path, mem_metrics *mem);
	bool get_procfs_stat_metrics(const std::string &path, jiffies_t *cpu_load, mem_metrics *mem);
}

struct load_map_value_t {
	jiffies_t raw; // the raw jiffies value read from procfs
	jiffies_t adjusted; // the value when adjusted for the previous readings
	mem_metrics mem;
};

typedef std::unordered_map<pid_t, load_map_value_t> load_map_t;


struct cpu_load_data_t {
	jiffies_t fetch_time;
	load_map_t load_map;
};

class procfs_scanner_cpu : public sysdig::async_key_value_source<std::string, std::shared_ptr<cpu_load_data_t>> {
public:
	procfs_scanner_cpu(const std::string& host_root, uint64_t ttl_s, sinsp_procfs_parser* parser) :
		// a ttl of 0 we'll use to indicate the user only wants synchronous results
		async_key_value_source<std::string, std::shared_ptr<cpu_load_data_t>>(ttl_s == 0 ? UINT64_MAX : 0, UINT64_MAX),
		m_nprocs(sysconf(_SC_NPROCESSORS_ONLN)),
		m_proc_root(host_root + "/proc/"),
		m_ttl_s(ttl_s),
		m_prev_data(std::make_shared<cpu_load_data_t>()),
		m_last_fetch_time(0),
		m_parser(parser)
	{
	}
	

	// threading nodes: both this method and the lookup method may be referring to the m_prev_data struct, with
	// the lookup method potentially changing it. This does not need to be synchronized, however.
	//
	// For there to be a race, async infra would have to be returning a new value to the lookup. That
	// can't happen at the same time that the async infra is fetching a new value. Assuming calls
	// to our lookup function are single threaded (which they are), then we can't both be in
	// this function AND have a successful lookup happen at the same time.
	void run_impl();

	// returns the load data. Data is always valid, but may be incomplete
	// if initial fetch is not done yet. If data is too old, it's
	// still returned and a new fetch is started
	std::shared_ptr<cpu_load_data_t> get_data();


private:
	const std::string m_kv_key = "procfs_cpu_load";
	const long m_nprocs;

	// host /proc mount point
	std::string m_proc_root;

	// amount of time we hold on to data before requesting new data
	uint64_t m_ttl_s;

	void scan_all_processes(cpu_load_data_t* load_data);
	void scan_process(load_map_t* load_map, uint64_t pid);

	std::shared_ptr<cpu_load_data_t> m_prev_data;
	uint64_t m_last_fetch_time;

	sinsp_procfs_parser* m_parser;
};


typedef std::unordered_map<pid_t, mem_metrics> mem_map_t;

class procfs_scanner_mem : public sysdig::async_key_value_source<std::string, std::shared_ptr<mem_map_t>> {
public:
	procfs_scanner_mem(const std::string& host_root, uint64_t ttl_s) :
		async_key_value_source<std::string, std::shared_ptr<mem_map_t>>(ttl_s == 0 ? UINT64_MAX : 0, UINT64_MAX),
		m_nprocs(sysconf(_SC_NPROCESSORS_ONLN)),
		m_proc_root(host_root + "/proc/"),
		m_ttl_s(ttl_s),
		m_last_fetch_time(0)
	{
		m_prev_data = std::make_shared<mem_map_t>();
	}
	

	void run_impl();
	std::shared_ptr<mem_map_t> get_data();

private:
	const std::string m_kv_key = "procfs_cpu_load";
	const long m_nprocs;

	// host /proc mount point
	std::string m_proc_root;

	// amount of time we hold on to data before requesting new data
	uint64_t m_ttl_s;

	void scan_all_processes(mem_map_t* mem_map);
	void scan_process(mem_map_t* mem_map, uint64_t pid);

	std::shared_ptr<mem_map_t> m_prev_data;
	uint64_t m_last_fetch_time;

};

}
