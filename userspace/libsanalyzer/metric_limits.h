#pragma once

#include <vector>
#include <unordered_map>
#include <string>
#include <ctime>
#include <cmath>

// introduce a macro (or inline function) like this and put it in a well-known place?
//
// there's a lot of debug/trace logging that's unnecessarily eating up
// production performance, mainly because string has to be constructed
// (and is often concatenated), only to be discarded
#ifdef HAS_ANALYZER
#define SINSP_LOG(M, L) if(g_logger.get_severity() >= sinsp_logger::L) \
                           g_logger.log(M, sinsp_logger::L);
#else
#define SINSP_LOG(M, L)
#endif // HAS_ANALYZER

class metric_limits
{
public:
	class entry
	{
	public:
#ifndef DENSE_HASH_MAP
		entry() = delete;
		entry(bool allow);
#else
		entry(bool allow = true);
#endif
		void set_allow(bool a = true);
		bool get_allow();
		double last_access() const;

	private:
		void access();

		bool m_allow = true;
		time_t m_access = 0;
	};

	typedef std::pair<std::string, bool> filter_pair_t;
	typedef std::vector<filter_pair_t> list_t;
#if defined (SPARSEPP_MAP)
	typedef spp::sparse_hash_map<std::string, entry> map_t;
#elif defined (DENSE_HASH_MAP)
	typedef google::dense_hash_map<std::string, entry> map_t;
#else
	typedef std::unordered_map<std::string, entry> map_t;
#endif

	metric_limits() = delete;
	metric_limits(const std::vector<std::string>& excluded,
				  const std::vector<std::string>& included,
				  uint64_t max_entries = 3000,
				  uint64_t expire_seconds = 86400);

	bool allow(const std::string& metric);
	bool has(const std::string& metric);
	uint64_t cached();
	void purge_cache();
	void clear_cache();
	uint64_t cache_max_entries() const;
	uint64_t cache_expire_seconds() const;

private:
	void insert(const std::string& metric, bool value);
	double last_purge() const;
	uint64_t purge_limit();

	double last_log() const;
	void log();

	list_t m_filters;
	map_t m_cache;
	uint64_t m_max_entries = 3000;
	time_t m_last_purge = 0;
	uint64_t m_purge_seconds = 86400; // 24hr
	time_t m_last_log = 0;
	const unsigned m_log_seconds = 300; // 5min
};

inline bool metric_limits::has(const std::string& metric)
{
	return (m_cache.find(metric) != m_cache.end());
}

inline uint64_t metric_limits::cached()
{
	purge_cache();
	return m_cache.size();
}

inline void metric_limits::clear_cache()
{
	m_cache.clear();
}

inline uint64_t metric_limits::purge_limit()
{
	return static_cast<uint64_t>(round((double)m_max_entries * 2 / 3));
}

inline double metric_limits::last_purge() const
{
	time_t now; time(&now);
	return difftime(now, m_last_purge);
}

inline double metric_limits::last_log() const
{
	time_t now; time(&now);
	return difftime(now, m_last_log);
}

inline uint64_t metric_limits::cache_max_entries() const
{
	return m_max_entries;
}

inline uint64_t metric_limits::cache_expire_seconds() const
{
	return m_purge_seconds;
}

inline metric_limits::entry::entry(bool allow): m_allow(allow)
{
	access();
}

inline void metric_limits::entry::set_allow(bool a)
{
	m_allow = a;
	access();
}

inline bool metric_limits::entry::get_allow()
{
	access();
	return m_allow;
}

inline void metric_limits::entry::access()
{
	time(&m_access);
}

inline double metric_limits::entry::last_access() const
{
	time_t now; time(&now);
	return difftime(now, m_access);
}
