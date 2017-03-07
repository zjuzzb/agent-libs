#pragma once

#include <vector>
#include <unordered_map>
#include <string>
#include <ctime>

class metric_limits
{
public:
	class entry
	{
	public:
		entry() = delete;
		entry(bool allow);

		void set_allow(bool a = true);
		bool get_allow();
		double last_access() const;

	private:
		void access();

		bool m_allow = true;
		time_t m_access = 0;
	};

	typedef std::vector<std::string> list_t;
	typedef std::unordered_map<std::string, entry> map_t;

	metric_limits() = delete;
	metric_limits(const list_t& excluded,
				  const list_t& included,
				  uint64_t max_entries = 3000,
				  uint64_t expire_seconds = 86400);

	bool allow(const std::string& metric);
	bool has(const std::string& metric);
	uint64_t cached();
	void purge_cache();

private:
	void insert(const std::string& metric, bool value);

	const list_t& m_excluded;
	const list_t& m_included;
	map_t m_cache;
	uint64_t m_max_entries = 3000;
	uint64_t m_expire_seconds = 86400;
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

inline void metric_limits::insert(const std::string& metric, bool value)
{
	purge_cache();
	if(m_cache.size() < m_max_entries)
	{
		m_cache.insert({metric, entry(value)});
	}
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
