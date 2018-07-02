#include "mount_points_limits.h"

mount_points_limits::mount_points_limits(const mount_points_filter_vec& filters,
					 unsigned limit_size)
	: m_limit_size(limit_size), m_current_size(0), m_limit_logged(false)
{
	for (const auto& flt : filters)
	{
		vector<string> patterns = sinsp_split(flt.to_string(), '|');
		if (patterns.size() != 3)
		{
			g_logger.log("Mount points limits: exactly three patterns are required.", sinsp_logger::SEV_WARNING);
			continue;
		}
		m_filters.push_back(flt);
	}
}

bool mount_points_limits::allow(const std::string& device,
				const std::string& fs_type,
				const std::string& mount_dir)
{
#ifndef CYGWING_AGENT
	auto filter_it = std::find_if(m_filters.begin(), m_filters.end(),
			      [&](const user_configured_filter& f) -> bool {
			      vector<string> patterns = sinsp_split(f.to_string(), '|');
			      return fnmatch(patterns[0].c_str(), device.c_str(), FNM_EXTMATCH) == 0 &&
				      fnmatch(patterns[1].c_str(), fs_type.c_str(), FNM_EXTMATCH) == 0 &&
				      fnmatch(patterns[2].c_str(), mount_dir.c_str(), FNM_EXTMATCH) == 0;
				      });

	if (filter_it != m_filters.end())
	{
		if (!filter_it->included())
			return false;
	}
#endif

	return true;
}

void mount_points_limits::log_if_max_mount_limit_reached()
{
	if (!m_limit_logged && limit_is_reached()){
		g_logger.log("Max mount points limit reached.", sinsp_logger::SEV_DEBUG);
		m_limit_logged = true;
	}
}

void mount_points_limits::reset()
{
	m_current_size = 0;
	m_limit_logged = false;
}
