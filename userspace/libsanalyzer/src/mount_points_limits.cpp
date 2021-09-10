#include "mount_points_limits.h"
#include "common_logger.h"
#include "sinsp.h"

COMMON_LOGGER();

//certain libs (cough-cough musl) don't support EXTMATCH. So we map it to something
//those patterns will unfortunately not work on binaries
#ifndef FNM_EXTMATCH
#define FNM_EXTMATCH 0
#endif


mount_points_limits::mount_points_limits(const mount_points_filter_vec& filters,
					 unsigned limit_size)
	: m_limit_size(limit_size), m_current_size(0)
{
	for (const auto& flt : filters)
	{
		std::vector<std::string> patterns = sinsp_split(flt.to_string(), '|');
		if (patterns.size() != 3)
		{
			LOG_WARNING("Mount points limits: exactly three patterns are required.");
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
			      std::vector<std::string> patterns = sinsp_split(f.to_string(), '|');
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
	if (limit_is_reached()){
		LOG_DEBUG("Max mount points limit reached.");
	}
}

void mount_points_limits::reset()
{
	m_current_size = 0;
}
