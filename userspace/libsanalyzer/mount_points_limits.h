#pragma once

#include "filter_limits.h"

// filter used for mount points is same as for the metric limits
typedef std::vector<user_configured_filter> mount_points_filter_vec;

class mount_points_limits
{
public:

	typedef std::shared_ptr<mount_points_limits> sptr_t;

	mount_points_limits() = default;
	mount_points_limits(const mount_points_limits&) = delete;
	mount_points_limits(const mount_points_filter_vec& filters, unsigned limit_size);
	~mount_points_limits() = default;

	bool allow(const std::string& device,
				const std::string& fs_type,
				const std::string& mount_dir);
	void increase()
	{
		m_current_size++;
	}

	bool limit_is_reached() const 
	{
		return m_current_size >= m_limit_size;
	}
	
	void log_if_max_mount_limit_reached();

	void reset();
	mount_points_filter_vec get_filters() const { return m_filters; }

private:

	mount_points_filter_vec m_filters;
	const unsigned m_limit_size;
	unsigned m_current_size;
};
