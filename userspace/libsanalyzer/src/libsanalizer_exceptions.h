#pragma once
#include <stdexcept>

class cpu_num_detection_error : public std::runtime_error
{
public:
	explicit cpu_num_detection_error(const std::string& msg)
		: runtime_error(msg)
	{
	}

	virtual ~cpu_num_detection_error() noexcept
	{
	}
};
