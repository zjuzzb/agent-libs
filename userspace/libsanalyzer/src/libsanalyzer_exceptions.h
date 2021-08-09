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

class k8s_namespace_store_error : public std::runtime_error
{
public:
	explicit k8s_namespace_store_error(const std::string& msg)
		: runtime_error(msg)
	{
	}

	virtual ~k8s_namespace_store_error() noexcept
	{
	}
};


class persistent_state_error : public std::runtime_error
{
public:
	explicit persistent_state_error(const std::string& msg)
		: runtime_error(msg)
		  {
		  }

	virtual ~persistent_state_error() noexcept
	{
	}
};


class persistent_state_error_too_old : public persistent_state_error
{
public:
	explicit persistent_state_error_too_old(const std::string& msg)
		: persistent_state_error(msg)
	{
	}

	virtual ~persistent_state_error_too_old() noexcept
	{
	}
};
