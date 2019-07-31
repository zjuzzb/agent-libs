/**
 * @file
 *
 * Implementation of type_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "yaml_configuration.h"
#include <vector>
#include <sstream>

template<typename data_type>
type_config<data_type>::type_config(const data_type& default_value,
				    const std::string& description,
				    const std::string& key,
				    const std::string& subkey,
				    const std::string& subsubkey)
        : configuration_unit(key, subkey, subsubkey, description),
          m_default(default_value),
          m_data(default_value),
	  m_configured(default_value),
	  m_mutable_only_in_internal(false)
{
}

template<typename data_type>
void type_config<data_type>::init(const yaml_configuration& raw_config)
{

#ifndef SYSDIG_TEST
	// Some configuration params are only available on internal test builds.
	if(m_mutable_only_in_internal)
	{
		return;
	}
#endif

	/*
	 * This is a little tricky.  There are multiple sets of keys
	 * and multiple yamls (in raw_config) and we want the value from the
	 * first yaml which has any of the keys.
	 * So just brute force through all of the keys and pick whichever has
	 * a value in the yaml that takes the highest priority.
	 */
	const int PRIORITY_NOT_FOUND = -1;
	int current_data_priority = std::numeric_limits<int>::max();
	m_data = m_default;

	for(const config_key &key : keys())
	{
		data_type value = m_default;
		int priority = PRIORITY_NOT_FOUND;

		if (key.subkey.empty())
		{
			priority = raw_config.get_scalar_depth<data_type>(key.key,
									  value);
		}
		else if (key.subsubkey.empty())
		{
			priority = raw_config.get_scalar_depth<data_type>(key.key,
									  key.subkey,
									  value);
		}
		else
		{
			priority = raw_config.get_scalar_depth<data_type>(key.key,
									  key.subkey,
									  key.subsubkey,
									  value);
		}

		if (priority == PRIORITY_NOT_FOUND)
		{
			continue;
		}

		if (priority < current_data_priority)
		{
			// The lower the value, the higher the priority
			m_data = value;
			current_data_priority = priority;
		}
		else if (current_data_priority == priority)
		{
			const std::string message =
				get_key_string() + " and " + key.to_string() +
				" are alternate keys but exist in the same yaml file";
			throw yaml_configuration_exception(message);
		}
	}

	if (m_min && m_data < *m_min)
	{
		m_data = *m_min;
	}
	else if (m_max && m_data > *m_max)
	{
		m_data = *m_max;
	}

	m_configured = m_data;
}

template<typename data_type>
const data_type& type_config<data_type>::get() const
{
	return m_data;
}

template<typename data_type>
data_type& type_config<data_type>::get()
{
	return m_data;
}

template<typename data_type>
void type_config<data_type>::set(const data_type& value)
{
	m_data = value;
}

template<typename data_type>
const data_type& type_config<data_type>::configured() const
{
	return m_configured;
}

template<typename data_type>
std::string type_config<data_type>::value_to_string() const
{
	return get_value_string(m_data);
}

template<typename data_type>
bool type_config<data_type>::string_to_value(const std::string& value)
{
	return get_value(value, m_data);
}

template<typename data_type>
void type_config<data_type>::set_default(const data_type& value)
{
	m_default = value;
}

template<typename data_type>
void type_config<data_type>::min(const data_type& value)
{
	m_min.reset(new data_type(value));
}

template<typename data_type>
void type_config<data_type>::max(const data_type& value)
{
	m_max.reset(new data_type(value));
}

template<typename data_type>
void type_config<data_type>::post_init(const post_init_delegate& value)
{
	m_post_init = value;
}

template<typename data_type>
void type_config<data_type>::post_init()
{
	if(m_post_init)
	{
		m_post_init(*this);
	}
}

