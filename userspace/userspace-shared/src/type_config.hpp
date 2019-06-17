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

        if(get_subkey().empty())
        {
                m_data = raw_config.get_scalar<data_type>(get_key(), m_default);
        }
        else if(get_subsubkey().empty())
        {
		m_data = raw_config.get_scalar<data_type>(get_key(),
							  get_subkey(),
							  m_default);
        }
        else
        {
		m_data = raw_config.get_scalar<data_type>(get_key(),
							  get_subkey(),
							  get_subsubkey(),
							  m_default);
        }

	if(m_min && m_data < *m_min)
	{
		m_data = *m_min;
	}
	else if(m_max && m_data > *m_max)
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

