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
          m_data(default_value)
{
}

template<typename data_type>
void type_config<data_type>::init(const yaml_configuration& raw_config)
{
        if (get_subkey().empty())
        {
                m_data = raw_config.get_scalar<data_type>(get_key(), m_default);
        }
        else if (get_subsubkey().empty())
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
}

template<typename data_type>
data_type& type_config<data_type>::get()
{
        return m_data;
}

template<typename data_type>
const data_type& type_config<data_type>::get() const
{
        return m_data;
}

template<typename data_type>
std::string type_config<data_type>::value_to_string() const
{
	return get_value_string(m_data);
}
