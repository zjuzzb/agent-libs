/**
 * @file
 *
 * Implementation of configuration_manager and configuration_unit.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "configuration_manager.h"
#include "type_config.h"
#include <assert.h>
#include <map>
#include <json/json.h>

namespace
{

configuration_manager* s_instance = nullptr;

} // end namespace


configuration_manager& configuration_manager::instance()
{
	if(s_instance == nullptr)
	{
		s_instance = new configuration_manager();
	}

	return *s_instance;
}

void configuration_manager::init_config(const yaml_configuration& raw_config)
{
	for (const auto& config : m_config_map)
	{
		config.second->init(raw_config);
	}

	for(const auto& config : m_config_map)
	{
		config.second->post_init();
	}
}

void configuration_manager::print_config(const log_delegate& logger)
{
	for (const auto& config : m_config_map)
	{
		if(!config.second->hidden())
		{
			logger(config.second->to_string());
		}
	}
}

void configuration_manager::register_config(configuration_unit* config)
{
	if (config == nullptr || config->get_key_string().size() == 0)
	{
		assert(false);
		return;
	}

	if (m_config_map.find(config->get_key_string()) != m_config_map.end())
	{
		assert(false);
		return;
	}

	m_config_map.emplace(config->get_key_string(), config);
}

void configuration_manager::deregister_config(configuration_unit* config)
{
	if (config == nullptr || config->get_key_string().size() == 0)
	{
		return;
	}

	m_config_map.erase(config->get_key_string());
}

bool configuration_manager::is_registered(configuration_unit* config)
{
	return m_config_map.find(config->get_key_string()) != m_config_map.end();
}

std::string configuration_manager::to_yaml() const
{
	std::string yaml;
	yaml.reserve(1024);

	const std::string *previous_key = nullptr;
	const std::string *previous_subkey = nullptr;
	const std::string *previous_subsubkey = nullptr;

	for(const auto& value : m_config_map)
	{
		const configuration_unit &config = *value.second;

		if(!previous_key || config.get_key() != *previous_key)
		{
			yaml += "\n" + config.get_key() + ":";
			previous_key = &config.get_key();
			previous_subkey = nullptr;
			previous_subsubkey = nullptr;
		}

		if(!config.get_subkey().empty())
		{
			if(!previous_subkey || config.get_subkey() != *previous_subkey)
			{
				yaml += "\n  " + config.get_subkey() + ":";
				previous_subkey = &config.get_subkey();
				previous_subsubkey = nullptr;
			}
		}

		if(!config.get_subsubkey().empty())
		{
			if(!previous_subsubkey || config.get_subsubkey() != *previous_subsubkey)
			{
				previous_subsubkey = &config.get_subsubkey();
				yaml += "\n    " + config.get_subsubkey() + ":";
			}
		}

		yaml += " " + config.value_to_string();
	}

	yaml += "\n";
	return yaml;
}

std::string configuration_manager::to_json() const
{
	Json::Value result;
	Json::Value config_list;
	int i = 0;

	for(const auto& itr : m_config_map)
	{
		Json::Value value;
		Json::Reader reader;

		if(reader.parse(itr.second->to_json(), value))
		{
			config_list[i++] = value;
		}
		else
		{
			fprintf(stderr,
			        "[%s]:%d: Failed to parse '%s' into JSON",
			        __FUNCTION__,
			        __LINE__,
			        itr.second->to_json().c_str());
		}
	}

	result["configs"] = config_list;

	return result.toStyledString();
}

const configuration_unit* configuration_manager::get_configuration_unit(
		const std::string& name) const
{
	configuration_unit* config = nullptr;
	config_map_t::const_iterator itr = m_config_map.find(name);
	
	if(itr != m_config_map.end())
	{
		config = itr->second;
	}

	if(config == nullptr)
	{
		printf("[%s]:%d: Warning: config should not be nullptr\n",
		       __FILE__,
		       __LINE__);
	}

	return config;
}

configuration_unit* configuration_manager::get_mutable_configuration_unit(
		const std::string& name)
{
	configuration_unit* config = nullptr;
	config_map_t::const_iterator itr = m_config_map.find(name);
	
	if(itr != m_config_map.end())
	{
		config = itr->second;
	}

	if(config == nullptr)
	{
		printf("[%s]:%d: Warning: config should not be nullptr\n",
		       __FILE__,
		       __LINE__);
	}

	return config;
}
