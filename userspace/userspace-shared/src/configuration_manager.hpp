/**
 * @file
 *
 * Implementation of configuration_manager%'s template methods.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */

template<typename config_type>
const type_config<config_type>* configuration_manager::get_config(
		const std::string& name)
{
	config_map_t::const_iterator itr = m_config_map.find(name);
	const type_config<config_type>* config = nullptr;
	
	if(itr != m_config_map.end())
	{
		config = dynamic_cast<type_config<config_type>*>(itr->second);
	}

	if(config == nullptr)
	{
		printf("[%s]:%d: Warning: config should not be nullptr\n",
		       __FILE__,
		       __LINE__);
	}

	return config;
}
