/**
 * @file
 *
 * Implementation of configuration_manager%'s template methods.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */

template<typename config_type>
const type_config<config_type>* configuration_manager::get_config(
		const std::string& name) const
{
	const configuration_unit* const config_unit = get_configuration_unit(name);
	const type_config<config_type>* config = nullptr;
	
	if(config_unit != nullptr)
	{
		config = dynamic_cast<const type_config<config_type>*>(config_unit);
	}
	
	if(config == nullptr)
	{
		printf("[%s]:%d: Warning: config \"%s\" should not be nullptr\n",
		       __FILE__,
		       __LINE__,
		       name.c_str());
	}

	return config;
}

template<typename config_type>
type_config<config_type>* configuration_manager::get_mutable_config(
   const std::string& name)
{
	configuration_unit* config_unit = get_mutable_configuration_unit(name);
	type_config<config_type>* config = nullptr;
	
	if(config_unit != nullptr)
	{
		config = dynamic_cast<type_config<config_type>*>(config_unit);
	}
	
	if(config == nullptr)
	{
		printf("[%s]:%d: Warning: config \"%s\" should not be nullptr\n",
		       __FILE__,
		       __LINE__,
		       name.c_str());
	}

	return config;
}
