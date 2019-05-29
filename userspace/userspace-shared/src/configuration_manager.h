/**
 * @file
 * The new configuration scheme provides an easy way of acquiring config values from
 * a central location without having to pass them around, and without the central location
 * needing to be aware of how to parse individual types.
 *
 * Usage:
 *
 * (in some cpp file)
 *
 * type_config<uint64_t> my_config_variable_name(some_default_value,
 *                                               "description",
 *                                               "key_name_in_yaml");
 *
 * The data is automatically populated from the yaml, and can then be freely used:
 *
 * my_config_variable_name.get()
 *
 * Interface to configuration_manager and configuration_unit.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "type_config.h"
#include <string>
#include <functional>
#include <map>

class yaml_configuration;
class configuration_unit;

/**
 * Manages all the individual configuration units.  It's expected that each
 * configuration_unit registers with the configuration manager upon construction
 * and deregisters with it on destruction.  Once registered, calls to
 * init_config or print_config will ensure that configuration_unit is accounted
 * for.
 */
class configuration_manager
{
public:
	/*
	 * The print_config function enables clients to provide a logging
	 * function to invoke.  This is the type of that logging function.
	 */
	using log_delegate = std::function<void(const std::string&)>;

	/**
	 * Return the singleton instance of the configuration_manager.
	 *
	 * Why a singleton and not just have an all-static API?  Having a
	 * bonafide object is more flexible. With this, we can have a
	 * polymorphic configuration manager (e.g., if we decide to have a
	 * custom version of this for unit tests).  This also gives us the
	 * flexibility to make configuration_manager implement future
	 * interfaces.
	 */
	static configuration_manager& instance();

	/**
	 * Initializes each configuration_unit registered.
	 *
	 * @param raw_config the yaml_configuration containing all the data
	 */
	void init_config(const yaml_configuration& raw_config);

	/**
	 * Prints each configuration_unit registered.
	 */
	void print_config(const log_delegate& logger);

	/**
	 * Registers a configuration_unit to be inited/printed at the
	 * appropriate time.
	 *
	 * Config should be non-null and contain a non-zero length and unique
	 * keystring.  Registration is permanent, and all future calls to
	 * init_config/print_config will do work on this configuration unit.
	 *
	 * NOTE: NOT thread safe
	 *
	 * @param config the configuration unit which we want to register
	 */
	void register_config(configuration_unit* config);

	/**
	 * Deregisters the given configuration_unit.
	 */
	void deregister_config(configuration_unit* config);

	/**
	 * Returns true if the given config is registered, false otherwise.
	 */
	bool is_registered(configuration_unit *config);

	/**
	 * Get the config object with the given name.  If there is no config
	 * with the given name, or if the config with the given name isn't
	 * of the given config_type, then this will return nullptr.  Client
	 * code is responsible for ensuring that these parameters are correct.
	 *
	 * @tparam config_type The underlying type of the configuration's value
	 *
	 * @param[in] name The name (key) for the configuration.
	 */
	template<typename config_type>
	const type_config<config_type>* get_config(const std::string& name) const;

	/**
	 * Get the config object with the given name.  If there is no config
	 * with the given name, or if the config with the given name isn't
	 * of the given config_type, then this will return nullptr.  Client
	 * code is responsible for ensuring that these parameters are correct.
	 * Only use this if you need a non-const config.
	 *
	 * @tparam config_type The underlying type of the configuration's value
	 *
	 * @param[in] name The name (key) for the configuration.
	 */
	template<typename config_type>
	type_config<config_type>* get_mutable_config(const std::string& name);

	/**
	 * Generate a yaml from the registered configuration.
	 */
	std::string to_yaml() const;
private:
	using config_map_t = std::map<std::string, configuration_unit*>;

	// Prevent clients from creating copies, deleting, assigning, etc.
	configuration_manager() = default;
	~configuration_manager() = default;
	configuration_manager(const configuration_manager& rhs) = delete;
	configuration_manager(const configuration_manager&& rhs) = delete;
	configuration_manager& operator=(const configuration_manager& rhs) = delete;
	configuration_manager& operator=(const configuration_manager&& rhs) = delete;

	config_map_t m_config_map;
};

#include "configuration_manager.hpp"
