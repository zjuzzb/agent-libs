/**
 * @file
 *
 * Interface to configuration_manager and configuration_unit.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>
#include <functional>

class yaml_configuration;
class configuration_unit;

/**
 * Manages all the individual configuration units.  It's expected that each
 * configuration_unit registers with the configuration manager upon construction
 * and deregisters with it on destruction.  Once registered, calls to
 * init_config or print_config will ensure that configuration_unit is accounted
 * for.
 */
namespace configuration_manager
{
	/*
	 * The print_config function enables clients to provide a logging
	 * function to invoke.  This is the type of that logging function.
	 */
	using log_delegate = std::function<void(const std::string&)>;

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
	bool is_registered(configuration_unit* config);
};
