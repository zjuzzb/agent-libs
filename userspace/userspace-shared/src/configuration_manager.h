#pragma once
#include "yaml_configuration.h"

/**
 * The new configuration scheme provides an easy way of acquiring config values from
 * a central location without having to pass them around, and without the central location
 * needing to be aware of how to parse individual types.
 *
 * Usage:
 *
 * (in some cpp file)
 *
 * type_config<uint64_t> my_config_variable_name(some_default_value, "key_name_in_yaml")
 *
 * The data is automatically populated from the yaml, and can then be freely used:
 *
 * my_config_variable_name.get()
 *
 * If you have a not-yet-supported type, you'll most likely get a compile error saying it
 * can't find "type_config<your_type>::to_string". If your type is a scalar, then you'll
 * simply need to implement that function. If it's specific to your module, you should just
 * do this in your module, otherwise, add it to the cpp file here so it is shared.
 *
 * If your data type is NOT a scalar, then you'll likely need to implement your own
 * init function. It probably makes the most sense to derive directly from configuration_unit
 *
 * NOTE: registering new keys is NOT thread safe, and thus should only be done statically, which
 * will guarantee us single-threadedness
 */


/**
 * Base class that represents a single unit of configuration. Must be derived from in
 * order to implement type-specific functions.
 */
class configuration_unit
{
public:
	/**
	 * Our yaml interface has three levels of keys possible. If a given value only
	 * requries fewer values, set the other strings to "". This constructor
	 * should register this object with the configuration_manager class.
	 */
	configuration_unit(const std::string& key,
			   const std::string& subkey,
			   const std::string& subsubkey,
			   const std::string& description);

	/**
	 * Prints the value stored by this config.
	 *
	 * Expected to generally be of the form
	 * key.subkey.subsubkey: value
	 * subkeys can be skipped if empty, and more complex config types may need
	 * to modify this format as they see fit
	 *
	 * @return the string conversion of this object
	 */
	virtual std::string to_string() const = 0;

	/**
	 * Initializes the value stored in the raw config.
	 *
	 * @param raw_config the yaml_configuration containing the configuration data
	 */
	virtual void init(const yaml_configuration& raw_config) = 0;
	
	/**
	 * Return the canonical string for the config.
	 *
	 * key_string will be of the form:
	 * key | key.subkey | key.subkey.subsubkey
	 *
	 * @return the canonical string for the config
	 */
	const std::string& get_key_string() const;

protected:
	std::string m_key;
	std::string m_subkey;
	std::string m_subsubkey;
	std::string m_description;
	std::string m_keystring;
};

/**
 * An implementation of configuration_unit which supports scalar types.
 *
 * Typename can be an arbitrary type which yaml_configuration::get_scalar can parse
 */
template<typename data_type>
class type_config : public configuration_unit
{
public:
	/**
	 * Our yaml interface has three levels of keys possible. If a given value only
	 * requries fewer values, set the other strings to "". This constructor
	 * should register this object with the configuration_manager class.
	 *
	 * The value of this config is set to the default at construction, and so will
	 * be valid, even if the yaml file has not been parsed yet.
	 */
	type_config(const data_type& default_value,
		    const std::string& description,
		    const std::string& key,
		    const std::string& subkey = "",
		    const std::string& subsubkey = "");

public: // stuff for configuration_unit
	std::string to_string() const override;
	void init(const yaml_configuration& raw_config) override;

public: // other stuff

	/**
	 * Will return default value unless otherwise updated or initialized to something else.
	 *
	 * @return the value of this config
	 */
	virtual data_type& get();

	/**
	 * Will return default value unless otherwise updated or initialized to something else.
	 * @return the value of this config
	 *
	 */
	virtual const data_type& get_const() const;

private:
	const data_type m_default;
	data_type m_data;
};

#include "type_config.hpp"

/**
 * "singleton" class which manages all the individual configuration units.
 * It's expected that each configuration_unit registers with this class upon construction.
 * Once registered, calls to init_config or print_config will ensure that configuration_unit
 * is accounted for.
 */
class configuration_manager
{
public:
	/**
	 * Initializes each configuration_unit registered.
	 *
	 * @param raw_config the yaml_configuration containing all the data
	 */
	static void init_config(const yaml_configuration& raw_config);

	using log_delegate=std::function<void(const std::string&)>;
	/**
	 * Prints each configuration_unit registered.
	 */
	static void print_config(const log_delegate& logger);

	/**
	 * Registers a configuration_unit to be inited/printed at the appropriate time.
	 *
	 * Config should be non-null and contain a non-zero length and unique keystring.
	 * Registration is permanent, and all future calls to init_config/print_config
	 * will do work on this configuration unit.
	 *
	 * NOTE: NOT thread safe
	 *
	 * @param config the configuration unit which we want to register
	 */
	static void register_config(configuration_unit* config);
private:
	/**
	 * fetches the backing map, allocating it if it doesn't exist
	 *
	 * NOT thread safe
	 */
	static std::map<std::string, configuration_unit*>& get_map();

	static std::map<std::string, configuration_unit*>* config_map;
};
