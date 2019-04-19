/**
 * @file
 *
 * Interface to type_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <string>
#include <sstream>
#include <type_traits>
#include <vector>

class yaml_configuration;

/**
 * The new configuration scheme provides an easy way of acquiring config values
 * from a central location without having to pass them around, and without the
 * central location needing to be aware of how to parse individual types.
 *
 * Usage:
 *
 * (in some cpp file)
 *
 * type_config<uint64_t> my_config_variable_name(some_default_value,
 *                                               "key_name_in_yaml")
 *
 * The data is automatically populated from the yaml, and can then be freely
 * used:
 *
 * my_config_variable_name.get()
 *
 * If you have a not-yet-supported type, you'll most likely get a compile error
 * saying it can't find "get_value_string<your_type>". If your type is a scalar,
 * then you'll simply need to implement that function. If it's specific to your
 * module, you should just do this in your module, otherwise, add it to the cpp
 * file here so it is shared.
 *
 * If your data type is NOT a scalar, then you'll likely need to implement your
 * own init function. It probably makes the most sense to derive directly from
 * configuration_unit
 *
 * NOTE: registering new keys is NOT thread safe, and thus should only be done
 * statically, which will guarantee us single-threadedness
 */
class configuration_unit
{
public:
	/**
	 * Our yaml interface has three levels of keys possible. If a given
	 * value only requries fewer values, set the other strings to "". This
	 * constructor should register this object with the configuration_manager
	 * class.
	 */
	configuration_unit(const std::string& key,
			   const std::string& subkey,
			   const std::string& subsubkey,
			   const std::string& description);
	virtual ~configuration_unit();

	/**
	 * Return a "key: value" representation of this config.
	 *
	 * Expected to generally be of the form
	 * key.subkey.subsubkey: value
	 * subkeys can be skipped if empty, and more complex config types may
	 * need to modify this format as they see fit
	 *
	 * @return the string conversion of this object
	 */
	std::string to_string() const;

	/**
	 * Returns a string representation of the value of this config.
	 */
	virtual std::string value_to_string() const = 0;

	/**
	 * Initializes the value stored in the raw config.
	 *
	 * @param raw_config the yaml_configuration containing the configuration
	 *                   data
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

	/** Returns the key for this configuration_unit. */
	const std::string& get_key() const;

	/** Returns the subkey for this configuration_unit. */
	const std::string& get_subkey() const;

	/** Returns the subsubkey for this configuration_unit. */
	const std::string& get_subsubkey() const;

	/** Returns the description for this configuration_unit. */
	const std::string& get_description() const;

protected:
	/**
	 * Returns a string representation for anything that std::to_string() can
	 * handle.
	 */
	template<typename value_type>
	static std::string get_value_string(const value_type& value)
	{
		return std::to_string(value);
	}

	/**
	 * Override of get_value_string() for type std::vector<value_type>.
	 *
	 * @returns a string representation of the given value_vector in the form
	 *          "[value1, value2, value3]"
	 */
	template<typename value_type>
	static std::string get_value_string(const std::vector<value_type>& value_vector)
	{
		std::stringstream out;

		out << "[";

		typename std::vector<value_type>::const_iterator i = value_vector.begin();

		if (i != value_vector.end())
		{
			out << get_value_string<value_type>(*i);

			for (++i; i != value_vector.end(); ++i)
			{
				out << ", " << get_value_string<value_type>(*i);
			}
		}

		out << "]";

		return out.str();
	}

private:
	const std::string m_key;
	const std::string m_subkey;
	const std::string m_subsubkey;
	const std::string m_description;
	std::string m_keystring;
};

/**
 * Specialization of get_value_string() for type bool.
 *
 * @returns "true" if the given value is true and "false" otherwise.
 */
template<>
inline std::string configuration_unit::get_value_string<bool>(const bool& value)
{
	return value ? "true" : "false";
}

/**
 * Specialization of get_value_string() for type string.
 *
 * @returns the given value.
 */
template<>
inline std::string configuration_unit::get_value_string<std::string>(const std::string& value)
{
	return value;
}


/**
 * An implementation of configuration_unit which supports scalar types.
 *
 * Typename can be an arbitrary type which yaml_configuration::get_scalar can
 * parse
 */
template<typename data_type>
class type_config : public configuration_unit
{
	static_assert(!std::is_same<data_type, uint8_t>::value,
	              "data_type = uint8_t is not supported");
	static_assert(!std::is_same<data_type, int8_t>::value,
	              "data_type = int8_t is not supported");
public:
	/**
	 * Our yaml interface has three levels of keys possible. If a given
	 * value only requries fewer values, set the other strings to "". This
	 * constructor should register this object with the configuration_manager
	 * class.
	 *
	 * The value of this config is set to the default at construction, and
	 * so will be valid, even if the yaml file has not been parsed yet.
	 */
	type_config(const data_type& default_value,
		    const std::string& description,
		    const std::string& key,
		    const std::string& subkey = "",
		    const std::string& subsubkey = "");

public: // stuff for configuration_unit
	std::string value_to_string() const override;
	void init(const yaml_configuration& raw_config) override;

public: // other stuff

	/**
	 * Returns a reference to the current value of this type_config.
	 *
	 * @return the value of this config
	 */
	data_type& get();

	/**
	 * Returns a const reference to the current value of this type_config.
	 *
	 * @return the value of this config
	 */
	const data_type& get() const;

private:
	const data_type m_default;
	data_type m_data;
};

#include "type_config.hpp"
