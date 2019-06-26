/**
 * @file
 *
 * Interface to type_config.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <memory>
#include <string>
#include <sstream>
#include <type_traits>
#include <vector>
#include <functional>

class yaml_configuration;

/**
 * This configuration scheme provides an easy way of acquiring
 * config values from a central location without having to pass
 * them around, and without the central location needing to be
 * aware of how to parse individual types.
 *
 * Usage:
 *
 * (in some cpp file)
 *
 * type_config<uint64_t> my_config_variable_name(some_default_value,
 *                                               "key_name_in_yaml");
 *
 * OR if using the optional fields (like min and max)
 *
 *
 * type_config<uint64_t>::ptr  my_config_variable_name =
 *      type_config_builder<int>(some_default_value, "key_name_in_yaml")
 *          .min(10).max(50).get();
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
	 * value requires fewer values, set the other strings to "".
	 * This constructor should register this object with the
	 * configuration_manager class.
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

	/** Stop this configuration value from showing up in logs */
	void hidden(bool value);

	/** Returns whether the value is hidden from logs */
	bool hidden() const;

	/** Called after all configuration params have been init'd */
	virtual void post_init() = 0;

	/**
	 * Returns a JSON-formatted representation of this configuration_unit.
	 */
	std::string to_json() const;

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
	bool m_hidden;
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
	using ptr = std::shared_ptr<const type_config<data_type>>;
	using mutable_ptr = std::shared_ptr<type_config<data_type>>;

	/**
	 * Our yaml interface has three levels of keys possible. If a given
	 * value only requires fewer values, set the other strings to "". This
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

	/**
	 * sets the value of this config to input value
	 */
	virtual void set(const data_type& value);

	/**
	 * Returns a const reference to the current value of this type_config.
	 *
	 * @return the value of this config
	 */
	const data_type& get() const;

	/**
         * Returns a non-const reference to the current value of this
         * type_config.
         *
         * @return the value of this config
         */
        data_type& get();

public: // other stuff
	/**
	 * Returns a the value configured in the yaml (or the default).
	 * This is useful to get what the value was before the
	 * post_init() function changes the value.
	 *
	 * @return the value of this config
	 */
	const data_type& configured() const;

	/**
	 * sets a new default value. While it shouldn't be common,
	 * is required for a very small number of configs that have their default
	 * value determined dynamically.
	 */
	void set_default(const data_type& value);

	/**
	 * Set the minimum value.
	 */
	void min(const data_type& value);

	/**
	 * Set the maximum value.
	 */
	void max(const data_type& value);

	/**
	 * Set whether the param can be changed from the default outside
	 * of an internal build
	 */
	void mutable_only_in_internal_build(bool value) { m_mutable_only_in_internal = value; }

	/**
	 * Get whether the param can be changed from the default outside of an
	 * internal build
	 */
	bool mutable_only_in_internal_build() { return m_mutable_only_in_internal; }

	/**
	 * Set the post_init delegate. This allows the configuration
	 * value to be changed after all init functions are called for
	 * all configuration parameters. This is useful if one value
	 * depends on another.
	 */
	using post_init_delegate = std::function<void(type_config<data_type> &)>;
	void post_init(const post_init_delegate& value);

	/**
	 *  Call the post_init delegate if it was provided
	 */
	void post_init() override;

private:
	data_type m_default;
	data_type m_data;

	data_type m_configured;
	bool m_mutable_only_in_internal;

	// Using unique_ptr in lieu of std::optional
	std::unique_ptr<data_type> m_min;
	std::unique_ptr<data_type> m_max;
	post_init_delegate m_post_init;

	friend class test_helper;
};

/**
 * Helper to create a (usually static) instance of an
 * type_config by calling functions to set the appropriate
 * characteristics. This keeps us from having many different
 * constructors for the type_config
 */
template<typename data_type>
class type_config_builder
{
public:
	type_config_builder(const data_type& default_value,
			    const std::string& description,
			    const std::string& key,
			    const std::string& subkey = "",
			    const std::string& subsubkey = "") :
	   m_type_config(new type_config<data_type>(default_value, description, key, subkey, subsubkey))
	{}

	/**
	 * Set the max configuration value
	 */
	type_config_builder& max(const data_type& value)
	{
		m_type_config->max(value);
		return *this;
	}

	/**
	 * Set the min configuration value
	 */
	type_config_builder& min(const data_type& value)
	{
		m_type_config->min(value);
		return *this;
	}

	/**
	 * Keep the config from showing up in logs
	 */
	type_config_builder& hidden()
	{
		m_type_config->hidden(true);
		return *this;
	}

	/**
	 * Only allow the default value to be overridden in an internal test
	 * build
	 */
	type_config_builder& mutable_only_in_internal_build()
	{
		m_type_config->mutable_only_in_internal_build(true);
		return *this;
	}

	/**
	 * Set a delegate that will be called after all of the
	 * configurables are init'd. This is useful if one config
	 * depends on another.
	 */
	type_config_builder& post_init(const typename type_config<data_type>::post_init_delegate& value)
	{
		m_type_config->post_init(value);
		return *this;

	}

	/**
	 * Return the generated instance
	 */
	typename type_config<data_type>::ptr get()
	{
		return m_type_config;
	}

	/**
	 * Return a mutable version of the generated instance. Since
	 * these configs are meant to only be changed during static
	 * init, make sure you know what you are doing if you use this.
	 */
	typename type_config<data_type>::mutable_ptr get_mutable()
	{
		return m_type_config;
	}

private:
	typename type_config<data_type>::mutable_ptr m_type_config;
};
#include "type_config.hpp"

