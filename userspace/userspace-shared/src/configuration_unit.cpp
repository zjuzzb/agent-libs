/**
 * @file
 *
 * Implementation of configuration_unit.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "type_config.h"
#include "configuration_manager.h"
#include "common_logger.h"
#include <string>
#include <json/json.h>

configuration_unit::configuration_unit(const std::string& key,
				       const std::string& subkey,
				       const std::string& subsubkey,
				       const std::string& description) :
   m_description(description),
   m_hidden(false)
{

	m_keys.push_back(config_key(key, subkey, subsubkey));

	m_keystring = primary_key().to_string();

	configuration_manager::instance().register_config(this);
}

configuration_unit::~configuration_unit()
{
	configuration_manager::instance().deregister_config(this);
}

std::string configuration_unit::to_string() const
{
	return get_key_string() + ": " + value_to_string();
}

const std::string& configuration_unit::get_key_string() const
{
	return m_keystring;
}

const std::string& configuration_unit::get_key() const
{
	return primary_key().key;
}

const std::string& configuration_unit::get_subkey() const
{
	return primary_key().subkey;
}

const std::string& configuration_unit::get_subsubkey() const
{
	return primary_key().subsubkey;
}

const std::string& configuration_unit::get_description() const
{
	return m_description;
}

void configuration_unit::hidden(const bool value)
{
	m_hidden = value;
}

bool configuration_unit::hidden() const
{
	return m_hidden;
}

std::string configuration_unit::to_json() const
{
	Json::Value root;

	root[m_keystring]["description"] = m_description;
	root[m_keystring]["value"] = value_to_string();

	return root.toStyledString();
}

void configuration_unit::from_json(const std::string& json)
{
	Json::Value root;
	Json::Reader reader;

	if(!reader.parse(json, root))
	{
		throw configuration_unit::exception("Failed to parse json");
	}

	Json::Value value = root["value"];

	if(value.isNull())
	{
		throw configuration_unit::exception(
				"Root element does not contain a value");
	}

	if(!value.isString())
	{
		throw configuration_unit::exception(
				"Value is not a string");
	}

	if(!string_to_value(value.asString()))
	{
		throw configuration_unit::exception(
				"Unable to parse given value to expected type");
	}
}

configuration_unit::exception::exception(const std::string& msg):
	std::runtime_error("configuration_unit::exception: " + msg)
{ }
