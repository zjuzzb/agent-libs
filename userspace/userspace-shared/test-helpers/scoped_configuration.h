#pragma once

#include "yaml_configuration.h"
#include <memory>

namespace test_helpers
{

/**
 * Manages lifetime of a set of configuration values.
 * On construction, use the given yaml to set the configuration 
 * values. On destruction, reset all configuration back to
 * default.
 * Note that this only works for configs that use the 
 * configuration_manager.
 */
class scoped_configuration
{
public:
	scoped_configuration();
	scoped_configuration(const std::string& yaml);
	~scoped_configuration();

	/**
	 * Returns whether the yaml was successfully loaded.
	 */
	bool loaded() const;

private:
	yaml_configuration m_yaml;
	std::string m_old_yaml;

	// This is necessary because of the shortcomings of trying to stash everything in
	// the yaml. There is other metadata that must be saved. Until such a time as
	// we can fix this properly, perhaps by copying the value of the entire config
	// map, we'll just cache these values here
	std::map<std::string, bool> m_set_in_config_map;
};

} // namespace test_helpers
