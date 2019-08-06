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
};

} // namespace test_helpers
