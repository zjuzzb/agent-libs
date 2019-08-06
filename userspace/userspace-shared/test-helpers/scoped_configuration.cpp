#include "scoped_configuration.h"
#include <configuration_manager.h>

namespace test_helpers
{

scoped_configuration::scoped_configuration():
	// yaml_configuration has no default constructor
	m_yaml("this_will_never_be_a_real_config_value_so_ignore_it: true"),
	m_old_yaml(configuration_manager::instance().to_yaml())
{ }

scoped_configuration::scoped_configuration(const std::string &yaml) :
	m_yaml(yaml),
	m_old_yaml(configuration_manager::instance().to_yaml())
{
	configuration_manager::instance().init_config(m_yaml);
}

scoped_configuration::~scoped_configuration()
{
	yaml_configuration old_yaml(m_old_yaml);
	configuration_manager::instance().init_config(old_yaml);
}

bool scoped_configuration::loaded() const
{
	return 0 == m_yaml.errors().size();
}

} // namespace test_helpers
