#include "scoped_configuration.h"
#include <configuration_manager.h>

namespace test_helpers
{

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
