#pragma once

#include <configuration_manager.h>

namespace test_helpers
{

/**
 * Manages lifetime of a single configuration value. The value
 * is set back when this object is destroyed
 *
 * Note that this only works for configs that use the
 * configuration_manager.
 */
template <typename config_type>
class scoped_config
{
public:
        scoped_config(const std::string& key, const config_type& value):
                m_key(key),
                m_old(configuration_manager::instance().get_config<config_type>(key)->get())
        {
                configuration_manager::instance().get_mutable_config<config_type>(key)->get() = value;
        }

        ~scoped_config()
        {
		configuration_manager::instance().get_mutable_config<config_type>(m_key)->get() = m_old;
        }

private:
        const std::string m_key;
        const config_type m_old;
};

}
