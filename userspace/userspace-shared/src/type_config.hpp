template<typename data_type>
type_config<data_type>::type_config(const data_type& default_value,
				    const std::string& description,
				    const std::string& key,
				    const std::string& subkey,
				    const std::string& subsubkey)
        : configuration_unit(key, subkey, subsubkey, description),
          m_default(default_value),
          m_data(default_value)
{
}

template<typename data_type>
void type_config<data_type>::init(const yaml_configuration& raw_config)
{
        if (m_subkey.empty())
        {
                m_data = raw_config.get_scalar<data_type>(m_key, m_default);
        }
        else if (m_subsubkey.empty())
        {
		m_data = raw_config.get_scalar<data_type>(m_key,
							  m_subkey,
							  m_default);
        }
        else
        {
		m_data = raw_config.get_scalar<data_type>(m_key,
							  m_subkey,
							  m_subsubkey,
							  m_default);
        }
}

template<typename data_type>
data_type& type_config<data_type>::get()
{
        return m_data;
}

template<typename data_type>
const data_type& type_config<data_type>::get_const() const
{
        return m_data;
}
