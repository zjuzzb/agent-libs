#pragma once
#include "Poco/File.h"
#include "Poco/Exception.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <yaml-cpp/yaml.h>
#pragma GCC diagnostic pop

#include <unordered_map>

/**
 * Exception thrown from the yaml_configuration infrastructure
 */
class yaml_configuration_exception : public std::runtime_error
{
public:
	yaml_configuration_exception(const std::string& what) :
	   std::runtime_error(what)
	{
	}
};

/**
* WARNING: avoid assignment operator on YAML::Node object
* they modifies underlying tree even on const YAML::Node objects
*/
class yaml_configuration
{
public:
	// If the constructor hits an exception, set an error and let the caller handle it
	yaml_configuration(const std::string& str)
	{
		try
		{
			if(!add_root(YAML::Load(str)))
			{
				add_error("Cannot read config file, reason: not valid format");
			}
		}
		catch (const YAML::ParserException& ex)
		{
			m_errors.emplace_back(std::string("Cannot read config file, reason: ") + ex.what());
		}
	}

	yaml_configuration(std::string&& str)
	{
		try
		{
			if(!add_root(YAML::Load(str)))
			{
				add_error("Cannot read config file, reason: not valid format");
			}
		}
		catch (const YAML::ParserException& ex)
		{
			m_errors.emplace_back(std::string("Cannot read config file, reason: ") + ex.what());
		}
	}

	yaml_configuration(const std::initializer_list<std::string>& file_paths)
	{
		// We cant use logging because it's not initialized yet
		for (const auto& path : file_paths)
		{
			try
			{
				Poco::File conf_file(path);
				if(conf_file.exists())
				{

					if(!add_root(YAML::LoadFile(path)))
					{
						add_error(std::string("Cannot read config file: ") + path + " reason: not valid format");
					}
				}
				else
				{
					m_warnings.emplace_back(std::string("Config file: ") + path + " does not exists");
				}
			}
			catch(const YAML::BadFile& ex)
			{
				m_errors.emplace_back(std::string("YAML::BadFile:Cannot read config file: ") + path + " reason: " + ex.what());
			}
			catch(const YAML::ParserException& ex)
			{
				m_errors.emplace_back(std::string("YAML::ParserException:Cannot read config file: ") + path + " reason: " + ex.what());
			}
			catch (const Poco::AssertionViolationException& ex)
			{
				m_errors.emplace_back(std::string("Poco::AssertionViolationException:Cannot read config file: ") + path + " reason: " + ex.what());
			}
		}
	}

	/**
	* Will retrieve first found arbitrarily deeply nested sequence
	* into an STL container T. Also supports scalars;
	* if found entity is scalar, a container with a
	* single member is returned.
	*/
	template<typename T, typename... Args>
	T get_first_deep_sequence(Args... args) const
	{
		T ret;
		try
		{
			for(const auto& root : m_roots)
			{
				get_sequence(ret, root, args...);
				if (!ret.empty())
					return ret;
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(std::string("Config file error."));
		}
		return ret;
	}

	/**
	* Will retrieve arbitrarily deeply nested sequence
	* into an STL container T. Also supports scalars;
	* if found entity is scalar, a container with a
	* single member is returned.
	*/
	template<typename T, typename... Args>
	T get_deep_merged_sequence(Args... args)
	{
		T ret;
		try
		{
			for(const auto& root : m_roots)
			{
				get_sequence(ret, root, args...);
			}
		}
		catch (const YAML::BadConversion& ex)
		{
			m_errors.emplace_back(std::string("Config file error."));
		}
		return ret;
	}

	/**
	* Will retrieve arbitrarily deeply nested sequence
	* into an STL container T. Also supports scalars;
	* if found entity is scalar, a container with a
	* single member is returned.
	*/
	template<typename T, typename... Args>
	static T get_deep_sequence(yaml_configuration& config, const YAML::Node& root, Args... args)
	{
		T ret;
		try
		{
			get_sequence(ret, root, args...);
		}
		catch (const YAML::BadConversion& ex)
		{
			config.add_error(std::string("Config file error."));
		}
		return ret;
	}

	/**
	* Get a scalar value from config, like:
	* customerid: "578c60dc-c8b2-11e4-a615-6c4008aec9fe"
	* Throws if value is not found.
	*/
	template<typename T>
	T get_scalar(const std::string& key) const
	{
		for(const auto& root : m_roots)
		{
			auto node = root[key];
			if (node.IsDefined())
			{
				return node.as<T>();
			}
		}
		throw yaml_configuration_exception("Entry not found: " + key);
	}

	/**
	* Get a scalar value and return the how far down the list of configs that we
	* needed to search to find the key.
	* Returns 0 if found in the first level, 1 for the second level, etc.
	*/
	template<typename T>
	int get_scalar_depth(const std::string& key, T &value) const
	{
		for(auto itr = m_roots.begin(); itr != m_roots.end(); ++itr)
		{

			try
			{
				auto node = (*itr)[key];
				if (node.IsDefined())
				{
					value = node.as<T>();
					return std::distance(m_roots.begin(), itr);
				}
			} catch (const YAML::BadConversion& ex)
			{
				m_errors.emplace_back(std::string("Config file error at key: ") + key);
			}
		}

		return -1;
	}

	/**
	* Get a scalar value from config, like:
	* customerid: "578c60dc-c8b2-11e4-a615-6c4008aec9fe"
	*/
	template<typename T>
	T get_scalar(const std::string& key, const T &default_value) const
	{
		T value;
		if(get_scalar_depth(key, value) < 0)
		{
			return default_value;
		}

		return value;
	}

	/**
	* Get a scalar value and return the how far down the list of configs that we
	* needed to search to find the key and the subkey.
	* Returns 0 if found in the first level, 1 for the second level, etc.
	*/
	template<typename T>
	int get_scalar_depth(const std::string& key, const std::string& subkey, T& value) const
	{
		for(auto itr = m_roots.begin(); itr != m_roots.end(); ++itr)
		{
			try
			{
				auto node = (*itr)[key][subkey];
				if (node.IsDefined())
				{
					value = node.as<T>();
					return std::distance(m_roots.begin(), itr);
				}
			}
			catch (const YAML::BadConversion& ex)
			{
				m_errors.emplace_back(std::string("Config file error at key: ") + key + "." + subkey);
			}
		}

		return -1;
	}

	/**
	* Utility method to get scalar values inside a 2 level nested structure like:
	* server:
	*   address: "collector.sysdigcloud.com"
	*   port: 6666
	*
	* get_scalar<std::string>("server", "address", "localhost")
	*/
	template<typename T>
	T get_scalar(const std::string& key, const std::string& subkey, const T& default_value) const
	{
		T value;
		if (get_scalar_depth(key, subkey, value) < 0)
		{
			return default_value;
		}

		return value;
	}

	/**
	* Get a scalar value and return the how far down the list of configs that we
	* needed to search to find the key, the subkey and the subsubkey.
	* Returns 0 if found in the first level, 1 for the second level, etc.
	*/
	template<typename T>
	int get_scalar_depth(const std::string& key, const std::string& subkey, const std::string& subsubkey, T& value) const
	{
		for(auto itr = m_roots.begin(); itr != m_roots.end(); ++itr)
		{
			try
			{
				auto node = (*itr)[key][subkey][subsubkey];
				if (node.IsDefined())
				{
					value = node.as<T>();
					return std::distance(m_roots.begin(), itr);
				}
			}
			catch (const YAML::BadConversion& ex)
			{
				m_errors.emplace_back(std::string("Config file error at key: ") + key + "." + subkey);
			}
		}

		return -1;
	}

	template<typename T>
	T get_scalar(const std::string& key, const std::string& subkey, const std::string& subsubkey, const T& default_value) const
	{
		T value;
		if (get_scalar_depth(key, subkey, subsubkey, value) < 0)
		{
			return default_value;
		}

		return value;
	}

	/**
	* get data from a sequence of objects, they
	* will be merged between settings file and
	* default files, example:
	*
	* common_metrics:
	*  - cpu
	*  - memory
	*
	* get_merged_sequence<std::string>("common_metrics")
	*/
	template<typename T>
	std::vector<T> get_merged_sequence(const std::string& key)
	{
		std::vector<T> ret;
		for(const auto& root : m_roots)
		{
			for(const auto& item : root[key])
			{
				try
				{
					ret.push_back(item.as<T>());
				}
				catch (const YAML::BadConversion& ex)
				{
					m_errors.emplace_back(std::string("Config file error at key ") + key);
				}
			}
		}
		return ret;
	}

	template<typename T>
	std::vector<T> get_merged_sequence(const std::string& key, std::vector<T> &default_value)
	{
		bool defined = false;
		std::vector<T> ret;
		for(const auto& root : m_roots)
		{
			auto node = root[key];
			if(node.IsDefined())
			{
				defined = true;

				for(const auto& item : node)
				{
					try
					{
						ret.push_back(item.as<T>());
					}
					catch (const YAML::BadConversion& ex)
					{
						m_errors.emplace_back(std::string("Config file error at key ") + key);
					}
				}
			}
		}
		if(defined)
		{
			return ret;
		}
		else
		{
			return default_value;
		}
	}

	/**
	* Get data from a map of objects, they
	* will be merged between settings and
	* default file, example:
	*
	* per_process_metrics:
	*   cassandra:
	*     - cpu
	*     - memory
	*   mongodb:
	*     - net
	*
	* get_merged_map<std::vector<std::string>>("per_process_metrics")
	*/
	template<typename T>
	std::unordered_map<std::string, T> get_merged_map(const std::string& key)
	{
		std::unordered_map<std::string, T> ret;
		for(auto it = m_roots.rbegin(); it != m_roots.rend(); ++it)
		{
			for(const auto& item : (*it)[key])
			{
				try
				{
					ret[item.first.as<std::string>()] = item.second.as<T>();
				}
				catch (const YAML::BadConversion& ex)
				{
					m_errors.emplace_back(std::string("Config file error at key ") + key);
				}
			}
		}
		return ret;
	}

	template<typename T>
	void get_map(std::unordered_map<std::string, T>& ret, const YAML::Node& node, const std::string& key)
	{
		YAML::Node child_node = node[key];
		if(child_node.IsDefined())
		{
			for(const auto& item : child_node)
			{
				try
				{
					ret[item.first.as<std::string>()] = item.second.as<T>();
				}
				catch (const YAML::BadConversion& ex)
				{
					m_errors.emplace_back(std::string("Config file error at key ") + key);
				}
			}
		}
	}

	template<typename T, typename... Args>
	void get_map(std::unordered_map<std::string, T>& ret, const YAML::Node& node, const std::string& key, Args... args)
	{
		YAML::Node child_node = node[key];
		if(child_node.IsDefined())
		{
			get_map(ret, child_node, args...);
		}
	}

	template<typename T, typename... Args>
	std::unordered_map<std::string, T> get_first_deep_map(Args... args)
	{
		std::unordered_map<std::string, T> ret;
		for(auto it = m_roots.begin(); it != m_roots.end(); ++it)
		{
			get_map(ret, *it, args...);
			if (!ret.empty())
				return ret;
		}
		return ret;
	}

	inline const std::vector<std::string>& errors() const
	{
		return m_errors;
	}

	inline const std::vector<std::string>& warnings() const
	{
		return m_warnings;
	}

	void add_warning(const std::string& warning)
	{
		m_warnings.emplace_back(warning);
	}

	// WARN: when possible we should avoid using directly underlying YAML nodes
	const std::vector<YAML::Node>& get_roots() const
	{
		return m_roots;
	}

	void add_error(const std::string& err)
	{
		m_errors.emplace_back(err);
	}

private:
	// no-op needed to compile and terminate recursion
	template <typename T>
	static void get_sequence(T&, const YAML::Node&)
	{
	}

	// called with the last variadic arg (where the sequence is expected to be found)
	template <typename T>
	static void get_sequence(T& ret, const YAML::Node& node, const std::string& name)
	{
		YAML::Node child_node = node[name];
		if(child_node.IsDefined())
		{
			if(child_node.IsSequence())
			{
				for(const YAML::Node& item : child_node)
				{
					ret.insert(ret.end(), item.as<typename T::value_type>());
				}
			}
			else if(child_node.IsScalar())
			{
				ret.insert(ret.end(), child_node.as<typename T::value_type>());
			}
		}
	}

	template<typename T, typename... Args>
	static void get_sequence(T& ret, const YAML::Node& node, const std::string& arg1, Args... args)
	{
		YAML::Node child_node = node[arg1];
		get_sequence(ret, child_node, args...);
	}

	bool add_root(YAML::Node&& root)
	{
		if (root.IsMap())
		{
			m_roots.emplace_back(root);
			return true;
		}
		else
		{
			return false;
		}
	}

	std::vector<YAML::Node> m_roots;
	mutable std::vector<std::string> m_errors;
	mutable std::vector<std::string> m_warnings;
};

