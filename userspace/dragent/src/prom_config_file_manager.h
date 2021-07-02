#pragma once

#include <map>
#include <string>
#include <yaml-cpp/yaml.h>
#include "Poco/SHA1Engine.h"
#include "draios.pb.h"
#include "type_config.h"

class prom_config_file_manager
{
public:
	enum source_t {
		Local = 0,
		Backend = 1,
	};
	typedef struct {
		source_t m_source;
		std::string m_config_data;
		std::string m_digest;
		YAML::Node m_yaml;
	} prom_config_info_t;

	// Map from priority+name to config_info
	typedef std::map<std::pair<int,std::string>, prom_config_info_t> config_map_t;
	// Map from file type to above map
	typedef std::map<draiosproto::config_file_type, config_map_t> type_config_map_t;

private:
	// Singleton
	prom_config_file_manager();
public:
	static prom_config_file_manager *instance()
	{
		static prom_config_file_manager inst;
		return &inst;
	}
	prom_config_file_manager(prom_config_file_manager const&) = delete;
	void operator=(prom_config_file_manager const&) = delete;

	bool enabled() const;

	void refresh_custom_configs();
	void load_local_configs();
	int save_config(const draiosproto::config_file &config_file, std::string &errstr);

	// Returns true if files were updated.
	bool have_changes(draiosproto::config_file_type type);
	bool have_changes();

	bool merge_and_save_configs(draiosproto::config_file_type type);
	bool merge_and_save_configs();

	// Checks if files were updated and will merge if so.
	void update_files();

	void set_root_dir(const std::string &root_dir) { m_root_dir = root_dir; }
	void set_v2(bool v2) { m_v2_enabled = v2; }

	static bool copy_file(const std::string &src, const std::string &dest);
private:
	std::string get_digest(const std::string &content);

	// Store the config in memory. Returns -1 on error, 0 if we already have it, 1 if we added it.
	int store_config(source_t src, draiosproto::config_file_type type, int priority, const std::string &file_name, const std::string &config_data);

	template<typename datatype>
	static bool write_file(const std::string &dir_name, const std::string &file_name, datatype &config_data, std::string &errstr);

	static bool read_file(const std::string &path, std::string &content);
	int load_dir(draiosproto::config_file_type type, const std::string &dir, int prio);

	std::recursive_mutex m_mutex;
	type_config_map_t m_type_config_map;
	Poco::SHA1Engine m_sha1_engine;
	std::string m_root_dir;
	std::map<draiosproto::config_file_type, bool> m_changed;
	time_t m_refresh_ts = 0;
	bool m_v2_enabled = false;
};
