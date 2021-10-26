#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "prom_config_file_manager.h"
#include "configuration.h"
#include "common_logger.h"

#include <Poco/NumberFormatter.h>
#include <Poco/SortedDirectoryIterator.h>
#include <Poco/DigestEngine.h>
#include <yaml-cpp/yaml.h>

COMMON_LOGGER();
using namespace std;

#define DEFAULT_PRIORITY	50
#define LEGACY_CUSTOM_PRIORITY	40

type_config<bool> c_prom_config_enabled(
	false,
	"Enable merge and use of backend-managed prometheus configuration files",
	"prom_config_files",
	"enabled");

type_config<bool> c_prom_config_merge_default(
	false,
	"Merge prometheus default configuration file after custom configuration",
	"prom_config_files",
	"merge_default");

type_config<string> c_scraper_src_dir(
	"etc/promscrape.yaml.d",
	"Source directory for promscrape config files (pre-merge)",
	"prom_config_files",
	"promscrape_src_dir");

type_config<string> c_scraper_out_dir(
	"etc",
	"Output directory for merged promscrape config file",
	"prom_config_files",
	"promscrape_out_dir");

type_config<string> c_scraper_out_file(
	"promscrape.yaml",
	"Final merged promscrape config filename",
	"prom_config_files",
	"promscrape_out_file");

type_config<string> c_cluster_conf_src_dir(
	"etc/prom_cluster_conf.yaml.d",
	"Source directory for cluster collector config files (pre-merge)",
	"prom_config_files",
	"cluster_conf_src_dir");

type_config<string> c_cluster_conf_out_dir(
	"/host/var/run",
	"Output directory for merged cluster collector config file",
	"prom_config_files",
	"cluster_conf_out_dir");

type_config<string> c_cluster_conf_out_file(
	"promcc_conf.yaml",
	"Merged cluster collector config filename",
	"prom_config_files",
	"cluster_conf_out_file");

type_config<string> c_cluster_rules_src_dir(
	"etc/prom_cluster_rules.yaml.d",
	"Source directory for cluster collector rule files (pre-merge)",
	"prom_config_files",
	"cluster_rules_src_dir");

type_config<string> c_cluster_rules_out_dir(
	"/host/var/run",
	"Output directory for merged cluster collector rule file(s)",
	"prom_config_files",
	"cluster_rules_out_dir");

type_config<string> c_cluster_rules_out_file(
	"promcc_rules.yaml",
	"Merged cluster collector rule filename",
	"prom_config_files",
	"cluster_rules_out_file");

static string buildpath(const string &rootdir, const string &dir)
{
	if (!dir.empty() && (dir[0] == '/'))
	{
		return dir;
	}
	else
	{
		return rootdir + "/" + dir;
	}
}

prom_config_file_manager::prom_config_file_manager() :
	m_root_dir("/opt/draios"),
	m_refresh_ts(0)
{
	m_changed[draiosproto::PROM_LOCAL_CONFIG] = false;
	m_changed[draiosproto::PROM_CLUSTER_CONFIG] = false;
	m_changed[draiosproto::PROM_CLUSTER_RULES] = false;
}

bool prom_config_file_manager::enabled() const
{
	return c_prom_config_enabled.get_value() && m_v2_enabled;
}

bool prom_config_file_manager::read_file(const std::string &file, std::string &content)
{
	// Not the most efficient
	try {
		ifstream s(file);
		stringstream buf;
		buf << s.rdbuf();
		content = buf.str();
	}
	catch(const ifstream::failure &e)
	{
		std::cerr << "Error reading file " << file << ": " << e.what() << "\n";
		LOG_WARNING("Error reading file %s: %s", file.c_str(), e.what());
		return false;
	}
	return true;
}

int prom_config_file_manager::load_dir(draiosproto::config_file_type type, const std::string &dir,
	int prio)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	int num = 0;
	LOG_DEBUG("load_dir(%s, %d)", dir.c_str(), prio);
	try {
		Poco::SortedDirectoryIterator end;
		Poco::SortedDirectoryIterator it(dir);

		for ( ; it != end; ++it)
		{
			if (it->isDirectory() && !it.name().empty() &&
				(it.name()[0] >= '0') && (it.name()[0] <= '9'))
			{
				int pr = 99;
				try {
					pr = stoi(it.name());
				}
				catch(const std::out_of_range &e)
				{
					LOG_WARNING("Failed to determine config priority: %s: %s", it.name().c_str(), e.what());
				}
				load_dir(type, it.path().toString(), pr);
				continue;
			}
			// Only read files ending in .yaml or .yml
			if (it->isFile() && it->canRead() && (it.name().size() >= 5) &&
				(!it.name().compare(it.name().size() - 5, string::npos, ".yaml") ||
				!it.name().compare(it.name().size() - 4, string::npos, ".yml")))
			{
				LOG_DEBUG("load file %s", it.path().toString().c_str());
				string content;
				if (read_file(it.path().toString(), content))
				{
					store_config(Local, type, prio, it.name(), content);
					num++;
				}
				else
				{
					LOG_WARNING("Failed to read prom config file %s", it.path().toString().c_str());
				}
			}
		}
	}
	catch (const Poco::IOException &e)
	{
		LOG_DEBUG("Failed to load directory %s: %s", dir.c_str(), e.what());
		return -1;
	}
	return num;
}

// Load/update custom legacy configuration file
void prom_config_file_manager::refresh_custom_configs()
{
	if (!enabled())
	{
		return;
	}
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	const char *paths[] = { "etc/prometheus.yaml", "etc/kubernetes/config/prometheus.yaml" };

	struct stat st;
	for (const char *p : paths)
	{
		string path = buildpath(m_root_dir, p);
		int rc = stat(path.c_str(), &st);
		if (rc >= 0)
		{
			if (st.st_mtime > m_refresh_ts)
			{
				string content;
				LOG_INFO("Found %s prometheus config %s", (m_refresh_ts != 0) ? "updated" : "initial", p);
				if (read_file(path, content))
				{
					store_config(Local, draiosproto::PROM_LOCAL_CONFIG, LEGACY_CUSTOM_PRIORITY, p, content);
				}
				else
				{
					LOG_WARNING("Failed to read custom prometheus configuration: %s", path.c_str());
				}
				m_refresh_ts = st.st_mtime;
			}
			break;
		}
	}
}

void prom_config_file_manager::load_local_configs()
{
	if (!enabled())
	{
		return;
	}

	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	LOG_DEBUG("load_local_configs()");
	if (c_prom_config_merge_default.get_value())
	{
		string path = buildpath(m_root_dir, "etc/prometheus-v2.default.yaml");
		string content;
		if (read_file(path, content))
		{
			store_config(Local, draiosproto::PROM_LOCAL_CONFIG, DEFAULT_PRIORITY, "prometheus-v2.default.yaml", content);
		}
		else
		{
			LOG_WARNING("Failed to read default prometheus configuration to merge: %s", path.c_str());
		}
	}
	load_dir(draiosproto::PROM_LOCAL_CONFIG, buildpath(m_root_dir, c_scraper_src_dir.get_value()), 99);
	refresh_custom_configs();
	load_dir(draiosproto::PROM_CLUSTER_CONFIG, buildpath(m_root_dir, c_cluster_conf_src_dir.get_value()), 99);
	load_dir(draiosproto::PROM_CLUSTER_RULES, buildpath(m_root_dir, c_cluster_rules_src_dir.get_value()), 99);
}

static bool find_scrape_job(const YAML::Node &node, const string &job_name)
{
	if (!node["scrape_configs"] || !node["scrape_configs"].IsSequence())
	{
		return false;
	}

	for (auto job = node["scrape_configs"].begin(); job != node["scrape_configs"].end(); job++)
	{
		if (!job->IsMap())
		{
			continue;
		}
		if ((*job)["job_name"].IsScalar() && ((*job)["job_name"].as<string>() == job_name))
		{
			return true;
		}
	}
	return false;
}

// Returns true if files were updated.
bool prom_config_file_manager::merge_and_save_configs(draiosproto::config_file_type type)
{
	if (!enabled())
	{
		return false;
	}

	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	YAML::Node out_yaml;
	for (auto map_it = m_type_config_map[type].begin() ; map_it != m_type_config_map[type].end(); map_it++)
	{
		LOG_DEBUG("merging %02d/%s", map_it->first.first, map_it->first.second.c_str());
		const auto &yaml = map_it->second.m_yaml;
		if (!yaml.IsMap())
		{
			LOG_DEBUG("not a map!");
			continue;
		}
		for (auto line = yaml.begin(); line != yaml.end(); line++)
		{
			if (!line->first.IsScalar())
			{
				LOG_DEBUG("first is not scalar");
				continue;
			}
			const string &name = line->first.as<string>();
			LOG_DEBUG("found %s, type %d", name.c_str(), line->second.Type());
			if (name == "global")
			{
				if (!line->second.IsMap())
				{
					LOG_DEBUG("global is not a map, skipping\n");
					continue;
				}
				if (!out_yaml[name])
				{
					LOG_DEBUG("Don't have global yet, copying");
					out_yaml[name] = line->second;
					continue;
				}
				for (auto glob_line = line->second.begin(); glob_line != line->second.end(); glob_line++)
				{
					if (!out_yaml[name][glob_line->first.as<string>()])
					{
						LOG_DEBUG("Didn't find %s.%s, adding", name.c_str(), glob_line->first.as<string>().c_str());
						out_yaml[name][glob_line->first.as<string>()] = glob_line->second;
					}
					else
					{
						LOG_DEBUG("Already have %s.%s", name.c_str(), glob_line->first.as<string>().c_str());
					}
				}
			}
			else if (name == "scrape_configs")
			{
				if (!line->second.IsSequence())
				{
					LOG_DEBUG("scrape_configs is not a sequence, skipping\n");
					continue;
				}
				if (!out_yaml[name])
				{
					LOG_DEBUG("Don't have scrape_configs yet, copying");
					out_yaml[name] = line->second;
				}
				else
				{
					// Should be a sequence of maps
					for (auto scrape_line = line->second.begin(); scrape_line != line->second.end(); scrape_line++)
					{
						if (!scrape_line->IsMap())
						{
							LOG_DEBUG("Not a map!");
							continue;
						}
						const auto &job = *scrape_line;
						if (!job["job_name"] || !job["job_name"].IsScalar())
						{
							LOG_DEBUG("Scrape config doesn't have scalar job_name");
							continue;
						}
						string job_name = job["job_name"].as<string>();
						if (find_scrape_job(out_yaml, job_name))
						{
							LOG_DEBUG("Scrape job %s already exists", job_name.c_str());
							continue;
						}
						LOG_DEBUG("Adding scrape job %s", job_name.c_str());
						out_yaml[name].push_back(job);
					}
				}
			}
			else
			{
				if (!out_yaml[name])
				{
					LOG_DEBUG("Didn't find %s, adding", name.c_str());
					out_yaml[name] = line->second;
				}
				else
				{
					LOG_DEBUG("%s already exists", name.c_str());
				}
			}
		}
	}

	string dir;
	string file;
	switch(type) {
	case draiosproto::PROM_LOCAL_CONFIG:
		dir = c_scraper_out_dir.get_value();
		file = c_scraper_out_file.get_value();
		break;
	case draiosproto::PROM_CLUSTER_CONFIG:
		dir = c_cluster_conf_out_dir.get_value();
		file = c_cluster_conf_out_file.get_value();
		break;
	case draiosproto::PROM_CLUSTER_RULES:
		dir = c_cluster_rules_out_dir.get_value();
		file = c_cluster_rules_out_file.get_value();
		break;
	default:
		LOG_WARNING("Unhandled scraper type: %d", (int)type);
		return false;
	}
	dir = buildpath(m_root_dir, dir);
	string errstr;

	if (!write_file(dir, file, out_yaml, errstr))
	{
		LOG_WARNING("Failed to write merged file %s: %s", file.c_str(), errstr.c_str());
		return false;
	}
	m_changed[type] = false;
	return true;
}

bool prom_config_file_manager::merge_and_save_configs()
{
	if (!enabled())
	{
		return false;
	}

	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	draiosproto::config_file_type types[] = {
		draiosproto::PROM_LOCAL_CONFIG,
		draiosproto::PROM_CLUSTER_CONFIG,
		draiosproto::PROM_CLUSTER_RULES
	};
	bool rc = true;
	
	for (auto type : types)
	{
		if (have_changes(type))
		{
			rc = rc && merge_and_save_configs(type);
		}
	}

	return rc;
}

void prom_config_file_manager::update_files()
{
	if (!enabled())
	{
		return;
	}
	std::lock_guard<std::recursive_mutex> lock(m_mutex);

	refresh_custom_configs();

	if (!have_changes())
	{
		return;
	}
	bool reload_promscrape = have_changes(draiosproto::PROM_LOCAL_CONFIG);
	LOG_INFO("Got new prometheus configs, merging");
	merge_and_save_configs();

	if (reload_promscrape)
	{
		pid_t ppid = getppid();
		int rc = kill(ppid, SIGHUP);
		LOG_INFO("Signalling promscrape (through parent %d) to reload config: kill returned %d", ppid, rc);
	}
}

bool prom_config_file_manager::have_changes(draiosproto::config_file_type type)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	return m_changed[type];
}

bool prom_config_file_manager::have_changes()
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	return have_changes(draiosproto::PROM_LOCAL_CONFIG) ||
		have_changes(draiosproto::PROM_CLUSTER_CONFIG) ||
		have_changes(draiosproto::PROM_CLUSTER_RULES);
}

int prom_config_file_manager::save_config(const draiosproto::config_file &config_file, string &errstr)
{
	if (!enabled())
	{
		LOG_INFO("Prom config management is disabled, but was asked to save a config file anyway.");
		return -1;
	}

	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	LOG_DEBUG("save_config(%s)", config_file.name().c_str());
	if ((config_file.type() != draiosproto::PROM_LOCAL_CONFIG) && 
		(config_file.type() != draiosproto::PROM_CLUSTER_CONFIG) && 
		(config_file.type() != draiosproto::PROM_CLUSTER_RULES))
	{
		errstr = "Invalid Prometheus file type " + Poco::NumberFormatter::format(config_file.type()) +
			" for " + Poco::NumberFormatter::format0(config_file.priority(), 2) + "-" + config_file.name();
		return -1;
	}

	int rc = store_config(Backend, config_file.type(), config_file.priority(), config_file.name(), config_file.content());

	if (rc > 0)
	{
		LOG_DEBUG("Creating new file %s", config_file.name().c_str());

		string dir;
		switch(config_file.type()) {
		case draiosproto::PROM_LOCAL_CONFIG:
			dir = c_scraper_src_dir.get_value();
			break;
		case draiosproto::PROM_CLUSTER_CONFIG:
			dir = c_cluster_conf_src_dir.get_value();
			break;
		case draiosproto::PROM_CLUSTER_RULES:
			dir = c_cluster_rules_src_dir.get_value();
			break;
		default:
			LOG_WARNING("Unhandled scraper type: %d", (int)config_file.type());
			return -1;
		}
		dir = buildpath(m_root_dir, dir) + "/" + Poco::NumberFormatter::format0(config_file.priority(), 2);

		if (!write_file(dir, config_file.name(), config_file.content(), errstr))
		{
			return -1;
		}
	}
	return rc;
}

int prom_config_file_manager::store_config(source_t src, draiosproto::config_file_type type, int prio, const std::string &file_name, const std::string &config_data)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	auto &map = m_type_config_map[type];
	auto key = make_pair(prio, file_name);
	auto it = map.find(key);

	string new_digest = get_digest(config_data);

	if (it != map.end())
	{
		// We already have the file. Compare them to see if it has been updated
		if (new_digest == it->second.m_digest)
		{
			LOG_DEBUG("Already have %02d/%s with same digest (%s), ignoring",
				prio, file_name.c_str(), new_digest.c_str());
			return 0;
		}
		LOG_DEBUG("Already have %02d/%s with different digest, overwriting", prio, file_name.c_str());
	}
	else
	{
		LOG_DEBUG("Storing new file %02d/%s", prio, file_name.c_str());
	}

	prom_config_info_t info;

	try
	{
		info.m_yaml = YAML::Load(config_data);
	}
	catch (const YAML::ParserException& ex)
	{
		LOG_INFO("Yaml error in %02d-%s: %s", prio, file_name.c_str(), ex.what());
		return -1;
	}

	info.m_source = src;
	info.m_config_data = config_data;
	info.m_digest = std::move(new_digest);

	m_type_config_map[type][key] = std::move(info);
	m_changed[type] = true;
	return 1;
}

string prom_config_file_manager::get_digest(const string &content)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	if (content.empty())
	{
		return content;
	}

	m_sha1_engine.reset();
	m_sha1_engine.update(content.c_str(), content.length());
	auto digest = m_sha1_engine.digest();

	return Poco::DigestEngine::digestToHex(digest);
}

template<typename datatype>
bool prom_config_file_manager::write_file(const std::string &dir_name, const std::string &file_name, datatype &config_data, std::string &errstr)
{
	try {
		Poco::File dir(dir_name);
		if (!dir.exists())
		{
			LOG_DEBUG("Trying to create directory %s", dir_name.c_str());
			dir.createDirectories();
		}
		// Write to a temp file first
		Poco::File file(dir_name + "/." + file_name + ".tmp");
		LOG_DEBUG("Writing to %s", file.path().c_str());
		ofstream of;
		of.open(file.path(), ofstream::out | ofstream::trunc);

		of << config_data;
		of.close();
		LOG_DEBUG("Renaming to %s/%s", dir_name.c_str(), file_name.c_str());
		file.renameTo(dir_name + "/" + file_name);
	}
	catch (Poco::IOException &e)
	{
		std::cerr << "Failed to write file" << dir_name << " / " << file_name << ": " << e.what() << "\n";
		LOG_WARNING("Failed to write file %s/%s: %s", dir_name.c_str(), file_name.c_str(), e.what());
		errstr = "Failed to write file" + dir_name + "/" + file_name + ": " + e.what();
		return false;
	}
	return true;
}

template bool prom_config_file_manager::write_file<const std::string>(const std::string &dir_name, const std::string &file_name, const std::string &config_data, std::string &errstr);
template bool prom_config_file_manager::write_file<const YAML::Node>(const std::string &dir_name, const std::string &file_name, const YAML::Node &config_data, std::string &errstr);

bool prom_config_file_manager::copy_file(const std::string &src, const std::string &dest)
{
	string content;
	if (!read_file(src, content))
	{
		return false;
	}
	Poco::Path path(dest);
	string filename = path.getFileName();
	string dir = path.makeParent().toString();
	LOG_DEBUG("Copying from %s to %s / %s", src.c_str(), dir.c_str(), filename.c_str());
	string error;
	return write_file(dir, filename, content, error);
}
