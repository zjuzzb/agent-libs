#include "promscrape_conf.h"

// Statically initialize the prometheus timeout config
// Min value : 01 sec
// Max value : 60 sec
// Default   : 01 sec
type_config<uint32_t>::ptr promscrape_conf::c_promscrape_timeout =
    type_config_builder<uint32_t>(
        1 /*default value of 1 second*/,
        "The value in seconds we wait to scrape prometheus endpoints before timing out.",
        "prometheus",
        "timeout")
        .min(1)
        .max(60)
        .build();

Json::Value prom_process::to_json() const
{
	Json::Value ret;
	ret["name"] = m_name;
	ret["pid"] = m_pid;
	ret["vpid"] = m_vpid;
	ret["ports"] = Json::Value(Json::arrayValue);

	ret["timeout"] = promscrape_conf::c_promscrape_timeout->get_value();
	if (m_path.size() > 0)
		ret["path"] = m_path;

	for (auto port : m_ports)
	{
		ret["ports"].append(Json::UInt(port));
	}

	Json::Value opts;
	for (auto option : m_options)
	{
		opts[option.first] = option.second;
	}
	if (!opts.empty())
		ret["options"] = opts;

	Json::Value tags = Json::Value(Json::arrayValue);
	for (auto tag : m_tags)
	{
		// Transfer tag list as array
		tags.append(tag.first + ":" + tag.second);
	}
	if (!tags.empty())
		ret["tags"] = tags;

	return ret;
}

