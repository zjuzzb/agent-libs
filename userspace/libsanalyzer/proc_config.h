//
// Created by Luca Marturana on 03/10/2016.
//

#pragma once

#include "sinsp.h"
#include "app_checks.h"
#include <yaml-cpp/yaml.h>

class proc_config {
public:
	inline proc_config(const string& conf);

	const vector<app_check>& app_checks() const
	{
		return m_app_checks;
	}
private:
	vector<app_check> m_app_checks;
};

proc_config::proc_config(const string &conf)
{
	try
	{
		// An empty var is a valid conf
		if(conf.empty())
		{
			return;
		}

		auto root = YAML::Load(conf);
		if (root.IsMap())
		{
			const auto& app_checks_node = root["app_checks"];
			if(app_checks_node.IsSequence())
			{
				for(const auto& check_node : app_checks_node)
				{
					m_app_checks.emplace_back(check_node.as<app_check>());
				}
			}
		}
		else
		{
			g_logger.format(sinsp_logger::SEV_WARNING, "Invalid SYSDIG_AGENT_CONF var=%s reason=Root YAML is not a Map", conf.c_str());
		}
	}
	catch (const YAML::BadConversion& ex)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Invalid SYSDIG_AGENT_CONF var=%s reason=Wrong fields", conf.c_str());
	}
	catch ( const YAML::ParserException& ex)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Invalid SYSDIG_AGENT_CONF var=%s reason=Wrong YAML syntax", conf.c_str());
	}
}