#include "configuration_console.h"
#include "command_line_error.h"
#include "command_line_manager.h"
#include "common_logger.h"
#include <fstream>
#include <yaml-cpp/yaml.h>
#include <vector>

namespace
{

COMMON_LOGGER();

/**
 * Dump the contents of a file to a string
 */
std::string file_contents_to_string(const std::string& file)
{
	std::ifstream t(file.c_str());
	std::string str;

	t.seekg(0, std::ios::end);   
	str.reserve(t.tellg());
	t.seekg(0, std::ios::beg);

	str.assign((std::istreambuf_iterator<char>(t)),
		    std::istreambuf_iterator<char>());

	return str;
}

void obfuscate(YAML::Node &node)
{
	if (node.IsSequence())
	{
		for (YAML::Node::iterator itr = node.begin(); itr != node.end(); ++itr)
		{
			const YAML::Node &const_child = *itr;
			YAML::Node &temp = *const_cast<YAML::Node*>(&const_child);
			obfuscate(temp);
		}
	}
	else if (node.IsMap())
	{
		for (YAML::Node::iterator itr = node.begin(); itr != node.end(); ++itr)
		{
			const YAML::Node &const_child = itr->second;
			YAML::Node &temp = *const_cast<YAML::Node*>(&const_child);
			obfuscate(temp);
		}
	}
	else if (node.IsScalar())
	{
		node ="********";
		node.SetTag("");
	}
}

void obfuscate(YAML::Node &node, const std::vector<std::string> &sensitive_keys)
{
	if (!node.IsDefined()) 
	{
		return;
	}

	if (node.IsSequence())
	{
		for (YAML::Node::iterator itr = node.begin(); itr != node.end(); ++itr)
		{
			const YAML::Node &const_child = *itr;
			YAML::Node &temp = *const_cast<YAML::Node*>(&const_child);
			obfuscate(temp, sensitive_keys);
		}

	}
	else if(node.IsMap())
	{
		for (auto &sensitive_key : sensitive_keys) 
		{
			auto found = node[sensitive_key];
			if (found.IsDefined())
			{
				obfuscate(found);
			}
		}
	}
}

void emit_ordered_yaml(const YAML::Node &node, YAML::Emitter &emitter) 
{
	switch (node.Type()) {
	case YAML::NodeType::Sequence:
		{
			emitter << YAML::BeginSeq;
			for (size_t i = 0; i < node.size(); i++) 
			{
				emit_ordered_yaml(node[i], emitter);
			}
			emitter << YAML::EndSeq;
			break;
		}
	case YAML::NodeType::Map:
		{
			emitter << YAML::BeginMap;

			// First collect all the keys
			std::vector<std::string> keys(node.size());
			int key_it = 0;
			for (YAML::const_iterator it = node.begin(); it != node.end(); ++it) 
			{
				keys[key_it++] = it->first.as<std::string>();
			}

			// Then sort them
			std::sort(keys.begin(), keys.end());

			// Then emit all the entries in sorted order.
			for (size_t i = 0; i < keys.size(); i++)
			{
				emitter << YAML::Key;
				emitter << keys[i];
				emitter << YAML::Value;
				emit_ordered_yaml(node[keys[i]], emitter);
			}
			emitter << YAML::EndMap;
			break;
		}
	default:
		emitter << node;
		break;
	}
}

std::string config_file_to_string(const std::string &file)
{
	try
	{
		std::string file_contents = file_contents_to_string(file);
		return configuration_console::remove_sensitive_configuration(file_contents);
	}
	catch(YAML::Exception& e) 
	{
		THROW_CLI_ERROR("An error occurred when parsing the config file.");
	}

	return "";
}

} // namespace

namespace configuration_console
{

std::string remove_sensitive_configuration(const std::string &yaml)
{
	auto root = YAML::Load(yaml);

	if (!root.IsMap()) 
	{
		return "An error occurred when parsing the config file to "
		       "remove sensitive content.";
	}

	// We don't want to bother selectively removing from app_check configs, 
	// so just wipe everything under conf
	auto app_checks_node = root["app_checks"];
	if (app_checks_node.IsDefined())
	{
		obfuscate(app_checks_node, {"conf"});
	}

	// If any of these keys exist, obfuscate them
	const std::vector<std::string> sensitive_keys = {
		"customerid", 
		"username", 
		"password", 
		"proxy_password", 
		"k8s_ssl_key_password"
	};
	obfuscate(root, sensitive_keys);

	// It might be better to leave the yaml in whatever order the 
	// customer put it in but that doesn't seem possible with the current
	// version of yaml-cpp so instead we trick it into being alphabetical
	YAML::Emitter emitter;
	emit_ordered_yaml(root, emitter);
	return emitter.c_str();
}

void add(const std::string &title, 
         const std::string &file,
         const command_line_permissions& perms)
{
	std::ifstream f(file.c_str());
	if(!f.good())
	{
		LOG_DEBUG("Not adding CLI for %s because the file doesn't exist", title.c_str());
		return;
	}

	static bool first = true;
	if (first)
	{
		command_line_manager::instance().register_folder("agent", "Commands to view status and configuration of the Sysdig Agent.");
		command_line_manager::instance().register_folder("agent configuration", "Commands to view the configuration of the Sysdig Agent.");
		first = false;
	}

	command_line_manager::command_info cmd;
	cmd.permissions = perms;
	cmd.type = command_line_manager::content_type::YAML;
	cmd.short_description = std::string("Show the ") + title + " configuration file.";
	cmd.handler =  [file](const command_line_manager::argument_list &args) {return config_file_to_string(file);};
	cmd.long_description = cmd.short_description +
		"\n\nThe configuration file is read and sensitive data is removed. The resultant yaml file is displayed.";
	command_line_manager::instance().register_command(std::string("agent configuration show-") + title + "-yaml", cmd);
}

}
