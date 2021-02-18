#include "custom_container.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "common_logger.h"
#include "cgroup_limits.h"
#include "type_config.h"

#include <Poco/Exception.h>

#include <sys/utsname.h>

using namespace std;
using namespace libsinsp::cgroup_limits;

type_config<std::string> c_substitute_container_label_char(
    "_", 
	"Substitution character for custom container label value",
	"substitute_container_label_char");

void custom_container::subst_token::render(std::string& out, const render_context& ctx, const std::vector<std::string>& env) const
{
	if (m_capture_id < 0)
	{
		out.append(m_var_name);
		return;
	}

	const auto it = ctx.find(m_var_name);
	if (it == ctx.end())
	{
		if (m_var_name != "cgroup" && m_capture_id == 0)
		{
			for (const auto& env_it : env)
			{
				auto pos = env_it.find(m_var_name + '=');
				if (pos != 0)
				{
					continue;
				}
				auto value = env_it.substr(m_var_name.length()+1, std::string::npos);
				out.append(value);
				return;
			}
			// no matching env var, substitute an empty string
			return;
		}
		throw Poco::RuntimeException("Could not find match named " + m_var_name + ", if this is not a typo, please add it to custom_containers.environ_match");
	}

	it->second.render(out, m_capture_id);
}

void custom_container::subst_template::parse(const string& pattern)
{
	size_t pos = 0;

	while (pos < pattern.length())
	{
		size_t start_tag = pattern.find('<', pos);

		if (start_tag > pos || start_tag == string::npos)
		{
			// a static string, outside <> markers
			m_tokens.push_back(subst_token(pattern.substr(pos, start_tag-pos)));
		}
		if (start_tag == string::npos)
			break;

		size_t end_tag = pattern.find('>', start_tag);
		if (end_tag == string::npos)
		{
			throw Poco::RuntimeException("'<' without a matching '>'");
		}
		if (end_tag == start_tag+1)
		{
			throw Poco::RuntimeException("Empty <> tag");
		}
		string tag = pattern.substr(start_tag+1, end_tag-start_tag-1);
		size_t colon = tag.find(':');
		int capture = 0;
		if (colon != string::npos)
		{
			try {
				capture = stoi(tag.substr(colon+1, string::npos));
			} catch (...) {
				throw Poco::RuntimeException("Invalid capture group number " + tag.substr(colon+1, string::npos));
			}
			tag = tag.substr(0, colon);
		}
		m_tokens.push_back(subst_token(tag, capture));

		pos = end_tag + 1;
	}
}

custom_container::resolver::resolver()
{
	struct utsname nodename;
	const char *hostname;
	if (uname(&nodename) == 0)
	{
		hostname = nodename.nodename;
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Cannot get hostname: %s", strerror(errno));
		hostname = "localhost";
	}
	const char *dot = strchr(hostname, '.');
	size_t len = strlen(hostname);
	size_t shortname_len = dot ? dot - hostname :  len;

	m_hostname = custom_container::match{
		.m_str = hostname,
		.m_matches = {
			{0, len},
			{0, shortname_len}
		}
	};
}

bool custom_container::resolver::match_cgroup(sinsp_threadinfo* tinfo, render_context& render_ctx)
{
	if (!m_cgroup_match)
	{
		return true;
	}

	for(const auto& it : tinfo->m_cgroups)
	{
		string cgroup = it.second;
		Poco::RegularExpression::MatchVec matches;
		if (m_cgroup_match->match(cgroup, 0, matches, 0))
		{
			render_ctx.emplace("cgroup", custom_container::match { .m_str = cgroup, .m_matches = matches });
			return true;
		}
	}
	return false;
}


bool custom_container::resolver::match_environ(sinsp_threadinfo* tinfo, render_context& render_ctx)
{
	auto num_matches = m_environ_match.size();
	auto env = tinfo->get_env();
	for (const auto& env_it : env)
	{
		Poco::RegularExpression::MatchVec matches;

		if (num_matches == 0)
			return true;

		auto pos = env_it.find('=');
		auto var_name = env_it.substr(0, pos);
		auto match = m_environ_match.find(var_name);

		if (match == m_environ_match.end())
			continue;

		if (match->second->match(env_it, pos+1, matches, 0))
		{
			render_ctx.emplace(match->first, custom_container::match { .m_str = env_it, .m_matches = move(matches) });
		}
		else
		{
			return false;
		}
		num_matches--;
	}

	if (num_matches > 0)
	{
		return false;
	}
	return true;
}

sinsp_threadinfo* custom_container::resolver::match_environ_tree(sinsp_threadinfo *tinfo, render_context &render_ctx)
{
	sinsp_threadinfo* found_tinfo = nullptr;
	sinsp_threadinfo::visitor_func_t visitor = [&] (sinsp_threadinfo *ptinfo)
	{
		// match_environ returns true on match. this closure flips this to
		// false meaning stop iterating
		bool found = match_environ(ptinfo, render_ctx);
		if (found)
		{
			found_tinfo = ptinfo;
		}
		return !found;
	};

	if (visitor(tinfo))
	{
		tinfo->traverse_parent_state(visitor);
	}
	return found_tinfo;
}

void custom_container::resolver::clean_label(std::string& val, clean_action check)
{
	/*
	* Based on parameter "check" each character of val is checked to be in either the whitelist_name 
	* or the whitelist_value list.  If parameter val contains a character not in the appropriate 
	* whitelist_xxxx replace it with the sustitution character.  For action CHECK_VALUE, the
	* dragent.yaml config "substitute_container_label_char" is used to establish the substitution 
	* character.  Note the substitution character must also be a valid member of the whitelist_value.
	*/
	if (check == CHECK_NAME)
	{
		const std::string whitelist_name  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:._";
	    for (auto c = val.begin(); c != val.end(); ++c)
	    {
		    if (whitelist_name.find(*c) == std::string::npos)  // this indicates no matches.
		    {
			    *c = '_';
		    }
		}
	} else  /* check is CHECK_VALUE */
	{
		const std::string whitelist_value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:._/";
		for (auto c = val.begin(); c != val.end(); ++c)
	    {
			// determine if the character of val pointed to *c is a whitelist_value member:
		    if (whitelist_value.find(*c) == std::string::npos)
		    {
				// also validate the type_config substitution character is a whitelist_value member:
				if(whitelist_value.find(c_substitute_container_label_char.get_value()[0])!=std::string::npos)
				{
			        *c = c_substitute_container_label_char.get_value()[0];
				}
				else
				{
					g_logger.format(sinsp_logger::SEV_WARNING,"Invalid substitution character for custom container label value");
					*c = '_';  // apply the original default substitution character
				}
		    }	
		}
	}
}


bool custom_container::resolver::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;
	render_context render_ctx;
	container_info.m_type = CT_CUSTOM;
	bool metadata_complete = true;
	bool new_container = false;

	if (!m_enabled)
	{
		return false;
	}

	if (!match_cgroup(tinfo, render_ctx))
	{
		return false;
	}

	auto matched = match_environ_tree(tinfo, render_ctx);
	if (!matched)
	{
		return false;
	}

	render_ctx.emplace("hostname", m_hostname);

	auto env = matched->get_env();

	try {
		m_id_pattern.render(container_info.m_id, render_ctx, env);
	} catch (const Poco::RuntimeException& e) {
		g_logger.format(sinsp_logger::SEV_WARNING, "Disabling custom container support due to error in configuration: %s", e.message().c_str());
		set_enabled(false);
		return false;
	}
	if (container_info.m_id.empty())
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "Got empty container id for process %lu, possibly a configuration error", tinfo->m_tid);
		return false;
	}
	container_info.m_id = container_info.m_id.substr(0, m_max_id_length);
	
	clean_label(container_info.m_id, CHECK_NAME);

	if (m_config_test && tinfo->is_main_thread())
	{
		string cmd = tinfo->m_comm;

		for (const auto& arg : tinfo->m_args)
		{
			cmd += " " + arg;
		}

		m_dump[container_info.m_id]["processes"][tinfo->m_tid] = cmd;
	}

	tinfo->m_container_id = container_info.m_id;
	auto num_containers = manager->get_containers()->size();
	auto existing_container = manager->get_container(container_info.m_id);

	if (!existing_container && num_containers >= m_max)
	{
		if (!m_limit_logged)
		{
			g_logger.format(sinsp_logger::SEV_WARNING, "Custom container limit exceeded, ignoring new container %s of pid %lu", tinfo->m_container_id.c_str(), tinfo->m_tid);
			m_limit_logged = true;
		}
		return false;
	}
	m_limit_logged = false;

	if (existing_container != nullptr) {
		if (existing_container->m_metadata_deadline < sinsp_utils::get_current_time_ns()) {
			return true;
		}
		container_info = *existing_container;
	} else {
		container_info.m_metadata_deadline = sinsp_utils::get_current_time_ns() + (10 * ONE_SECOND_IN_NS);
		new_container = true;
	}

	if (m_name_pattern.empty())
	{
		container_info.m_name = container_info.m_id;
	}
	else if (container_info.m_name.empty())
	{
		try {
			m_name_pattern.render(container_info.m_name, render_ctx, env);
			if (container_info.m_name.empty())
			{
				metadata_complete = false;
			} else {

				clean_label(container_info.m_name, CHECK_NAME);
			}
		} catch (const Poco::RuntimeException& e) {
			g_logger.format(sinsp_logger::SEV_WARNING, "Disabling custom container name due to error in configuration: %s", e.message().c_str());
			m_name_pattern = custom_container::subst_template();
			container_info.m_name = container_info.m_id;
		}
	}

	if (container_info.m_image.empty()) {
		try {
			m_image_pattern.render(container_info.m_image, render_ctx, env);
			if (container_info.m_image.empty())
			{
				if (m_incremental_metadata)
				{
					metadata_complete = false;
				}
			} else {				

				clean_label(container_info.m_image, CHECK_NAME);
			}
		} catch (const Poco::RuntimeException &e) {
			g_logger.format(sinsp_logger::SEV_WARNING,
							"Disabling custom container image due to error in configuration: %s", e.message().c_str());
			m_image_pattern = custom_container::subst_template();
			container_info.m_image = "";
		}
	}

	auto it = m_label_patterns.begin();  // this is of type std::unordered_map<std::string, subst_template>

	while (it != m_label_patterns.end())
	{
		if (container_info.m_labels.find(it->first) == container_info.m_labels.end())
		{				
			try {
				string s;
				it->second.render(s, render_ctx, env);
				if (s.empty()) {
					if (m_incremental_metadata)
					{
						metadata_complete = false;
					}
				} else {
					// this is the only call to clean_label() for action CHECK_VALUE
					clean_label(s, CHECK_VALUE);
					container_info.m_labels.emplace(it->first, move(s));
				}
			} catch (const Poco::RuntimeException& e) {
				g_logger.format(sinsp_logger::SEV_WARNING, "Disabling custom container label %s due to error in configuration: %s", it->first.c_str(), e.message().c_str());
				it = m_label_patterns.erase(it);
				continue;
			}

		}
		++it;
	}

	if (m_config_test)
	{
		m_dump[container_info.m_id]["name"] = container_info.m_name;
		if (!container_info.m_image.empty())
		{
			m_dump[container_info.m_id]["image"] = container_info.m_image;
		}
		if (!container_info.m_labels.empty())
		{
			m_dump[container_info.m_id]["labels"] = container_info.m_labels;
		}
	}

	if (metadata_complete)
	{
		container_info.m_metadata_deadline = 0;
	}

	if(new_container && query_os_for_missing_info)
	{
		auto cpu_cgroup = tinfo->get_cgroup("cpu");
		auto mem_cgroup = tinfo->get_cgroup("memory");
		auto cpuset_cgroup = tinfo->get_cgroup("cpuset");
		cgroup_limits_key key(container_info.m_id, cpu_cgroup, mem_cgroup, cpuset_cgroup);
		cgroup_limits_value resource_limits;
		get_cgroup_resource_limits(key, resource_limits, false);
		container_info.m_cpu_shares = resource_limits.m_cpu_shares;
		container_info.m_cpu_quota = resource_limits.m_cpu_quota;
		container_info.m_memory_limit = resource_limits.m_memory_limit;
		container_info.m_cpuset_cpu_count = resource_limits.m_cpuset_cpu_count;

		if(m_config_test)
		{
			m_dump[container_info.m_id]["resources"]["cpu_shares"] = resource_limits.m_cpu_shares;
			m_dump[container_info.m_id]["resources"]["cpu_quota"] = resource_limits.m_cpu_quota;
			m_dump[container_info.m_id]["resources"]["cpu_quota_period"] = resource_limits.m_cpu_period;
			m_dump[container_info.m_id]["resources"]["memory_limit"] = resource_limits.m_memory_limit;
			m_dump[container_info.m_id]["resources"]["cpuset_cpus"] = resource_limits.m_cpuset_cpu_count;
		}
	}

	if (new_container)
	{
		auto container = make_shared<sinsp_container_info>(container_info);
		manager->add_container(container, tinfo);
		manager->notify_new_container(*container.get());
	}
	else // if(updated_container)
	{
		auto container = make_shared<sinsp_container_info>(container_info);
		manager->replace_container(container);
	}
	return true;
}

void custom_container::resolver::dump_container_table()
{
	YAML::Emitter out;
	out << YAML::BeginMap;
	out << YAML::Key << "custom_containers";
	out << YAML::Value << YAML::BeginMap;

	if (m_dump.size() > (size_t)m_max)
	{
		g_logger.format(sinsp_logger::SEV_WARNING, "%d custom containers present, while the limit is %d. Only a subset will be reported",
			m_dump.size(), m_max);
	}

	for (const auto& it : m_dump)
	{
		out << YAML::Key << it.first;
		out << YAML::Value << YAML::BeginMap;

		if (it.second["name"]) out << YAML::Key << "name" << YAML::Value << it.second["name"];
		if (it.second["image"]) out << YAML::Key << "image" << YAML::Value << it.second["image"];
		if (it.second["labels"]) out << YAML::Key << "labels" << YAML::Value << it.second["labels"];
		if (it.second["processes"]) out << YAML::Key << "processes" << YAML::Value << it.second["processes"];
		if (it.second["resources"]) out << YAML::Key << "resources" << YAML::Value << it.second["resources"];

		out << YAML::EndMap;
	}

	out << YAML::EndMap;
	out << YAML::EndMap;
	cerr << out.c_str() << '\n';
}

string custom_container::resolver::get_labels() const
{
	string s;
	if (!m_enabled)
	{
		return s;
	}

	for (auto it = m_label_patterns.cbegin(); it != m_label_patterns.cend(); ++it)
	{
		if (!s.empty())
		{
			s.append(",");
		}
		s.append(it->first);
	}

	return s;
}
