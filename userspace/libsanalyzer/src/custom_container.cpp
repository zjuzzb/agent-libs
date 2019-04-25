#include "custom_container.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "logger.h"

#include <Poco/Exception.h>

#include <sys/utsname.h>

using namespace std;

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

void custom_container::resolver::clean_label(std::string& val)
{
	const std::string whitelist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:._";
	for (auto c = val.begin(); c != val.end(); ++c)
	{
		if (whitelist.find(*c) == std::string::npos)
		{
			*c = '_';
		}
	}
}


bool custom_container::resolver::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;
	render_context render_ctx;
	container_info.m_type = CT_CUSTOM;
	bool metadata_complete = true;

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
	clean_label(container_info.m_id);

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
	auto container = manager->get_container(container_info.m_id);
	if (!container && m_num >= m_max)
	{
		if (!m_limit_logged)
		{
			g_logger.format(sinsp_logger::SEV_WARNING, "Custom container limit exceeded, ignoring new container %s of pid %lu", tinfo->m_container_id.c_str(), tinfo->m_tid);
			m_limit_logged = true;
		}
		return false;
	}
	m_limit_logged = false;

	if (container != nullptr) {
		if (container->m_metadata_deadline < sinsp_utils::get_current_time_ns()) {
			return true;
		}
	} else {
		container_info.m_metadata_deadline = sinsp_utils::get_current_time_ns() + (10 * ONE_SECOND_IN_NS);
		container = &container_info;
	}

	if (m_name_pattern.empty())
	{
		container->m_name = container->m_id;
	}
	else if (container->m_name.empty())
	{
		try {
			m_name_pattern.render(container->m_name, render_ctx, env);
			if (container->m_name.empty())
			{
				metadata_complete = false;
			} else {
				clean_label(container->m_name);
			}
		} catch (const Poco::RuntimeException& e) {
			g_logger.format(sinsp_logger::SEV_WARNING, "Disabling custom container name due to error in configuration: %s", e.message().c_str());
			m_name_pattern = custom_container::subst_template();
			container->m_name = container->m_id;
		}
	}

	if (container->m_image.empty()) {
		try {
			m_image_pattern.render(container->m_image, render_ctx, env);
			if (container->m_image.empty())
			{
				if (m_incremental_metadata)
				{
					metadata_complete = false;
				}
			} else {
				clean_label(container->m_image);
			}
		} catch (const Poco::RuntimeException &e) {
			g_logger.format(sinsp_logger::SEV_WARNING,
							"Disabling custom container image due to error in configuration: %s", e.message().c_str());
			m_image_pattern = custom_container::subst_template();
			container->m_image = "";
		}
	}

	auto it = m_label_patterns.begin();
	while (it != m_label_patterns.end())
	{
		if (container->m_labels.find(it->first) == container->m_labels.end())
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
					clean_label(s);
					container->m_labels.emplace(it->first, move(s));
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
		m_dump[container->m_id]["name"] = container->m_name;
		if (!container->m_image.empty())
		{
			m_dump[container->m_id]["image"] = container->m_image;
		}
		if (!container->m_labels.empty())
		{
			m_dump[container->m_id]["labels"] = container->m_labels;
		}
	}

	if (metadata_complete)
	{
		container->m_metadata_deadline = 0;
	}
	if (container == &container_info)
	{
		manager->add_container(container_info, tinfo);
		manager->notify_new_container(container_info);
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
