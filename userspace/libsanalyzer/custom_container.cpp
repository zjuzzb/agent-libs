#include "custom_container.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "logger.h"

#include <Poco/Exception.h>

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


bool custom_container::resolver::resolve(sinsp_container_manager* manager, sinsp_threadinfo* tinfo, bool query_os_for_missing_info)
{
	sinsp_container_info container_info;
	render_context render_ctx;
	container_info.m_type = CT_CUSTOM;

	if (!m_enabled || !match_cgroup(tinfo, render_ctx) || !match_environ(tinfo, render_ctx))
	{
		return false;
	}

	auto env = tinfo->get_env();

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

	tinfo->m_container_id = container_info.m_id;
	if (manager->container_exists(container_info.m_id))
	{
		return true;
	}

	if (m_name_pattern.empty())
	{
		container_info.m_name = container_info.m_id;
	}
	else
	{
		try {
			m_name_pattern.render(container_info.m_name, render_ctx, env);
			if (container_info.m_name.empty())
			{
				g_logger.format(sinsp_logger::SEV_WARNING, "Custom container of pid %lu returned an empty name, assuming it's not a match", tinfo->m_tid);
				return false;
			}
		} catch (const Poco::RuntimeException& e) {
			g_logger.format(sinsp_logger::SEV_WARNING, "Disabling custom container name due to error in configuration: %s", e.message().c_str());
			m_name_pattern = custom_container::subst_template();
			container_info.m_name = container_info.m_id;
		}
	}

	try {
		m_image_pattern.render(container_info.m_image, render_ctx, env);
	} catch (const Poco::RuntimeException& e) {
		g_logger.format(sinsp_logger::SEV_WARNING, "Disabling custom container image due to error in configuration: %s", e.message().c_str());
		m_image_pattern = custom_container::subst_template();
		container_info.m_image = container_info.m_id;
	}

	auto it = m_label_patterns.begin();
	while (it != m_label_patterns.end())
	{
		try {
			string s;
			it->second.render(s, render_ctx, env);
			if (!s.empty())
			{
				container_info.m_labels.emplace(it->first, move(s));
			}
		} catch (const Poco::RuntimeException& e) {
			g_logger.format(sinsp_logger::SEV_WARNING, "Disabling custom container label %s due to error in configuration: %s", it->first.c_str(), e.message().c_str());
			it = m_label_patterns.erase(it);
			continue;
		}
		++it;
	}

	manager->add_container(container_info, tinfo);
	manager->notify_new_container(container_info);
	return true;
}
