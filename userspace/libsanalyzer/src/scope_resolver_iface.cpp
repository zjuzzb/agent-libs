#include "common_logger.h"
#include "scope_resolver_iface.h"

namespace
{
COMMON_LOGGER();
}

bool operator==(const scope_predicates &a,
		const scope_predicates &b)
{
	if(a.size() != b.size())
	{
		return false;
	}

	for(int i=0; i<a.size(); i++)
	{
		if(a[i].key() != b[i].key())
		{
			return false;
		}

		if(a[i].op() != b[i].op())
		{
			return false;
		}

		if(a[i].values().size() != b[i].values().size())
		{
			return false;
		}

		for(int j = 0; j < a[i].values().size(); j++)
		{
			if(a[i].values().at(j) != b[i].values().at(j))
			{
				return false;
			}
		}
	}

	return true;
}
bool scope_resolver_iface::match_predicate(const draiosproto::scope_predicate& p, const std::string& value)
{
	// KISS for now
	LOG_DEBUG(
		"infra_state: Evaluating %s %s %s%s with value %s",
		p.key().c_str(),
		draiosproto::scope_operator_Name(p.op()).c_str(),
		p.values(0).c_str(),
		((p.op() == draiosproto::IN_SET || p.op() == draiosproto::NOT_IN_SET) ? "..." : ""),
		value.c_str());
	bool ret;
	switch (p.op())
	{
	case draiosproto::EQ:
		ret = p.values(0) == value;
		break;
	case draiosproto::NOT_EQ:
		ret = p.values(0) != value;
		break;
	case draiosproto::CONTAINS:
		ret = value.find(p.values(0)) != std::string::npos;
		break;
	case draiosproto::NOT_CONTAINS:
		ret = value.find(p.values(0)) == std::string::npos;
		break;
	case draiosproto::STARTS_WITH:
		ret = value.substr(0, p.values(0).size()) == p.values(0);
		break;
	case draiosproto::IN_SET:
		ret = false;
		for (auto v : p.values())
		{
			if (v == value)
			{
				ret = true;
				break;
			}
		}
		break;
	case draiosproto::NOT_IN_SET:
		ret = true;
		for (auto v : p.values())
		{
			if (v == value)
			{
				ret = false;
				break;
			}
		}
		break;
	default:
		LOG_WARNING("infra_state: Cannot evaluate scope_predicate %s",
			    p.DebugString().c_str());
		ret = true;
	}

	return ret;
}

static std::string predicates_as_str(::scope_predicates preds)
{
	std::string buf;
	for(int i=0; i < preds.size(); i++)
	{
		if(buf != "")
		{
			buf += " ";
		}
		buf += preds[i].DebugString();
	}

	return buf;
}

static std::string tags_as_str(const std::map<std::string, std::string> &agent_tags)
{
	std::string buf;

	for(auto &it : agent_tags)
	{
		if(buf != "")
		{
			buf += " ";
		}

		buf += it.first + "=" + it.second;
	}

	return buf;
}

bool scope_resolver_iface::match_agent_tag_predicates(const scope_predicates &predicates,
						      const std::map<std::string, std::string> &agent_tags,
						      scope_predicates &remaining_predicates)
{
	// First, iterate over scope predicates and find those that
	// use "agent.tag.XXX". Check those scope predicates against
	// the configured agent tags, and also remove them from the
	// set of scope predicates before continuing.
	LOG_DEBUG("match_agent_tag_predicates preds " + predicates_as_str(predicates) +
		  " agent tags " + tags_as_str(agent_tags));
	remaining_predicates.Clear();

	for(auto &pred : predicates)
	{
		if(pred.key().rfind("agent.tag.") == 0)
		{
			auto it = agent_tags.find(pred.key());
			if(it == agent_tags.end())
			{
				return false;
			}
			if(match_predicate(pred, it->second) == false)
			{
				return false;
			}
		}
		else
		{
			auto newpred = remaining_predicates.Add();
			newpred->CopyFrom(pred);
		}
	}

	return true;
}

