#include "common_logger.h"
#include "scope_resolver_iface.h"

namespace
{
COMMON_LOGGER();
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
