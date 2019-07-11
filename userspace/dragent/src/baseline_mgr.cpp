#include "baseline_mgr.h"
#include "infrastructure_state.h"
#include "common_logger.h"

#ifndef CYGWING_AGENT
security_baseline::security_baseline(const draiosproto::baseline &baseline)
	: draiosproto::baseline(baseline)
{
	// Convert the scope value (collection of
	// keys/values, no operator, statement) to a
	// predicate (same keys/values linked by "and" with an "equals" operator, a test)
	for(auto sv : scope())
	{
		draiosproto::scope_predicate *sp = m_predicates.Add();
		sp->set_key(sv.key());
		sp->set_op(draiosproto::EQ);
		sp->add_values(sv.value());
	}
}

security_baseline::~security_baseline()
{
}

baseline_mgr::baseline_mgr()
{
}

baseline_mgr::~baseline_mgr()
{
}

bool baseline_mgr::load(const draiosproto::baselines &baselines, std::string &errstr)
{
	m_baselines.clear();
	m_cache.clear();

	for (auto &baseline : baselines.baseline_list())
	{
		std::string grp_key = "";
		for (auto sv : baseline.scope())
		{
			grp_key += sv.key() + "_";
		}
		grp_key.pop_back();
		auto key = make_pair(grp_key, baseline.id());
		m_baselines[key] = make_unique<security_baseline>(baseline);
	}

	g_log->debug(std::to_string(baselines.baseline_list().size()) + " baselines loaded");

	return true;
}

std::shared_ptr<security_baseline> baseline_mgr::lookup(const std::string &container_id, infrastructure_state *infra_state, const security_policy &spolicy)
{
	if(!spolicy.has_baseline_details())
	{
		return NULL;
	}

	g_log->debug("Lookup baseline for container " + container_id + ", policy " + std::to_string(spolicy.id()));

	auto cache_key = make_pair(container_id, spolicy.id());
	if(m_cache.find(cache_key) != m_cache.end())
	{
		return m_cache[cache_key];
	}

	std::string grp_key = "";
	for (auto k : spolicy.baseline_details().baselines_wanted())
	{
		grp_key += k.key() + "_";
	}
	grp_key.pop_back();

	// loop over all the baselines with the same grouping of the policy
	auto key = make_pair(grp_key, "");
	for(auto it = m_baselines.lower_bound(key); it != m_baselines.end(); ++it)
	{
		infrastructure_state::uid_t uid = make_pair("container", container_id);
		if(infra_state->match_scope(uid, it->second->predicates()))
		{
			m_cache[cache_key] = it->second;
			return it->second;
		}
	}

	// no baseline found for this <container_id, grouping key> pair
	m_cache[cache_key] = NULL;

	return NULL;
}
#endif // CYGWING_AGENT
