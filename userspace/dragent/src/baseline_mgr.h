#pragma once

#include <set>
#include <map>

#include <sinsp.h>

#ifndef CYGWING_AGENT
#include "security_policy.h"
#include "infrastructure_state.h"

//
// Wrapper around draiosproto::baseline that add a numeric id and mantains
// the information needed to matching its scope against containers
// (so they don't need to be recreated for every match)
//

class SINSP_PUBLIC security_baseline : public draiosproto::baseline
{
public:
	security_baseline(const draiosproto::baseline &baseline);
	virtual ~security_baseline();

	inline const scope_predicates &predicates() const
	{
		return m_predicates;
	}

private:
	scope_predicates m_predicates;
};

class SINSP_PUBLIC baseline_mgr
{
public:
	baseline_mgr();

	virtual ~baseline_mgr();
	
	bool load(const draiosproto::baselines &baselines, std::string &errstr);

	// Given a container_id and a smart policy, this method returns the baseline to match against.
	std::shared_ptr<security_baseline> lookup(const std::string &container_id, infrastructure_state *infra_state, const security_policy &spolicy);
private:

	// (grouping_name, baseline_name) -> baseline
	std::map<std::pair<std::string, std::string>, std::shared_ptr<security_baseline>> m_baselines;

	// (container_id, smart policy id) -> baseline
	std::unordered_map<std::pair<std::string, uint64_t>, std::shared_ptr<security_baseline>> m_cache;
};
#endif // CYGWING_AGENT
