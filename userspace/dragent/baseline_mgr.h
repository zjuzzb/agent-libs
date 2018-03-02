#pragma once

#include <set>
#include <map>

#include <sinsp.h>

#ifndef CYGWING_AGENT
#include "security_policy.h"

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

	// Given a smart policy, this method returns the list of baselines to
	// match against.
	// It uses both the baseline scope_indicator and the policy scope to
	// filter out the baselines of containers that aren't in the policy scope
	// (e.g. baseline from k8s.ns=prod, policy scope contains k8s.ns=dev)
	std::vector<const security_baseline *> lookup(const security_policy &spolicy);

private:

	// (grouping_name, baseline_name) -> baseline
	std::map<std::pair<std::string, std::string>, std::unique_ptr<security_baseline>> m_baselines;
};
#endif // CYGWING_AGENT
