#include "baseline_mgr.h"
#include "infrastructure_state.h"

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

std::vector<const security_baseline *> baseline_mgr::lookup(const security_policy &spolicy)
{
	std::vector<const security_baseline *> bls;
	
	if (!spolicy.has_baseline_details())
	{
		return bls;
	}

	g_log->debug("Lookup baselines for policy with id " + std::to_string(spolicy.id()));
	
	unsigned int n_filtered = 0;

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
		// filter out this baseline if there's no possible intersection
		// between the policy scope and the baseline grouping
		bool filter = false;
		for(const auto &pred : spolicy.scope_predicates())
		{
			for(const auto &entry : it->second->scope())
			{
				if(pred.key() == entry.key())
				{
					switch(pred.op())
					{
					case draiosproto::EQ:
						filter = pred.values(0) != entry.value();
						break;
					case draiosproto::NOT_EQ:
						filter = pred.values(0) == entry.value();
					case draiosproto::CONTAINS:
						filter = entry.value().find(pred.values(0)) == std::string::npos;
						break;
					case draiosproto::NOT_CONTAINS:
						filter = entry.value().find(pred.values(0)) != std::string::npos;
						break;
					case draiosproto::IN_SET: {
						bool found = false;
						for(auto v : pred.values()) {
							if (v == entry.value()) {
								found = true;
								break;
							}
						}
						filter = !found;
						break;
					}
					case draiosproto::NOT_IN_SET: {
						bool found = false;
						for(auto v : pred.values()) {
							if (v == entry.value()) {
								found = true;
								break;
							}
						}
						filter = found;
						break;
					}
					case draiosproto::STARTS_WITH:
						filter = entry.value().substr(0, pred.values(0).size()) != pred.values(0);
						break;
					}
					break;
				}
			}
		}

		if(!filter)
		{
			bls.push_back(it->second.get());
		}
		else
		{
			n_filtered++;
		}
	}

	g_log->debug("Lookup completed. " + std::to_string(bls.size()) + " baselines returned (" + std::to_string(n_filtered) + " filtered out)");

	return bls;
}
#endif // CYGWING_AGENT
