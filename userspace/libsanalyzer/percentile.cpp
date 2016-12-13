#include "percentile.h"


percentile::percentile(const std::vector<int>& pctls, double eps)
{
	if(eps <= 0 or eps >= 0.5)
	{
		throw sinsp_exception("Invalid max error specified: " + std::to_string(eps));
	}
	std::vector<double> percentiles;
	std::transform(std::begin(pctls), std::end(pctls), std::back_inserter(percentiles),
					[](int i) { return static_cast<double>(i)/100.0; });
	if(-1 == init_cm_quantile(eps, &percentiles[0], percentiles.size(), &m_cm))
	{
		std::ostringstream os;
		os << '[';
		for(const auto& p : percentiles) { os << p << ','; }
		os << ']';
		throw sinsp_exception("Invalid percentiles specified: " + os.str());
	}
	for(const auto& p : pctls)
	{
		m_pctl_map.insert({p, 0});
	}
}

percentile::~percentile()
{
	if(0 != destroy_cm_quantile(&m_cm))
	{
		//g_logger.log("Error destroying statsite quantile.", sinsp_logger::SEV_ERROR);
	}
}

const percentile::p_map_type& percentile::percentiles()
{
	if(0 != cm_flush(&m_cm))
	{
		throw sinsp_exception("Percentiles error while flushing.");
	}
	for(auto& pm : m_pctl_map)
	{
		pm.second = cm_query(&m_cm, static_cast<double>(pm.first) / 100.0);
	}
	return m_pctl_map;
}
