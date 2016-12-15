#include "percentile.h"
#include "sinsp_int.h"


percentile::percentile(const std::vector<int>& pctls, double eps)
{
	if(pctls.empty())
	{
		throw sinsp_exception("Percentiles: no percentiles specified");
	}
	if(eps <= 0 or eps >= 0.5)
	{
		throw sinsp_exception("Percentiles: Invalid max error specified: " + std::to_string(eps));
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
		throw sinsp_exception("Percentiles: Invalid percentiles specified: " + os.str());
	}
}

percentile::~percentile()
{
	if(0 != destroy_cm_quantile(&m_cm))
	{
		g_logger.log("Percentiles: Error destroying statsite quantile.", sinsp_logger::SEV_ERROR);
	}
}

percentile::p_map_type percentile::percentiles()
{
	p_map_type pm;
	if(m_cm.num_samples)
	{
		if(0 != cm_flush(&m_cm))
		{
			throw sinsp_exception("Percentiles error while flushing.");
		}
		for(uint32_t i = 0; i < m_cm.num_quantiles; ++i)
		{
			pm[m_cm.quantiles[i] * 100] = cm_query(&m_cm, m_cm.quantiles[i]);
		}
	}
	return pm;
}
