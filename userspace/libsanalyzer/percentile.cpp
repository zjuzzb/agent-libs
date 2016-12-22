#include "percentile.h"
#include "sinsp_int.h"
#include <cstring>

int percentile::m_ID = 0;

percentile::percentile(const std::set<double>& pctls, double eps): m_id(++m_ID)
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
					[](double d) { return d/100.0; });
	g_logger.log("***** Percentile " + std::to_string(m_id) + " construct");
	init(percentiles, eps);
}

percentile::~percentile()
{
	g_logger.log("***** Percentile " + std::to_string(m_id) + " destruct");
	destroy();
}

void percentile::init(std::vector<double>& percentiles, double eps)
{
	g_logger.log("***** Percentile " + std::to_string(m_id) + " init");
	if(-1 == init_cm_quantile(eps, &percentiles[0], percentiles.size(), &m_cm))
	{
		std::ostringstream os;
		os << '[';
		for(const auto& p : percentiles) { os << p << ','; }
		os << ']';
		throw sinsp_exception("Percentiles: Invalid percentiles specified: " + os.str());
	}
}

void percentile::destroy(std::vector<double>* percentiles)
{
	g_logger.log("***** Percentile " + std::to_string(m_id) + " destroy");
	if(percentiles)
	{
		*percentiles = get_percentiles();
	}

	if(0 != destroy_cm_quantile(&m_cm))
	{
		if(percentiles)
		{
			throw sinsp_exception("Percentiles: Error destroying statsite quantile.");
		}
		else
		{
			g_logger.log("Percentiles: Error destroying statsite quantile.", sinsp_logger::SEV_ERROR);
		}
	}
	std::memset(&m_cm, 0, sizeof(m_cm));
}

std::vector<double> percentile::get_percentiles() const
{
	std::vector<double> percentiles;
	for(uint32_t i = 0; i < m_cm.num_quantiles; ++i)
	{
		percentiles.push_back(m_cm.quantiles[i]);
	}
	return percentiles;
}

std::vector<double> percentile::get_samples() const
{
	std::vector<double> samples;
	for(uint32_t i = 0; i < m_cm.num_samples; ++i)
	{
		samples.push_back(m_cm.samples[i].value);
	}
	return samples;
}

void percentile::reset()
{
	if(sample_count())
	{
		std::vector<double> percentiles;
		destroy(&percentiles);
		init(percentiles);
	}
}

percentile::p_map_type percentile::percentiles()
{
	g_logger.log("***** Percentile " + std::to_string(m_id) + " percentiles");
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
