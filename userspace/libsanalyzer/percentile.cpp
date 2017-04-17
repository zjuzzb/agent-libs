#include "percentile.h"
#include "sinsp_int.h"
#include <cstring>

percentile::percentile(const std::set<double>& pctls, double eps)
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
					[](double d)
					{
						double ret = d/100.0;
						if(ret < 0 || ret > 1)
						{
							throw sinsp_exception("Percentiles: Invalid percentile specified: " + std::to_string(ret));
						}
						return ret;
					});
	init(&percentiles[0], percentiles.size(), eps);
}

percentile::~percentile()
{
	destroy();
}

percentile::percentile(const percentile& other)
{
	init(other.m_cm.quantiles, other.m_cm.num_quantiles, other.m_cm.eps);
	copy(other);
}

percentile& percentile::operator=(percentile other)
{
	if(this != &other)
	{
		destroy();
		init(other.m_cm.quantiles, other.m_cm.num_quantiles, other.m_cm.eps);
		copy(other);
	}
	return *this;
}

void percentile::copy(const percentile& other)
{
	other.flush();
	cm_sample* sample = other.m_cm.samples;
	while(sample)
	{
		if(0 != cm_add_sample(&m_cm, sample->value))
		{
			throw sinsp_exception("Percentiles error while adding value: " + std::to_string(sample->value));
		}
		sample = sample->next;
		++m_num_samples;
	}
}

void percentile::init(double* percentiles, size_t size, double eps)
{
	if(!size || 0 != init_cm_quantile(eps, percentiles, size, &m_cm))
	{
		std::ostringstream os;
		os << '[';
		for(size_t i = 0; i < size; ++i) { os << percentiles[i] << ','; }
		os << ']';
		throw sinsp_exception("Percentiles: Invalid percentiles specified: " + os.str());
	}
	m_num_samples = 0;
}

void percentile::destroy(std::vector<double>* percentiles)
{
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
	m_num_samples = 0;
}

std::vector<double> percentile::get_percentiles() const
{
	std::vector<double> percentiles(m_cm.quantiles, m_cm.quantiles + m_cm.num_quantiles);
	return percentiles;
}

std::vector<double> percentile::get_samples() const
{
	std::vector<double> samples;
	cm_sample* sample = m_cm.samples;
	while(sample)
	{
		samples.push_back(sample->value);
		sample = sample->next;
	}
	return samples;
}

void percentile::reset()
{
	if(sample_count())
	{
		double eps = m_cm.eps;
		std::vector<double> percentiles;
		destroy(&percentiles);
		init(&percentiles[0], percentiles.size(), eps);
	}
}

void percentile::flush() const
{
	if(m_num_samples)
	{
		if(0 != cm_flush(const_cast<cm_quantile*>(&m_cm)))
		{
			throw sinsp_exception("Percentiles error while flushing.");
		}
	}
}

percentile::p_map_type percentile::percentiles()
{
	flush();
	p_map_type pm;
	for(uint32_t i = 0; i < m_cm.num_quantiles; ++i)
	{
		pm[round(m_cm.quantiles[i] * 100.)] = cm_query(&m_cm, m_cm.quantiles[i]);
	}
	return pm;
}

void percentile::dump_samples()
{
	std::cout << "Dumping " << m_num_samples << " samples" << std::endl;
	cm_sample* sample = m_cm.samples;
	while(sample)
	{
		std::cout << "value=" << sample->value << ", width=" << sample->width << ", delta=" << sample->delta << std::endl;
		sample = sample->next;
	}
}
