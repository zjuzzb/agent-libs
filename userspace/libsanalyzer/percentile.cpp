#include "percentile.h"
#include "sinsp_int.h"
#include <cstring>
#include <cmath>

#define UNLIKELY(_x_)	__builtin_expect(!!(_x_), 0)

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
	init(percentiles, eps);
}

percentile::~percentile()
{
	destroy();
}

percentile::percentile(const percentile& other)
{
	init(other.m_percentiles, other.m_eps);
	copy(other);
}

percentile& percentile::operator=(const percentile &other)
{
	if(this != &other)
	{
		destroy();
		init(other.m_percentiles, other.m_eps);
		copy(other);
	}
	return *this;
}

void percentile::copy(const percentile& other)
{
	other.flush();
	m_num_samples += other.m_num_samples;
	if (other.m_num_samples) {
		alloc_tdigest_if_needed();
		m_digest->merge(other.m_digest.get());
	}
}

void percentile::alloc_tdigest_if_needed(void)
{
	if (UNLIKELY(m_digest == nullptr)) {
		// the default factor for unprocessed/buffered samples is 5, but 3
		// gets us comparable results with smaller memory foot print
		m_digest = std::unique_ptr<tdigest::TDigest>(
						new tdigest::TDigest(1/m_eps, 3/m_eps));
	}
}

void percentile::init(const std::vector<double> &percentiles, double eps)
{
	m_percentiles = percentiles;
	m_eps = eps;
	m_num_samples = 0;
}

void percentile::destroy(std::vector<double>* percentiles)
{
	if(percentiles)
	{
		*percentiles = m_percentiles;
	}

	m_digest.reset();
	m_eps = 0;
	m_percentiles.clear();
	m_num_samples = 0;
}

std::vector<double> percentile::get_percentiles() const
{
	return m_percentiles;
}

void percentile::reset()
{
	if(sample_count())
	{
		auto eps = m_eps;
		std::vector<double> percentiles;
		destroy(&percentiles);
		init(percentiles, eps);
	}
}

void percentile::flush() const
{
	if (m_digest) {
		m_digest->compress();
	}
}

percentile::p_map_type percentile::percentiles()
{
	flush();
	p_map_type pm;
	for (auto q : m_percentiles) {
		pm[round(q * 100.)] = (m_num_samples) ? m_digest->quantile(q) : 0;
	}
	return pm;
}

void percentile::dump_samples()
{
	std::cout << "Dumping " << m_num_samples << " samples" << std::endl;
	if (m_digest) {
		for (auto &c : m_digest->processed()) {
			std::cout << "value=" << c.mean() << ", weight=" << c.weight() << std::endl;
		}
		for (auto &c : m_digest->unprocessed()) {
			std::cout << "value=" << c.mean() << ", weight=" << c.weight() << std::endl;
		}
	}
}
