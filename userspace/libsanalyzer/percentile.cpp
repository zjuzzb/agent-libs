#include "percentile.h"
#include "sinsp_int.h"
#include <cstring>
#include <cmath>

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

percentile& percentile::operator=(percentile other)
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
	m_digest->merge(other.m_digest.get());
}

void percentile::init(const std::vector<double> &percentiles, double eps)
{
	m_percentiles = percentiles;
	m_eps = eps;
	// the default factor for unprocessed/buffered samples is 5, but 3
	// gets us comparable results with smaller memory foot print
	m_digest = std::unique_ptr<tdigest::TDigest>(
					new tdigest::TDigest(1/eps, 3/eps));
	m_num_samples = 0;
}

void percentile::destroy(std::vector<double>* percentiles)
{
	if(percentiles)
	{
		*percentiles = m_percentiles;
	}

	m_digest.release();
	m_eps = 0;
	m_percentiles.clear();
	m_num_samples = 0;
}

std::vector<double> percentile::get_percentiles() const
{
	return m_percentiles;
}

// XXX/nags: We should be returning the weight for each value which is
//           a crucial part for accurate percentiles
std::vector<double> percentile::get_samples() const
{
	std::vector<double> samples;
	auto &c1 = m_digest->processed();
	auto &c2 = m_digest->unprocessed();
	samples.reserve(c1.size() + c2.size());
	for (auto &c : c1) {
		samples.emplace_back(c.mean());
	}
	for (auto &c : c2) {
		samples.emplace_back(c.mean());
	}

	return samples;
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
	m_digest->compress();
}

percentile::p_map_type percentile::percentiles()
{
	flush();
	p_map_type pm;
	for (auto q : m_percentiles) {
		pm[round(q * 100.)] = m_digest->quantile(q);
	}
	return pm;
}

void percentile::dump_samples()
{
	std::cout << "Dumping " << m_num_samples << " samples" << std::endl;
	for (auto &c : m_digest->processed()) {
		std::cout << "value=" << c.mean() << ", weight=" << c.weight() << std::endl;
	}
	for (auto &c : m_digest->unprocessed()) {
		std::cout << "value=" << c.mean() << ", weight=" << c.weight() << std::endl;
	}
}
