#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
#include "tdigest/tdigest.h"

class percentile
{
public:
	typedef std::map<int, double> p_map_type;

	percentile() = delete;
	percentile(const std::set<double>& pctls, double eps = .01);
	~percentile();

	percentile(const percentile& other);
	percentile& operator=(percentile other);

	template <typename T>
	void add(T val)
	{
		m_digest->add(val);
		++m_num_samples;
	}

	template <typename T>
	void copy(const std::vector<T>& val)
	{
		reset();
		for(auto &v: val) {
			add(v);
		}
	}

	void merge(const percentile *other)
	{
		m_digest->merge(other->m_digest.get());
		m_num_samples += other->sample_count();
	}

	p_map_type percentiles();

	template <typename P, typename C>
	void to_protobuf(P* proto, C* (P::*add_func)())
	{
		p_map_type pm = percentiles();
		for(const auto& p : pm)
		{
			C* cp = (proto->*add_func)();
			cp->set_percentile(p.first);
			cp->set_value(p.second);
		}
		reset();
	}

	template <typename P, typename C>
	static void to_protobuf(const p_map_type& pm, P* proto, C* (P::*add_func)())
	{
		for(const auto& p : pm)
		{
			C* cp = (proto->*add_func)();
			cp->set_percentile(p.first);
			cp->set_value(p.second);
		}
	}

	void reset();
	std::vector<double> get_percentiles() const;
	uint32_t sample_count() const;

	void dump_samples();
	void flush() const;

private:
	void init(const std::vector<double> &percentiles, double eps = 0.1);
	void copy(const percentile& other);
	void destroy(std::vector<double>* percentiles = nullptr);

	std::vector<double> m_percentiles;
	double m_eps;
	std::unique_ptr<tdigest::TDigest> m_digest;
	size_t m_num_samples = 0;
};

inline uint32_t percentile::sample_count() const
{
	return m_num_samples;
}
