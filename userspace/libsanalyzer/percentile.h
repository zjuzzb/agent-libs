#pragma once

#include "sinsp.h"
#include "sinsp_int.h"
extern "C"
{
	#include "cm_quantile.h"
}

//
// statsite wrapper http://statsite.github.io/statsite/
//

class percentile
{
public:
	typedef std::map<int, double> p_map_type;

	percentile(const std::set<double>& pctls, double eps = .01);
	~percentile();

	percentile(const percentile& other);
	percentile& operator=(percentile other);

	template <typename T>
	void add(T val, bool do_flush = true)
	{
		if(0 != cm_add_sample(&m_cm, val))
		{
			throw sinsp_exception("Percentiles error while adding value: " + std::to_string(val));
		}
		++m_num_samples;
		if(do_flush) { flush(); }
	}

	template <typename T>
	void copy(const std::vector<T>& val)
	{
		reset();
		insert(val);
	}

	template <typename T>
	void insert(const std::vector<T>& val)
	{
		if(val.size())
		{
			for(const auto& v : val) { add(v, false); }
			flush();
		}
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

	void reset();
	std::vector<double> get_percentiles() const;
	std::vector<double> get_samples() const;
	uint32_t sample_count() const;

	void dump_samples();
	void flush();

private:
	void init(double* percentiles, size_t size, double eps = 0.1);
	void copy(const percentile& other);
	void destroy(std::vector<double>* percentiles = nullptr);

	cm_quantile m_cm = {0};
	 // cm_quantile::num_samples is not a reliable source of information
	size_t m_num_samples = 0;
};

inline uint32_t percentile::sample_count() const
{
	return m_num_samples;
}
