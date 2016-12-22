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

	template <typename T>
	void add(T val)
	{
		g_logger.log("***** " + std::to_string(m_id) + " ADD  val=" + std::to_string(val));
		if(0 != cm_add_sample(&m_cm, val))
		{
			throw sinsp_exception("Percentiles error while adding value: " + std::to_string(val));
		}
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
		g_logger.log("***** " + std::to_string(m_id) + " HAS " + std::to_string(sample_count()) + " vals, INSERT " + std::to_string(val.size()) + " vals");
		for(const auto& v : val) { add(v); }
	}

	p_map_type percentiles();

	template <typename P, typename C>
	void to_protobuf(P* proto, C* (P::*add_func)())
	{
		g_logger.log("***** Percentile " + std::to_string(m_id) + " to_protobuf");
		p_map_type pm = percentiles();
		for(const auto& p : pm)
		{
			C* cp = (proto->*add_func)();
			cp->set_percentile(p.first);
			cp->set_value(p.second);
		}
	}

	void reset();
	std::vector<double> get_percentiles() const;
	std::vector<double> get_samples() const;
	uint32_t sample_count() const;

	int m_id = 0;
private:
	void init(std::vector<double>& percentiles, double eps = 0.1);
	void destroy(std::vector<double>* percentiles = nullptr);

	cm_quantile m_cm = {0};
	static int m_ID;
};

inline uint32_t percentile::sample_count() const
{
	return m_cm.num_samples;
}
