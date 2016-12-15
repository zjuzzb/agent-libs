#pragma once

#include "sinsp.h"
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

	percentile(const std::vector<int>& pctls, double eps = .01);

	~percentile();

	template <typename T>
	void add(T val)
	{
		if(0 != cm_add_sample(&m_cm, val))
		{
			throw sinsp_exception("Percentiles error while adding value: " + std::to_string(val));
		}
	}

	template <typename T>
	void copy(const std::vector<T>& val)
	{
		for(const auto& v : val) { add(v); }
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
	}

private:
	cm_quantile m_cm;
};
