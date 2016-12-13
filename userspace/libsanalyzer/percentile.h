#pragma once

#include "sinsp.h"
#include <iomanip>

//
// based on http://onlinestatbook.com/2/introduction/percentiles.html
//
// Data is sorted so that x[1] is the smallest value and x[n] is the largest,
// with N = total number of observations
//
// Rank R = (P / 100) * (N + 1)
//
// If R is an integer, the Pth percentile is the number with rank R.
// When R is not an integer, the Pth percentile is calculated by interpolation:
//
// 1) I[R] - integer portion of R
// 2) F[R] - fractional portion of R
// 3) Find scores with rank I[R] and I[R+1]
// 4) Interpolate by multiplying the difference between scores by F[R]
//    and adding result to the lower score:
//
//    R = F[R] * (I[R+1] - I[R])) + I[R];
//

template <typename T, typename TP = float>
class percentile
{
public:
	typedef std::vector<int> p_type;
	typedef std::multiset<T> v_type;
	typedef std::map<int, TP> p_map_type;

	percentile(const p_type& pctls, TP error = .005): m_percentiles(pctls), m_error(error)
	{
		for(const auto& p : m_percentiles)
		{
			if(p <= 0 || p > 100)
			{
				throw sinsp_exception("Invalid percentile specified: " + std::to_string(p));
			}
		}
	}

	void add(T val)
	{
		m_values.insert(val);
	}

	void copy(const std::vector<TP>& val)
	{
		m_values.clear();
		std::copy(val.begin(), val.end(), std::inserter(m_values, m_values.end()));
	}

	p_map_type percentiles() const
	{
		p_map_type pctl_map;
		int n = static_cast<int>(m_values.size());
		for(const auto& P : m_percentiles)
		{
			TP R = static_cast<TP>(P / 100.0) * static_cast<TP>(n + 1.0);
			int ir = static_cast<int>(floor(R));
			TP fr = R - ir;
			int r = static_cast<int>(R);
			TP val(0.0);
			if(m_values.size())
			{
				if(P == 100) // 100th percentile
				{
					val = *m_values.rbegin();
					continue;
				}
				auto it = m_values.begin();
				if(fr < m_error) // rank is integer
				{
					for(int i = 0; it != m_values.end(); ++i, ++it)
					{
						if((i + 1) == r)
						{
							val = *it;
							break;
						}
					}
				}
				else // rank is decimal
				{
					TP ir1(0.0), ir2(0.0);
					for(int i = 0; it != m_values.end(); ++i, ++it)
					{
						if((i + 1) == r) { ir1 = *it; }
						else if(i == r) { ir2 = *it; }
						if(ir1 && ir2) { break; }
					}
					if(it == m_values.end())
					{
						if(ir2 == 0 && ir1 != 0)
						{
							ir2 = ir1;
						}
					}
					// calculate the value
					val = (fr * (ir2 - ir1)) + ir1;
				}
			}
			pctl_map.insert({P, val});
		}

		return pctl_map;
	}

	template <typename P, typename C>
	void to_protobuf(P* proto) const
	{
		p_map_type pm = percentiles();
		for(const auto& p : pm)
		{
			C* cp = proto->add_percentile();
			cp->set_percentile(p.first);
			cp->set_value(p.second);
		}
	}

private:
	p_type m_percentiles;
	v_type m_values;
	double m_error;
};