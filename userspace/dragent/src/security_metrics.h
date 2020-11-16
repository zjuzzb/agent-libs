#ifndef CYGWING_AGENT
#pragma once

class security_evt_metrics : public internal_metrics::ext_source
{
public:
	security_evt_metrics()
	{
	}

	virtual ~security_evt_metrics()
	{
	}

	void init(std::string &prefix, bool include_falco)
	{
		m_prefix = prefix;
		m_include_falco = include_falco;
	}

	inline std::string &get_prefix()
	{
		return m_prefix;
	}

	enum reason
	{
		EVM_MATCH_ACCEPT = 0,
		EVM_MATCH_DENY,
		EVM_MATCH_NEXT,
		EVM_MISS_NO_FALCO_ENGINE,
		EVM_MISS_EF_DROP_FALCO,
		EVM_MISS_FALCO_EVTTYPE,
		EVM_MISS_QUAL,
		EVM_MISS_CONDS,
		EVM_MATCH_ITEMS,
		EVM_NOT_MATCH_ITEMS,
		EVM_MAX
	};

	void incr(reason res)
	{
		m_metrics[res]++;
	}

	void reset()
	{
		std::fill_n(m_metrics, EVM_MAX, 0);
	}

	std::string to_string()
	{
		std::string str;

		for(uint32_t i = 0; i < EVM_MAX; i++)
		{
			str += " " + m_prefix + "." +
				m_metric_names[i] + "=" +
				std::to_string(m_metrics[i]);
		}

		return str;
	}

	virtual void send_all(draiosproto::statsd_info* statsd_info)
	{
		for(uint32_t i=0; i<EVM_MAX; i++)
		{
			if((i == EVM_MISS_NO_FALCO_ENGINE ||
			    i == EVM_MISS_EF_DROP_FALCO ||
			    i == EVM_MISS_FALCO_EVTTYPE) &&
			   !m_include_falco)
			{
				continue;
			}
			internal_metrics::write_metric(statsd_info,
						       std::string("security.") + m_prefix + "." + m_metric_names[i],
						       draiosproto::STATSD_COUNT,
						       m_metrics[i]);
			m_metrics[i] = 0;
		}
	}

	virtual void send_some(draiosproto::statsd_info* statsd_info)
	{
	};

private:
	std::string m_prefix;
	bool m_include_falco;
	uint64_t m_metrics[EVM_MAX];
	std::string m_metric_names[EVM_MAX]{
			"match.accept",
			"match.deny",
			"match.next",
			"miss.no_falco_engine",
			"miss.ef_drop_falco",
			"miss.falco_evttype",
			"miss.qual",
			"miss.conds",
			"match.match_items",
			"match.not_match_items"};
};

#endif // CYGWING_AGENT
