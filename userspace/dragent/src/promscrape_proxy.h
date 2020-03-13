#pragma once

#include "promscrape.h"

#include <metric_limits.h>
#include <prometheus.h>
#include "watchdog_runnable.h"

class promscrape_proxy : public dragent::watchdog_runnable {
public:
	explicit promscrape_proxy(std::shared_ptr<promscrape> ps) :
		dragent::watchdog_runnable("promscrape"),
		m_promscrape(ps)
	{
	}

	void do_run() override
	{
		while (heartbeat() && m_promscrape)
		{
			m_promscrape->next_th();
		}
	}
private:
	std::shared_ptr<promscrape> m_promscrape;
};
