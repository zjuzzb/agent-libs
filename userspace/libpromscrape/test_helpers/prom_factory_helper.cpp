#include <memory>

#include "prom_factory_helper.h"
#include "prom_v1.h"
#include "prom_v2.h"
#include "prom_base.h"
#include "promscrape_conf.h"

/**
 * A helper factory method to create a mock Prometheus scraper
 * 
 * @param ml - metric limits 
 * @param prom_conf - prometheus configuration
 * @param threaded - whether the scraper should use single
 *  				or multi-threaded.
 * @param interval_cb - The time interval to process and receive
 *  				  each scrape.
 * @return the created prometheus scraper.
 */
std::shared_ptr<prom_base> prom_factory_helper::get(metric_limits::sptr_t ml, const promscrape_conf &prom_conf, bool threaded, prom_base::interval_cb_t interval_cb)
{

	std::shared_ptr<prom_base> base;
	if (prom_conf.prom_sd())
	{
		base = std::make_shared<prom_v2>(ml,
			                             prom_conf,
			                             threaded,
			                             interval_cb, 
			                             nullptr);
	}
	else
	{
		base = std::make_shared<prom_v1>(ml,
			                             prom_conf,
			                             threaded,
			                             interval_cb,
                                         nullptr,
                                         nullptr);
	}

	return base;
}
