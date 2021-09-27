#include <memory>

#include "prom_factory.h"
#include "prom_v1.h"
#include "prom_v2.h"
#include "prom_grpc.h"
#include "prom_helper.h"

/**
 * A factory method to create a Prometheus scraper based on the
 * provided dragent configuration.
 * 
 * @param ml - metric limits 
 * @param prom_conf - prometheus configuration
 * @param threaded - whether the scraper should use single
 *  				or multi-threaded.
 * @param interval_cb - The time interval to process and receive
 *  				  each scrape.
 * @return the created prometheus scraper.
 */
std::shared_ptr<prom_base> prom_factory::get(metric_limits::sptr_t ml, const prometheus_conf &prom_conf, bool threaded, prom_base::interval_cb_t interval_cb)
{

    std::unique_ptr<prom_streamgrpc_iface> prom_stream_grpc(new prom_streamgrpc(prom_helper::c_promscrape_sock.get_value()));
	std::shared_ptr<prom_base> base;
	if (prom_conf.prom_sd())
	{
		base = std::make_shared<prom_v2>(ml,
			                             prom_conf.get_scrape_conf(),
			                             threaded,
			                             interval_cb, 
			                             std::move(prom_stream_grpc));
	}
	else
	{
        std::unique_ptr<prom_unarygrpc_iface> prom_unary_grpc(new prom_unarygrpc(prom_helper::c_promscrape_sock.get_value()));
		base = std::make_shared<prom_v1>(ml,
			                             prom_conf.get_scrape_conf(),
			                             threaded,
			                             interval_cb, 
			                             std::move(prom_unary_grpc),
			                             std::move(prom_stream_grpc));
	}

	return base;
}



