#pragma once

#include <memory>
#include <string>
#include <map>

#include "agent-prom.pb.h"
#include "draios.pb.h"
#include "promscrape_conf.h"
#include "limits/metric_limits.h"

class prom_v2 : public prom_base
{
public:
	// Map from url+job_name to job_id for Promscrape V2
	typedef std::map<std::pair<std::string, std::string>, int64_t> prom_joburl_map_t;

	explicit prom_v2(metric_limits::sptr_t ml, const promscrape_conf &scrape_conf, bool threaded, prom_base::interval_cb_t interval_cb, std::unique_ptr<prom_streamgrpc_iface> grpc_start);

	void next_th()override final;

private:
	void handle_result(agent_promscrape::ScrapeResult &result)override final;
	void prune_jobs(uint64_t ts)override final;
	void delete_job(int64_t job_id)override final;

	prom_joburl_map_t m_joburls;

	friend class prom_v2_helper;
};
