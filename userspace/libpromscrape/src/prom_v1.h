#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>

#include "agent-prom.grpc.pb.h"
#include "agent-prom.pb.h"
#include "draios.pb.h"
#include "promscrape_conf.h"
#include "limits/metric_limits.h"
#include "interval_runner.h"
#include "prom_grpc_iface.h"
#include "promscrape_conf.h"
#include "prom_base.h"
#include "prom_job.h"
#include <thread_safe_container/blocking_queue.h>

class prom_base;

class prom_v1 : public prom_base
{

public:
	typedef std::map<std::string, std::string> tag_map_t;
	typedef std::unordered_map<std::string, std::string> tag_umap_t;

	explicit prom_v1(metric_limits::sptr_t ml, const promscrape_conf &prom_conf, bool threaded, interval_cb_t interval_cb,
		std::unique_ptr<prom_unarygrpc_iface> grpc_applyconfig, std::unique_ptr<prom_streamgrpc_iface> grpc_start);

	void sendconfig(const std::vector<prom_process> &prom_procs)override final;

	void next_th()override final;

private:
	void sendconfig_th(const std::vector<prom_process> &prom_procs);
	void handle_result(agent_promscrape::ScrapeResult &result)override final;
	void prune_jobs(uint64_t ts)override final;
	void reset()override final;

	void addscrapeconfig(int pid, const std::string &url,
		const std::string &container_id, const std::map<std::string, std::string> &options,
		const std::string &path, uint16_t port, const tag_map_t &tags,
		const tag_umap_t &infra_tags, uint64_t ts);
	void settargetauth(agent_promscrape::Target *target,
		const std::map<std::string, std::string> &options);
	int64_t assign_job_id(int pid, const std::string &url, const std::string &container_id,
		const tag_map_t &tags, uint64_t ts);
	void applyconfig();

	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_config_conn;
    std::unique_ptr<prom_unarygrpc_iface> m_grpc_applyconfig;

	thread_safe_container::blocking_queue<std::vector<prom_process>> m_config_queue;
	std::vector<prom_process> m_last_prom_procs;
	std::shared_ptr<agent_promscrape::Config> m_config;
	bool m_resend_config;
	uint64_t m_last_config_ts = 0;

	friend class prom_v1_helper;
};


