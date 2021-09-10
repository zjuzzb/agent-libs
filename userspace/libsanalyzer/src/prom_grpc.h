#pragma once

#include <functional>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>

#include "coclient.h"
#include "common_logger.h"
#include "stream_grpc_status.h"
#include "agent-prom.grpc.pb.h"
#include "prom_grpc_iface.h"

class prom_unarygrpc : public prom_unarygrpc_iface
{
public:
	prom_unarygrpc(const std::string& sock) : prom_unarygrpc_iface(sock)
	{
	}

	bool start_unary_connection(int64_t boot_ts, std::shared_ptr<agent_promscrape::Config>& config, prom_unarygrpc_iface::resp_cb_t response_cb) override;
	void reset() override;
	void process_queue() override;

private:
	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_config_conn;
	std::unique_ptr<unary_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncApplyConfig)> m_grpc_applyconfig;
};

class prom_streamgrpc : public prom_streamgrpc_iface
{

public:
	prom_streamgrpc(const std::string& sock) : prom_streamgrpc_iface(sock)
	{
	}

	void start_stream_connection(int64_t boot_ts, prom_streamgrpc_iface::resp_cb_t response_cb)override;
	bool started() override;
	void reset() override;
	void process_queue() override;

private:
	uint64_t m_boot_ts;
	std::shared_ptr<agent_promscrape::ScrapeService::Stub> m_start_conn;
	std::unique_ptr<streaming_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncGetData)> m_grpc_start;
};
