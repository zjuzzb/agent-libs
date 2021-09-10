#pragma once

#include "promscrape.h"
#include "running_state_runnable.h"
#include "prom_config_file_manager.h"
#include "protocol_handler.h"
#include "common_logger.h"

#include <string>
#include <time.h>
#include <signal.h>
#include <limits/metric_limits.h>
#include <prometheus.h>

class promscrape_proxy : public dragent::running_state_runnable {
public:
	explicit promscrape_proxy(std::shared_ptr<promscrape> ps, protocol_handler *ph, connection_manager *cm) :
		dragent::running_state_runnable("promscrape"),
		m_promscrape(ps),
		m_protocol_handler(ph),
		m_connection_manager(cm)
	{
		auto msg_cb = [this](std::shared_ptr<draiosproto::raw_prometheus_metrics> msg) {
			send_raw_prom_message(msg);
		};
		m_promscrape->set_raw_bypass_callback(msg_cb);

		m_start_time = time(nullptr);
	}

	void send_raw_prom_message(std::shared_ptr<draiosproto::raw_prometheus_metrics> msg)
	{
		if (m_protocol_handler == nullptr)
			return;
		if (!m_connection_manager->get_negotiated_raw_prometheus_support())
		{
			// Add logging
			g_logger.log("Tried to send raw prometheus metric message, but not supported by backend", sinsp_logger::SEV_WARNING);
			return;
		}
		m_protocol_handler->transmit(draiosproto::message_type::RAW_PROMETHEUS_METRICS, *msg,
			protocol_queue::item_priority::BQ_PRIORITY_MEDIUM, msg->timestamp_ns());
	}

	void do_run() override
	{
		for (uint32_t cnt = 0; heartbeat() && m_promscrape; cnt++)
		{
			// Note that get_negotiated_raw_prometheus_support() returns a cached value and
			// can potentially change after a reconnection.
			// It seems unlikely for a collector to suddenly stop accepting these messages though.
			m_promscrape->set_allow_bypass(m_connection_manager->get_negotiated_raw_prometheus_support());

			// next_th will wait for 100 ms (when no new configs are available).
			m_promscrape->next_th();

			// Only check for config file updates every second
			if (!(cnt%10))
			{
				prom_config_file_manager::instance()->update_files();
			}
		}
	}
private:
	std::shared_ptr<promscrape> m_promscrape;

	protocol_handler *m_protocol_handler;
	connection_manager *m_connection_manager;

	time_t m_start_time;
	bool m_injected_file = false;
};

class promscrape_stats_proxy : public dragent::running_state_runnable {
public:
	explicit promscrape_stats_proxy(std::shared_ptr<promscrape> ps) :
		dragent::running_state_runnable("promscrape_stats"),
		m_promscrape(ps)
	{
	}

	void do_run() override
	{
		while (heartbeat() && m_promscrape)
		{
			m_promscrape->periodic_gather_stats();
			sleep(1);
		}
	}
private:
	std::shared_ptr<promscrape> m_promscrape;
};
