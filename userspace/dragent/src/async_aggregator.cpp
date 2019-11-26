/**
 * @file
 *
 * Implementation of async_aggregator, which wraps the draiosproto::metrics aggregator
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#define __STDC_FORMAT_MACROS
#include "async_aggregator.h"
#include "analyzer_flush_message.h"
#include "analyzer_utils.h" // make_unique
#include "dragent_message_queues.h"
#include "type_config.h"
#include "configuration_manager.h"

namespace dragent
{
type_config<uint32_t>::ptr c_samples_between_flush =
    type_config_builder<uint32_t>(10,
                                  "Number of analyzer samples between outputs.",
                                  "aggregator",
                                  "samples_between_flush")
        .hidden()
        .build();

type_config<uint32_t>::ptr c_container_limit =
    type_config_builder<uint32_t>(20,
                                  "Number of analyzer samples between each aggregated sample",
                                  "aggregator",
                                  "container_limit")
        .hidden()
        .build();

std::shared_ptr<aggregator_limits> aggregator_limits::global_limits =
	std::make_shared<aggregator_limits>();

async_aggregator::async_aggregator(flush_queue& input_queue,
                                   flush_queue& output_queue,
                                   uint64_t queue_timeout_ms)
    : dragent::watchdog_runnable("aggregator"),
      m_stop_thread(false),
      m_queue_timeout_ms(queue_timeout_ms),
      m_input_queue(input_queue),
      m_output_queue(output_queue),
      m_builder(),
      m_count_since_flush(0),
      m_aggregation_interval(c_samples_between_flush->get_value())
{
	m_aggregator = new metrics_message_aggregator_impl(m_builder);
	m_aggregated_data = std::make_shared<flush_data_message>(
	    0, nullptr, make_unique<draiosproto::metrics>(), 0, 0, 0, 0, 0);
}

void aggregator_limits::cache_limits(const draiosproto::aggregation_context& context)
{
	m_jmx = context.metr_limits().jmx();
	m_statsd = context.metr_limits().statsd();
	m_app_check = context.metr_limits().app_check();
	m_prometheus = context.metr_limits().prometheus();
	m_connections = context.metr_limits().connections();
	m_prog_aggregation_count = context.metr_limits().prog_aggregation_count();
	m_prom_metrics_weight = context.metr_limits().prom_metrics_weight();
	m_top_files_count = context.metr_limits().top_files_count();
	m_top_devices_count = context.metr_limits().top_devices_count();
	m_host_server_ports = context.metr_limits().host_server_ports();
	m_container_server_ports = context.metr_limits().container_server_ports();
	m_kubernetes_pods = context.metr_limits().kubernetes_pods();
	m_kubernetes_jobs = context.metr_limits().kubernetes_jobs();
	m_containers = context.metr_limits().containers();
	m_event_count = context.metr_limits().event_count();
	m_client_queries = context.metr_limits().client_queries();
	m_server_queries = context.metr_limits().server_queries();
	m_client_query_types = context.metr_limits().client_query_types();
	m_server_query_types = context.metr_limits().server_query_types();
	m_client_tables = context.metr_limits().client_tables();
	m_server_tables = context.metr_limits().server_tables();
	m_client_status_codes = context.metr_limits().client_status_codes();
	m_server_status_codes = context.metr_limits().server_status_codes();
	m_client_urls = context.metr_limits().client_urls();
	m_server_urls = context.metr_limits().server_urls();
	m_client_ops = context.metr_limits().client_ops();
	m_server_ops = context.metr_limits().server_ops();
	m_client_collections = context.metr_limits().client_collections();
	m_server_collections = context.metr_limits().server_collections();
	m_container_mounts = context.metr_limits().container_mounts();
	m_metrics_mounts = context.metr_limits().metrics_mounts();

	m_do_limiting = context.enforce();
}

bool aggregator_limits::handle_message(const draiosproto::message_type type,
                                       uint8_t* buffer,
                                       size_t buffer_size)
{
	if (type != draiosproto::message_type::AGGREGATION_CONTEXT)
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
		                "Aggregator received unexpected message of type %d, ignoring.",
		                type);
		return false;
	}

	draiosproto::aggregation_context context;
	dragent_protocol::buffer_to_protobuf(buffer, buffer_size, &context);

	cache_limits(context);
	return true;
}

void aggregator_limits::set_builder_limits(message_aggregator_builder_impl& builder)
{
	builder.set_statsd_info_statsd_metrics_limit(m_statsd);
	builder.set_app_info_metrics_limit(m_app_check);
	builder.set_prometheus_info_metrics_limit(m_prometheus);
	builder.set_metrics_ipv4_connections_limit(m_connections);
	builder.set_metrics_ipv4_incomplete_connections_v2_limit(m_connections);
	builder.set_metrics_programs_limit(m_prog_aggregation_count);
	builder.set_process_top_files_limit(m_top_files_count);
	builder.set_metrics_top_files_limit(m_top_files_count);
	builder.set_container_top_files_limit(m_top_files_count);
	builder.set_container_top_devices_limit(m_top_devices_count);
	builder.set_metrics_top_devices_limit(m_top_devices_count);
	builder.set_process_top_devices_limit(m_top_devices_count);
	builder.set_host_network_by_serverports_limit(m_host_server_ports);
	builder.set_container_network_by_serverports_limit(m_container_server_ports);
	builder.set_k8s_state_pods_limit(m_kubernetes_pods);
	builder.set_k8s_state_jobs_limit(m_kubernetes_jobs);
	builder.set_metrics_containers_limit(m_containers);
	builder.set_metrics_events_limit(m_event_count);
	builder.set_sql_info_client_queries_limit(m_client_queries);
	builder.set_sql_info_server_queries_limit(m_server_queries);
	builder.set_sql_info_client_query_types_limit(m_client_query_types);
	builder.set_sql_info_server_query_types_limit(m_server_query_types);
	builder.set_sql_info_client_tables_limit(m_client_tables);
	builder.set_sql_info_server_tables_limit(m_server_tables);
	builder.set_http_info_client_status_codes_limit(m_client_status_codes);
	builder.set_http_info_server_status_codes_limit(m_server_status_codes);
	builder.set_http_info_client_urls_limit(m_client_urls);
	builder.set_http_info_server_urls_limit(m_server_urls);
	builder.set_mongodb_info_client_ops_limit(m_client_ops);
	builder.set_mongodb_info_servers_ops_limit(m_server_ops);
	builder.set_mongodb_info_client_collections_limit(m_client_collections);
	builder.set_mongodb_info_server_collections_limit(m_server_collections);
	builder.set_container_mounts_limit(m_container_mounts);
	builder.set_metrics_mounts_limit(m_metrics_mounts);

	// prom metrics weight is a bit of a funny one. It's not really a limit
	// so much as a config pushed from the backend. So we'll just set the config
	configuration_manager::instance()
	    .get_mutable_config<double>("aggregator.prom_metrics_weight")
	    ->set(m_prom_metrics_weight);
}

async_aggregator::~async_aggregator()
{
	stop();
	delete m_aggregator;
	m_aggregated_data = nullptr;
}

uint32_t async_aggregator::count_attributes(const draiosproto::jmx_attribute& attribute)
{
	uint32_t count = 1;  // for us
	for (auto attr : attribute.subattributes())
	{
		// yes this is recursive, but it is populated and handled
		// recursively everywhere else, so should be alright
		count += count_attributes(attr);
	}
	return count;
}

void async_aggregator::limit_jmx_attributes_helper(draiosproto::java_info& java_info,
                                                   int64_t& attributes_remaining)
{
	for (uint32_t bean_counter = 0 /*lol*/; bean_counter < java_info.beans().size(); bean_counter++)
	{
		if (attributes_remaining <= 0)
		{
			(*java_info.mutable_beans())[bean_counter].clear_attributes();
		}
		else
		{
			auto bean = java_info.beans()[bean_counter];
			for (uint32_t attr = 0; attr < bean.attributes().size(); attr++)
			{
				attributes_remaining -= count_attributes(bean.attributes()[attr]);
			}
		}
	}
}

void async_aggregator::limit_jmx_attributes(draiosproto::metrics& metrics, uint32_t limit)
{
	int64_t attributes_remaining = limit;
	limit_jmx_attributes_helper(*metrics.mutable_protos()->mutable_java(), attributes_remaining);
	limit_jmx_attributes_helper(
	    *metrics.mutable_unreported_counters()->mutable_protos()->mutable_java(),
	    attributes_remaining);
	for (uint32_t i = 0; i < metrics.programs().size(); i++)
	{
		limit_jmx_attributes_helper(
		    *(*metrics.mutable_programs())[i].mutable_procinfo()->mutable_protos()->mutable_java(),
		    attributes_remaining);
	}
	for (uint32_t i = 0; i < metrics.containers().size(); i++)
	{
		limit_jmx_attributes_helper(
		    *(*metrics.mutable_containers())[i].mutable_protos()->mutable_java(),
		    attributes_remaining);
	}
}

void async_aggregator::do_run()
{
	while (!m_stop_thread && heartbeat())
	{
		std::shared_ptr<flush_data_message> input_data;
		bool ret = m_input_queue.get(&input_data, m_queue_timeout_ms);
		if (!ret)
		{
			continue;
		}

		if (m_stop_thread)
		{
			return;
		}

		(void)heartbeat();

		// we cache this value as it can change at any time, and we
		// want a consistent number as we proceed through this logic.
		// this avoids the need for a lock
		uint32_t aggr_interval_cache = m_aggregation_interval;

		if (m_count_since_flush >= aggr_interval_cache && m_count_since_flush != 0)
		{
			g_logger.format(
			    sinsp_logger::SEV_INFO,
			    "Decreased aggregation interval. Discarding previously aggregated data.");
			m_aggregator->reset();
			m_aggregated_data = std::make_shared<flush_data_message>(
			    0, nullptr, make_unique<draiosproto::metrics>(), 0, 0, 0, 0, 0);
			m_count_since_flush = 0;
		}

		if (aggr_interval_cache == 0)
		{
			// this should probably be set already, but just be sure
			input_data->m_flush_interval = 0;
			if (!m_output_queue.put(input_data))
			{
				g_logger.format(sinsp_logger::SEV_WARNING, "Queue full, discarding sample");
			}
		}
		else
		{
			m_aggregated_data->m_ts = input_data->m_ts;
			m_aggregated_data->m_metrics_sent = input_data->m_metrics_sent;
			m_aggregator->aggregate(*input_data->m_metrics, *m_aggregated_data->m_metrics);

			m_count_since_flush++;
			if (m_count_since_flush == aggr_interval_cache)
			{
				m_aggregator->override_primary_keys(*m_aggregated_data->m_metrics);
				m_aggregator->reset();
				if (aggregator_limits::global_limits->m_do_limiting)
				{
					aggregator_limits::global_limits->set_builder_limits(m_builder);
					metrics_message_aggregator::limit(m_builder, *m_aggregated_data->m_metrics);
					limit_jmx_attributes(*m_aggregated_data->m_metrics,
					                     aggregator_limits::global_limits->m_jmx);
				}

				m_aggregated_data->m_flush_interval = aggr_interval_cache;

				if (!m_output_queue.put(m_aggregated_data))
				{
					g_logger.format(sinsp_logger::SEV_WARNING, "Queue full, discarding sample");
				}
				m_aggregated_data = std::make_shared<flush_data_message>(
				    0, nullptr, make_unique<draiosproto::metrics>(), 0, 0, 0, 0, 0);
				m_count_since_flush = 0;
			}
		}
	}
}

void async_aggregator::stop()
{
	m_stop_thread = true;
	m_input_queue.clear();
}

void async_aggregator::set_aggregation_interval(uint32_t interval)
{
	m_aggregation_interval = interval;
}

}  // end namespace dragent
