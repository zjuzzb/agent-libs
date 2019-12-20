/**
 * @file
 *
 * Interface to async aggregator
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "aggregator_overrides.h"
#include "analyzer_flush_message.h"
#include "thread_safe_container/blocking_queue.h"
#include "watchdog_runnable.h"
#include "connection_manager.h"  // because aggregator_limits is a message_handler. should probably be broken down a bit.
#include "metrics_file_emitter.h"
#include "aggregation_context.pb.h"
#include "dragent_settings_interface.h"

class test_helper;

namespace dragent
{

class aggregator_limits : public connection_manager::message_handler
{
public:
	static std::shared_ptr<aggregator_limits> global_limits;

	aggregator_limits()
	{
	}

	void cache_limits(const draiosproto::aggregation_context& context);
	bool handle_message(const draiosproto::message_type type,
	                    uint8_t* buffer,
	                    size_t buffer_size) override;

	void set_builder_limits(message_aggregator_builder_impl& builder);

	bool m_do_limiting = true;

	// The backend does not understand some field locations that are natively
	// produced by the agent, so until they do, we have to perform a translation
	// for the backend. SMBACK-3978
	bool m_relocate_moved_fields = true;

	// we don't use the actual proto message here so that we can
	// get atomic update of each individual value and not worry about
	// synchronization across the connection manager and aggregator threads.
	// We don't care if the limits are consistent among themselves, as that
	// will only last 1 emission...we just care that we get either the new or
	// the old value. Reading from the protobuf object might not guarantee that.
	uint32_t m_jmx = UINT32_MAX;
	uint32_t m_statsd = UINT32_MAX;
	uint32_t m_app_check = UINT32_MAX;
	uint32_t m_prometheus = UINT32_MAX;
	uint32_t m_connections = UINT32_MAX;
	uint32_t m_prog_aggregation_count = UINT32_MAX;
	double m_prom_metrics_weight = 1;
	uint32_t m_top_files_count = UINT32_MAX;
	uint32_t m_top_devices_count = UINT32_MAX;
	uint32_t m_container_server_ports = UINT32_MAX;
	uint32_t m_host_server_ports = UINT32_MAX;
	uint32_t m_kubernetes_pods = UINT32_MAX;
	uint32_t m_kubernetes_jobs = UINT32_MAX;
	uint32_t m_containers = UINT32_MAX;
	uint32_t m_event_count = UINT32_MAX;
	uint32_t m_client_queries = UINT32_MAX;
	uint32_t m_server_queries = UINT32_MAX;
	uint32_t m_client_query_types = UINT32_MAX;
	uint32_t m_server_query_types = UINT32_MAX;
	uint32_t m_client_tables = UINT32_MAX;
	uint32_t m_server_tables = UINT32_MAX;
	uint32_t m_client_status_codes = UINT32_MAX;
	uint32_t m_server_status_codes = UINT32_MAX;
	uint32_t m_client_urls = UINT32_MAX;
	uint32_t m_server_urls = UINT32_MAX;
	uint32_t m_client_ops = UINT32_MAX;
	uint32_t m_server_ops = UINT32_MAX;
	uint32_t m_client_collections = UINT32_MAX;
	uint32_t m_server_collections = UINT32_MAX;
	uint32_t m_container_mounts = UINT32_MAX;
	uint32_t m_metrics_mounts = UINT32_MAX;
};

/**
 * The async stage which takes queue items, runs them through the aggregator
 * and eventually puts them on an output queue.
 */
class async_aggregator : public dragent::watchdog_runnable
{
public:
	using queue_t = typename thread_safe_container::blocking_queue<std::shared_ptr<flush_data_message>>;

	/**
	 * Initialize this async_aggregator.
	 */
	async_aggregator(queue_t& input_queue,
			 queue_t& output_queue,
			 uint64_t timeout_ms,
			 const std::string& root_dir);

	~async_aggregator();

	void stop();

	/**
	 * sets the number of input protobufs to aggregate before generating an output.
	 * Setting to 0 disables aggregation altogether
	 *
	 * Setting the aggregation_interval_source (below) will override any interval
	 * set via this function.
	 *
	 * @param[in] interval count of input samples between outputs
	 */
	void set_aggregation_interval(uint32_t interval_s);

	/**
	 * Sets the aggregation interval source.
	 *
	 * The source is an object that knows the canonical negotiated aggregation
	 * interval. Setting this function overrides any interval set above.
	 */
	void set_aggregation_interval_source(aggregation_interval_source* source);

private:
	/**
	 * This will block waiting for work, do that work, then block
	 * again waiting for work. This method will terminate when the
	 * async_aggregator is destroyed or stop() is called.
	 */
	void do_run();

public:
	/**
	 * backend has a GLOBAL limit for jmx attributes. there's no
	 * good place to do this limiting
	 */
	static uint32_t count_attributes(const draiosproto::jmx_attribute& attribute);
	static void limit_jmx_attributes_helper(draiosproto::java_info& java_info,
	                                        int64_t& attributes_remaining);
	static void limit_jmx_attributes(draiosproto::metrics& metrics, uint32_t limit);

	/**
	 * some metrics locations were moved when agent aggregation was implemented. BE
	 * doesn't know how to handle that yet.
	 */
	static void relocate_moved_fields(draiosproto::metrics& metrics);
	static void relocate_prom_metrics(draiosproto::proto_info& proto_info);

private:
	std::atomic<bool> m_stop_thread;
	uint64_t m_queue_timeout_ms;

	queue_t& m_input_queue;
	queue_t& m_output_queue;
	message_aggregator_builder_impl m_builder;
	metrics_message_aggregator_impl* m_aggregator;
	std::shared_ptr<flush_data_message> m_aggregated_data;
	aggregation_interval_source* m_aggregation_interval_source;

	uint32_t m_count_since_flush;
	uint32_t m_aggregation_interval;

	metrics_file_emitter m_file_emitter;

	friend class ::test_helper;
};

}  // end namespace dragent
