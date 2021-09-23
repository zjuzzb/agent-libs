#include <memory>

#include "agent-prom.pb.h"
#include "common_logger.h"
#include "configuration_manager.h"
#include "type_config.h"
#include "promscrape_conf.h"

COMMON_LOGGER();

namespace prom_helper
{

type_config<bool> c_use_promscrape(
	true,
	"Whether or not to use promscrape for prometheus metrics",
	"use_promscrape");

type_config<bool> c_prom_service_discovery(
    false,
    "Whether or not to enable Prometheus Service Discovery (aka promscrape_v2)",
    "prometheus",
	"prom_service_discovery");

// Promscrape GRPC server address: At this point the default agent root-dir is not yet
// known, so it will be inserted during config validation
type_config<std::string> c_promscrape_sock(
	"unix:/run/promscrape.sock",
	"Socket address URL for promscrape server",
	"promscrape_address");

type_config<bool> c_allow_bypass(
	true,
	"Allow a metric endpoint to bypass limits and filters",
	"promscrape_allow_bypass");

type_config<std::string> c_promscrape_web_sock(
	"127.0.0.1:9990",
	"Socket address URL for promscrape web server",
	"promscrape_web_address");

type_config<bool> c_promscrape_web_enable(
	true,
	"Enable promscrape web server with target status",
	"promscrape_web_enable");

type_config<int> c_promscrape_connect_interval(
	10,
	"Interval for attempting to connect to promscrape",
	"promscrape_connect_interval");

type_config<int> c_promscrape_connect_delay(
	10,
	"Delay before attempting to connect to promscrape",
	"promscrape_connect_delay");

type_config<bool>::mutable_ptr c_export_fastproto =
	type_config_builder<bool>(false,
	"Whether or not to export metrics using newer protocol",
	"promscrape_fastproto")
	.post_init([](type_config<bool> &config)
{
		bool &value = config.get_value();
		if (!value)
		{
			return;
		}
		if (!c_use_promscrape.get_value())
		{
			LOG_INFO("promscrape_fastproto enabled without promscrape, disabling");
			value = false;
		}
})
	.build_mutable();

type_config<int> c_promscrape_stats_log_interval(
    60,
    "Interval for logging promscrape timeseries statistics",
    "promscrape_stats_log_interval");

type_config<bool> c_always_gather_stats(
    false,
    "Gather statistics and metadata in the background for all prometheus targets",
    "promscrape_gather_stats");

uint64_t get_one_second_in_ns()
{
    static const uint64_t ONE_SECOND_IN_NS = 1000000000LL;
    return ONE_SECOND_IN_NS;
}

/**
 * Called by prometheus::validate_config() right after prometheus
 * configuration has been read from config file.
 * Ensures that configuration is consistent.
 * 
 */
void validate_config(bool prom_enabled, const promscrape_conf& scrape_conf, const std::string &root_dir)
{
	bool &use_promscrape = c_use_promscrape.get_value();
	if (use_promscrape && !prom_enabled)
	{
		LOG_INFO("promscrape enabled without prometheus, disabling");
		use_promscrape = false;
	}
	bool &fastproto = (*c_export_fastproto).get_value();
	
	if (fastproto && !scrape_conf.ingest_raw())
	{
		LOG_INFO("promscrape_fastproto is only supported for raw metrics, disabling."
			" Enable prometheus.ingest_raw to enable fastproto");
		fastproto = false;
	}
	if (fastproto && scrape_conf.ingest_calculated())
	{
		LOG_INFO("ingest_calculated is enabled but not supported with promscrape_fastproto."
			"You will only get raw prometheus metrics");
	}
	std::string &sock = c_promscrape_sock.get_value();
	if (sock.compare(0,6,"unix:/") == 0)
	{
		// Insert root-dir for unix socket address
		sock = "unix:" + root_dir + "/" + sock.substr(6);
	}
}

/**
 * Currently only supported for 10s flush when fastproto is
 * enabled. Returns true if the aggregator callback mechanism
 * can be used to emit metrics instead of the analyzer.
 */
bool can_use_metrics_request_callback()
{
	return c_export_fastproto->get_value() &&
		   configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value();
}

/**
 *  Promscrape v2 doesn't populate the legacy_metric_type field
 *  For some reason the C++ protobuf API doesn't have a way
 *  to check field existence but instead the field is reported
 *  as 0 which in this case equals MT_INVALID
 * 
 * @param mt Legacy metric type
 * 
 * @return bool true if raw, false otherwise.
 */
bool metric_type_is_raw(agent_promscrape::Sample::LegacyMetricType mt)
{

	return (mt == agent_promscrape::Sample::MT_RAW) ||
		   (mt == agent_promscrape::Sample::MT_INVALID);
}

int elapsed_s(uint64_t old, uint64_t now)
{
	return (now - old) / get_one_second_in_ns();
}

/**
 * Given a sample, find the value of the given label name.
 * 
 */
std::string get_label_value(const agent_promscrape::Sample &sample, const std::string &labelname)
{
	for (const auto &label : sample.labels())
	{
		if (label.name() == labelname)
		{
			return label.value();
		}
	}
	return "";
}

/**
 * Add a label to given set of labels.
 * 
 */
void set_label_value(google::protobuf::RepeatedPtrField<agent_promscrape::Label> *labels,
	const std::string &name, const std::string &value)
{
	for (auto &label :*labels)
	{
		if (!label.name().compare(name))
		{
			label.set_value(value);
			return;
		}
	}
	auto new_label = labels->Add();
	new_label->set_name(name);
	new_label->set_value(value);
}

}

