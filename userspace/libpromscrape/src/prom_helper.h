#pragma once

#include <memory>
#include <string>

#include "agent-prom.pb.h"
#include "promscrape_conf.h"
#include "type_config.h"

namespace prom_helper
{
extern type_config<bool>c_use_promscrape;
extern type_config<std::string>c_promscrape_sock;
extern type_config<std::string>c_promscrape_web_sock;
extern type_config<bool>c_promscrape_web_enable;
extern type_config<bool>::mutable_ptr c_export_fastproto;
extern type_config<bool>c_allow_bypass;
extern type_config<bool>c_prom_service_discovery;
extern type_config<int>c_promscrape_connect_interval;
extern type_config<int>c_promscrape_connect_delay;
extern type_config<int>c_promscrape_stats_log_interval;
extern type_config<bool>c_always_gather_stats;

uint64_t get_one_second_in_ns();

// Returns whether or not the metrics_request_callback can be used by
// the aggregator to populate the metrics protobuf
bool can_use_metrics_request_callback();

void validate_config(bool prom_enabled, const promscrape_conf& scrape_conf, const std::string &root_dir);

bool metric_type_is_raw(agent_promscrape::Sample::LegacyMetricType mt);

int elapsed_s(uint64_t old, uint64_t now);

std::string get_label_value(const agent_promscrape::Sample &sample, const std::string &labelname);

void set_label_value(google::protobuf::RepeatedPtrField<agent_promscrape::Label> *labels,
	const std::string &name, const std::string &value);

}


