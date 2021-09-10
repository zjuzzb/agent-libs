
#pragma once

#include <string>
#include <map>

#include "promscrape.h"
#include <json/json.h>


namespace promscrape_cli 
{

typedef struct target_data {
    target_data();
    std::string url;
    std::string health;
    std::string pool;
    std::string pod;
    std::string error;
    promscrape_stats::metric_stats stats;
    int get_total_filtered_metrics() const;
    int get_total_unsent_metrics() const;
} target_data_t;

/**
 * 
 * Get the list of targets monitored by Prometheus 
 * 
 * @param[in] data  - The targets JSON output from Prometheus
 * @param[in] stats_map - Promscrape statistics map to verify 
 *       against existing targets
 * @param output - The output to display.
 */
void display_targets(const Json::Value &data,
                     const promscrape_stats::stats_map_t &stats_map,
                     std::string &output);

/**
 * 
 * Get details of specific target monitored by Prometheus 
 * 
 * @param[in] data  - The targets JSON output from Prometheus
 * @param[in] stats_map - Promscrape statistics map to verify 
 *  	 against existing targets
 * @param[in] url - The URL of the target. 
 * @param output - The output to display.
 */
void display_target(const Json::Value &data,
                    const promscrape_stats::stats_map_t &stats_map,
                    const std::string &url,
                    std::string &output);

/**
 * 
 * Get detailed output of all targets monitored by Prometheus 
 * 
 * @param[in] data  - The targets JSON output from Prometheus
 * @param[in] stats_map - Promscrape statistics map to verify 
 *       against existing targets
 * @param output - The output to display.
 */
void display_target_instances(const Json::Value &data,
                              const promscrape_stats::stats_map_t &stats_map,
                              std::string &output);
/**
 * 
 * Get the metadata of the given target 
 * @param[in] url - URL for which metadata is requested
 * @param[in] metric_map - Metrics map managed by Promscrape
 * @param[out] output - Result
 * @param[in] do_limit - When set to true only
 *  	 DISPLAY_ROWS_LIMIT metadata are returned.
 */
void display_target_metadata(const std::string &url,
                         const promscrape_stats::metric_metadata_map_t &metric_map,
                         std::string &output, const bool do_limit);

/**
 * Get the overall Prometheus statistics
 *
 * @param[in]  stats_map - Existing stats data for all the
 *  	 targets
 * @param[out] output - Result.
 */
void display_prometheus_stats(const promscrape_stats::stats_map_t &stats_map, std::string &output);

/**
 * Get the latest scrape for the given target. 
 * 
 * @param url - The url to scrape.
 * @param output - Result.
 */
void get_target_scrape(const std::string &url, std::string &output);
};
