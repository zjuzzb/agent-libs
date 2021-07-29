#include <memory>
#include "common_logger.h"
#include "promscrape.h"
#include "promscrape_cli.h"
#include "uri.h"
#include "Poco/Exception.h"
#include "tabulate.hpp"

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPClientSession.h>
#include <json/json.h>

#include <stdexcept>

COMMON_LOGGER();
using namespace std;

using namespace tabulate;

namespace {

const int DISPLAY_ROWS_LIMIT = 10;

void get_targets(const Json::Value &data,
                 const promscrape_stats::stats_map_t& stats_map,
                 vector<promscrape_cli::target_data_t>& targets)
{
	if (!data.isObject() || !data.isMember("activeTargets"))
	{
		return;
	}

    for (const auto& target : data["activeTargets"])
	{
		promscrape_cli::target_data_t t;
		if (target.isMember("scrapePool"))
		{
			t.pool = target["scrapePool"].asString();
		}
		if (!target.isMember("scrapeUrl"))
		{
			LOG_INFO("target data: no URL");
			continue;
		}
		if (!target.isMember("health"))
		{
			LOG_INFO("target data: no health");
			continue;
		}

		t.url = target["scrapeUrl"].asString();
		t.health = target["health"].asString();
		if (target.isMember("lastError") && (t.health != "up"))
		{
			t.error = target["lastError"].asString();
		}
		if (target.isMember("discoveredLabels") && target["discoveredLabels"].isMember("__meta_kubernetes_pod_name"))
		{
			t.pod = target["discoveredLabels"]["__meta_kubernetes_pod_name"].asString();
		}

		auto stats_itr = stats_map.find(t.url);
		if (stats_itr != stats_map.end()) {
			t.stats = stats_itr->second;
		}

		targets.push_back(t);
	}
}

bool get_target(const Json::Value &data,
                const promscrape_stats::stats_map_t& stats_map,
                const std::string& url,
                promscrape_cli::target_data_t& target)
{
    vector<promscrape_cli::target_data_t> targets;
    get_targets(data, stats_map, targets);

	if (targets.empty()) 
    {
        return false;
    }

    for (const auto& tgt : targets)
    {
		if (tgt.url == url) {
            target = tgt;
            return true;
        }
    }

    return false;
}

std::string get_target_row(const promscrape_cli::target_data_t& target) 
{
    Table table;
    table.format().corner("").border("").column_separator("");

    //Target details
    table.add_row({"URL", target.url});
    table.add_row({"Health", target.health});
    table.add_row({"Instance/Pod", target.pod});
    
    //Total metrics
    auto& stats= target.stats;
    table.add_row({"Total Metrics Scraped", to_string(stats.raw_scraped + stats.calc_scraped)});
    table.add_row({"Total Metrics Sent", to_string(stats.raw_sent + stats.calc_sent)});
    table.add_row({"Total Metrics Filtered", to_string(target.get_total_filtered_metrics())});
    table.add_row({"Total Metrics Unsent", to_string(target.get_total_unsent_metrics())});
    table.add_row({"Metrics Over Global Limit", to_string(stats.over_global_limit)});
    

    //Raw metrics
    table.add_row({"Raw Metrics:"});
    table.add_row({"Scraped", to_string(stats.raw_scraped)});
    table.add_row({"Sent", to_string(stats.raw_sent)});
    table.add_row({"Filtered By Job", to_string(stats.raw_job_filter_dropped)});
    table.add_row({"Filtered By Global", to_string(stats.raw_global_filter_dropped)});
    table.add_row({"Metrics Over Job Limit", to_string(stats.raw_over_job_limit)});

    //Calculated Metrics
    table.add_row({"Calculated Metrics:"});
    table.add_row({"Scraped", to_string(stats.calc_scraped)});
    table.add_row({"Sent", to_string(stats.calc_sent)});
    table.add_row({"Filtered By Job", to_string(stats.calc_job_filter_dropped)});
    table.add_row({"Filtered By Global", to_string(stats.calc_global_filter_dropped)});
    table.add_row({"Metrics Over Job Limit", to_string(stats.calc_over_job_limit)});

    //Error
    table.add_row({"Error", (target.error.empty() ? "-" : target.error)});

    return table.str();
}

} // end anonymous namespace

promscrape_cli::target_data::target_data()
{
    memset(&stats, 0, sizeof(stats));
}

int promscrape_cli::target_data::get_total_filtered_metrics() const
{
    return stats.raw_job_filter_dropped +
           stats.raw_global_filter_dropped +
           stats.calc_job_filter_dropped +
           stats.calc_global_filter_dropped;
}

int promscrape_cli::target_data::get_total_unsent_metrics() const
{
    int unsent = stats.raw_scraped -
                 stats.raw_job_filter_dropped -
                 stats.raw_global_filter_dropped - 
                 stats.raw_sent;
    unsent += stats.calc_scraped -
              stats.calc_job_filter_dropped -
              stats.calc_global_filter_dropped -
              stats.calc_sent;
    return unsent;
}

void promscrape_cli::display_targets(const Json::Value &data,
                                     const promscrape_stats::stats_map_t& stats_map,
                                     std::string &output)
{
    vector<target_data_t> targets;
    get_targets(data, stats_map, targets);

    if (targets.empty()) 
    {
        output.append("No targets monitored. \n");
        return;
    }

    map<string, Table> pool_map;
	for (const auto& target : targets)
	{
        if (pool_map.find(target.pool) == pool_map.end()) {
            Table pool_tbl;
            pool_tbl.format().corner("").border("").column_separator("");
            pool_tbl.add_row({"URL", "Health", "Pod", "Sent/Total"});
            pool_map[target.pool] = pool_tbl;
        }
		auto &stats = target.stats;
		auto total = stats.raw_scraped + stats.calc_scraped;
		auto sent = stats.raw_sent + stats.calc_sent;
		std::string sent_str = to_string(sent) + "/" + to_string(total);
		pool_map[target.pool].add_row({ target.url, target.health, target.pod, sent_str });
    }

    Table table;
    table.format().corner("").border("").column_separator("");
    for (auto it = pool_map.begin(); it != pool_map.end(); it++) {
        table.add_row({"Pool: " + it->first});
        table.add_row({it->second});
    }
    output.append(table.str() + "\n");
	output.append("Use \"prometheus target show -details\" for detailed output of individual targets\n");
}

void promscrape_cli::display_target(const Json::Value &data,
                                    const promscrape_stats::stats_map_t& stats_map,
                                    const std::string& url,
                                     std::string &output)
{
    target_data_t target;
    const bool ret = get_target(data, stats_map, url, target);

    if (!ret) 
    {
        output.append("No targets monitored.\n");
        return;
    }

    output.append(get_target_row(target) + "\n");
    
}

void promscrape_cli::display_target_instances(const Json::Value &data,
                                              const promscrape_stats::stats_map_t& stats_map,
                                              std::string &output)
{
    vector<target_data_t> targets;
    get_targets(data, stats_map, targets);

    if (targets.empty()) 
    {
        output.append("No targets monitored.\n");
        return;
    }

    std::set<string> urls;
    for (const auto& target : targets)
	{
        auto ret = urls.insert(target.url);
        if (ret.second) {
            output.append(get_target_row(target) + "\n");
        }
    }
    
    output.append("\n");
}

void promscrape_cli::display_target_metadata(const std::string& url,
                                         const promscrape_stats::metric_metadata_map_t& metric_map,
                                         std::string &output, const bool do_limit)
{
	Table table;
	table.format().corner("").border("").column_separator("");
	table.add_row({"Name", "Type", "#TS", "Description"});
	table.column(3).format().width(80);
	output.append("Instance: " + url + "\n");
	std::set<std::pair<int,string>> sorted;
	int count = 0;
	for (auto metric_it = metric_map.begin(); metric_it != metric_map.end(); metric_it++, count++)
	{
		if (do_limit && count == DISPLAY_ROWS_LIMIT) {
			break;
		}
		sorted.insert(make_pair(metric_it->second.timeseries, metric_it->first));
	}
	for (auto item_it = sorted.rbegin(); item_it != sorted.rend(); item_it++)
	{
		try {
			table.add_row({item_it->second,
							  metric_map.at(item_it->second).type, to_string(item_it->first),
							  metric_map.at(item_it->second).help});
		} catch (const std::out_of_range& ex) {
			output = "Out of range exception hit while collecting metadata for target " + url + ". Reason: " + ex.what() + "\n";
			return;
		}
	}
	output.append(table.str() + "\n");
}

// Copied from log_summary()
void promscrape_cli::display_prometheus_stats(const promscrape_stats::stats_map_t& stats_map,
                                          std::string &output)
{
	int unsent_global = 0;

	Table table;
	table.format().corner("").border("").column_separator("");
	table.add_row({"Total Targets", to_string(stats_map.size())});

	for (const auto &stat : stats_map)
	{
		if (stat.second.over_global_limit)
		{
			int unsent = stat.second.raw_scraped -
                         stat.second.raw_job_filter_dropped -
                         stat.second.raw_global_filter_dropped - 
                         stat.second.raw_sent;
			unsent += stat.second.calc_scraped -
                      stat.second.calc_job_filter_dropped -
                      stat.second.calc_global_filter_dropped -
                      stat.second.calc_sent;
            
			if (stat.second.over_global_limit)
			{
				unsent_global += unsent;
			}
		}
	}
	
	table.add_row({"Global Unsent Metrics", to_string(unsent_global)});
	output.append(table.str() + "\n");

	//We will add job specific stats once we associate stats with job.
	//The stats_map doesn't have that yet.
}

void promscrape_cli::get_target_scrape(const std::string& url, string &output)
{
	LOG_DEBUG("Command line: Trying to scrape %s", url.c_str());
	if (url.empty())
	{
		output.append("Target URL (-url) is a required argument.\n");
		return;
	}

	try
	{
		uri uri(url);
		string host = uri.get_host();
		uint16_t port = uri.get_port();
		string path = uri.get_path();

		if (!uri.get_query().empty())
		{
			path += "?" + uri.get_query();
		}
		if (host.empty() || !port)
		{
			output.append("Invalid URL\n");
			return;
		}

		Poco::Net::HTTPClientSession session(host, port);
		string method("GET");
		Poco::Net::HTTPRequest request(method, path);
		Poco::Net::HTTPResponse response;
		session.sendRequest(request);
		std::istream &resp = session.receiveResponse(response);

		output.append(std::istreambuf_iterator<char>(resp), {});
	}
	catch (const Poco::Exception& ex)
	{
		output.append("HTTP GET failed: " + ex.displayText());
	}
}


