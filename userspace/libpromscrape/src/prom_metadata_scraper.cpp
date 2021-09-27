#include <memory>
#include <string>

#include "common_logger.h"
#include "promscrape.h"
#include "prom_metadata_scraper.h"
#include "type_config.h"
#include "wall_time.h"
#include "prom_helper.h"

#include <sys/time.h>
#include <Poco/Exception.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/URI.h>
#include <json/json.h>

COMMON_LOGGER();
using namespace prom_helper;

prom_metadata_scraper::prom_metadata_scraper() :
	m_gather_interval(10 * get_one_second_in_ns()),
	m_gather_stats(false),
	m_gather_stats_count(0)
{
}

void prom_metadata_scraper::process_targets(const Json::Value &data)
{
	if (!data.isObject() || !data.isMember("data"))
	{
		return;
	}

	auto targets = data["data"];
	if (!targets.isObject() || !targets.isMember("activeTargets"))
	{
		return;
	}

	for (const auto &target : targets["activeTargets"])
	{
		target_data_t t;
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
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_target_map.emplace(t.url, std::move(t));
		}
	}
}

void prom_metadata_scraper::process_metadata(const Json::Value &local_targets_metadata)
{
	if (!local_targets_metadata.isObject() || !local_targets_metadata.isMember("data")) return;
	for (const auto &metric : local_targets_metadata["data"])
	{

		if (!metric.isMember("target") || !metric["target"].isMember("instance") ||
			!metric["target"]["instance"].isString() ||
			metric["target"]["instance"].asString().empty())
		{
			LOG_INFO("metric metadata is missing target or instance");
			continue;
		}
		std::string instance = metric["target"]["instance"].asString();

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			auto it = m_metadata_map.find(instance);
			if (it == m_metadata_map.end())
			{
				prom_job_metadata metric_metadata(instance);
				metric_metadata.process_metric_metadata(metric);
				m_metadata_map.insert({ instance, std::move(metric_metadata) });
			}
			else
			{
				it->second.process_metric_metadata(metric);
			}
		}
	}
}

/**
 * Check if collection is enabled or not.
 * 
 * @return bool
 */
bool prom_metadata_scraper::gather_stats_enabled()
{
	// Currently only supported with promscrape v2
	return c_always_gather_stats.get_value() || m_gather_stats;
}

/**
 * Allow an external caller to control collection of stats.
 *
 */
void prom_metadata_scraper::enable_gather_stats(bool enable)
{
	m_gather_stats = enable;
	m_gather_stats_count++; // Make sure to start right away
}

/**
 * Sends an HTTP request to Prometheus targets to capture
 * metadata of targets.
 * 
 */
void prom_metadata_scraper::gather_target_stats()
{
	if (!gather_stats_enabled())
	{
		return;
	}
	std::string targets_path("/api/v1/targets");
	std::string targets_metadata_path("/api/v1/targets/metadata");

	try
	{
		Poco::Net::HTTPClientSession session("127.0.0.1", 9990);
		std::string method("GET");
		Poco::Net::HTTPRequest request(method, targets_path);
		Poco::Net::HTTPResponse response;
		session.sendRequest(request);
		std::istream &resp = session.receiveResponse(response);

		Json::Reader json_reader;
		Json::Value local_targets;
		bool rc;
		{
			rc = json_reader.parse(resp, local_targets);
		}
		LOG_INFO("local target data parse %s", rc ? "successful" : "failed");

		Poco::Net::HTTPRequest request2(method, targets_metadata_path);
		Poco::Net::HTTPResponse response2;

		Json::Value local_targets_metadata;
		session.sendRequest(request2);
		std::istream &resp2 = session.receiveResponse(response2);

		{
			rc = json_reader.parse(resp2, local_targets_metadata);
		}
		LOG_INFO("local target metadata parse %s", rc ? "successful" : "failed");
		process_metadata(local_targets_metadata);
	} catch (const Poco::Exception &ex)
	{
		LOG_INFO("Gather target stats exception: %s", ex.displayText().c_str());
	}
}

/**
 * Gather the targets and target metadata. Called externally in
 * a periodic manner.
 * 
 */
void prom_metadata_scraper::periodic_gather_stats()
{
	if (!gather_stats_enabled())
	{
		return;
	}
	m_gather_interval.run([this]()
	{
			// Skip the first call on startup
			if (m_gather_stats_count)
			{
				gather_target_stats();
			}
			m_gather_stats_count++;
	}, wall_time::nanoseconds());
}

/**
 * Given a scrape, update the number of times a metric sample
 * appears in the scrape for the current URL.
 *
 * @param instance The instance URL.
 * @param scrape_result The input scrape result. Responsibility
 *  					of the caller to make sure the input is
 *  					not freed.
 */
void prom_metadata_scraper::process_scrape(std::string instance, const std::shared_ptr<agent_promscrape::ScrapeResult> &result)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	auto it = m_metadata_map.find(instance);
	if (it == m_metadata_map.end())
	{
		LOG_DEBUG("No metadata (yet) for instance %s", instance.c_str());
		return;
	}

	it->second.process_scrape(result);
}



