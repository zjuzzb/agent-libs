#include <memory>

#include "common_logger.h"
#include "prom_job_metadata.h"

#include <json/json.h>

COMMON_LOGGER();
using namespace std;

namespace
{

bool endswith(const string &str, const string &end)
{
	if (str.length() < end.length()) return false;

	return (!str.compare(str.length() - end.length(), end.length(), end));
}

} //anonymous

/**
 * Given a scrape, update the number of times a metric sample
 * appears in the scrape for the current URL.
 * 
 * @param scrape_result The input scrape result. Responsibility
 *  					of the caller to make sure the input is
 *  					not freed.
 */
void prom_job_metadata::process_scrape(const std::shared_ptr<agent_promscrape::ScrapeResult> &scrape_result)
{
	if (scrape_result == nullptr)
	{
		return;
	}

	if (m_metric_metadata.empty())
	{
		LOG_DEBUG("No metadata (yet) for instance %s", m_url.c_str());
		return;
	}

	string lastname;
	int lastcount = 0;
	// Assuming samples for each metric name are contiguous
	for (const auto &sample : scrape_result->samples())
	{
		string name = sample.metric_name();

		// Take off postfixes to match metadata name
		if (endswith(name, "_sum")) name.resize(name.length() - 4);
		else if (endswith(name, "_count")) name.resize(name.length() - 6);
		else if (endswith(name, "_bucket")) name.resize(name.length() - 7);
/*
		else if (endswith(name, "_total"))
			name.resize(name.length() - 6);
*/

		if (name == lastname)
		{
			lastcount++;
			continue;
		}
		if (!lastname.empty())
		{
			m_metric_metadata[lastname].timeseries = lastcount;
		}
		lastname = name;
		lastcount = 1;
	}
	if (!lastname.empty())
	{
		m_metric_metadata[lastname].timeseries = lastcount;
	}
}

/**
 * Given a metric, populate the object with its information.
 * 
 * @param metric The input metric sample.
 */
void prom_job_metadata::process_metric_metadata(const Json::Value &metric)
{
	if (!metric.isMember("metric") || !metric["metric"].isString() ||
		metric["metric"].asString().empty())
	{
		LOG_INFO("metric metadata is missing metric name");
		return;
	}
	const string name = metric["metric"].asString();

	if (metric.isMember("type") && metric["type"].isString())
	{
		m_metric_metadata[name].type = metric["type"].asString();
	}

	if (metric.isMember("unit") && metric["unit"].isString())
	{
		m_metric_metadata[name].unit = metric["unit"].asString();
	}

	if (metric.isMember("help") && metric["help"].isString())
	{
		m_metric_metadata[name].help = metric["help"].asString();
	}
}



