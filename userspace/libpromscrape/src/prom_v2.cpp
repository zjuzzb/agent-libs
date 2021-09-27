#include <memory>
#include <mutex>

#include "common_logger.h"
#include "prom_helper.h"
#include "prom_infra_iface.h"
#include "uri.h"
#include "prom_job.h"
#include "prom_base.h"
#include "prom_v2.h"
#include "promscrape_conf.h"
#include "utils.h"

// #define DEBUG_PROMSCRAPE	1

COMMON_LOGGER();
using namespace std;
using namespace prom_helper;

prom_v2::prom_v2(metric_limits::sptr_t ml,
	const promscrape_conf &scrape_conf,
	bool threaded,
	interval_cb_t interval_cb,
	std::unique_ptr<prom_streamgrpc_iface> grpc_start):
	prom_base(ml, scrape_conf, threaded, interval_cb, std::move(grpc_start))
{
}

/**
 * Creates a job with the given scrape result and adds it to the
 * prom_v2 map. 
 * 
 */
void prom_v2::handle_result(agent_promscrape::ScrapeResult &result)
{
#ifdef DEBUG_PROMSCRAPE
	LOG_DEBUG("received result: %s", result.DebugString().c_str());
#endif

	static int64_t g_prom_job_id = 0;
	std::string url;
	std::string job_name;

	// For promscrape_v2 we associate job_ids with url-jobname combination
	if (result.url().size() < 1)
	{
		LOG_INFO("Missing url from promscrape v2 result, dropping scrape results");
		return;
	}

	url = result.url();
	if (!result.meta_samples().empty())
	{
		job_name = get_label_value(result.meta_samples()[0], "job");
	}

	if (job_name.empty() && !result.samples().empty())
	{
		job_name = get_label_value(result.samples()[0], "job");
	}

	prom_job job(url);
	job.handle_result(m_metric_limits, result, m_prom_conf.ingest_raw(), m_last_ts, m_infra_state);
	int64_t job_id = 0;

	{
		std::lock_guard<std::recursive_mutex> lock(m_map_mutex);
		auto key = make_pair(url, job_name);
		auto url_it = m_joburls.find(key);
		if (url_it != m_joburls.end())
		{
			job_id = url_it->second;
		}
		else
		{
			job_id = ++g_prom_job_id;
			m_joburls.emplace(key, job_id);
		}

		LOG_DEBUG("Job Add/Update - job %" PRId64 " for %s,%s", job_id, url.c_str(), job_name.c_str());
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			m_jobs.emplace(job_id, std::move(job));
			m_pids[0].emplace_back(job_id);
		}
		else
		{
			job_it->second = std::move(job);
		}

		/**
		* TODO - Call prom_metadata_Scraper to update timeseries count
		* for each metric in the result.
		*/

		/**
		 * Bypass requires multiple approvals
		 * 1. Backend approval after negotiation.
		 * 2. Config approval from dragent.
		 * 3. Source label approval (aka sysdig_bypass) from scrape
		 * result for the current job.
		 * 4. Allotment of callback function to handle bypass protobuf.
		 */
		const bool allow_bypass = m_allow_bypass && c_allow_bypass.get_value()
			&& job_it->second.bypass_limits()
			&& (m_bypass_cb != nullptr);

		if (allow_bypass)
		{

			auto msg = job_it->second.to_bypass_protobuf(m_next_ts, m_infra_state);
			if (msg == nullptr)
			{
				LOG_WARNING("Failed to create standalone protobuf message for job %" PRId64, job_id);
			}
			else
			{
				LOG_DEBUG("Sending limit-bypassed samples through standalone protobuf message");
				m_bypass_cb(msg);
			}
		}
	}
}

/**
 * Read prom_base for more info.
 * 
 */
void prom_v2::next_th()
{
	m_last_ts = m_next_ts;

	if (!started())
	{
		try_start();
	}
	if (m_threaded)
	{
		prune_jobs(m_next_ts);
	}

	if (m_grpc_start)
	{
		m_grpc_start->process_queue();
		if (m_start_failed)
		{
			reset();
		}
	}
}

/**
 * Promscrape V2 does service discovery itself, in which case we
 * prune based on time since last reception of data.
 *
 * Read prom_base for more info.
 * 
 */
void prom_v2::prune_jobs(uint64_t ts)
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);

	if (ts <= m_last_prune_ts)
	{
		return;
	}
	m_last_prune_ts = ts;

	for (auto it = m_jobs.begin(); it != m_jobs.end(); ++it)
	{

		if (elapsed_s(it->second.data_ts(), ts) < m_prom_conf.metric_expiration())
		{
			continue;
		}

		LOG_DEBUG("Marking scrape job %" PRId64 "as stale", it->first);

		it->second.set_stale(true);
	}
}

/**
 * Iterate the V2 map and delete job associated with the job id.
 *
 * @param job_id - job id to delete
 */
void prom_v2::delete_job(int64_t job_id)
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);

	prom_base::delete_job(job_id);

	for (auto joburl_it = m_joburls.begin(); joburl_it != m_joburls.end(); joburl_it++)
	{
		if (joburl_it->second == job_id)
		{
			LOG_DEBUG("Removing job %" PRId64 " for %s,%s", job_id,
				joburl_it->first.first.c_str(), joburl_it->first.second.c_str());
			m_joburls.erase(joburl_it);
			break;
		}
	}
}
