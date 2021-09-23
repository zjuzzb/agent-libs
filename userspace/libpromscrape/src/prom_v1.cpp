#include "prom_v1.h"

#include "common_logger.h"
#include "configuration_manager.h"
#include "type_config.h"
#include "utils.h"
#include "stream_grpc_status.h"
#include "prom_infra_iface.h"
#include "prom_job.h"
#include "prom_base.h"
#include "promscrape_conf.h"
#include "prom_helper.h"

#include <Poco/URI.h>
#include <Poco/Exception.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPClientSession.h>

#include <json/json.h>
#include <memory>
#include <mutex>

// #define DEBUG_PROMSCRAPE	1

COMMON_LOGGER();
using namespace std;
using namespace prom_helper;

prom_v1::prom_v1(metric_limits::sptr_t ml,
	const promscrape_conf &scrape_conf,
	bool threaded,
	prom_base::interval_cb_t interval_cb,
	std::unique_ptr<prom_unarygrpc_iface> grpc_applyconfig,
	std::unique_ptr<prom_streamgrpc_iface> grpc_start):
	prom_base(ml, scrape_conf, threaded, interval_cb, std::move(grpc_start)),
    m_grpc_applyconfig(std::move(grpc_applyconfig)),
	m_config_queue(3),
	m_resend_config(false),
	m_last_config_ts(0)
{
}

void prom_v1::reset()
{
	prom_base::reset();

	LOG_INFO("resetting config connection");

	// Resetting config connection
	if (m_grpc_applyconfig)
	{
        m_grpc_applyconfig->reset();
	}
	m_resend_config = true;
}

/**
 * Given a scrape result, update an existing job ID with a new
 * scrape and updated config information from the scrape.
 * The method fails and returns if the job id is not already
 * present in the Promscrape_V1 scrapper map.
 * 
 */
void prom_v1::handle_result(agent_promscrape::ScrapeResult &result)
{
#ifdef DEBUG_PROMSCRAPE
	LOG_DEBUG("received result: %s", result.DebugString().c_str());
#endif

	std::string url;
	int64_t job_id = result.job_id();

	{
		// Temporary lock just to make sure the job still exists
		std::lock_guard<std::recursive_mutex> lock(m_map_mutex);
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			LOG_INFO("received results for unknown job %" PRId64, job_id);
			// Dropping results for unknown (possibly pruned) job
			return;
		}

		if (result.url().size() < 1)
		{
			url = job_it->second.url();
		}
		else
		{
			url = result.url();
			if (url != job_it->second.url())
			{
				LOG_INFO("job %" PRId64 ": scraped url %s doesn't match requested url %s",
					job_id, url.c_str(), job_it->second.url().c_str());
			}
		}
	}

	LOG_DEBUG("Handling result for Job with id %" PRId64 " and url %s", job_id, url.c_str());

	prom_job job(url);
	job.handle_result(m_metric_limits, result, m_prom_conf.ingest_raw(), m_last_ts, m_infra_state);

	{
		std::lock_guard<std::recursive_mutex> lock(m_map_mutex);
		LOG_DEBUG("Job Add/Update - job %" PRId64 " for %s", job_id, url.c_str());
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			// Job must have gotten pruned while we were copying the result
			LOG_INFO("job %" PRId64" got pruned while processing", job_id);
			return;
		}

		job.set_pid(job_it->second.pid());
		job.set_container_id(job_it->second.container_id());
		job.set_config_ts(job_it->second.config_ts());
		job.set_tags(job_it->second.add_tags());
		job.set_stale(job_it->second.stale());
		job_it->second = std::move(job);

		/**
		* TODO - Call prom_metadata_Scraper to update timeseries count
		* or each metric in the result.
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
			&& m_allow_bypass && job_it->second.bypass_limits()
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

void prom_v1::applyconfig()
{
	if (!started())
	{
		m_resend_config = true;
		return;
	}

	auto callback = [this](bool ok, agent_promscrape::Empty &empty)
	{
			if (ok)
			{
				LOG_DEBUG("config sent successfully");
			}
			else
			{
				LOG_INFO("failed to send config, retrying");
				m_resend_config = true;
			}
	};

	if (m_grpc_applyconfig)
	{
		bool ret = m_grpc_applyconfig->start_unary_connection(m_boot_ts, m_config, callback);
		if (ret)
		{
			m_resend_config = false;
		} else
		{
			m_resend_config = true;
		}
	} else
	{
		LOG_ERROR("No unary connection object provided to Promscrape \n");
	}
}

/**
 * For the processes identified to have prometheus
 * configuration, send a config update to the prometheus
 * process.
 * 
 */
void prom_v1::sendconfig(const std::vector<prom_process> &prom_procs)
{
	// Comparison may fail if ordering is different, but shouldn't happen usually
	if (prom_procs == m_last_prom_procs)
	{
		LOG_TRACE("not sending duplicate config");
		return;
	}
	m_last_prom_procs = prom_procs;

	if (!m_threaded)
	{
		sendconfig_th(prom_procs);
		prune_jobs(m_next_ts);
	}
	else
	{
		if (!m_config_queue.put(prom_procs))
		{
			LOG_INFO("config queue full");
		}
	}
}

int64_t prom_v1::assign_job_id(int pid, const std::string &url, const std::string &container_id,
	const tag_map_t &tags, uint64_t ts)
{
	static int64_t g_prom_job_id = 0;

	// Not taking a lock here as it should already be held by the caller
	int64_t job_id = 0;
	auto pid_it = m_pids.find(pid);
	if (pid_it != m_pids.end())
	{
		// Go through list of job_ids for this pid
		for (auto j : pid_it->second)
		{
			job_id = j;
			auto job_it = m_jobs.find(job_id);
			if (job_it == m_jobs.end())
			{
				LOG_WARNING("job %" PRId64 " missing from job-map ", job_id);
				continue;
			}
			else
			{
				// Compare existing job to proposed one
				if ((job_it->second.pid() == pid) && (job_it->second.url() == url))
				{
					LOG_DEBUG("found existing job %" PRId64 " for %d.%s", job_id, pid, url.c_str());
					// Update config timestamp
					job_it->second.set_config_ts(ts);
					job_it->second.set_stale(false);

					// XXX: If tags changed we should update them
					return job_id;
				}
			}
		}
	}

	job_id = ++g_prom_job_id;
	prom_job job(url);
	job.set_pid(pid);
	job.set_container_id(container_id);
	job.set_config_ts(ts);
	job.set_tags(tags);

	LOG_DEBUG("creating job %" PRId64 " for %d.%s", job_id, pid, url.c_str());
	m_jobs.emplace(job_id, std::move(job));
	m_pids[pid].emplace_back(job_id);
	return job_id;
}

void prom_v1::addscrapeconfig(int pid, const std::string &url,
	const std::string &container_id, const std::map<std::string, std::string> &options, const std::string &path,
	uint16_t port, const tag_map_t &tags, const tag_umap_t &infra_tags, uint64_t ts)
{
	std::string joburl;
	auto scrape = m_config->add_scrape_configs();
	auto target = scrape->mutable_target();
	// Specified url overrides scheme, host, port, path
	if (!url.empty())
	{
		joburl = url;
		try
		{
			Poco::URI uri(url);
			target->set_scheme(uri.getScheme());
			target->set_address(uri.getHost() + ":" + std::to_string(uri.getPort()));
			if (uri.getQuery().empty())
			{
				target->set_metrics_path(uri.getPath());
			}
			else
			{
				target->set_metrics_path(uri.getPath() + "?" + uri.getQuery());
			}

			auto tagp = target->add_tags();
			tagp->set_name("port");
			tagp->set_value(std::to_string(uri.getPort()));
		} catch (Poco::Exception &ex )
		{
			LOG_ERROR("Could not parse the url %s (%s). Returning without adding scrape config.", url.c_str(), ex.what());
		    return;
		}
	}
	else
	{
		std::string scheme("http");
		auto opt_it = options.find("use_https");
		if (opt_it != options.end() && (!opt_it->second.compare("true") || !opt_it->second.compare("True")))
		{
			scheme = std::string("https");
		}
		std::string host("localhost");
		opt_it = options.find("host");
		if (opt_it != options.end())
		{
			host = opt_it->second;
		}

		joburl = scheme + "://" + host + ":" + std::to_string(port) + path;
		target->set_scheme(scheme);
		target->set_address(host + ":" + std::to_string(port));
		target->set_metrics_path(path);

		auto tagp = target->add_tags();
		tagp->set_name("port");
		tagp->set_value(std::to_string(port));
	}
	for (const auto &infra_tag : infra_tags)
	{
		auto tagp = target->add_tags();
		tagp->set_name(infra_tag.first);
		tagp->set_value(infra_tag.second);
	}

	// Set auth method if configured in options
	settargetauth(target, options);
	int64_t job_id = assign_job_id(pid, joburl, container_id, tags, ts);
	scrape->set_job_id(job_id);
}

void prom_v1::settargetauth(agent_promscrape::Target *target,
	const std::map<std::string, std::string> &options)
{
	auto opt_it = options.find("auth_cert_path");
	if (opt_it != options.end())
	{
		auto auth_cert = target->mutable_auth_creds()->mutable_auth_cert();
		auth_cert->set_auth_cert_path(opt_it->second);

		opt_it = options.find("auth_key_path");
		if (opt_it != options.end())
		{
			auth_cert->set_auth_key_path(opt_it->second);
		}
		return;
	}

	opt_it = options.find("auth_token_path");
	if (opt_it != options.end())
	{
		target->mutable_auth_creds()->set_auth_token_path(opt_it->second);
		return;
	}

	opt_it = options.find("username");
	if (opt_it != options.end())
	{
		auto auth_user_pass = target->mutable_auth_creds()->mutable_auth_user_passwd();
		auth_user_pass->set_username(opt_it->second);

		opt_it = options.find("password");
		if (opt_it != options.end())
		{
			auth_user_pass->set_password(opt_it->second);
		}
	}
}

void prom_v1::sendconfig_th(const std::vector<prom_process> &prom_procs)
{
	m_config = make_shared<agent_promscrape::Config>();
	m_config->set_scrape_interval_sec(m_prom_conf.interval());
	m_config->set_ingest_raw(m_prom_conf.ingest_raw());
	m_config->set_ingest_legacy(m_prom_conf.ingest_calculated());
	m_config->set_legacy_histograms(m_prom_conf.histograms());

	{   // Scoping lock here because applyconfig doesn't need it and prune_jobs takes its own lock
		std::lock_guard<std::recursive_mutex> lock(m_map_mutex);

		for (const auto &p : prom_procs)
		{
			std::string empty;
			auto opt_it = p.options().find("url");
			if (opt_it != p.options().end() && !opt_it->second.empty())
			{
				// Specified url overrides everything else
				addscrapeconfig(p.pid(), opt_it->second, p.container_id(), p.options(),
					p.path(), 0, p.tags(), p.infra_tags(), m_next_ts);
				continue;
			}
			if (p.ports().empty())
			{
				LOG_WARNING("scrape rule for pid %d doesn't include port number or url", p.pid());
				continue;
			}

			for (auto port : p.ports())
			{
				addscrapeconfig(p.pid(), empty, p.container_id(), p.options(), p.path(),
					port, p.tags(), p.infra_tags(), m_next_ts);
			}
		}
		m_last_config_ts = m_next_ts;
	}
	LOG_DEBUG("sending config %s", m_config->DebugString().c_str());
	applyconfig();
}

/**
 * See prom_base::next_th for more info
 * 
 */
void prom_v1::next_th()
{
	m_last_ts = m_next_ts;

	if (!started())
	{
		try_start();
	}

	if (m_threaded)
	{
		std::vector<prom_process> procs;
		// Look for new configs with 100 ms timeout.
		// This also ensures we don't spin idle when threaded
		if (m_config_queue.get(&procs, 100))
		{
			sendconfig_th(procs);
		}
		prune_jobs(m_next_ts);
	}

	if (m_grpc_applyconfig)
	{
		m_grpc_applyconfig->process_queue();
	}
	if (m_grpc_start)
	{
		m_grpc_start->process_queue();
		if (m_start_failed)
		{
			reset();
		}
	}
	if (m_resend_config && started())
	{
		applyconfig();
	}
}

/**
 * Mark jobs as stale if their config timestamp
 * is less than the previous config timestamp.
 *
 * @param ts Current input timestamp to compare with the last
 *  		 prune timestamp.
 */
void prom_v1::prune_jobs(uint64_t ts)
{
	std::lock_guard<std::recursive_mutex> lock(m_map_mutex);

	if (ts <= m_last_prune_ts)
	{
		return;
	}
	m_last_prune_ts = ts;

	for (auto it = m_jobs.begin(); it != m_jobs.end(); ++it)
	{

		if (it->second.config_ts() >= m_last_config_ts)
		{
			continue;
		}

		LOG_DEBUG("Marking scrape job %" PRId64 ", pid %d as stale", it->first, it->second.pid());

		it->second.set_stale(true);
	}
}




