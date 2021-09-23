#include <memory>
#include <string>
#include <cinttypes>

#include "common_logger.h"
#include "configuration_manager.h"
#include "prom_infra_iface.h"
#include "prom_job.h"
#include "prom_helper.h"

COMMON_LOGGER();
using namespace prom_helper;

prom_job::prom_job(const std::string &url) : m_url(url),
	m_pid(0),
	m_config_ts(0),
	m_data_ts(0),
	m_last_total_samples(0),
	m_bypass_limits(false),
	m_stale(false),
	m_omit_source(false),
	m_result_ptr(nullptr),
	m_count_over_global_limit(0)
{
}

/**
 * Converts the stored scrape to the specific protobuf
 * as per the configuration.
 * 
 * @param proto - The templatize output protobuf
 * @param limit - The allowed limit of metrics to send
 * @param max_limit - The maximum allowed?
 * @param[out] filtered - The total filtered metrics sent as
 *  	 part of the protobuf.
 * @param[out] total - The total metrics actually processed
 *  	 before the filtering.
 * @param[in] infra_ptr - The prom_infra_iface to obtain
 *  	 container specific information.
 *
 *@return unsigned int - The total sum of raw and collected
 *  	  samples sent.
 */
template<typename metric>
unsigned int prom_job::to_protobuf(metric *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total, prom_infra_iface *infra_ptr)
{
	unsigned int raw_num_samples = 0;
	unsigned int calc_num_samples = 0;
	unsigned int over_limit = 0;

	if (m_result_ptr == nullptr)
	{
		return 0;
	}

	if (m_bypass_limits)
	{
		LOG_DEBUG("Metrics for bypass job with url %s were already sent previously, skipping", m_url.c_str());
		return 0;
	}

	LOG_DEBUG("have metrics for job with url %s", m_url.c_str());

	bool ml_log = metric_limits::log_enabled();

	// Lambda for adding samples from samples or metasamples
	auto add_sample = [this, &proto](const agent_promscrape::Sample &sample)
	{
			auto newmet = proto->add_metrics();
			newmet->set_name(sample.metric_name());
			newmet->set_value(m_stale ? nan("") : sample.value());
			if (sample.legacy_metric_type() == agent_promscrape::Sample::MT_INVALID)
			{
				newmet->set_type(draiosproto::app_metric_type::APP_METRIC_TYPE_PROMETHEUS_RAW);
			}
			else
			{
				newmet->set_type(static_cast<draiosproto::app_metric_type>(sample.legacy_metric_type()));
			}
			newmet->set_prometheus_type(static_cast<draiosproto::prometheus_type>(sample.raw_metric_type()));
			for (const auto &bucket : sample.buckets())
			{
				auto newbucket = newmet->add_buckets();
				newbucket->set_label(bucket.label());
				newbucket->set_count(bucket.count());
			}
			for (const auto &label : sample.labels())
			{
				auto newtag = newmet->add_tags();
				newtag->set_key(label.name());
				newtag->set_value(label.value());
			}
			// Add configured tags
			for (const auto &tag : m_add_tags)
			{
				auto newtag = newmet->add_tags();
				newtag->set_key(tag.first);
				newtag->set_value(tag.second);
			}
	};

	// The current limit policy, similar to upstream prometheus, is:
	//  - In order to avoid incorrect reporting, if the total number of timeseries
	//    for the endpoint exceeds the metric limit, all the timeseries for that
	//    endpoint will be dropped.

	if (m_result_ptr->samples().size() > limit)
	{
		over_limit = m_result_ptr->samples().size() - limit;
	}

	for (const auto &sample : m_result_ptr->samples())
	{
		if (over_limit)
		{
			if (!ml_log)
			{
				break;
			}
			LOG_INFO("[promscrape] metric over limit (total, %u max): %s",
				max_limit, sample.metric_name().c_str());
			continue;
		}

		add_sample(sample);
		--limit;
		if (prom_helper::metric_type_is_raw(sample.legacy_metric_type()))
		{
			++raw_num_samples;
		}
		else
		{
			++calc_num_samples;
		}
	}

	// Add metadata samples. These should always get sent and
	// don't count towards the metric limit either.
	for (auto &sample :*m_result_ptr->mutable_meta_samples())
	{
		// Adjust scrape_series_added to reflect agent metric limits and filters
		if (sample.metric_name() == "scrape_series_added")
		{
			// Scrape metadata only applies to raw metrics
			sample.set_value(raw_num_samples);
		}
		// Promscrape tends to send these as metric type unknown, which tends
		// to confuse the backend. They make most sense as gauges.
		if ((sample.raw_metric_type() == agent_promscrape::Sample::RAW_INVALID) ||
			(sample.raw_metric_type() == agent_promscrape::Sample::RAW_UNKNOWN))
		{
			sample.set_raw_metric_type(agent_promscrape::Sample::RAW_GAUGE);
		}
		add_sample(sample);
	}

	if (filtered)
	{
		// Metric filtering happens on ingestion (in handle_result)
		// so the number of samples here is the filtered count
		*filtered += m_result_ptr->samples().size();
	}
	if (total)
	{
		*total += m_last_total_samples;
	}

	// Update metric stats
	m_count_over_global_limit = over_limit;
	m_raw_stats.sent = raw_num_samples;
	m_calc_stats.sent = calc_num_samples;

	return raw_num_samples + calc_num_samples;
}

template unsigned int prom_job::to_protobuf<draiosproto::app_info>(draiosproto::app_info *proto, unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total, prom_infra_iface *infra_ptr);
template unsigned int prom_job::to_protobuf<draiosproto::prometheus_info>(draiosproto::prometheus_info *proto, unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total, prom_infra_iface *infra_ptr);

/**
 * Converts the stored scrape to the specific protobuf
 * as per the configuration.
 * 
 * @param proto - Draios protobuf
 * @param limit - The allowed limit of metrics to send
 * @param max_limit - The maximum allowed?
 * @param[out] filtered - The total filtered metrics sent as
 *  	 part of the protobuf.
 * @param[out] total - The total metrics actually processed
 *  	 before the filtering.
 * @param[in] infra_ptr - The prom_infra_iface to obtain
 *  	 container specific information.
 *
 *@return unsigned int - The total sum of raw and collected
 *  	  samples sent.
 */
template<>
unsigned int prom_job::to_protobuf(draiosproto::metrics *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total, prom_infra_iface *infra_ptr)
{
	if (m_result_ptr == nullptr)
	{
		return 0;
	}

	if (m_bypass_limits)
	{
		LOG_DEBUG("Metrics for bypass job with url %s were already sent previously, skipping", m_url.c_str());
		return 0;
	}

	auto prom = proto->add_prometheus();

	return to_protobuf_imp(prom, true, limit, max_limit, filtered, total, infra_ptr);
}

unsigned int prom_job::to_protobuf_imp(draiosproto::prom_metrics *prom, bool enforce_limits,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total, prom_infra_iface *infra_ptr)
{
	unsigned int raw_num_samples = 0;
	unsigned int calc_num_samples = 0;
	unsigned int over_limit = 0;

	if ((m_result_ptr == nullptr) || (prom == nullptr))
	{
		return 0;
	}

	LOG_DEBUG("have metrics for job with url %s", m_url.c_str());

	bool ml_log = enforce_limits && metric_limits::log_enabled();

	prom->set_timestamp(m_result_ptr->timestamp());
	for (const auto &tag : m_add_tags)
	{
		auto newtag = prom->add_common_labels();
		newtag->set_name(tag.first);
		newtag->set_value(tag.second);
	}

	if (!m_omit_source)
	{
		// Add pid in source_metadata, if we have a pid
		if (m_pid)
		{
			auto meta = prom->add_source_metadata();
			meta->set_name("pid");
			meta->set_value(std::to_string(m_pid));
		}
		if (!m_container_id.empty())
		{
			auto meta = prom->add_source_metadata();
			meta->set_name("container_id");
			meta->set_value(m_container_id);
		}
		for (const auto &source_label : m_result_ptr->source_labels())
		{
			// Only copy source labels with non-empty label and value
			if (source_label.name().empty() || source_label.value().empty())
			{
				continue;
			}
			auto meta = prom->add_source_metadata();
			meta->set_name(source_label.name());
			meta->set_value(source_label.value());
		}

		if (infra_ptr && !infra_ptr->get_k8s_cluster_id().empty())
		{
			auto meta = prom->add_source_metadata();
			meta->set_name("cluster_id");
			meta->set_value(infra_ptr->get_k8s_cluster_id());
		}

		LOG_DEBUG("job with url %s: Copied %d source labels: %d", m_url.c_str(), m_result_ptr->source_labels().size(), prom->source_metadata().size());
	}
	else if (infra_ptr && !infra_ptr->get_k8s_cluster_name().empty())
	{
		auto newlabel = prom->add_common_labels();
		newlabel->set_name("kube_cluster_name");
		newlabel->set_value(infra_ptr->get_k8s_cluster_name());
	}

	// Lambda for adding samples from samples or metasamples
	auto add_sample = [this, &prom](const agent_promscrape::Sample &sample)
	{
			// Only supported for RAW prometheus metrics
			auto newmet = prom->add_samples();
			newmet->set_metric_name(sample.metric_name());
			newmet->set_value(m_stale ? nan("") : sample.value());

			newmet->set_type(static_cast<draiosproto::prometheus_type>(sample.raw_metric_type()));

			for (const auto &label : sample.labels())
			{
				auto newtag = newmet->add_labels();
				newtag->set_name(label.name());
				newtag->set_value(label.value());
			}
	};

	// The current limit policy, similar to upstream prometheus, is:
	//  - In order to avoid incorrect reporting, if the total number of timeseries
	//    for the endpoint exceeds the metric limit, all the timeseries for that
	//    endpoint will be dropped.

	if (enforce_limits &&  (m_result_ptr->samples().size() > limit))
	{
		over_limit = m_result_ptr->samples().size() - limit;
	}

	for (const auto &sample : m_result_ptr->samples())
	{
		if (over_limit)
		{
			if (!ml_log)
			{
				break;
			}
			LOG_INFO("[promscrape] metric over limit (total, %u max): %s",
				max_limit, sample.metric_name().c_str());
			continue;
		}

		if (prom_helper::metric_type_is_raw(sample.legacy_metric_type()))
		{
			// Fastproto only supports raw metrics
			add_sample(sample);
			if (enforce_limits)
			{
				--limit;
			}
			++raw_num_samples;
		}
		else
		{
			++calc_num_samples;
		}
	}

	// Add metadata samples. These should always get sent and
	// don't count towards the metric limit either.
	for (auto &sample :*m_result_ptr->mutable_meta_samples())
	{
		// Adjust scrape_series_added to reflect agent metric limits and filters
		if (sample.metric_name() == "scrape_series_added")
		{
			// Scrape metadata only applies to raw metrics
			sample.set_value(raw_num_samples);
		}
		// Promscrape tends to send these as metric type unknown, which tends
		// to confuse the backend. They make most sense as gauges.
		if ((sample.raw_metric_type() == agent_promscrape::Sample::RAW_INVALID) ||
			(sample.raw_metric_type() == agent_promscrape::Sample::RAW_UNKNOWN))
		{
			sample.set_raw_metric_type(agent_promscrape::Sample::RAW_GAUGE);
		}
		add_sample(sample);
	}

	if (filtered)
	{
		// Metric filtering happens on ingestion (in handle_result)
		// so the number of samples here is the filtered count
		*filtered += m_result_ptr->samples().size();
	}
	if (total)
	{
		*total += m_last_total_samples;
	}


	// Update metric stats
	m_count_over_global_limit = over_limit;
	m_raw_stats.sent = raw_num_samples;
	m_calc_stats.sent = calc_num_samples;

	return raw_num_samples + calc_num_samples;
}

/**
 * Converts the stored scrape to the output protobuf.
 * There is no filtering involved here and this method sends
 * all the samples scraped to the protobuf.
 *
 * @param next_ts - The timestamp of the scrape
 * @param infra_ptr - The prom_infra_iface to obtain
 *  	 container specific information.
 *
 *@return draiosproto::raw_prometheus_metrics
 */
std::shared_ptr<draiosproto::raw_prometheus_metrics> prom_job::to_bypass_protobuf(uint64_t next_ts, prom_infra_iface *infra_ptr)
{
	static uint64_t msg_idx = 1;
	std::shared_ptr<draiosproto::raw_prometheus_metrics> metrics =
		std::make_shared<draiosproto::raw_prometheus_metrics>();

	if (m_result_ptr == nullptr)
	{
		LOG_DEBUG("Couldn't find scrape results for job with url %s", m_url.c_str());
		return metrics;
	}

	metrics->set_timestamp_ns(next_ts);
	metrics->set_index(msg_idx++);

	LOG_DEBUG("Creating bypass message for job with url %s", m_url.c_str());

	auto prom = metrics->add_prometheus();

	unsigned int limit = 10000000;
	to_protobuf_imp(prom, false, limit, limit, nullptr, nullptr, infra_ptr);

	return metrics;
}

void prom_job::process_samples(metric_limits::sptr_t metric_limits,
	agent_promscrape::ScrapeResult &result,
	bool allow_raw)
{
	int raw_total_samples = 0;  // total before filtering
	int raw_num_samples = 0;    // after
	int calc_total_samples = 0;
	int calc_num_samples = 0;

	// Do we need to filter incoming metrics?
	if (metric_limits && !m_bypass_limits)
	{
		m_result_ptr = std::make_shared<agent_promscrape::ScrapeResult>();
		m_result_ptr->set_job_id(result.job_id());
		m_result_ptr->set_timestamp(result.timestamp());
		m_result_ptr->set_url(result.url());
		for (const auto &sample : result.samples())
		{
			bool is_raw = metric_type_is_raw(sample.legacy_metric_type());
			std::string filter;
			if (metric_limits->allow(sample.metric_name(), filter, nullptr, "promscrape"))
			{
				auto newsample = m_result_ptr->add_samples();
				*newsample = sample;
				if (is_raw)
				{
					++raw_num_samples;
				}
				else
				{
					++calc_num_samples;
				}
			}

			if (is_raw)
			{
				++raw_total_samples;
			}
			else
			{
				++calc_total_samples;
			}
		}
		m_result_ptr->mutable_meta_samples()->CopyFrom(result.meta_samples());
		m_result_ptr->mutable_source_labels()->CopyFrom(result.source_labels());
	}
	else
	{
		// This could be a lot faster if we didn't have to copy the result protobuf
		// For instance we could use a new version of streaming_grpc_client that
		// just passes ownership of its protobuf
		m_result_ptr = std::make_shared<agent_promscrape::ScrapeResult>(std::move(result));
		for (const auto &sample : m_result_ptr->samples())
		{
			if (metric_type_is_raw(sample.legacy_metric_type()))
			{
				++raw_num_samples;
				++raw_total_samples;
			}
			else
			{
				++calc_num_samples;
				++calc_total_samples;
			}
		}
	}

	// Update metric stats
	int scraped = -1;
	int post_relabel = -1;
	int added = -1;
	for (const auto &meta_sample : m_result_ptr->meta_samples())
	{
		if (meta_sample.metric_name() == "scrape_samples_scraped")
		{
			scraped = meta_sample.value();
		}
		else if (meta_sample.metric_name() == "scrape_samples_post_metric_relabeling")
		{
			post_relabel = meta_sample.value();
		}
		else if (meta_sample.metric_name() == "scrape_series_added")
		{
			added = meta_sample.value();
		}
	}
	// Currently the metadata metrics sent by promscrape only apply to raw metrics
	if ((scraped < 0) || (post_relabel < 0) || (added < 0))
	{
		if (allow_raw)
		{
			LOG_INFO("Missing metadata metrics for %s. Results may be incorrect in "
				"subsequent metrics summary", m_url.c_str());
		}
		scraped = post_relabel = added = raw_total_samples;
	}

	m_raw_stats.scraped = scraped;
	m_raw_stats.job_filter_dropped = scraped - post_relabel;
	m_raw_stats.over_job_limit = post_relabel - added;
	m_raw_stats.global_filter_dropped = raw_total_samples - raw_num_samples;

	m_calc_stats.scraped = calc_total_samples;
	m_calc_stats.job_filter_dropped = 0;
	m_calc_stats.over_job_limit = 0;
	m_calc_stats.global_filter_dropped = calc_total_samples - calc_num_samples;

	m_last_total_samples = raw_total_samples + calc_total_samples;
	LOG_DEBUG("got %d of %d raw and %d of %d calculated samples for job with url %s",
		raw_num_samples, raw_total_samples, calc_num_samples, calc_total_samples, m_url.c_str());
}

std::string prom_job::get_instance()
{
	std::string instance;

	if (m_result_ptr)
	{
		if (!m_result_ptr->meta_samples().empty())
		{
			// Look for instance label only in first meta sample
			instance = get_label_value(m_result_ptr->meta_samples()[0], "instance");
		}
		if (instance.empty() && !m_result_ptr->samples().empty())
		{
			// Now look for instance label only in first sample
			instance = get_label_value(m_result_ptr->samples()[0], "instance");
		}
	}

	return instance;
}

void prom_job::process_host_info(prom_infra_iface *infra_ptr)
{
	if (!m_result_ptr)
	{
		return;
	}

	std::string instance = get_instance();
	if (!instance.empty())
	{
		bool local = false;
		prom_infra_iface::kind_uid_t uid;
		std::string host = instance.substr(0, instance.find(':'));

		if (!host.compare("localhost") || !host.compare("127.0.0.1"))
		{
			local = true;
		}
		else if (!host.empty())
		{
			local = infra_ptr->find_local_ip(host, &uid);
		}
		LOG_DEBUG("job with url %s: instance %s is %s", m_url.c_str(), instance.c_str(), local ? "local" : "not local");
		if (local)
		{
			auto new_source_label = m_result_ptr->add_source_labels();
			new_source_label->set_name("host_mac");
			new_source_label->set_value(infra_ptr->get_machine_id());
			if (!uid.first.compare("k8s_pod"))
			{
				LOG_DEBUG("job with url %s: instance %s, set pod_id to %s", m_url.c_str(),
					instance.c_str(), uid.second.c_str());
				set_label_value(m_result_ptr->mutable_source_labels(), "pod_id", uid.second);
			}
		}
	}
	else
	{
		LOG_DEBUG("job with url %s: couldn't find instance label", m_url.c_str());
	}
}

/**
 * Given a scrape result, the method processes the scrape and
 * copies it to its internal store. While processing, it adds
 * additional information related to the container and the host
 * from which the scrapes were processed. Processing also
 * populates the metric stats associated with the scrape.
 * 
 * @param metric_limits - Any global filtering for the samples. 
 * @param result - The scrape result to process.
 * @param allow_raw - Indicates if raw metrics can be processed
 *  				or not.
 * @param last_ts - The last processed scrape timestamp.
 * @param infra_ptr - The prom_infra_iface to populate
 *  				container information.
 */
void prom_job::handle_result(metric_limits::sptr_t metric_limits,
	agent_promscrape::ScrapeResult &result,
	bool allow_raw,
	uint64_t last_ts,
	prom_infra_iface *infra_ptr)
{
	// Attempt to find and fill in the container_id if it isn't available yet
	std::string container_id;
	std::string container_name;
	std::string pod_id;

	m_data_ts = last_ts; // Updating data timestamp

	for (const auto &source_label : result.source_labels())
	{
		if (source_label.name() == "container_id")
		{
			container_id = source_label.value();
		}
		else if (source_label.name() == "pod_id")
		{
			pod_id = source_label.value();
		}
		else if (source_label.name() == "container_name")
		{
			container_name = source_label.value();
		}
		else if ((source_label.name() == "sysdig_bypass") &&
				 (source_label.value() == "true"))
		{
			m_bypass_limits = true;
		}
		else if ((source_label.name() == "sysdig_omit_source") && !source_label.value().empty())
		{
			m_omit_source = true;
		}
	}

	process_samples(metric_limits, result, allow_raw);

	if (container_id.empty() && !pod_id.empty() && !container_name.empty() && infra_ptr)
	{
		prom_infra_iface::kind_uid_t uid = make_pair("k8s_pod", pod_id);
		container_id = infra_ptr->get_container_id_from_k8s_pod_and_k8s_pod_name(uid, container_name);
		LOG_DEBUG("Correlated container id %s from %s:%s", container_id.c_str(),
			pod_id.c_str(), container_name.c_str());
		if (!container_id.empty())
		{
			set_label_value(m_result_ptr->mutable_source_labels(), "container_id", container_id);
		}
	}

	// If no pod or container were given, we want to know if the source was running on this
	// host or not
	if (pod_id.empty() && container_id.empty() && infra_ptr)
	{
		process_host_info(infra_ptr);
	}
}

void prom_job::log_summary(int &unsent_global, int &unsent_job)
{
	if (m_count_over_global_limit || m_raw_stats.over_job_limit ||
		m_calc_stats.over_job_limit)
	{
		int unsent = m_raw_stats.scraped - m_raw_stats.job_filter_dropped -
			m_raw_stats.global_filter_dropped - m_raw_stats.sent;
		unsent += m_calc_stats.scraped - m_calc_stats.job_filter_dropped -
			m_calc_stats.global_filter_dropped - m_calc_stats.sent;
		LOG_INFO("endpoint %s: %d timeseries (after filter) not sent because of %s "
			"limit (%d over limit)", m_url.c_str(), unsent,
			m_count_over_global_limit ? "prometheus metric" : "job sample",
			m_count_over_global_limit ? m_count_over_global_limit :
			(m_raw_stats.over_job_limit + m_calc_stats.over_job_limit));

		if (m_count_over_global_limit)
		{
			unsent_global += unsent;
		}
		else
		{
			unsent_job += unsent;
		}
	}
	else
	{
		LOG_INFO("endpoint %s: %d total timeseries sent", m_url.c_str(), m_raw_stats.sent + m_calc_stats.sent);
	}

	LOG_INFO("endpoint %s: RAW: scraped %d, sent %d, dropped by: "
		"job filter %d, global filter %d",
		m_url.c_str(), m_raw_stats.scraped, m_raw_stats.sent,
		m_raw_stats.job_filter_dropped, m_raw_stats.global_filter_dropped);
	LOG_INFO("endpoint %s: CALCULATED: scraped %d, sent %d, dropped by: "
		"job filter %d, global filter %d",
		m_url.c_str(), m_calc_stats.scraped, m_calc_stats.sent,
		m_calc_stats.job_filter_dropped, m_calc_stats.global_filter_dropped);
}

void prom_job::clear()
{
	m_raw_stats = metric_stats();
	m_calc_stats = metric_stats();
	m_count_over_global_limit = 0;
}

/**
 * Get the total filtered metrics for the most
 * recent scrape.
 * 
 * @return int The total filtered metrics.
 */
int prom_job::get_total_filtered_metrics() const
{
	return m_raw_stats.job_filter_dropped +
		   m_raw_stats.global_filter_dropped +
		   m_calc_stats.job_filter_dropped +
		   m_calc_stats.global_filter_dropped;
}

/**
 * Get the total unsent metrics for the most
 * recent scrape in store.
 * 
 * @return int The total unsent metrics.
 */
int prom_job::get_total_unsent_metrics() const
{
	int unsent = m_raw_stats.scraped -
		m_raw_stats.job_filter_dropped -
		m_raw_stats.global_filter_dropped -
		m_raw_stats.sent;
	unsent += m_calc_stats.scraped -
		m_calc_stats.job_filter_dropped -
		m_calc_stats.global_filter_dropped -
		m_calc_stats.sent;
	return unsent;
}
