#include <memory>
#include "common_logger.h"
#include "promscrape.h"
#include "prometheus.h"
#include "analyzer_utils.h"
#include "type_config.h"
#include "uri.h"
#include "configuration_manager.h"

// #define DEBUG_PROMSCRAPE	1

COMMON_LOGGER();
using namespace std;

type_config<bool> promscrape::c_use_promscrape(
    false,
    "Whether or not to use promscrape for prometheus metrics",
    "use_promscrape");

type_config<string> c_promscrape_sock(
    "localhost:9876",
    "Socket address URL for promscrape server",
    "promscrape_address");

type_config<int> c_promscrape_connect_interval(
    10,
    "Interval for attempting to connect to promscrape",
    "promscrape_connect_interval");

type_config<bool> promscrape::c_export_fastproto(
    false,
    "Whether or not to export metrics using newer protocol",
    "promscrape_fastproto");

promscrape::promscrape(metric_limits::sptr_t ml,
	const prometheus_conf &prom_conf,
	bool threaded,
	interval_cb_t interval_cb):
		m_sock(c_promscrape_sock.get_value()),
		m_start_interval(c_promscrape_connect_interval.get_value() * ONE_SECOND_IN_NS),
		m_start_failed(false),
		m_metric_limits(ml),
		m_threaded(threaded),
		m_prom_conf(prom_conf),
		m_config_queue(3),
		m_interval_cb(interval_cb),
		m_last_proto_ts(0)
{
}

bool promscrape::started()
{
	return m_grpc_start != nullptr;
}

void promscrape::start()
{
	agent_promscrape::Empty empty;

	LOG_INFO("promscrape starting");

	auto callback = [this](streaming_grpc::Status status, agent_promscrape::ScrapeResult& result)
	{
		if(status == streaming_grpc::OK)
		{
			handle_result(result);
			return;
		}

		if(status == streaming_grpc::ERROR)
		{
			LOG_ERROR("promscrape start grpc failed");
		}
		else if(status == streaming_grpc::SHUTDOWN)
		{
			LOG_ERROR("promscrape grpc shut down");
		}
		else
		{
			LOG_ERROR("promscrape received unknown status %d", (int)status);
		}
		m_start_failed = true;
	};

	if (!m_start_conn) {
		LOG_INFO("promscrape: opening GRPC connection to %s", m_sock.c_str());
		grpc::ChannelArguments args;
		// Set maximum receive message size to unlimited
		args.SetMaxReceiveMessageSize(-1);

		m_start_conn = grpc_connect<agent_promscrape::ScrapeService::Stub>(m_sock, 10, &args);
		if (!m_start_conn) {
			LOG_ERROR("promscrape: failed to connect to %s", m_sock.c_str());
			return;
		}
	}
	m_grpc_start = make_unique<streaming_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncGetData)>(m_start_conn);
	m_grpc_start->do_rpc(empty, callback);
}

void promscrape::try_start()
{
	if (started())
	{
		return;
	}
	m_start_interval.run([this]()
	{
		start();
	}, sinsp_utils::get_current_time_ns() );
}

void promscrape::reset()
{
	m_grpc_start = nullptr;
	m_start_failed = false;
}

void promscrape::applyconfig(agent_promscrape::Config &config)
{
	auto callback = [this](bool ok, agent_promscrape::Empty& empty)
	{
		LOG_DEBUG("promscrape: config sent %s", ok ? "successfully" : "not ok");
	};

	if (!m_config_conn) {
		LOG_INFO("promscrape: opening GRPC connection to %s", m_sock.c_str());
		grpc::ChannelArguments args;
		// Set maximum receive message size to unlimited
		args.SetMaxReceiveMessageSize(-1);

		m_config_conn = grpc_connect<agent_promscrape::ScrapeService::Stub>(m_sock, 10, &args);
		if (!m_config_conn) {
			LOG_ERROR("promscrape: failed to connect to %s", m_sock.c_str());
			return;
		}
	}
	m_grpc_applyconfig = make_unique<unary_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncApplyConfig)>(m_config_conn);
	m_grpc_applyconfig->do_rpc(config, callback);
}

static int64_t g_prom_job_id = 0;

int64_t promscrape::assign_job_id(int pid, const string &url, const string &container_id,
	const tag_map_t &tags, uint64_t ts)
{
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
				LOG_WARNING("promscrape: job %" PRId64 " missing from job-map ", job_id);
				continue;
			}
			else
			{
				// Compare existing job to proposed one
				if ((job_it->second.pid == pid) && (job_it->second.url == url))
				{
					LOG_DEBUG("promscrape: found existing job %" PRId64 " for %d.%s", job_id, pid, url.c_str());
					// Update config timestamp
					job_it->second.config_ts = ts;

					// XXX: If tags changed we should update them
					return job_id;
				}
			}
		}
	}
	prom_job_config conf = {pid, url, container_id, ts, 0, 0, tags};

	job_id = ++g_prom_job_id;
	LOG_DEBUG("promscrape: creating job %" PRId64 " for %d.%s", job_id, pid, url.c_str());
	m_jobs.emplace(job_id, std::move(conf));
	m_pids[pid].emplace_back(job_id);
	return job_id;
}

void promscrape::addscrapeconfig(agent_promscrape::Config &config, int pid, const string &url,
        const string &container_id, const map<string, string> &options,
		uint16_t port, const tag_map_t &tags, uint64_t ts)
{
	string joburl;
	auto scrape = config.add_scrape_configs();
	auto target = scrape->mutable_target();
	// Specified url overrides scheme, host, port, path
	if (!url.empty()) {
		joburl = url;
		uri uri(url);
		target->set_scheme(uri.get_scheme());
		target->set_address(uri.get_host() + ":" + to_string(uri.get_port()));
		if (uri.get_query().empty())
		{
			target->set_metrics_path(uri.get_path());
		}
		else
		{
			target->set_metrics_path(uri.get_path() + "?" + uri.get_query());
		}
	} else {
		string scheme("http");
		auto opt_it = options.find("use_https");
		if (opt_it != options.end() && (!opt_it->second.compare("true") || !opt_it->second.compare("True")))
		{
		    scheme = string("https");
		}
		string host("localhost");
		opt_it = options.find("host");
		if (opt_it != options.end())
		{
		    host = opt_it->second;
		}
		string path;
		opt_it = options.find("path");
		if (opt_it != options.end())
		{
		    path = opt_it->second;
		}

		joburl = scheme + "://" + host + ":" + to_string(port) + path;
		target->set_scheme(scheme);
		target->set_address(host + ":" + to_string(port));
		target->set_metrics_path(path);
	}
	// scrape->set_job_name(to_string(pid) + "." + joburl);

	// Set auth method if configured in options
	settargetauth(target, options);
	int64_t job_id = assign_job_id(pid, joburl, container_id, tags, ts);
	scrape->set_job_id(job_id);
}

void promscrape::settargetauth(agent_promscrape::Target *target,
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

void promscrape::sendconfig(const vector<prom_process> &prom_procs)
{
	// Comparison may fail if ordering is different, but shouldn't happen usually
	if (prom_procs == m_last_prom_procs)
	{
		LOG_DEBUG("promscrape: not sending duplicate config");
		return;
	}
	m_last_prom_procs = prom_procs;

	if (!m_threaded)
	{
		sendconfig_th(prom_procs);
	}
	else
	{
		if (!m_config_queue.put(prom_procs))
		{
			LOG_INFO("promscrape: config queue full");
		}
	}
}

void promscrape::sendconfig_th(const vector<prom_process> &prom_procs)
{
	agent_promscrape::Config config;
	config.set_scrape_interval_sec(m_prom_conf.interval());
	config.set_ingest_raw(m_prom_conf.ingest_raw());
	config.set_ingest_legacy(m_prom_conf.ingest_calculated());
	config.set_legacy_histograms(m_prom_conf.histograms());

	{	// Scoping lock here because applyconfig doesn't need it and prune_jobs takes its own lock
		std::lock_guard<std::mutex> lock(m_map_mutex);

		for(const auto& p : prom_procs)
		{
			string empty;
			auto opt_it = p.options().find("url");
			if (opt_it != p.options().end())
			{
				// Specified url overrides everything else
				addscrapeconfig(config, p.pid(), opt_it->second, p.container_id(), p.options(), 0, p.tags(), m_next_ts);
				continue;
			}
			if (p.ports().empty())
			{
				LOG_WARNING("promscrape: scrape rule for pid %d doesn't include port number or url", p.pid());
				continue;
			}

			for (auto port : p.ports())
			{
				addscrapeconfig(config, p.pid(), empty, p.container_id(), p.options(), port, p.tags(), m_next_ts);
			}
		}
	}
	LOG_DEBUG("promscrape: sending config %s", config.DebugString().c_str());
	applyconfig(config);
	prune_jobs(m_next_ts);
}

void promscrape::next(uint64_t ts)
{
	m_next_ts = ts;

	if (!m_threaded)
	{
		next_th();
	}
}

void promscrape::next_th()
{
	m_last_ts = m_next_ts;

	if (!started())
	{
		try_start();
	}
	if (m_threaded)
	{
		LOG_DEBUG("promscrape: on thread looking for config");
		vector<prom_process> procs;
		if (m_config_queue.get(&procs, 100))
		{
			LOG_DEBUG("promscrape: on thread got config");
			sendconfig_th(procs);
		}
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
}

int elapsed_s(uint64_t old, uint64_t now)
{
	return (now - old) / ONE_SECOND_IN_NS;
}

void promscrape::handle_result(agent_promscrape::ScrapeResult &result)
{
	int64_t job_id = result.job_id();

	{
		// Temporary lock just to make sure the job still exists
		std::lock_guard<std::mutex> lock(m_map_mutex);
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			LOG_WARNING("promscrape: received results for unknown job %" PRId64, job_id);
			// Dropping results for unknown (possibly pruned) job
			return;
		}
	}

	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr;
	int total_samples = 0;	// total before filtering
	int num_samples = 0;	// after

	// Do we need to filter incoming metrics?
	if (m_metric_limits)
	{
		result_ptr = make_shared<agent_promscrape::ScrapeResult>();
		result_ptr->set_job_id(job_id);
		result_ptr->set_timestamp(result.timestamp());
		for (const auto &sample : result.samples())
		{
			string filter;
			if (m_metric_limits->allow(sample.metric_name(), filter, nullptr, "promscrape"))
			{
				auto newsample = result_ptr->add_samples();
				*newsample = sample;
				++num_samples;
			}
			++total_samples;
		}
	}
	else
	{
		// This could be a lot faster if we didn't have to copy the result protobuf
		// For instance we could use a new version of streaming_grpc_client that
		// just passes ownership of its protobuf
		result_ptr = make_shared<agent_promscrape::ScrapeResult>(std::move(result));
		num_samples = total_samples = (result_ptr->samples().size());
	}

	{
		// Lock again to write maps
		std::lock_guard<std::mutex> lock(m_map_mutex);
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			// Job must have gotten pruned while we were copying the result
			LOG_INFO("promscrape: job %" PRId64" got pruned while processing", job_id);
			return;
		}
		// Overwriting previous entry for job_id
		m_metrics[job_id] = result_ptr;

		job_it->second.data_ts = m_last_ts; // Updating data timestamp
		job_it->second.last_total_samples = total_samples;
	}

	LOG_DEBUG("promscrape: got %d of %d samples for job %" PRId64, num_samples, total_samples, job_id);
#ifdef DEBUG_PROMSCRAPE
	LOG_DEBUG("promscrape: received result: %s", result.DebugString().c_str());
#endif
}

void promscrape::prune_jobs(uint64_t ts)
{
	std::lock_guard<std::mutex> lock(m_map_mutex);
	for (auto it = m_jobs.begin(); it != m_jobs.end(); )
	{
		int elapsed = elapsed_s(it->second.config_ts, ts);
		if (elapsed < job_prune_time_s)
		{
			++it;
			continue;
		}
		// Remove job from pid-jobs list
		LOG_DEBUG("promscrape: retiring scrape job %" PRId64 ", pid %d after %d seconds inactivity", it->first, it->second.pid, elapsed);
		auto pidmap_it = m_pids.find(it->second.pid);
		if (pidmap_it == m_pids.end())
		{
			LOG_WARNING("promscrape: pid %d not found in pidmap for job %" PRId64, it->second.pid, it->first);
		}
		else
		{
			pidmap_it->second.remove(it->first);
			if (pidmap_it->second.empty())
			{
				// No jobs left for pid
				LOG_DEBUG("promscrape: no scrape jobs left for pid %d, removing", it->second.pid);
				m_pids.erase(pidmap_it);
			}
		}
		// Remove job from scrape results
		m_metrics.erase(it->first);
		// Remove job from jobs map
		it = m_jobs.erase(it);
	}
}

bool promscrape::pid_has_jobs(int pid)
{
	std::lock_guard<std::mutex> lock(m_map_mutex);
	return m_pids.find(pid) != m_pids.end();
}

std::shared_ptr<agent_promscrape::ScrapeResult> promscrape::get_job_result_ptr(
	uint64_t job_id, prom_job_config *config_copy)
{
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr;
	std::lock_guard<std::mutex> lock(m_map_mutex);

	auto it = m_metrics.find(job_id);
	if (it == m_metrics.end())
	{
		// No metrics for this job (yet)
		return nullptr;
	}
	result_ptr = it->second;

	auto jobit = m_jobs.find(job_id);
	if (jobit == m_jobs.end())
	{
		LOG_WARNING("promscrape: missing config for job %" PRId64, job_id);
		return nullptr;
	}
	// Copy the job config so the caller doesn't need to hold a lock
	if (config_copy)
	{
		*config_copy = jobit->second;
	}

	return result_ptr;
}

template<typename metric>
unsigned int promscrape::pid_to_protobuf(int pid, metric *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total)
{
	unsigned int num_metrics = 0;

	if (configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value())
	{
		// Hack to only write protobufs once per interval, where interval is the
		// negotiated interval between agent and collector
		// XXX: Use new aggregator callback instead of this interval. See SMAGENT-2293
		int interval = (m_interval_cb != nullptr) ? m_interval_cb() : 10;
		// Timestamp will be the same for different pids in same flush cycle
		if ((m_next_ts > m_last_proto_ts) &&
			(m_next_ts < (m_last_proto_ts + (interval * ONE_SECOND_IN_NS))))
		{
			LOG_DEBUG("promscrape: skipping protobuf");
			return num_metrics;
		}
		m_last_proto_ts = m_next_ts;
	}

	std::list<int64_t> jobs;
	{
		std::lock_guard<std::mutex> lock(m_map_mutex);
		auto it = m_pids.find(pid);
		if (it == m_pids.end())
			return num_metrics;
		// Copy job list
		jobs = it->second;
	}

	for (auto job : jobs) {
		LOG_DEBUG("promscrape: pid %d: have job %" PRId64, pid, job);
		num_metrics += job_to_protobuf(job, proto, limit, max_limit, filtered, total);
	}
	return num_metrics;
}

template unsigned int promscrape::pid_to_protobuf<draiosproto::app_info>(int pid, draiosproto::app_info *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total);
template unsigned int promscrape::pid_to_protobuf<draiosproto::prometheus_info>(int pid, draiosproto::prometheus_info *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total);
template unsigned int promscrape::pid_to_protobuf<draiosproto::metrics>(int pid, draiosproto::metrics *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total);

template<typename metric>
unsigned int promscrape::job_to_protobuf(int64_t job_id, metric *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total)
{
	unsigned int num_samples = 0;
	prom_job_config job_config;

	// We're going to use the results without a lock as it shouldn't get changed anywhere and
	// handle_result() always puts incoming data into a new shared_ptr
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr =
		get_job_result_ptr(job_id, &job_config);
	if (result_ptr == nullptr)
	{
		return num_samples;
	}

	LOG_DEBUG("promscrape: have metrics for job %" PRId64, job_id);

	bool ml_log = metric_limits::log_enabled();

	for (const auto &sample : result_ptr->samples())
	{
		if(limit <= 0)
		{
			if(!ml_log)
			{
				break;
			}
			LOG_INFO("[promscrape] metric over limit (total, %u max): %s",
				max_limit, sample.metric_name().c_str());
			continue;
		}
		auto newmet = proto->add_metrics();
		newmet->set_name(sample.metric_name());
		newmet->set_value(sample.value());
		newmet->set_type(static_cast<draiosproto::app_metric_type>(sample.legacy_metric_type()));
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
		for (const auto &tag : job_config.add_tags)
		{
			auto newtag = newmet->add_tags();
			newtag->set_key(tag.first);
			newtag->set_value(tag.second);
		}
		++num_samples;
		--limit;
	}

	if (filtered)
	{
		// Metric filtering happens on ingestion (in handle_result)
		// so the number of samples here is the filtered count
		*filtered += result_ptr->samples().size();
	}
	if (total)
	{
		*total += job_config.last_total_samples;
	}

	return num_samples;
}

template unsigned int promscrape::job_to_protobuf<draiosproto::app_info>(int64_t job_id,
	draiosproto::app_info *proto, unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total);
template unsigned int promscrape::job_to_protobuf<draiosproto::prometheus_info>(int64_t job_id,
	draiosproto::prometheus_info *proto, unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total);

template<>
unsigned int promscrape::job_to_protobuf(int64_t job_id, draiosproto::metrics *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total)
{
	unsigned int num_samples = 0;
	prom_job_config job_config;

	// We're going to use the results without a lock as it shouldn't get changed anywhere and
	// handle_result() always puts incoming data into a new shared_ptr
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr =
		get_job_result_ptr(job_id, &job_config);
	if (result_ptr == nullptr)
	{
		return num_samples;
	}

	LOG_DEBUG("promscrape: have metrics for job %" PRId64, job_id);

	bool ml_log = metric_limits::log_enabled();

	auto prom = proto->add_prometheus();
	prom->set_pid(job_config.pid);
	if (!job_config.container_id.empty())
	{
		prom->set_container_id(job_config.container_id);
	}
	prom->set_timestamp(result_ptr->timestamp());
	for (const auto &tag : job_config.add_tags)
	{
		auto newtag = prom->add_common_labels();
		newtag->set_name(tag.first);
		newtag->set_value(tag.second);
	}
	for (const auto &sample : result_ptr->samples())
	{
		if(limit <= 0)
		{
			if(!ml_log)
			{
				break;
			}
			LOG_INFO("[promscrape] metric over limit (total, %u max): %s",
				max_limit, sample.metric_name().c_str());
			continue;
		}

		// Only supported for RAW prometheus metrics
		auto newmet = prom->add_samples();
		newmet->set_metric_name(sample.metric_name());
		newmet->set_value(sample.value());

		newmet->set_type(static_cast<draiosproto::prometheus_type>(sample.raw_metric_type()));

		for (const auto &label : sample.labels())
		{
			auto newtag = newmet->add_labels();
			newtag->set_name(label.name());
			newtag->set_value(label.value());
		}
		++num_samples;
		--limit;
	}

	if (filtered)
	{
		// Metric filtering happens on ingestion (in handle_result)
		// so the number of samples here is the filtered count
		*filtered += result_ptr->samples().size();
	}

	return num_samples;
}
