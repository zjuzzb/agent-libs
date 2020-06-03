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

type_config<int> c_promscrape_stats_log_interval(
    60,
    "Interval for logging promscrape timeseries statistics",
    "promscrape_stats_log_interval");

type_config<bool> promscrape::c_use_promscrape(
    true,
    "Whether or not to use promscrape for prometheus metrics",
    "use_promscrape");

type_config<string> c_promscrape_sock(
    "127.0.0.1:9876",
    "Socket address URL for promscrape server",
    "promscrape_address");

type_config<int> c_promscrape_connect_interval(
    10,
    "Interval for attempting to connect to promscrape",
    "promscrape_connect_interval");

type_config<int> c_promscrape_connect_delay(
    10,
    "Delay before attempting to connect to promscrape",
    "promscrape_connect_delay");

type_config<bool>::mutable_ptr promscrape::c_export_fastproto =
	type_config_builder<bool>(false,
		"Whether or not to export metrics using newer protocol",
		"promscrape_fastproto")
	.post_init([](type_config<bool>& config)
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

int elapsed_s(uint64_t old, uint64_t now)
{
	return (now - old) / ONE_SECOND_IN_NS;
}

void promscrape::validate_config(prometheus_conf &prom_conf)
{
	bool &use_promscrape = c_use_promscrape.get_value();
	if (use_promscrape && !prom_conf.enabled())
	{
		LOG_INFO("promscrape enabled without prometheus, disabling");
		use_promscrape = false;
	}
	bool &fastproto = (*c_export_fastproto).get_value();
	if (fastproto && !prom_conf.ingest_raw())
	{
		LOG_INFO("promscrape_fastproto is only supported for raw metrics, disabling."
			" Enable prometheus.ingest_raw to enable fastproto");
		fastproto = false;
	}
}

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
		m_resend_config(false),
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
		LOG_INFO("opening GRPC connection to %s", m_sock.c_str());
		grpc::ChannelArguments args;
		// Set maximum receive message size to unlimited
		args.SetMaxReceiveMessageSize(-1);

		m_start_conn = grpc_connect<agent_promscrape::ScrapeService::Stub>(m_sock, 10, &args);
		if (!m_start_conn) {
			// Only log at error if we've been up for a while
			if (elapsed_s(m_boot_ts, sinsp_utils::get_current_time_ns()) < 30)
			{
				LOG_INFO("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					c_promscrape_connect_interval.get_value());
			}
			else
			{
				LOG_ERROR("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					c_promscrape_connect_interval.get_value());
			}
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
	if (!m_boot_ts)
	{
		m_boot_ts = sinsp_utils::get_current_time_ns();
	}
	if (elapsed_s(m_boot_ts, sinsp_utils::get_current_time_ns()) < c_promscrape_connect_delay.get_value())
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
	LOG_INFO("resetting connection");
	m_start_failed = false;
	m_grpc_start = nullptr;
	m_start_conn = nullptr;

	// Resetting config connection as well
	m_config_conn = nullptr;
	m_grpc_applyconfig = nullptr;
	m_resend_config = true;
}

void promscrape::applyconfig()
{
	if (!started())
	{
		m_resend_config = true;
		return;
	}

	auto callback = [this](bool ok, agent_promscrape::Empty& empty)
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

	if (!m_config_conn) {
		LOG_INFO("opening GRPC connection to %s", m_sock.c_str());
		grpc::ChannelArguments args;
		// Set maximum receive message size to unlimited
		args.SetMaxReceiveMessageSize(-1);

		m_config_conn = grpc_connect<agent_promscrape::ScrapeService::Stub>(m_sock, 10, &args);
		if (!m_config_conn) {
			if (elapsed_s(m_boot_ts, sinsp_utils::get_current_time_ns()) < 30)
			{
				LOG_INFO("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					c_promscrape_connect_interval.get_value());
			}
			else
			{
				LOG_ERROR("failed to connect to %s, retrying in %ds", m_sock.c_str(),
					c_promscrape_connect_interval.get_value());
			}
			m_resend_config = true;
			return;
		}
	}
	m_grpc_applyconfig = make_unique<unary_grpc_client(&agent_promscrape::ScrapeService::Stub::AsyncApplyConfig)>(m_config_conn);
	m_grpc_applyconfig->do_rpc(*m_config, callback);
	m_resend_config = false;
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
				LOG_WARNING("job %" PRId64 " missing from job-map ", job_id);
				continue;
			}
			else
			{
				// Compare existing job to proposed one
				if ((job_it->second.pid == pid) && (job_it->second.url == url))
				{
					LOG_DEBUG("found existing job %" PRId64 " for %d.%s", job_id, pid, url.c_str());
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
	LOG_DEBUG("creating job %" PRId64 " for %d.%s", job_id, pid, url.c_str());
	m_jobs.emplace(job_id, std::move(conf));
	m_pids[pid].emplace_back(job_id);
	return job_id;
}

void promscrape::addscrapeconfig(int pid, const string &url,
        const string &container_id, const map<string, string> &options, const string &path,
		uint16_t port, const tag_map_t &tags, const tag_umap_t &infra_tags, uint64_t ts)
{
	string joburl;
	auto scrape = m_config->add_scrape_configs();
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

		auto tagp = target->add_tags();
		tagp->set_name("port");
		tagp->set_value(to_string(uri.get_port()));
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

		joburl = scheme + "://" + host + ":" + to_string(port) + path;
		target->set_scheme(scheme);
		target->set_address(host + ":" + to_string(port));
		target->set_metrics_path(path);

		auto tagp = target->add_tags();
		tagp->set_name("port");
		tagp->set_value(to_string(port));
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
		LOG_TRACE("not sending duplicate config");
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
			LOG_INFO("config queue full");
		}
	}
}

void promscrape::sendconfig_th(const vector<prom_process> &prom_procs)
{
	m_config = make_shared<agent_promscrape::Config>();
	m_config->set_scrape_interval_sec(m_prom_conf.interval());
	m_config->set_ingest_raw(m_prom_conf.ingest_raw());
	m_config->set_ingest_legacy(m_prom_conf.ingest_calculated());
	m_config->set_legacy_histograms(m_prom_conf.histograms());

	{	// Scoping lock here because applyconfig doesn't need it and prune_jobs takes its own lock
		std::lock_guard<std::mutex> lock(m_map_mutex);

		for(const auto& p : prom_procs)
		{
			string empty;
			auto opt_it = p.options().find("url");
			if (opt_it != p.options().end())
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
		vector<prom_process> procs;
		if (m_config_queue.get(&procs, 100))
		{
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
	if (m_resend_config && started())
	{
		applyconfig();
	}
}

void promscrape::handle_result(agent_promscrape::ScrapeResult &result)
{
	int64_t job_id = result.job_id();
	std::string url;

	{
		// Temporary lock just to make sure the job still exists
		std::lock_guard<std::mutex> lock(m_map_mutex);
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			LOG_INFO("received results for unknown job %" PRId64, job_id);
			// Dropping results for unknown (possibly pruned) job
			return;
		}
		url = job_it->second.url;
	}

	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr;
	int raw_total_samples = 0;	// total before filtering
	int raw_num_samples = 0;	// after
	int calc_total_samples = 0;
	int calc_num_samples = 0;

	// Do we need to filter incoming metrics?
	if (m_metric_limits)
	{
		result_ptr = make_shared<agent_promscrape::ScrapeResult>();
		result_ptr->set_job_id(job_id);
		result_ptr->set_timestamp(result.timestamp());
		for (const auto &sample : result.samples())
		{
			bool is_raw = (sample.legacy_metric_type() == agent_promscrape::Sample::MT_RAW);
			string filter;
			if (m_metric_limits->allow(sample.metric_name(), filter, nullptr, "promscrape"))
			{
				auto newsample = result_ptr->add_samples();
				*newsample = sample;
				if (is_raw) {
					++raw_num_samples;
				} else {
					++calc_num_samples;
				}
			}
			if (is_raw) {
				++raw_total_samples;
			} else {
				++calc_total_samples;
			}
		}
		result_ptr->mutable_meta_samples()->CopyFrom(result.meta_samples());
	}
	else
	{
		// This could be a lot faster if we didn't have to copy the result protobuf
		// For instance we could use a new version of streaming_grpc_client that
		// just passes ownership of its protobuf
		result_ptr = make_shared<agent_promscrape::ScrapeResult>(std::move(result));
		for (const auto &sample : result.samples())
		{
			if (sample.legacy_metric_type() == agent_promscrape::Sample::MT_RAW)
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
	for (const auto &meta_sample : result_ptr->meta_samples())
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
		LOG_INFO("Missing metadata metrics for %s. Results may be incorrect in "
			"subsequent metrics summary", url.c_str());
		scraped = post_relabel = added = raw_total_samples;
	}
	m_stats.set_stats(url, scraped, scraped - post_relabel, post_relabel - added, raw_total_samples - raw_num_samples, calc_total_samples, 0, 0, calc_total_samples - calc_num_samples);

	{
		// Lock again to write maps
		std::lock_guard<std::mutex> lock(m_map_mutex);
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			// Job must have gotten pruned while we were copying the result
			LOG_INFO("job %" PRId64" got pruned while processing", job_id);
			return;
		}
		// Overwriting previous entry for job_id
		m_metrics[job_id] = result_ptr;

		job_it->second.data_ts = m_last_ts; // Updating data timestamp
		job_it->second.last_total_samples = raw_total_samples + calc_total_samples;
	}

	LOG_DEBUG("got %d of %d raw and %d of %d calculated samples for job %" PRId64,
		raw_num_samples, raw_total_samples, calc_num_samples, calc_total_samples, job_id);
#ifdef DEBUG_PROMSCRAPE
	LOG_DEBUG("received result: %s", result.DebugString().c_str());
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
		LOG_DEBUG("retiring scrape job %" PRId64 ", pid %d after %d seconds inactivity", it->first, it->second.pid, elapsed);
		auto pidmap_it = m_pids.find(it->second.pid);
		if (pidmap_it == m_pids.end())
		{
			LOG_WARNING("pid %d not found in pidmap for job %" PRId64, it->second.pid, it->first);
		}
		else
		{
			pidmap_it->second.remove(it->first);
			if (pidmap_it->second.empty())
			{
				// No jobs left for pid
				LOG_DEBUG("no scrape jobs left for pid %d, removing", it->second.pid);
				m_pids.erase(pidmap_it);
			}
		}
		// Remove job from scrape results
		m_metrics.erase(it->first);
		// Remove job from jobs map
		it = m_jobs.erase(it);
	}
}

// Currently only supported for 10s flush when fastproto is enabled
bool promscrape::can_use_metrics_request_callback()
{
	return promscrape::c_export_fastproto->get_value() &&
		configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value();
}

// metrics request callback
// Should only get called once per flush interval by the async aggregator
// Only when 10s flush is enabled
std::shared_ptr<draiosproto::metrics> promscrape::metrics_request_callback()
{
	unsigned int sent = 0;
	unsigned int remaining = m_prom_conf.max_metrics();
	unsigned int filtered = 0;
	unsigned int total = 0;
	shared_ptr<draiosproto::metrics> metrics = make_shared<draiosproto::metrics>();

	set<int> export_pids;
	{
		std::lock_guard<std::mutex> lock(m_export_pids_mutex);
		export_pids = std::move(m_export_pids);
		m_export_pids.clear();
	}

	for (int pid : export_pids)
	{
		LOG_DEBUG("callback: exporting pid %d", pid);
		if (promscrape::c_export_fastproto->get_value())
		{
			sent += pid_to_protobuf(pid, metrics.get(), remaining, m_prom_conf.max_metrics(),
				&filtered, &total, true);
		}
		else
		{
			// Shouldn't get here yet
			LOG_INFO("callback: export pid %d: not yet supported for per-process export", pid);
		}
	}
	metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_sent(sent);
	metrics->mutable_hostinfo()->mutable_resource_counters()->set_prometheus_total(total);
	if (remaining == 0)
	{
		LOG_WARNING("Prometheus metrics limit (%u) reached, %u sent of %u filtered, %u total",
			m_prom_conf.max_metrics(), sent, filtered, total);
	}
	else
	{
		LOG_DEBUG("Sent %u Prometheus metrics of %u filtered, %u total",
			sent, filtered, total);
	}

	return metrics;
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

	auto jobit = m_jobs.find(job_id);
	if (jobit == m_jobs.end())
	{
		LOG_WARNING("missing config for job %" PRId64, job_id);
		return nullptr;
	}
	if (jobit->second.config_ts < m_last_config_ts)
	{
		LOG_DEBUG("job %" PRId64 " was dropped %d seconds before latest config",
			job_id, elapsed_s(jobit->second.config_ts, m_last_config_ts));
		return nullptr;
	}

	auto it = m_metrics.find(job_id);
	if (it == m_metrics.end())
	{
		// No metrics for this job (yet)
		return nullptr;
	}
	result_ptr = it->second;

	// Copy the job config so the caller doesn't need to hold a lock
	if (config_copy)
	{
		*config_copy = jobit->second;
	}

	return result_ptr;
}

// Called by analyzer flush loop to ask if it should emit counters itself
bool promscrape::emit_counters() const
{
	if (!c_use_promscrape.get_value() ||
		!(configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value()))
	{
		return true;
	}
	return m_emit_counters;
}

template<typename metric>
unsigned int promscrape::pid_to_protobuf(int pid, metric *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback)
{
	unsigned int num_metrics = 0;

	if (!callback)
	{
		if (can_use_metrics_request_callback())
		{
			// Add pid to export set. The metrics_request_callback will trigger the
			// actual population of the protobuf by calling into this method with the
			// callback bool set to true
			LOG_DEBUG("adding pid %d to export set", pid);

			std::lock_guard<std::mutex> lock(m_export_pids_mutex);
			m_export_pids.emplace(pid);
			m_emit_counters = false;
			return 0;
		}
		else if (configuration_manager::instance().get_config<bool>("10s_flush_enable")->get_value())
		{
			// Hack to only write protobufs once per interval, where interval is the
			// negotiated interval between agent and collector
			// XXX: The new aggregator callback doesn't work yet for per-process metrics.
			// Once it does we can use that instead, like we do for the fastproto case above
			// See SMAGENT-2293
			int interval = (m_interval_cb != nullptr) ? m_interval_cb() : 10;
			// Timestamp will be the same for different pids in same flush cycle
			if ((m_next_ts > m_last_proto_ts) &&
				(m_next_ts < (m_last_proto_ts + (interval * ONE_SECOND_IN_NS) -
				(ONE_SECOND_IN_NS / 2))))
			{
				LOG_DEBUG("skipping protobuf");
				m_emit_counters = false;
				return num_metrics;
			}
			m_emit_counters = true;
			m_last_proto_ts = m_next_ts;
		}
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
		LOG_DEBUG("pid %d: have job %" PRId64, pid, job);
		num_metrics += job_to_protobuf(job, proto, limit, max_limit, filtered, total);
	}
	return num_metrics;
}

template unsigned int promscrape::pid_to_protobuf<draiosproto::app_info>(int pid, draiosproto::app_info *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback);
template unsigned int promscrape::pid_to_protobuf<draiosproto::prometheus_info>(int pid, draiosproto::prometheus_info *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback);
template unsigned int promscrape::pid_to_protobuf<draiosproto::metrics>(int pid, draiosproto::metrics *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total,
	bool callback);

template<typename metric>
unsigned int promscrape::job_to_protobuf(int64_t job_id, metric *proto,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total)
{
	unsigned int raw_num_samples = 0;
	unsigned int calc_num_samples = 0;
	unsigned int over_limit = 0;
	prom_job_config job_config;

	// We're going to use the results without a lock as it shouldn't get changed anywhere and
	// handle_result() always puts incoming data into a new shared_ptr
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr =
		get_job_result_ptr(job_id, &job_config);
	if (result_ptr == nullptr)
	{
		return 0;
	}

	LOG_DEBUG("have metrics for job %" PRId64, job_id);

	bool ml_log = metric_limits::log_enabled();

	// Lambda for adding samples from samples or metasamples
	auto add_sample = [&proto,&job_config](const agent_promscrape::Sample& sample)
	{
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
	};

	// The current limit policy, similar to upstream prometheus, is:
	//  - In order to avoid incorrect reporting, if the total number of timeseries
	//    for the endpoint exceeds the metric limit, all the timeseries for that
	//    endpoint will be dropped.

	if (result_ptr->samples().size() > limit)
	{
		over_limit = result_ptr->samples().size() - limit;
		limit = 0;
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

		add_sample(sample);
		--limit;
		if (sample.legacy_metric_type() == agent_promscrape::Sample::MT_RAW)
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
	for (auto &sample : *result_ptr->mutable_meta_samples())
	{
		// Adjust scrape_series_added to reflect agent metric limits and filters
		if (sample.metric_name() == "scrape_series_added")
		{
			// Scrape metadata only applies to raw metrics
			sample.set_value(raw_num_samples);
		}
		add_sample(sample);
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

	// Update metric stats
	m_stats.add_stats(job_config.url, over_limit, raw_num_samples, calc_num_samples);

	return raw_num_samples + calc_num_samples;
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
	unsigned int raw_num_samples = 0;
	unsigned int calc_num_samples = 0;
	unsigned int over_limit = 0;
	prom_job_config job_config;

	// We're going to use the results without a lock as it shouldn't get changed anywhere and
	// handle_result() always puts incoming data into a new shared_ptr
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr =
		get_job_result_ptr(job_id, &job_config);
	if (result_ptr == nullptr)
	{
		return 0;
	}

	LOG_DEBUG("have metrics for job %" PRId64, job_id);

	bool ml_log = metric_limits::log_enabled();

	auto prom = proto->add_prometheus();
	// Add pid in source_metadata
	auto meta = prom->add_source_metadata();
	meta->set_name("pid");
	meta->set_value(to_string(job_config.pid));
	if (!job_config.container_id.empty())
	{
		meta = prom->add_source_metadata();
		meta->set_name("container_id");
		meta->set_value(job_config.container_id);
	}
	prom->set_timestamp(result_ptr->timestamp());
	for (const auto &tag : job_config.add_tags)
	{
		auto newtag = prom->add_common_labels();
		newtag->set_name(tag.first);
		newtag->set_value(tag.second);
	}

	// Lambda for adding samples from samples or metasamples
	auto add_sample = [&prom](const agent_promscrape::Sample& sample)
	{
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
	};

	// The current limit policy, similar to upstream prometheus, is:
	//  - In order to avoid incorrect reporting, if the total number of timeseries
	//    for the endpoint exceeds the metric limit, all the timeseries for that
	//    endpoint will be dropped.

	if (result_ptr->samples().size() > limit)
	{
		over_limit = result_ptr->samples().size() - limit;
		limit = 0;
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

		add_sample(sample);
		--limit;
		if (sample.legacy_metric_type() == agent_promscrape::Sample::MT_RAW)
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
	for (auto &sample : *result_ptr->mutable_meta_samples())
	{
		// Adjust scrape_series_added to reflect agent metric limits and filters
		if (sample.metric_name() == "scrape_series_added")
		{
			// Scrape metadata only applies to raw metrics
			sample.set_value(raw_num_samples);
		}
		add_sample(sample);
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

	// Update metric stats
	m_stats.add_stats(job_config.url, over_limit, raw_num_samples, calc_num_samples);

	return raw_num_samples + calc_num_samples;
}

promscrape_stats::promscrape_stats() :
		m_log_interval(c_promscrape_stats_log_interval.get_value() * ONE_SECOND_IN_NS)
{
}

void promscrape_stats::set_stats(std::string url,
	int raw_scraped, int raw_job_filter_dropped,
	int raw_over_job_limit, int raw_global_filter_dropped,
	int calc_scraped, int calc_job_filter_dropped,
	int calc_over_job_limit, int calc_global_filter_dropped)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	metric_stats stats = {
		raw_scraped,
		raw_job_filter_dropped,
		raw_over_job_limit,
		raw_global_filter_dropped,
		0,
		calc_scraped,
		calc_job_filter_dropped,
		calc_over_job_limit,
		calc_global_filter_dropped,
		0,
		0
	};

	m_stats_map[url] = std::move(stats);
}

void promscrape_stats::add_stats(std::string url, int over_global_limit, int raw_sent, int calc_sent)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	auto it = m_stats_map.find(url);
	if (it == m_stats_map.end())
	{
		LOG_DEBUG("Ignoring additional stats for endpoint without scraping stats, url: %s", url.c_str());
		return;
	}

	it->second.over_global_limit = over_global_limit;
	it->second.raw_sent = raw_sent;
	it->second.calc_sent = calc_sent;
}

void promscrape_stats::log_summary()
{
	std::lock_guard<std::mutex> lock(m_mutex);

	LOG_INFO("Prometheus timeseries statistics, %lu endpoints", m_stats_map.size());
	for (const auto &stat : m_stats_map) {
		if (stat.second.over_global_limit || stat.second.raw_over_job_limit ||
			stat.second.calc_over_job_limit)
		{
			int unsent = stat.second.raw_scraped - stat.second.raw_job_filter_dropped -
				stat.second.raw_global_filter_dropped - stat.second.raw_sent;
			unsent += stat.second.calc_scraped - stat.second.calc_job_filter_dropped -
				stat.second.calc_global_filter_dropped - stat.second.calc_sent;
			LOG_INFO("endpoint %s: %d timeseries (after filter) not sent because of %s "
				"limit (%d over limit)", stat.first.c_str(), unsent,
				stat.second.over_global_limit ? "prometheus metric" : "job sample",
				stat.second.over_global_limit ? stat.second.over_global_limit :
				(stat.second.raw_over_job_limit + stat.second.calc_over_job_limit));
		}
		else
		{
			LOG_INFO("endpoint %s: %d total timeseries sent", stat.first.c_str(), stat.second.raw_sent + stat.second.calc_sent);
		}
		LOG_INFO("endpoint %s: RAW: scraped %d, sent %d, dropped by: "
			"job filter %d, global filter %d",
			stat.first.c_str(), stat.second.raw_scraped, stat.second.raw_sent,
			stat.second.raw_job_filter_dropped, stat.second.raw_global_filter_dropped);
		LOG_INFO("endpoint %s: CALCULATED: scraped %d, sent %d, dropped by: "
			"job filter %d, global filter %d",
			stat.first.c_str(), stat.second.calc_scraped, stat.second.calc_sent,
			stat.second.calc_job_filter_dropped, stat.second.calc_global_filter_dropped);
	}
}

void promscrape_stats::clear()
{
	std::lock_guard<std::mutex> lock(m_mutex);

	m_stats_map.clear();
}

void promscrape_stats::periodic_log_summary()
{
	m_log_interval.run([this]()
	{
		log_summary();
		clear();
	}, sinsp_utils::get_current_time_ns() );
}
