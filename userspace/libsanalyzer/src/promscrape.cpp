#include <memory>
#include "common_logger.h"
#include "promscrape.h"
#include "prometheus.h"
#include "analyzer_utils.h"
#include "type_config.h"
#include "uri.h"
#include "configuration_manager.h"
#include "infrastructure_state.h"
#include "Poco/Exception.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPClientSession.h>
#include <json/json.h>
#include "command_line_manager.h"
#include "tabulate.hpp"

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

// Promscrape GRPC server address: At this point the default agent root-dir is not yet
// known, so it will be inserted during config validation
type_config<string> promscrape::c_promscrape_sock(
    "unix:/run/promscrape.sock",
    "Socket address URL for promscrape server",
    "promscrape_address");

type_config<bool> promscrape::c_allow_bypass(
	true,
    "Allow a metric endpoint to bypass limits and filters",
    "promscrape_allow_bypass");

type_config<string> promscrape::c_promscrape_web_sock(
    "127.0.0.1:9990",
    "Socket address URL for promscrape web server",
    "promscrape_web_address");

type_config<bool> promscrape::c_promscrape_web_enable(
    true,
    "Enable promscrape web server with target status",
    "promscrape_web_enable");

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

type_config<bool> promscrape_stats::c_always_gather_stats(
    false,
    "Gather statistics and metadata in the background for all prometheus targets",
    "promscrape_gather_stats");

int elapsed_s(uint64_t old, uint64_t now)
{
	return (now - old) / ONE_SECOND_IN_NS;
}

void promscrape::validate_config(prometheus_conf &prom_conf, const string &root_dir)
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
	if (fastproto && prom_conf.ingest_calculated())
	{
		LOG_INFO("ingest_calculated is enabled but not supported with promscrape_fastproto."
			"You will only get raw prometheus metrics");
	}
	string &sock = c_promscrape_sock.get_value();
	if (sock.compare(0,6,"unix:/") == 0)
	{
		// Insert root-dir for unix socket address
		sock = "unix:" + root_dir + "/" + sock.substr(6);
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
		m_last_proto_ts(0),
		m_stats(prom_conf, this),
		m_infra_state(nullptr)
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
	// We don't send scrape configs for v2
	if (is_promscrape_v2())
	{
		m_resend_config = false;
		return;
	}
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

int64_t promscrape::job_url_to_job_id(const std::string &url)
{
	std::lock_guard<std::mutex> lock(m_map_mutex);

	auto url_it = m_joburls.find(url);
	if (url_it != m_joburls.end())
	{
		return url_it->second;
	}

	int64_t job_id = 0;
	prom_job_config conf = {
		0,	// pid
		url,	// url
		"",	// container_id
		m_next_ts,  // config_ts
		0,	// data_ts
		0,	// last_total_samples
		{},	// add_tags
		false,	// bypass_limits
		false
	};

	job_id = ++g_prom_job_id;
	LOG_DEBUG("creating job %" PRId64 " for %s", job_id, url.c_str());
	m_jobs.emplace(job_id, std::move(conf));
	m_joburls.emplace(url, job_id);
	m_pids[0].emplace_back(job_id);
	return job_id;
}

int64_t promscrape::assign_job_id(int pid, const string &url, const string &container_id,
	const tag_map_t &tags, uint64_t ts)
{
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
	prom_job_config conf = {pid, url, container_id, ts, 0, 0, tags, false, false};

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
	// We don't send scrape configs for v2
	if (is_promscrape_v2())
	{
		return;
	}
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
		// Look for new configs with 100 ms timeout.
		// This also ensures we don't spin idle when threaded
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

static void set_label_value(google::protobuf::RepeatedPtrField<agent_promscrape::Label> *labels,
	const string &name, const string &value)
{
	for (auto &label : *labels)
	{
		if (!label.name().compare(name))
		{
			label.set_value(value);
			return;
		}
	}
	auto new_label = labels->Add();
	new_label->set_name(name);
	new_label->set_value(value);
}

void promscrape::handle_result(agent_promscrape::ScrapeResult &result)
{
#ifdef DEBUG_PROMSCRAPE
	LOG_DEBUG("received result: %s", result.DebugString().c_str());
#endif
	int64_t job_id;
	string url;
	bool bypass_limits = false;
	bool omit_source = false;

	if (is_promscrape_v2())
	{
		// For promscrape_v2 we associate job_ids with urls
		if (result.url().size() < 1)
		{
			LOG_INFO("Missing url from promscrape v2 result, dropping scrape results");
			return;
		}
		url = result.url();
		// job_url_to_job_id will create the job as needed
		job_id = job_url_to_job_id(url);
	}
	else
	{
		// Temporary lock just to make sure the job still exists
		std::lock_guard<std::mutex> lock(m_map_mutex);

		job_id = result.job_id();
		auto job_it = m_jobs.find(job_id);
		if (job_it == m_jobs.end())
		{
			LOG_INFO("received results for unknown job %" PRId64, job_id);
			// Dropping results for unknown (possibly pruned) job
			return;
		}
		if (result.url().size() < 1)
		{
			url = job_it->second.url;
		}
		else
		{
			url = result.url();
			if (url != job_it->second.url)
			{
				LOG_INFO("job %" PRId64 ": scraped url %s doesn't match requested url %s",
					job_id, url.c_str(), job_it->second.url.c_str());
			}
		}
	}

	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr;
	int raw_total_samples = 0;	// total before filtering
	int raw_num_samples = 0;	// after
	int calc_total_samples = 0;
	int calc_num_samples = 0;

	// Attempt to find and fill in the container_id if it isn't available yet
	string container_id;
	string container_name;
	string pod_id;

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
		else if (allow_bypass() && (source_label.name() == "sysdig_bypass") &&
			(source_label.value() == "true"))
		{
			bypass_limits = true;
		}
		else if ((source_label.name() == "sysdig_omit_source") && !source_label.value().empty())
		{
			omit_source = true;
		}
	}

	// Do we need to filter incoming metrics?
	if (m_metric_limits && !bypass_limits)
	{
		result_ptr = make_shared<agent_promscrape::ScrapeResult>();
		result_ptr->set_job_id(job_id);
		result_ptr->set_timestamp(result.timestamp());
		result_ptr->set_url(result.url());
		for (const auto &sample : result.samples())
		{
			bool is_raw = metric_type_is_raw(sample.legacy_metric_type());
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
		result_ptr->mutable_source_labels()->CopyFrom(result.source_labels());
	}
	else
	{
		// This could be a lot faster if we didn't have to copy the result protobuf
		// For instance we could use a new version of streaming_grpc_client that
		// just passes ownership of its protobuf
		result_ptr = make_shared<agent_promscrape::ScrapeResult>(std::move(result));
		for (const auto &sample : result.samples())
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
		if (m_prom_conf.ingest_raw())
		{
			LOG_INFO("Missing metadata metrics for %s. Results may be incorrect in "
				"subsequent metrics summary", url.c_str());
		}
		scraped = post_relabel = added = raw_total_samples;
	}
	m_stats.set_stats(url, scraped, scraped - post_relabel, post_relabel - added, raw_total_samples - raw_num_samples, calc_total_samples, 0, 0, calc_total_samples - calc_num_samples);

	if (container_id.empty() && !pod_id.empty() && !container_name.empty() && m_infra_state)
	{
		infrastructure_state::uid_t uid = make_pair("k8s_pod", pod_id);
		container_id = m_infra_state->get_container_id_from_k8s_pod_and_k8s_pod_name(uid, container_name);
		LOG_DEBUG("Correlated container id %s from %s:%s", container_id.c_str(),
			pod_id.c_str(), container_name.c_str());
		if (!container_id.empty())
		{
			set_label_value(result_ptr->mutable_source_labels(), "container_id", container_id);
		}
	}
	string instance;

	if (!result_ptr->meta_samples().empty())
	{
		// Look for instance label only in first meta sample
		const auto &meta_sample = result_ptr->meta_samples()[0];
		for (const auto &label : meta_sample.labels())
		{
			if (!label.name().compare("instance"))
			{
				instance = label.value();
				break;
			}
		}
	}
	if (instance.empty() && !result_ptr->samples().empty())
	{
		// Now look for instance label only in first sample
		const auto &sample = result_ptr->samples()[0];
		for (const auto &label : sample.labels())
		{
			if (!label.name().compare("instance"))
			{
				instance = label.value();
				break;
			}
		}
	}
	// If no pod or container were given, we want to know if the source was running on this
	// host or not
	if (pod_id.empty() && container_id.empty() && m_infra_state)
	{
		if (!instance.empty())
		{
			bool local = false;
			infrastructure_state::uid_t uid;
			string host = instance.substr(0, instance.find(':'));

			if (!host.compare("localhost") || !host.compare("127.0.0.1"))
			{
				local = true;
			}
			else if (!host.empty())
			{
				local = m_infra_state->find_local_ip(host, &uid);
			}
			LOG_DEBUG("job %" PRId64": instance %s is %s", job_id, instance.c_str(), local ? "local" : "not local");
			if (local)
			{
				auto new_source_label = result_ptr->add_source_labels();
				new_source_label->set_name("host_mac");
				new_source_label->set_value(m_infra_state->get_machine_id());
				if (!uid.first.compare("k8s_pod"))
				{
					LOG_DEBUG("job %" PRId64": instance %s, set pod_id to %s", job_id,
						instance.c_str(), uid.second.c_str());
					set_label_value(result_ptr->mutable_source_labels(), "pod_id", uid.second);
				}
			}
		}
		else
		{
			LOG_DEBUG("job %" PRId64": couldn't find instance label", job_id);
		}
	}

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
		job_it->second.bypass_limits = bypass_limits;
		job_it->second.omit_source = omit_source;
	}
	if (!instance.empty())
	{
		m_stats.process_scrape(instance, result_ptr);
	}

	LOG_DEBUG("got %d of %d raw and %d of %d calculated samples for job %" PRId64,
		raw_num_samples, raw_total_samples, calc_num_samples, calc_total_samples, job_id);
	if (bypass_limits && (m_bypass_cb != nullptr))
	{
		auto msg = create_bypass_protobuf(job_id);
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

void promscrape::prune_jobs(uint64_t ts)
{
	std::lock_guard<std::mutex> lock(m_map_mutex);
	for (auto it = m_jobs.begin(); it != m_jobs.end(); )
	{
		int elapsed = elapsed_s(it->second.config_ts, ts);
		int prune_time = job_prune_time_s;
		if (is_promscrape_v2())
		{
			// Promscrape V2 does service discovery itself, so we can't prune
			// based on configuration time. We prune based on expiration after
			// reception of data instead.
			elapsed = elapsed_s(it->second.data_ts, ts);
			prune_time = m_prom_conf.metric_expiration();
		}
		if (elapsed < prune_time)
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
		if (it->second.pid == 0)
		{
			auto joburl_it = m_joburls.find(it->second.url);
			if (joburl_it != m_joburls.end())
			{
				// Removing entry joburls map
				LOG_DEBUG("Removing job for %s", it->second.url.c_str());
				m_joburls.erase(joburl_it);
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

bool promscrape::pid_has_metrics(int pid)
{
	std::lock_guard<std::mutex> lock(m_map_mutex);
	const auto pidmap_it = m_pids.find(pid);
	if (pidmap_it == m_pids.end())
	{
		return false;
	}
	for (uint64_t job_id : pidmap_it->second)
	{
		if (m_metrics.find(job_id) != m_metrics.end())
		{
			return true;
		}
	}
	return false;
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
	// Promscrape v1 sends all currently active targets each cycle, so if a job
	// was configured before the last cycle, it must have been dropped 
	// Doesn't apply to v2 since Promscrape does all discovery by itself.
	if (!is_promscrape_v2() && (jobit->second.config_ts < m_last_config_ts))
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

bool promscrape::metric_type_is_raw(agent_promscrape::Sample::LegacyMetricType mt)
{
	// Promscrape v2 doesn't populate the legacy_metric_type field
	// For some reason the C++ protobuf API doesn't have a way to check
	// field existence but instead the field is reported as 0 which
	// in this case equals MT_INVALID
	return (mt == agent_promscrape::Sample::MT_RAW) ||
		(mt == agent_promscrape::Sample::MT_INVALID);
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
	if (job_config.bypass_limits && (m_bypass_cb != nullptr))
	{
		LOG_DEBUG("Metrics for bypass job %" PRId64 " were already sent previously, skipping", job_id);
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
	}

	for (const auto &sample : result_ptr->samples())
	{
		if(over_limit)
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
		if (metric_type_is_raw(sample.legacy_metric_type()))
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
	prom_job_config job_config;

	// We're going to use the results without a lock as it shouldn't get changed anywhere and
	// handle_result() always puts incoming data into a new shared_ptr
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr =
		get_job_result_ptr(job_id, &job_config);
	if (result_ptr == nullptr)
	{
		return 0;
	}
	if (job_config.bypass_limits && (m_bypass_cb != nullptr))
	{
		LOG_DEBUG("Metrics for bypass job %" PRId64 " were already sent previously, skipping", job_id);
		return 0;
	}

	auto prom = proto->add_prometheus();

	return result_to_protobuf(job_id, result_ptr, &job_config, prom, true,
		limit, max_limit, filtered, total);
}

unsigned int promscrape::result_to_protobuf(int64_t job_id,
	std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr,
	prom_job_config *job_config, draiosproto::prom_metrics *prom, bool enforce_limits,
	unsigned int &limit, unsigned int max_limit,
	unsigned int *filtered, unsigned int *total)
{
	unsigned int raw_num_samples = 0;
	unsigned int calc_num_samples = 0;
	unsigned int over_limit = 0;

	if ((result_ptr == nullptr) || (prom == nullptr))
	{
		return 0;
	}

	LOG_DEBUG("have metrics for job %" PRId64, job_id);

	bool ml_log = enforce_limits && metric_limits::log_enabled();

	prom->set_timestamp(result_ptr->timestamp());
	for (const auto &tag : job_config->add_tags)
	{
		auto newtag = prom->add_common_labels();
		newtag->set_name(tag.first);
		newtag->set_value(tag.second);
	}

	if (!job_config->omit_source)
	{
		// Add pid in source_metadata, if we have a pid
		if (job_config->pid)
		{
			auto meta = prom->add_source_metadata();
			meta->set_name("pid");
			meta->set_value(to_string(job_config->pid));
		}
		if (!job_config->container_id.empty())
		{
			auto meta = prom->add_source_metadata();
			meta->set_name("container_id");
			meta->set_value(job_config->container_id);
		}
		for (const auto &source_label : result_ptr->source_labels())
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
		if (m_infra_state && !m_infra_state->get_k8s_cluster_id().empty())
		{
			auto meta = prom->add_source_metadata();
			meta->set_name("cluster_id");
			meta->set_value(m_infra_state->get_k8s_cluster_id());
		}
		LOG_DEBUG("job %" PRId64 ": Copied %d source labels: %d", job_id, result_ptr->source_labels().size(), prom->source_metadata().size());
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

	if (enforce_limits &&  (result_ptr->samples().size() > limit))
	{
		over_limit = result_ptr->samples().size() - limit;
	}

	for (const auto &sample : result_ptr->samples())
	{
		if(over_limit)
		{
			if(!ml_log)
			{
				break;
			}
			LOG_INFO("[promscrape] metric over limit (total, %u max): %s",
				max_limit, sample.metric_name().c_str());
			continue;
		}

		if (metric_type_is_raw(sample.legacy_metric_type()))
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
	for (auto &sample : *result_ptr->mutable_meta_samples())
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
		*filtered += result_ptr->samples().size();
	}
	if (total)
	{
		*total += job_config->last_total_samples;
	}

	// Update metric stats
	m_stats.add_stats(job_config->url, over_limit, raw_num_samples, calc_num_samples);

	return raw_num_samples + calc_num_samples;
}

std::shared_ptr<draiosproto::raw_prometheus_metrics> promscrape::create_bypass_protobuf(int64_t job_id)
{
	static uint64_t msg_idx = 1;
	std::list<int64_t> jobs;

	if (job_id >= 0)
	{
		std::lock_guard<std::mutex> lock(m_map_mutex); // scoped lock
		if (m_jobs.find(job_id) == m_jobs.end())
		{
			LOG_WARNING("Tried to create raw prometheus protobuf for non-existing job %" PRId64, job_id);
			return nullptr;
		}
		jobs.push_back(job_id);
	}
	else
	{
		std::lock_guard<std::mutex> lock(m_map_mutex); // scoped lock
		for(auto it = m_jobs.begin(); it != m_jobs.end(); it++)
		{
			if (it->second.bypass_limits)
			{
				jobs.push_back(it->first);
			}
		}
	}

	if (jobs.empty())
	{
		return nullptr;
	}

	shared_ptr<draiosproto::raw_prometheus_metrics> metrics =
		make_shared<draiosproto::raw_prometheus_metrics>();

	metrics->set_timestamp_ns(m_next_ts);
	metrics->set_index(msg_idx++);

	for (auto job_id : jobs) {
		LOG_DEBUG("Creating bypass message for job %" PRId64, job_id);

		prom_job_config job_config;

		// We're going to use the results without a lock as it shouldn't get changed anywhere and
		// handle_result() always puts incoming data into a new shared_ptr
		std::shared_ptr<agent_promscrape::ScrapeResult> result_ptr =
			get_job_result_ptr(job_id, &job_config);
		if (result_ptr == nullptr)
		{
			LOG_DEBUG("Couldn't find scrape results for job %" PRId64, job_id);
			continue;
		}
		auto prom = metrics->add_prometheus();

		unsigned int limit = 10000000;
		result_to_protobuf(job_id, result_ptr, &job_config, prom, false,
			limit, limit, nullptr, nullptr);
	}

	return metrics;
}

using namespace tabulate;

void promscrape_stats::get_target_stats(std::string &output)
{
	output.clear();
	std::lock_guard<std::mutex> lock_json(m_json_mutex);

	if (!m_local_targets.isObject() || !m_local_targets.isMember("data"))
		return;
	auto data = m_local_targets["data"];
	if (!data.isObject() || !data.isMember("activeTargets"))
		return;

	int row = 0;
	string lastpool;
	Table table;
	table.format().corner("").border("").column_separator("");
	table.add_row({"URL", "ST", "sent", "filt", "lim", "pod", "error"});
	table[0].format().font_style({FontStyle::bold});
	for (const auto& target : data["activeTargets"])
	{
		if (target.isMember("scrapePool"))
		{
			string pool = target["scrapePool"].asString();
			if (pool != lastpool)
			{
				if (row)
				{
					output.append(table.str() + "\n");
					// Didn't see an easy way to clear the table
					Table newtable;
					table = newtable;
					table.format().corner("").border("").column_separator("");
					table.add_row({"URL", "ST", "sent", "filt", "lim", "pod", "error"});
					table[0].format().font_style({FontStyle::bold});
					row = 0;
				}
				output.append("Pool: " + pool + "\n");
				lastpool = pool;
			}
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

		string url = target["scrapeUrl"].asString();
		string health = target["health"].asString();
		int sent = 0, total = 0;
		int filt = 0, lim = 0;
		string sent_str;
		string pod;
		string error;
		if (target.isMember("lastError") && (health != "up"))
		{
			error = target["lastError"].asString();
		}
		if (target.isMember("discoveredLabels") && target["discoveredLabels"].isMember("__meta_kubernetes_pod_name"))
		{
			pod = target["discoveredLabels"]["__meta_kubernetes_pod_name"].asString();
		}

		{
			// Watch out for deadlocks (m_json_mutex -> m_mutex)
			std::lock_guard<std::mutex> lock(m_mutex);
			auto stats = m_stats_map.find(url);
			if (stats != m_stats_map.end())
			{
				total = stats->second.raw_scraped + stats->second.calc_scraped;
				sent = stats->second.raw_sent + stats->second.calc_sent;
				filt = stats->second.raw_job_filter_dropped +
					stats->second.raw_global_filter_dropped +
					stats->second.calc_job_filter_dropped +
					stats->second.calc_global_filter_dropped;
				lim = total - filt - sent;
			}
		}
		sent_str = to_string(sent) + "/" + to_string(total);
		table.add_row({url, health, sent_str, to_string(filt), to_string(lim), pod, error});

		if (health == "up")
		{
			table[row+1][1].format().font_background_color(Color::green).font_color(Color::white);
		}
		else
		{
			table[row+1][1].format().font_background_color(Color::red).font_color(Color::white);
		}
		if (sent < 1)
		{
			table[row+1][2].format().font_background_color(Color::red).font_color(Color::white);
		}
		else if (sent<total)
		{
			table[row+1][2].format().font_background_color(Color::yellow).font_color(Color::grey);
		}
		row++;
	}
	if (row)
	{
		output.append(table.str() + "\n");
	}
}

void promscrape_stats::get_target_metadata(std::string &output, const std::string &url)
{
	output.clear();
	std::lock_guard<std::mutex> lock(m_mutex);

	auto dump_data = [this, &output](const string &instance)
	{
		if (m_metadata_map.find(instance) == m_metadata_map.end())
		{
			output.append("No metadata for instance " + instance + "\n");
			return;
		}
		Table table;
		table.format().corner("").border("").column_separator("");
		table.add_row({"name", "type", "#ts", "description"});
		table[0].format().font_style({FontStyle::bold});
		table.column(3).format().width(80);
		output.append("Instance: " + instance + "\n");
		std::set<std::pair<int,string>> sorted;
		for (auto metric_it = m_metadata_map[instance].begin(); metric_it != m_metadata_map[instance].end(); metric_it++)
		{
			sorted.insert(make_pair(metric_it->second.timeseries,metric_it->first));
		}
		for (auto item_it = sorted.rbegin(); item_it != sorted.rend(); item_it++)
		{
			table.add_row({item_it->second,
				m_metadata_map[instance][item_it->second].type, to_string(item_it->first),
				m_metadata_map[instance][item_it->second].help});
		}
		output.append(table.str() + "\n");
	};

	// Metadata is mapped to instance, not url
	// There's currently no way to keep metadata apart for multiple urls with
	// the same host:port
	if (!url.empty())
	{
		dump_data(url);
		return;
	}

	for (auto inst : m_metadata_map)
	{
		dump_data(inst.first);
	}
}

// Copied from log_summary()
void promscrape_stats::get_stats(std::string &output)
{
	output.clear();
	std::lock_guard<std::mutex> lock(m_mutex);
	int unsent_global = 0;
	int unsent_job = 0;
	char buffer[1024];

	snprintf(buffer, sizeof(buffer), "Prometheus timeseries statistics, %lu endpoints\n", m_stats_map.size());
	output.append(buffer);
	for (const auto &stat : m_stats_map) {
		if (stat.second.over_global_limit || stat.second.raw_over_job_limit ||
			stat.second.calc_over_job_limit)
		{
			int unsent = stat.second.raw_scraped - stat.second.raw_job_filter_dropped -
				stat.second.raw_global_filter_dropped - stat.second.raw_sent;
			unsent += stat.second.calc_scraped - stat.second.calc_job_filter_dropped -
				stat.second.calc_global_filter_dropped - stat.second.calc_sent;
			snprintf(buffer, sizeof(buffer), "%s: %d timeseries (after filter) not sent because of %s "
				"limit (%d over limit)\n", stat.first.c_str(), unsent,
				stat.second.over_global_limit ? "prometheus metric" : "job sample",
				stat.second.over_global_limit ? stat.second.over_global_limit :
				(stat.second.raw_over_job_limit + stat.second.calc_over_job_limit));
			output.append(buffer);

			if (stat.second.over_global_limit)
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
			snprintf(buffer, sizeof(buffer), "%s: %d total timeseries sent\n", stat.first.c_str(), stat.second.raw_sent + stat.second.calc_sent);
			output.append(buffer);
		}
		snprintf(buffer, sizeof(buffer), "    RAW: scraped %d, sent %d, dropped by: "
			"job filter %d, global filter %d\n",
			stat.second.raw_scraped, stat.second.raw_sent,
			stat.second.raw_job_filter_dropped, stat.second.raw_global_filter_dropped);
		output.append(buffer);
		snprintf(buffer, sizeof(buffer), "    CALCULATED: scraped %d, sent %d, dropped by: "
			"job filter %d, global filter %d\n",
			stat.second.calc_scraped, stat.second.calc_sent,
			stat.second.calc_job_filter_dropped, stat.second.calc_global_filter_dropped);
		output.append(buffer);
	}
	if (unsent_global)
	{
		snprintf(buffer, sizeof(buffer), "Prometheus metrics limit (%u) reached. %d timeseries not sent"
			" to avoid data inconsistencies\n",
			m_prom_conf.max_metrics(), unsent_global);
		output.append(buffer);
	}
	if (unsent_job)
	{
		snprintf(buffer, sizeof(buffer), "Prometheus job sample limit reached. %d timeseries not sent"
			" to avoid data inconsistencies\n",
			unsent_job);
		output.append(buffer);
	}
}

void promscrape_stats::process_metadata()
{
	// Watch out for deadlocks
	std::lock_guard<std::mutex> lock_json(m_json_mutex);
	std::lock_guard<std::mutex> lock(m_mutex);

	if (!m_local_targets_metadata.isObject() || !m_local_targets_metadata.isMember("data"))
		return;
	for (const auto& metric : m_local_targets_metadata["data"])
	{
		if (!metric.isMember("metric") || !metric["metric"].isString() ||
			metric["metric"].asString().empty())
		{
			LOG_INFO("metric metadata is missing metric name");
			continue;
		}
		string name = metric["metric"].asString();
		if (!metric.isMember("target") || !metric["target"].isMember("instance") ||
			!metric["target"]["instance"].isString() ||
			metric["target"]["instance"].asString().empty())
		{
			LOG_INFO("metric metadata is missing target or instance");
			continue;
		}
		string instance = metric["target"]["instance"].asString();

		if (metric.isMember("type") && metric["type"].isString())
		{
			m_metadata_map[instance][name].type = metric["type"].asString();
		}
		if (metric.isMember("unit") && metric["unit"].isString())
		{
			m_metadata_map[instance][name].unit = metric["unit"].asString();
		}
		if (metric.isMember("help") && metric["help"].isString())
		{
			m_metadata_map[instance][name].help = metric["help"].asString();
		}
	}
}

static bool endswith(const string &str, const string &end)
{
	if (str.length() < end.length())
		return false;

	return (!str.compare (str.length() - end.length(), end.length(), end));
}

void promscrape_stats::process_scrape(string instance, std::shared_ptr<agent_promscrape::ScrapeResult> result)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_metadata_map.find(instance) == m_metadata_map.end())
	{
		LOG_DEBUG("No metadata (yet) for instance %s", instance.c_str());
		return;
	}

	string lastname;
	int lastcount = 0;
	// Assuming samples for each metric name are contiguous
	for (const auto &sample : result->samples())
	{
		string name = sample.metric_name();

		// Take off postfixes to match metadata name
		if (endswith(name, "_sum"))
			name.resize(name.length() - 4);
		else if (endswith(name, "_count"))
			name.resize(name.length() - 6);
		else if (endswith(name, "_bucket"))
			name.resize(name.length() - 7);
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
			m_metadata_map[instance][lastname].timeseries = lastcount;
		}
		lastname = name;
		lastcount = 1;
	}
	if (!lastname.empty())
	{
		m_metadata_map[instance][lastname].timeseries = lastcount;
	}
}

void promscrape_stats::get_scrape(string &output, const std::string &arg)
{
	string url = arg;
	output.clear();
	if (url.empty())
	{
		for (const auto &job : m_promscrape->job_map())
		{
			if (job.second.last_total_samples > 0)
			{
				url = job.second.url;
				break;
			}
		}
	}

	LOG_DEBUG("Command line: Trying to scrape %s", url.c_str());

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

bool promscrape_stats::gather_stats_enabled()
{
	// Currently only supported with promscrape v2
	return m_promscrape->is_promscrape_v2() && (c_always_gather_stats.get_value() || m_gather_stats);
}

void promscrape_stats::enable_gather_stats(bool enable)
{
	m_gather_stats = enable;
	m_gather_stats_count++; // Make sure to start right away
}

void promscrape_stats::gather_target_stats()
{
	if (!gather_stats_enabled())
	{
		return;
	}
	string targets_path("/api/v1/targets");
	string targets_metadata_path("/api/v1/targets/metadata");

	try
	{
		Poco::Net::HTTPClientSession session("127.0.0.1", 9990);
		string method("GET");
		Poco::Net::HTTPRequest request(method, targets_path);
		Poco::Net::HTTPResponse response;
		session.sendRequest(request);
		std::istream &resp = session.receiveResponse(response);

		bool rc;
		{
			std::lock_guard<std::mutex> lock(m_json_mutex);
			rc = m_json_reader.parse(resp, m_local_targets);
		}
		LOG_INFO("local target data parse %s", rc ? "successful" : "failed");

		Poco::Net::HTTPRequest request2(method, targets_metadata_path);
		Poco::Net::HTTPResponse response2;

		session.sendRequest(request2);
		std::istream &resp2 = session.receiveResponse(response2);

		{
			std::lock_guard<std::mutex> lock(m_json_mutex);
			rc = m_json_reader.parse(resp2, m_local_targets_metadata);
		}
		LOG_INFO("local target metadata parse %s", rc ? "successful" : "failed");
		process_metadata();
	}
	catch (const Poco::Exception& ex)
	{
		LOG_INFO("Gather target stats exception: %s", ex.displayText().c_str());
	}
}

void promscrape_stats::periodic_gather_stats()
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
	}, sinsp_utils::get_current_time_ns() );
}

void promscrape_stats::init_command_line()
{
	command_line_manager &cli = command_line_manager::instance();

	command_line_manager::command_info cmd_tgt;
	cmd_tgt.permissions = {CLI_AGENT_INTERNAL_DIAGNOSTICS};
	cmd_tgt.short_description = "Shows Active Prometheus targets";
	cmd_tgt.type = command_line_manager::content_type::TEXT;
	cmd_tgt.handler = [this](const command_line_manager::argument_list &args) {
		string output;
		if (!m_promscrape->is_promscrape_v2())
		{
			return string("Target data is currently only supported with Prometheus service discovery enabled (Promscrape v2)\n");
		}
		if (!gather_stats_enabled())
		{
			enable_gather_stats();
			return string("Starting target data collection now. Please try again in a few seconds\n");
		}
		get_target_stats(output);
		return output;
	};
	cli.register_command("prometheus target show", cmd_tgt);

	command_line_manager::command_info cmd_meta;
	cmd_meta.permissions = {CLI_AGENT_INTERNAL_DIAGNOSTICS};
	cmd_meta.short_description = "Shows Prometheus target metadata";
	cmd_meta.type = command_line_manager::content_type::TEXT;
	cmd_meta.handler = [this](const command_line_manager::argument_list &args) {
		if (!m_promscrape->is_promscrape_v2())
		{
			return string("Target data is currently only supported with Prometheus service discovery enabled (Promscrape v2)\n");
		}
		if (!gather_stats_enabled())
		{
			enable_gather_stats();
			return string("Starting target data collection now. Please try again in a few seconds\n");
		}
		string output;
		string url;
		if (!args.empty() && (args[0].first == "url"))
		{
			url = args[0].second;
		}
		get_target_metadata(output, url);
		return output;
	};
	cli.register_command("prometheus metadata show", cmd_meta);

	command_line_manager::command_info cmd_scrape;
	cmd_scrape.permissions = {CLI_NETWORK_CALLS_TO_REMOTE_PODS};
	cmd_scrape.short_description = "Scrapes Prometheus target";
	cmd_scrape.type = command_line_manager::content_type::YAML;
	cmd_scrape.handler = [this](const command_line_manager::argument_list &args) {
		string output;
		string url;
		if (!args.empty() && (args[0].first == "url"))
		{
			url = args[0].second;
		}
		get_scrape(output, url);
		return output;
	};
	cli.register_command("prometheus target scrape", cmd_scrape);

	command_line_manager::command_info cmd_stats;
	cmd_stats.permissions = {CLI_AGENT_STATUS};
	cmd_stats.short_description = "Shows Prometheus scraping statistics";
	cmd_stats.type = command_line_manager::content_type::TEXT;
	cmd_stats.handler = [this](const command_line_manager::argument_list &args) {
		string output;
		get_stats(output);
		return output;
	};
	cli.register_command("prometheus target show-stats", cmd_stats);
}

promscrape_stats::promscrape_stats(const prometheus_conf &prom_conf, promscrape *ps) :
		m_log_interval(c_promscrape_stats_log_interval.get_value() * ONE_SECOND_IN_NS),
		m_prom_conf(prom_conf),
		m_gather_interval(10 * ONE_SECOND_IN_NS),
		m_gather_stats(false),
		m_gather_stats_count(0),
		m_promscrape(ps)
{
	init_command_line();
}

void promscrape_stats::set_stats(std::string url,
	int raw_scraped, int raw_job_filter_dropped,
	int raw_over_job_limit, int raw_global_filter_dropped,
	int calc_scraped, int calc_job_filter_dropped,
	int calc_over_job_limit, int calc_global_filter_dropped)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	if (m_stats_map.find(url) == m_stats_map.end())
	{
		metric_stats stats;
		memset(&stats, 0, sizeof(stats));
		m_stats_map[url] = std::move(stats);
	}

	m_stats_map[url].raw_scraped = raw_scraped;
	m_stats_map[url].raw_job_filter_dropped = raw_job_filter_dropped;
	m_stats_map[url].raw_over_job_limit = raw_over_job_limit;
	m_stats_map[url].raw_global_filter_dropped = raw_global_filter_dropped;
	m_stats_map[url].calc_scraped = calc_scraped;
	m_stats_map[url].calc_job_filter_dropped = calc_job_filter_dropped;
	m_stats_map[url].calc_over_job_limit = calc_over_job_limit;
	m_stats_map[url].calc_global_filter_dropped = calc_global_filter_dropped;
}

void promscrape_stats::add_stats(std::string url, int over_global_limit, int raw_sent, int calc_sent)
{
	std::lock_guard<std::mutex> lock(m_mutex);

	if (m_stats_map.find(url) == m_stats_map.end())
	{
		metric_stats stats;
		memset(&stats, 0, sizeof(stats));
		m_stats_map[url] = std::move(stats);
	}

	m_stats_map[url].over_global_limit = over_global_limit;
	m_stats_map[url].raw_sent = raw_sent;
	m_stats_map[url].calc_sent = calc_sent;
}

void promscrape_stats::log_summary()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	int unsent_global = 0;
	int unsent_job = 0;

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

			if (stat.second.over_global_limit)
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
	if (unsent_global)
	{
		LOG_WARNING("Prometheus metrics limit (%u) reached. %d timeseries not sent"
			" to avoid data inconsistencies, see preceding info logs for details",
			m_prom_conf.max_metrics(), unsent_global);
	}
	if (unsent_job)
	{
		LOG_WARNING("Prometheus job sample limit reached. %d timeseries not sent"
			" to avoid data inconsistencies, see preceding info logs for details",
			unsent_job);
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
