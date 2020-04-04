/**
 * @file
 *
 * Implementation of the security_config namespace.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */

#include "common.pb.h"
#include "common_logger.h"
#include "configuration_manager.h"
#include "security_config.h"
#include "type_config.h"

#include <Poco/NumberFormatter.h>

#include <vector>

using Poco::NumberFormatter;

namespace
{
COMMON_LOGGER();

type_config<std::string>::mutable_ptr c_policies_file =
    type_config_builder<std::string>("", "Security policies file", "security", "policies_file")
        .hidden()
        .build_mutable();

type_config<std::string>::mutable_ptr c_policies_v2_file =
    type_config_builder<std::string>("",
                                     "Security policies v2 file",
                                     "security",
                                     "policies_v2_file")
        .hidden()
        .build_mutable();

type_config<std::string>::mutable_ptr c_baselines_file =
    type_config_builder<std::string>("", "Security policies file", "security", "baselines_file")
        .hidden()
        .build_mutable();

type_config<uint64_t>::mutable_ptr c_report_interval_ns =
    type_config_builder<uint64_t>(1000000000, /* 1s */
                                  "Security report interval in nanoseconds",
                                  "security",
                                  "report_interval")
        .hidden()
        .build_mutable();

type_config<uint64_t>::mutable_ptr c_throttled_report_interval_ns =
    type_config_builder<uint64_t>(10000000000, /* 10s */
                                  "Throttled security report interval in nanoseconds",
                                  "security",
                                  "throttled_report_interval")
        .hidden()
        .build_mutable();

type_config<uint64_t>::ptr c_actions_poll_interval_ns =
    type_config_builder<uint64_t>(100000000, /* 100 ms */
                                  "Actions poll interval in nanoseconds",
                                  "security",
                                  "actions_poll_interval_ns")
        .hidden()
        .build();

type_config<double>::ptr c_policy_events_rate =
    type_config_builder<double>(0.5, "Policy events rate", "security", "policy_events_rate")
        .hidden()
        .build();

type_config<uint64_t>::ptr c_policy_events_max_burst =
    type_config_builder<uint64_t>(50,
                                  "Policy events maximum burst",
                                  "security",
                                  "policy_events_max_burst")
        .hidden()
        .build();

type_config<bool>::ptr c_send_monitor_events =
    type_config_builder<bool>(false, "Send monitor events?", "security", "send_monitor_events")
        .hidden()
        .build();

type_config<std::string>::ptr c_default_compliance_schedule =
    type_config_builder<std::string>("08:00:00Z/P1D",  // By default runs once per day at 8am utc
                                     "Default compliance schedule",
                                     "security",
                                     "default_compliance_schedule")
        .hidden()
        .build();

type_config<bool>::ptr c_send_compliance_events =
    type_config_builder<bool>(false,
                              "Send compliance events?",
                              "security",
                              "send_compliance_events")
        .hidden()
        .build();

type_config<bool>::ptr c_send_compliance_results =
    type_config_builder<bool>(true,
                              "Send compliance results?",
                              "security",
                              "send_compliance_results")
        .hidden()
        .build();

type_config<bool>::ptr c_include_desc_in_compliance_results =
    type_config_builder<bool>(true,
                              "Send compliance results?",
                              "security",
                              "include_desc_compliance_results")
        .hidden()
        .build();

type_config<uint64_t>::ptr c_compliance_refresh_interval =
    type_config_builder<uint64_t>(120000000000,
                                  "Compliance refresh interval",
                                  "security",
                                  "compliance_refresh_interval")
        .hidden()
        .build();

type_config<std::string>::ptr c_compliance_kube_bench_variant =
    type_config_builder<std::string>("",
                                     "Kube bench variant",
                                     "security",
                                     "compliance_kube_bench_variant")
        .hidden()
        .build();

type_config<bool>::ptr c_compliance_send_failed_results =
    type_config_builder<bool>(true,
                              "Send failed compliance results?",
                              "security",
                              "compliance_send_failed_results")
        .hidden()
        .build();

type_config<bool>::ptr c_compliance_save_temp_files =
    type_config_builder<bool>(false,
                              "Save temp compliance files?",
                              "security",
                              "compliance_save_temp_files")
        .hidden()
        .build();

type_config<bool>::ptr c_k8s_audit_server_enabled =
    type_config_builder<bool>(true,
                              "Kubernetes audit server enabled?",
                              "security",
                              "k8s_audit_server_enabled")
        .hidden()
        .build();

type_config<uint64_t>::ptr c_k8s_audit_server_refresh_interval =
    type_config_builder<uint64_t>(120000000000,
                                  "Kubernetes audit server refresh interval",
                                  "security",
                                  "k8s_audit_server_refresh_interval")
        .hidden()
        .build();

type_config<std::string>::ptr c_k8s_audit_server_url =
    type_config_builder<std::string>("localhost",
                                     "Kubernetes audit server url",
                                     "security",
                                     "k8s_audit_server_url")
        .hidden()
        .build();

type_config<uint16_t>::ptr c_k8s_audit_server_port =
    type_config_builder<uint16_t>(7765,
                                  "Kubernetes audit server port",
                                  "security",
                                  "k8s_audit_server_port")
        .hidden()
        .build();

type_config<bool>::ptr c_k8s_audit_server_tls_enabled =
    type_config_builder<bool>(false,
                              "Kubernetes audit server TLS enabled?",
                              "security",
                              "k8s_audit_server_tls_enabled")
        .hidden()
        .build();

type_config<std::string>::ptr c_k8s_audit_server_x509_cert_file =
    type_config_builder<std::string>("",
                                     "Kubernetes audit server x509 certificate file",
                                     "security",
                                     "k8s_audit_server_x509_cert_file")
        .hidden()
        .build();

type_config<std::string>::ptr c_k8s_audit_server_x509_key_file =
    type_config_builder<std::string>("",
                                     "Kubernetes audit server x509 key file",
                                     "security",
                                     "k8s_audit_server_x509_key_file")
        .hidden()
        .build();

type_config<std::vector<std::string>>::ptr c_k8s_audit_server_path_uris =
    type_config_builder<std::vector<std::string>>({"/k8s_audit", "/k8s-audit"},
                                                  "Kubernetes audit server path uris",
                                                  "security",
                                                  "k8s_audit_server_path_uris")
        .hidden()
        .build();

}  // end namespace

namespace libsanalyzer
{
security_config* security_config::c_security_config = new security_config();

security_config::security_config()
    : feature_base(SECURE,
                   &draiosproto::feature_status::set_secure_enabled,
                   {COINTERFACE, DRIVER, FULL_SYSCALLS})
{
}

security_config& security_config::instance()
{
	return *c_security_config;
}

std::string security_config::get_policies_file()
{
	return c_policies_file->get_value();
}

void security_config::set_policies_file(const std::string& filename)
{
	c_policies_file->set(filename);
}

std::string security_config::get_policies_v2_file()
{
	return c_policies_v2_file->get_value();
}

void security_config::set_policies_v2_file(const std::string& filename)
{
	c_policies_v2_file->set(filename);
}

std::string security_config::get_baselines_file()
{
	return c_baselines_file->get_value();
}

void security_config::set_baselines_file(const std::string& filename)
{
	c_baselines_file->set(filename);
}

uint64_t security_config::get_report_interval_ns()
{
	return c_report_interval_ns->get_value();
}

void security_config::set_report_interval_ns(const uint64_t interval)
{
	c_report_interval_ns->set(interval);
}

uint64_t security_config::get_throttled_report_interval_ns()
{
	return c_throttled_report_interval_ns->get_value();
}

void security_config::set_throttled_report_interval_ns(const uint64_t interval)
{
	c_throttled_report_interval_ns->set(interval);
}

uint64_t security_config::get_actions_poll_interval_ns()
{
	return c_actions_poll_interval_ns->get_value();
}

double security_config::get_policy_events_rate()
{
	return c_policy_events_rate->get_value();
}

uint64_t security_config::get_policy_events_max_burst()
{
	return c_policy_events_max_burst->get_value();
}

bool security_config::get_send_monitor_events()
{
	return c_send_monitor_events->get_value();
}

std::string security_config::get_default_compliance_schedule()
{
	return c_default_compliance_schedule->get_value();
}

bool security_config::get_send_compliance_events()
{
	return c_send_compliance_events->get_value();
}

bool security_config::get_send_compliance_results()
{
	return c_send_compliance_results->get_value();
}

bool security_config::get_include_desc_in_compliance_results()
{
	return c_include_desc_in_compliance_results->get_value();
}

uint64_t security_config::get_compliance_refresh_interval()
{
	return c_compliance_refresh_interval->get_value();
}

std::string security_config::get_compliance_kube_bench_variant()
{
	return c_compliance_kube_bench_variant->get_value();
}

bool security_config::get_compliance_send_failed_results()
{
	return c_compliance_send_failed_results->get_value();
}

bool security_config::get_compliance_save_temp_files()
{
	return c_compliance_save_temp_files->get_value();
}

bool security_config::get_k8s_audit_server_enabled()
{
	return c_k8s_audit_server_enabled->get_value();
}

uint64_t security_config::get_k8s_audit_server_refresh_interval()
{
	return c_k8s_audit_server_refresh_interval->get_value();
}

std::string security_config::get_k8s_audit_server_url()
{
	return c_k8s_audit_server_url->get_value();
}

uint16_t security_config::get_k8s_audit_server_port()
{
	return c_k8s_audit_server_port->get_value();
}

bool security_config::get_k8s_audit_server_tls_enabled()
{
	return c_k8s_audit_server_tls_enabled->get_value();
}

std::string security_config::get_k8s_audit_server_x509_cert_file()
{
	return c_k8s_audit_server_x509_cert_file->get_value();
}

std::string security_config::get_k8s_audit_server_x509_key_file()
{
	return c_k8s_audit_server_x509_key_file->get_value();
}

const std::vector<std::string>& security_config::get_k8s_audit_server_path_uris()
{
	return c_k8s_audit_server_path_uris->get_value();
}

bool security_config::initialize()
{
	// Add security to tags. Should probably have some sort of tag manager, but this
	// will have to do
	std::string tags =
	    configuration_manager::instance().get_config<std::string>("tags")->get_value();
	if (tags != "")
	{
		tags += ",";
	}
	tags += "sysdig_secure.enabled:true";
	configuration_manager::instance().get_mutable_config<std::string>("tags")->set(tags);

	generate_status_log();
	return true;
}

void security_config::generate_status_log()
{
	if (c_default_compliance_schedule->get_value() != "")
	{
		LOG_INFO(
		    "When not otherwise specified, will run compliance "
		    "tasks with schedule: " +
		    c_default_compliance_schedule->get_value());
	}

	if (get_enabled())
	{
		LOG_INFO("Security Features: Enabled");

		if (c_policies_v2_file->get_value() != "")
		{
			LOG_INFO("Using security policies v2 file: " + c_policies_v2_file->get_value());
		}
		else if (c_policies_file->get_value() != "")
		{
			LOG_INFO("Using security policies file: " + c_policies_file->get_value());
		}

		if (c_baselines_file->get_value() != "")
		{
			LOG_INFO("Using security baselines file: " + c_baselines_file->get_value());
		}

		LOG_INFO("Security Report Interval (ms)" +
		         NumberFormatter::format(c_report_interval_ns->get_value() / 1000000));
		LOG_INFO("Security Throttled Report Interval (ms)" +
		         NumberFormatter::format(c_throttled_report_interval_ns->get_value() / 1000000));
		LOG_INFO("Security Actions Poll Interval (ms)" +
		         NumberFormatter::format(c_actions_poll_interval_ns->get_value() / 1000000));

		LOG_INFO("Policy events rate: " +
		         NumberFormatter::format(c_policy_events_rate->get_value()));
		LOG_INFO("Policy events max burst: " +
		         NumberFormatter::format(c_policy_events_max_burst->get_value()));
		LOG_INFO(std::string("Will ") + (c_send_monitor_events->get_value() ? "" : "not ") +
		         "send sysdig monitor events when policies trigger");

		LOG_INFO(std::string("Will ") + (c_send_compliance_events->get_value() ? "" : "not ") +
		         "send compliance events");
		LOG_INFO(std::string("Will ") + (c_send_compliance_results->get_value() ? "" : "not ") +
		         "send compliance results");
		LOG_INFO(std::string("Will check for new compliance tasks to run every ") +
		         NumberFormatter::format(c_compliance_refresh_interval->get_value() / 1000000000) +
		         " seconds");

		LOG_INFO(std::string("Increased statsd metric limit by 100 for compliance tasks"));

		if (c_compliance_kube_bench_variant->get_value() != "")
		{
			LOG_INFO(std::string("Will force kube-bench compliance check to run " +
			                     c_compliance_kube_bench_variant->get_value() + " variant"));
		}

		LOG_INFO(std::string("Will ") + (c_compliance_save_temp_files->get_value() ? "" : "not ") +
		         "keep temporary files for compliance tasks on disk");

		if (c_k8s_audit_server_enabled->get_value())
		{
			LOG_INFO(std::string("K8s Audit Server configured"));
			LOG_INFO(std::string("K8s Audit Server tls enabled:  ") +
			         std::to_string(c_k8s_audit_server_tls_enabled->get_value()));
			LOG_INFO(std::string("K8s Audit Server URL:  ") + c_k8s_audit_server_url->get_value());
			LOG_INFO(std::string("K8s Audit Server port: ") +
			         std::to_string(c_k8s_audit_server_port->get_value()));
			LOG_INFO(std::string("K8s Audit Server path uris: ") +
			         c_k8s_audit_server_path_uris->value_to_string());

			if (c_k8s_audit_server_tls_enabled->get_value())
			{
				LOG_INFO(std::string("K8s Audit Server X509 crt file: ") +
				         c_k8s_audit_server_x509_cert_file->get_value());
				LOG_INFO(std::string("K8s Audit Server X509 key file: ") +
				         c_k8s_audit_server_x509_key_file->get_value());
			}
		}
	}
}

}  // namespace libsanalyzer
