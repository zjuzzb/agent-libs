/**
 * @file
 *
 * Interface to the security_config namespace.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <cstdint>
#include <string>

namespace libsanalyzer {

/**
 * Exposes APIs to read security-related configuration values.
 */
namespace security_config {

/**
 * Returns true if security is enabled, false otherwise.
 */
bool is_enabled();

/**
 * Enables or disables security based on the given parameter.
 */
void set_enabled(bool enabled);

/**
 * Returns the configured security policies filename.
 */
std::string get_policies_file();

/**
 * Updates the configured security policies filename to the given filename.
 */
void set_policies_file(const std::string& filename);

/**
 * Returns the configured security policies v2 filename.
 */
std::string get_policies_v2_file();

/**
 * Updates the configured security policies v2 filename to the given filename.
 */
void set_policies_v2_file(const std::string& filename);

/**
 * Returns the configured security baselines filename.
 */
std::string get_baselines_file();

/**
 * Updates the configured security baselines filename to the given filename.
 */
void set_baselines_file(const std::string& filename);

/**
 * Returns the configured report security interval in nanoseconds.
 */
uint64_t get_report_interval_ns();

/**
 * Updates the configured security report interval to the given interval.
 */
void set_report_interval_ns(uint64_t interval);

/**
 * Returns the configured throttled security report interval in nanoseconds.
 */
uint64_t get_throttled_report_interval_ns();

/**
 * Updates the configured throttled security report interval to the given
 * interval.
 */
void set_throttled_report_interval_ns(uint64_t interval);

/**
 * Returns the configured actions poll interval in nanoseconds.
 */
uint64_t get_actions_poll_interval_ns();

/**
 * Returns the configured policy event rate.
 */
double get_policy_events_rate();

/**
 * Returns the configured policy event max burst.
 */
uint64_t get_policy_events_max_burst();

/**
 * Returns true if we send monitor-related events, false otherwise.
 */
bool get_send_monitor_events();

/**
 * Returns the default compliance schedule.
 */
std::string get_default_compliance_schedule();

/**
 * Returns true if we should send compliance events, false otherwise.
 */
bool get_send_compliance_events();

/**
 * Returns true if we should send compliance results, false otherwise.
 */
bool get_send_compliance_results();

/**
 * Returns true if we should include descriptions in compliance results.
 */
bool get_include_desc_in_compliance_results();

/**
 * Returns the compliance refresh interval.
 */
uint64_t get_compliance_refresh_interval();

/**
 * Returns the compliance kube bench variant.
 */
std::string get_compliance_kube_bench_variant();

/**
 * Returns true if we should send failed compliance results, false otherwise.
 */
bool get_compliance_send_failed_results();

/**
 * Returns true if we should save temp compliance files, false otherwise.
 */
bool get_compliance_save_temp_files();

/**
 * Returns true if we audit the k8s server, false otherwise.
 */
bool get_k8s_audit_server_enabled();

/**
 * Returns the configured k8s audit server refresh interval.
 */
uint64_t get_k8s_audit_server_refresh_interval();

/**
 * Returns the configured k8s audit server URL.
 */
std::string get_k8s_audit_server_url();

/**
 * Returns the configured k8s audit server port.
 */
uint16_t get_k8s_audit_server_port();

/**
 * Returns true if the k8s audit server is configued with TLS enabled, false
 * otherwise.
 */
bool get_k8s_audit_server_tls_enabled();

/**
 * Returns the configured path to the k8s audit server x509 certificate file.
 */
std::string get_k8s_audit_server_x509_cert_file();

/**
 * Returns the configured path to the k8s audit server x509 key file.
 */
std::string get_k8s_audit_server_x509_key_file();

/**
 * Logs the state of the security configuration to the standard logger.
 */
void generate_status_log();

} // end security_config
} // end libsanalyzer
