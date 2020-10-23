#pragma once

#include "analyzer.h"
#include "analyzer_utils.h"
#include "connectinfo.h"
#include "type_config.h"

#include <draios.pb.h>
#include <secure.pb.h>
#include <google/protobuf/util/json_util.h>
#include <sinsp.h>

#include "secure_helper.h"
#include "secure_netsec_cidr.h"
#include "secure_netsec_obj.h"
#include "secure_netsec_handler.h"
#include "secure_netsec_data_ready_handler.h"
#include "secure_netsec_internal_metrics.h"


class sinsp_analyzer;

#define NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MIN    60000000000  //  1 min
#define NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL       180000000000  //  3 min
#define NETWORK_TOPOLOGY_DEFAULT_REPORT_INTERVAL_MAX  1800000000000  // 30 min
#define NETWORK_TOPOLOGY_FREQUENCY_THRESHOLD_NS           100000000  // 100 ms


//
// This class keeps track of the kubernetes connection for network
// security.
//
class secure_netsec
{
public:
	secure_netsec(infrastructure_state* infrastructure_state);
	secure_netsec();
	~secure_netsec();

	// clearing all the state of the communications and the
	// protobuf communication summary
	void clear();

	// clearing all inactive communications and the protobuf
	// communication summary
	void clear_after_flush(uint64_t ts);

	void flush(uint64_t ts);

	void set_data_handler(secure_netsec_data_ready_handler* handler);
	void set_internal_metrics(secure_netsec_internal_metrics* internal_metrics);

	void set_cluster_id(std::string cluster_id);
	void set_cluster_name(std::string cluster_name);
	void set_command_k8s_cidr(std::string k8s_cluster_cidr, std::string k8s_service_cidr);

	static type_config<bool> c_secure_netsec_enabled;
	static type_config<uint64_t> c_secure_netsec_report_interval;
	static type_config<std::string> c_secure_netsec_cluster_cidr;
	static type_config<std::string> c_secure_netsec_service_cidr;
	static type_config<int> c_secure_netsec_connections_limit;
	static type_config<std::vector<std::string>> c_secure_netsec_filtered_process_names;

	bool is_k8s_cidr_configured() const
	{
		return m_k8s_cidrs_configured;
	}

	inline uint64_t get_secure_netsec_report_interval() const
	{
		return c_secure_netsec_report_interval.get_value();
	}

	void init(sinsp_ipv4_connection_manager* conn,
		  infrastructure_state* infrastructure_state);

	void add_connection_async(const _ipv4tuple& tuple,
				  sinsp_connection& conn,
				  sinsp_connection::state_transition transition);

	bool is_tuple_in_k8s_cidr(const ipv4tuple &tuple) const;

	void enrich_connection(k8s_communication* k8s_comm,
			       bool force_resolution);
	bool add_connection(sinsp_connection& conn, ipv4tuple tuple);

	void fetch_cgs(const std::string& kind);
	bool add_cg(std::shared_ptr<draiosproto::container_group> cg);

	bool has_data()
	{
		return m_k8s_cluster_communication.has_data();
	}

	void serialize_protobuf();

	void serialize_json(std::string *jsonString)
	{
		::google::protobuf::util::MessageToJsonString(*m_k8s_communication_summary, jsonString);
	}

	const secure::K8SCommunicationSummary* get_k8s_communication_summary()
	{
		return m_k8s_communication_summary;
	}

private:
	secure::K8SClusterCommunication* serialize_cluster_information();
	void reset_counters();

	// Connection to communication validation helpers
	bool validate_container(sinsp_connection& conn);
	bool validate_comm(sinsp_connection& conn, k8s_communication* k8s_comm);
	bool validate_pod_owner(const string &kind, string &tag);

	bool enrich_endpoint(k8s_communication* k8s_comm, k8s_pod_owner* owner, uint32_t ip);
	std::shared_ptr<draiosproto::container_group>
		resolve_ip_to_cg(const uint32_t &ip, bool *found);

	bool congroup_to_pod_owner(std::shared_ptr<draiosproto::container_group> cg,
				   const string &tag_name,
				   secure::K8SPodOwner* k8s_pod_owner);

	void congroup_to_metadata(std::shared_ptr<draiosproto::container_group> cg,
				  k8s_metadata* k8s_metadata);
	void congroup_to_endpoint(std::shared_ptr<draiosproto::container_group> cg,
				  k8s_endpoint* k8s_endpoint);

	void congroup_to_namespace(std::shared_ptr<draiosproto::container_group> cg,
				   k8s_namespace* k8s_namespace);

	void congroup_to_service(std::shared_ptr<draiosproto::container_group> cg,
				 k8s_service* k8s_service);

	bool insert_or_update_communication(ipv4tuple tuple, const k8s_communication& k8s_comm);
	bool insert_or_update_pod_owner(const k8s_pod_owner& pod_owner);

	const secure::K8SCommunicationSummary* get_netsec_summary(uint64_t timestamp);

	std::string m_cluster_id;
	std::string m_cluster_name;

	bool m_k8s_cidrs_configured;
	uint32_t m_cluster_cidr_netip;
	uint32_t m_cluster_cidr_netmask;
	uint32_t m_service_cidr_netip;
	uint32_t m_service_cidr_netmask;

	secure::K8SCommunicationSummary* m_k8s_communication_summary;
	std::unique_ptr<run_on_interval> m_get_events_interval;
	infrastructure_state* m_infrastructure_state = nullptr;
	sinsp_ipv4_connection_manager* m_connection_manager = nullptr;
	k8s_cluster_communication m_k8s_cluster_communication;

	secure_netsec_data_ready_handler* m_netsec_data_handler = nullptr;
	secure_netsec_internal_metrics* m_netsec_internal_metrics = nullptr;

	bool m_netsec_sent;
	bool m_netsec_run;

	// key metrics, and relative pseudo-formulas
	uint m_connection_count = 0;
	uint m_connection_dropped_count = 0;
	// all connections = invalid + cidr_out + cidr_in
	uint m_communication_invalid = 0;
	uint m_communication_cidr_out = 0;
	uint m_communication_cidr_in = 0;
	// all connections = ingress + egress
	uint m_communication_ingress_count = 0;
	uint m_communication_egress_count = 0;
	// unresolved connections can be determined using the following equation
	//
	//  unresolved connections =
	//        all connections - (resolved_client + resolved_server)
	uint m_resolved_client = 0;
	uint m_resolved_server = 0;
	uint m_resolved_owner = 0;
};
