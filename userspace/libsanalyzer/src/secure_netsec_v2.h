#pragma once

#include "connectinfo.h"
#include "infrastructure_state.h"
#include "secure_netsec_cidr.h"
#include "secure_netsec_conn.h"
#include "secure_netsec_util.h"

#include <ostream>
#include <secure.pb.h>
#include <sinsp.h>

class secure_netsec_conn;

class secure_netsec_v2
{
public:
	secure_netsec_v2(sinsp_ipv4_connection_manager *conn,
	                 infrastructure_state *infrastructure_state,
	                 secure_netsec &parent);

	void
	on_conn_event(const sinsp_conn_message &msg);

	void
	on_cg_event(const cg_ptr_t &cg, const std::string &ip, infra_time_point_t tp);

	void
	serialize(secure::K8SClusterCommunication *cluster);

	void
	on_container(const cg_ptr_t &cg);

	void
	flush();

private:
	using netsec_conn_ptr_t = std::unique_ptr<secure_netsec_conn>;

	typedef log_guard_sp<secure_netsec_v2> log_guard_;
	friend class log_guard_sp<secure_netsec_v2>;

	struct cronjob
	{
		cronjob(const cg_ptr_t &cjcg, const std::string &uid, const infrastructure_state &);
		void add_uid(const std::string &uid);
		std::unique_ptr<k8s_cronjob> cjob;
		std::unordered_set<std::string> job_uids;
	};

	void
	update_owners(const std::string &kind, const std::string &uid);

	const sinsp_ipv4_connection_manager *m_conn_manager;
	const infrastructure_state *m_infra_state;
	secure_netsec &m_parent;
	secure_netsec_cidr m_cidr;
	infra_time_point_t m_last_flush;
	secure_netsec_metric_stats m_metrics{};

	using conn_id_map_t = std::unordered_map<std::string, netsec_conn_ptr_t>;
	using conn_time_map_t = std::set<std::pair<infra_time_point_t, std::string>>;
	using cron_jobs_map_t = std::unordered_map<std::string, cronjob>;

	conn_id_map_t m_conns_by_id;
	conn_time_map_t m_conns_by_time;
	conn_id_map_t m_cropped;
	cron_jobs_map_t m_cron_jobs;

};
