
#include "secure_netsec_v2.h"

#include "secure_netsec.h"

COMMON_LOGGER();

extern std::multimap<std::string, secure_netsec_conn*> conns_by_container_id;

secure_netsec_v2::secure_netsec_v2(sinsp_ipv4_connection_manager* conn,
                                   infrastructure_state* infrastructure_state,
                                   secure_netsec& parent)
    : m_conn_manager(conn),
      m_infra_state(infrastructure_state),
      m_parent(parent),
      m_cidr(infrastructure_state),
      m_last_flush (infra_clock::now())
{
	infrastructure_state::cg_ip_clbk_t ofunc =
	    [this](const cg_ptr_t& cg, const std::string ip, infra_time_point_t tp)
	{ on_cg_event(cg, ip, tp); };

	infrastructure_state->add_cg_ip_observer(ofunc);
}

// create or update netsec_conn
void secure_netsec_v2::on_conn_event(const sinsp_conn_message& msg)
{

	auto key = secure_netsec_util::sinsp_conn_message_key(msg);

	// create or update netsec_conn
	auto conn_id_iter = m_conns_by_id.find(key);

	if (conn_id_iter != m_conns_by_id.end())
	{
		conn_id_iter->second->accept_conn_msg(msg);
	}
	else
	{
		m_parent.m_connection_count++;
		auto on_owner = [&](const std::string& kind, const std::string& id)
		{ update_owners(kind, id); };

		auto conn =
		    secure_netsec_conn::create(msg, m_cidr, *m_infra_state, on_owner, key, m_metrics);
		if (conn == nullptr)
		{
			return;
		}

		m_conns_by_id.insert(std::make_pair(key, std::move(conn)));
		m_conns_by_time.insert({infra_clock::now(), key});
	}
}

void secure_netsec_v2::flush()
{
	m_cidr.configure(m_infra_state);

	if (infra_clock::now() - m_last_flush < std::chrono::seconds(10))
	{
		// not too often; 10 secs
		return;
	}

	for (auto time_iter = m_conns_by_time.begin(); time_iter != m_conns_by_time.end();)
	{
		if (time_iter->first > m_last_flush)
		{
			break;
		}
		auto conn_iter = m_conns_by_id.find(time_iter->second);
		if (conn_iter == m_conns_by_id.end())
		{
			LOG_ERROR("data inconsistency for conn_str_id=" + time_iter->second);
		}
		else
		{
			auto &conn = conn_iter->second;
			if (conn->age() < std::chrono::seconds(10))
			{
				++time_iter;
				continue;
			}
			const auto &key = conn->get_key();
			if (m_cropped.find(key) == m_cropped.end())
			{
				m_cropped[key] = std::move(conn);
			}
			m_conns_by_id.erase(conn_iter);
		}
		time_iter = m_conns_by_time.erase(time_iter);
	}
	m_last_flush = infra_clock::now();
}

void secure_netsec_v2::on_container(const cg_ptr_t& cg)
{
	LOG_DEBUG("on container event: ( %s ), %lu ", cg->uid().id().c_str(), conns_by_container_id.size());

	const auto& uid = cg->uid().id();
	for (auto iter = conns_by_container_id.lower_bound(uid); iter != conns_by_container_id.end(); ++iter)
	{
		if (iter->first != uid)
		{
			break;
		}
		iter->second->on_container(uid);
	}
}

void secure_netsec_v2::on_cg_event(const cg_ptr_t& cg, const string& ip, infra_time_point_t tp)
{
	return;
}

secure_netsec_v2::cronjob::cronjob(const cg_ptr_t& cjcg,
                                   const std::string& uid,
                                   const infrastructure_state& infra)
    :cjob(new k8s_cronjob())
{
	secure_netsec_cg(infra, cjcg).to_cronjob(cjob.get());
	job_uids.insert(uid);
}

void secure_netsec_v2::cronjob::add_uid(const std::string& uid)
{
	job_uids.insert(uid);
}

void secure_netsec_v2::update_owners(const std::string& kind,
                                     const std::string& uid)
{
	auto f = [&](const cg_ptr_t& cg)
	{
		// const auto& cg_wrap = secure_netsec_cg(*m_infra_state, cg);
		for (const auto& p_uid : cg->parents())
		{
			if (p_uid.kind() == "k8s_cronjob")
			{
				auto cj_iter = m_cron_jobs.find(p_uid.id());

				if (cj_iter == m_cron_jobs.end())
				{
					auto cjf = [&](const cg_ptr_t& cjcg)
					{
						m_cron_jobs.insert(
						    std::make_pair(p_uid.id(),
						                   cronjob(cjcg, cg->uid().id(), *m_infra_state)));
					};
					m_infra_state->find_clbk_cg("k8s_cronjob", p_uid.id(), cjf);
				}
				else
				{
					cj_iter->second.add_uid(cg->uid().id());
				}
			}
		}
	};

	if (kind == "k8s_job")
	{
		m_infra_state->find_clbk_cg(kind, uid, f);
	}
}

void secure_netsec_v2::serialize(secure::K8SClusterCommunication* cluster)
{

	std::unordered_map<std::string, std::unique_ptr<k8s_pod_owner>> owners;

	auto on_owner = [&owners](const k8s_pod_owner& owner)
	{
		if (!owner.has_metadata())
		{
			return;
		}
		const auto& iter = owners.find(owner.metadata().uid());
		if (iter == owners.end())
		{
			owners[owner.metadata().uid()] = make_unique<k8s_pod_owner>(owner);
		}
	};

	for (const auto& rp : m_cropped)
	{
		rp.second->serialize(cluster, m_metrics, on_owner);
	}

	m_cropped.clear();

	for (const auto& p : owners)
	{
		cluster->add_pod_owners()->CopyFrom(*p.second);
	}

	for (const auto& cjob_p : m_cron_jobs)
	{
		for (const auto& uid : cjob_p.second.job_uids )
		{
			cjob_p.second.cjob->add_job_uids(uid);
		}
		cluster->add_cronjobs()->CopyFrom(*(cjob_p.second.cjob));
	}

	m_cron_jobs.clear();

	m_parent.m_communication_ingress_count += cluster->ingresses_size();
	m_parent.m_communication_egress_count += cluster->egresses_size();
}
