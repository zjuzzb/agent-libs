
#include "secure_netsec_cg.h"

COMMON_LOGGER();

void secure_netsec_cg::to_metadata(k8s_metadata* meta) const
{
	meta->set_uid(m_cg->uid().id());

	// Namespace: we may have congroups with empty namespace. This
	// is may be due to purging done during
	// `infrastructure_state::connect_to_namespace'.
	if (m_cg->namespace_().empty())
	{
		string namespace_;
		m_infra_state.find_tag(make_pair(m_cg->uid().kind(), m_cg->uid().id()),
		                       "kubernetes.namespace.name",
		                       namespace_);
		meta->set_namespace_(namespace_);
	}
	else
	{
		meta->set_namespace_(m_cg->namespace_().c_str());
	}
}

void secure_netsec_cg::to_endpoint(k8s_endpoint* k8s_endpoint) const
{
	auto tag = m_cg->tags().find("kubernetes.endpoints.name");

	if (tag != m_cg->tags().end())
	{
		auto meta = k8s_endpoint->mutable_metadata();
		to_metadata(meta);
		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_endpoints");

		auto subset = k8s_endpoint->add_subsets();

		for (const auto& cg_ip_address : m_cg->ip_addresses())
		{
			struct sockaddr_in sa
			{
			};
			inet_pton(AF_INET, cg_ip_address.c_str(), &(sa.sin_addr));
			subset->add_addresses(ntohl(sa.sin_addr.s_addr));
		}
		for (const auto& cg_port : m_cg->ports())
		{
			subset->add_ports(cg_port.port());
		}
	}
}

void secure_netsec_cg::to_namespace(k8s_namespace* k8s_namespace) const
{
	auto tag = m_cg->tags().find("kubernetes.namespace.name");

	if (tag != m_cg->tags().end())
	{
		auto meta = k8s_namespace->mutable_metadata();
		to_metadata(meta);

		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_namespace");

		std::string k8s_namespace_tag = "kubernetes.namespace.label";

		for (const auto& t : m_cg->tags())
		{
			if (t.first.compare(0, k8s_namespace_tag.size(), k8s_namespace_tag) == 0)
			{
				auto& match_labels =
				    *(k8s_namespace->mutable_label_selector()->mutable_match_labels());

				// kubecollect provides label
				// infromation in the follwing form
				// kubernetes.namespace.label.<KEY> : <VALUE>'
				//
				// We need to trim away the prefix and
				// leave just the <KEY>.
				match_labels[t.first.substr(k8s_namespace_tag.size() + 1)] = t.second;
			}
		}
	}
}

void secure_netsec_cg::to_service(k8s_service* k8s_service) const
{
	auto tag = m_cg->tags().find("kubernetes.service.name");
	auto service_type = m_cg->internal_tags().find("kubernetes.service.type");

	if (tag != m_cg->tags().end())
	{
		auto meta = k8s_service->mutable_metadata();
		to_metadata(meta);
		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_service");

		for (const auto& cg_ip_address : m_cg->ip_addresses())
		{
			struct sockaddr_in sa
			{
			};
			inet_pton(AF_INET, cg_ip_address.c_str(), &(sa.sin_addr));
			k8s_service->mutable_cluster_ip_details()->set_cluster_ip(ntohl(sa.sin_addr.s_addr));
			// only should be only one virtual service IP
			break;
		}

		for (const auto& cg_ports : m_cg->ports())
		{
			auto port = k8s_service->add_ports();
			port->set_port(cg_ports.port());
			port->set_protocol(cg_ports.protocol());
			if (cg_ports.target_port())
			{
				port->set_target_port(cg_ports.target_port());
			}
		}

		if (service_type != m_cg->internal_tags().end())
		{
			k8s_service->set_type(service_type->second.c_str());
		}
	}
}

void secure_netsec_cg::to_cronjob(k8s_cronjob* k8s_cronjob) const
{
	auto tag = m_cg->tags().find("kubernetes.cronJob.name");

	if (tag != m_cg->tags().end())
	{
		auto meta = k8s_cronjob->mutable_metadata();
		to_metadata(meta);
		meta->set_name(tag->second.c_str());
		meta->set_kind("k8s_cronjob");

		for (const auto& it : m_cg->pod_template_labels())
		{
			(*k8s_cronjob->mutable_template_labels())[it.first] = it.second;
		}
	}
}

infra_time_point_t secure_netsec_cg::tag_ts(const string& tag_name) const
{
	try
	{
		uint64_t ts = 0;

		const auto& inttag_it = m_cg->internal_tags().find(tag_name);
		if (inttag_it != m_cg->internal_tags().end())
		{
			ts = std::stoull(inttag_it->second);
		}

		const auto& tag_it = m_cg->tags().find(tag_name);
		if (tag_it != m_cg->tags().end())
		{
			ts = std::stoull(tag_it->second);
		}

		return infra_time_point_t(std::chrono::milliseconds(ts));
	}
	catch (const std::exception& e)
	{
		LOG_WARNING("unable to parse ts for %s, error: %s", tag_name.c_str(), e.what());
		// ignore;
	}
	return infra_time_point_t();
}

std::unique_ptr<secure::K8SPodOwner> secure_netsec_cg::get_k8s_owner() const
{
	// List of valid pod owners
	static const std::unordered_map<std::string, std::string> m_k8s_name_to_label_tag{
	    {"k8s_deployment", "kubernetes.deployment.name"},
	    {"k8s_daemonset", "kubernetes.daemonSet.name"},
	    {"k8s_statefulset", "kubernetes.statefulset.name"},
	    {"k8s_job", "kubernetes.job.name"}};

	auto owner = m_infra_state.get_pod_owner(m_cg);

	if (owner == nullptr)
	{
		LOG_DEBUG("no owner found for pod: %s", m_cg->uid().id().c_str());
		return nullptr;
	}

	// check cg_owner labels
	auto lbl_iter = m_k8s_name_to_label_tag.find(owner->uid().kind());
	if (lbl_iter == m_k8s_name_to_label_tag.end())
	{
		return nullptr;
	}

	auto tag_iter = owner->tags().find(lbl_iter->second);
	if (tag_iter == owner->tags().end())
	{
		return nullptr;
	}

	auto k8s_pod_owner = make_unique<secure::K8SPodOwner>();
	auto meta = k8s_pod_owner->mutable_metadata();

	secure_netsec_cg(m_infra_state, owner).to_metadata(meta);

	meta->set_name(tag_iter->second);
	meta->set_kind(owner->uid().kind());

	auto secure_label_selector = k8s_pod_owner->mutable_label_selector();
	auto label_selector = owner->label_selector();

	auto& match_labels = *secure_label_selector->mutable_match_labels();
	for (const auto& ml : label_selector.match_labels())
	{
		match_labels[ml.first] = ml.second;
	}

	auto match_expressions = secure_label_selector->mutable_match_expressions();
	for (const auto& me : label_selector.match_expressions())
	{
		auto p = match_expressions->Add();
		p->set_key(me.key());
		p->set_match_operator(me.match_operator());
		p->mutable_values()->CopyFrom(me.values());
	}

	for (const auto &it : owner->pod_template_labels())
	{
		(*k8s_pod_owner->mutable_template_labels())[it.first] = it.second;
	}


	return k8s_pod_owner;
}

bool secure_netsec_cg::is_node(const std::string& ip) const
{
	if (is_node())
	{
		return true;
	}

	bool found = false;
	auto f_cg = [&found](const cg_ptr_t& cg, const std::string& ip, infra_time_point_t tp)
	{
		const auto& kind = cg->uid().kind();
		found |= (kind == k8s_kind_node || kind == kind_node);
	};
	m_infra_state.find_clbk_cgs_by_ip(ip, f_cg);

	return found;
}

bool secure_netsec_cg::has_container(const string& id) const
{
	for (const auto& pkey : m_cg->children())
	{
		if (pkey.kind() == kind_container && pkey.id() == id)
		{
			return true;
		}
	}
	return false;
}

void secure_netsec_cg::container_to_pods(std::function<void(const cg_ptr_t&)> clbk) const
{
	if (!is_container())
	{
		return;
	}
	m_infra_state.find_clbk_container_pod(m_cg, clbk);
}

bool secure_netsec_cg::is_terminating() const
{
	const auto& inttag_it =
	    m_cg->internal_tags().find(infrastructure_state::POD_META_DELETION_TS_TAG);

	if (inttag_it != m_cg->internal_tags().end())
	{
		return true;
	}

	const auto& tag_it = m_cg->tags().find(infrastructure_state::POD_META_DELETION_TS_TAG);
	if (tag_it != m_cg->tags().end())
	{
		return true;
	}

	return false;
}

infra_time_point_t secure_netsec_cg::pod_creation_tp() const
{
	return tag_ts(infrastructure_state::POD_META_CREATION_TS_TAG);
}

std::string secure_netsec_cg::name() const
{
	for (const auto& l : m_cg->tags())
	{
		if (sinsp_utils::endswith(l.first, ".name") && l.first.find("kubernetes.") == 0 )
		{
			return l.second;
		}
	}

	return {};
}
