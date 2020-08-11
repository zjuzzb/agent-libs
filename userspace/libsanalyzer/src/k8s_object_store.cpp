#include "k8s_object_store.h"
#include "common_logger.h"

COMMON_LOGGER();

std::pair<bool, k8s_object_store::state_t::iterator> k8s_object_store::has_key(const k8s_object_store::state_key_t& key, k8s_object_store::state_t& state)
{
	bool ret = true;
	auto it = state.find(key);
	if(it == state.end())
	{
		LOG_DEBUG("key <%s,%s> not present in infrastructure state", key.first.c_str(), key.second.c_str());
		ret = false;
	}

	return std::make_pair(ret, it);
}

k8s_object_store::kind_and_name_t k8s_object_store::get_cg_kind_and_name(const draiosproto::container_group& cg)
{
	std::pair<std::string, std::string> ret;
	std::string kind = cg.uid().kind();

	ret.first = kind;

	std::string target;

	if(kind == k8s_object_store::DEPLOYMENT_KIND)
	{
		target = k8s_object_store::DEPLOYMENT_NAME_TAG;
	}
	else if(kind == k8s_object_store::REPLICASET_KIND)
	{
		target = k8s_object_store::REPLICASET_NAME_TAG;
	}
	else if(kind == k8s_object_store::REPLICATION_CONTROLLER_KIND)
	{
		target = k8s_object_store::REPLICATION_CONTROLLER_NAME_TAG;
	}

	if(!target.empty())
	{
		for(auto& tag : cg.tags())
		{
			if(tag.first == target)
			{
				ret.second = tag.second;
				break;
			}
		}
	}
	return ret;
}

bool k8s_object_store::repeated_field_has_link(const google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& rf, const state_key_t& new_link) const
{
	for(const auto& el : rf)
	{
		if(std::make_pair(el.kind(), el.id()) == new_link)
		{
			return true;
		}
	}
	return false;
}

void k8s_object_store::set_link_or_warn(
	google::protobuf::RepeatedPtrField<draiosproto::congroup_uid>& rf
	, const k8s_object_store::state_key_t& new_link) const
{
	bool already_set = repeated_field_has_link(rf, new_link);
	ASSERT(!already_set);

	if(!already_set)
	{
		auto* nl = rf.Add();
		nl->set_kind(new_link.first);
		nl->set_id(new_link.second);
	}
	else
	{
		LOG_WARNING("link to <%s,%s> already set",
			    new_link.first.c_str(),
			    new_link.second.c_str());
	}
}

const std::string k8s_object_store::DEPLOYMENT_NAME_TAG = "kubernetes.deployment.name";
const std::string k8s_object_store::REPLICASET_NAME_TAG = "kubernetes.replicaSet.name";
const std::string k8s_object_store::REPLICATION_CONTROLLER_NAME_TAG = "kubernetes.replicationController.name";
const std::string k8s_object_store::DEPLOYMENT_KIND = "k8s_deployment";
const std::string k8s_object_store::REPLICASET_KIND = "k8s_replicaset";
const std::string k8s_object_store::REPLICATION_CONTROLLER_KIND = "k8s_replicationcontroller";
const std::string k8s_object_store::HPA_KIND = "k8s_hpa";
const std::string k8s_object_store::TARGET_KIND_TAG = "hpa.scale.target.ref.kind";
const std::string k8s_object_store::TARGET_NAME_TAG = "hpa.scale.target.ref.name";
const std::string k8s_object_store::SERVICE_KIND = "k8s_service";
const std::string k8s_object_store::POD_KIND = "k8s_pod";
const std::string k8s_object_store::NODE_KIND = "k8s_node";
const std::string k8s_object_store::STATEFULSET_KIND = "k8s_statefulset";
const std::string k8s_object_store::STATEFULSET_SERVICE_TAG = "kubernetes.statefulset.service.name";
const std::string k8s_object_store::SERVICE_NAME_LABEL = "kubernetes.service.name";
const std::map<std::string, std::string> k8s_object_store::M_K8S_TO_SYSDIG_KIND(
	{{"Deployment", k8s_object_store::DEPLOYMENT_KIND}
	 , {"ReplicaSet", k8s_object_store::REPLICASET_KIND}
	 , {"ReplicationController", k8s_object_store::REPLICATION_CONTROLLER_KIND}});

