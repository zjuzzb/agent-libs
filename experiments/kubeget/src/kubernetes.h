//
// kubernetes.h
//
// extracts needed data from the kubernetes REST API interface
//

#include "Poco/Net/HTTPSClientSession.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/StreamCopier.h"
#include "Poco/NullStream.h"
#include "Poco/SharedPtr.h"
#include "Poco/URI.h"
#include "Poco/Path.h"
#include "Poco/Format.h"
#include "Poco/Exception.h"
#include "json/json.h"
#include "draios.pb.h"
#include "google/protobuf/text_format.h"
#include <strstream>
#include <utility>


class kubernetes
{
public:
	kubernetes(const Poco::URI& uri = Poco::URI("http://localhost:80"),
		const std::string& api = "/api/v1/");

	kubernetes(draiosproto::metrics& metrics,
		const Poco::URI& uri,
		const std::string& api = "/api/v1/");

	~kubernetes();

	const draiosproto::k8s_state& get_proto();

private:
	enum Component
	{
		K8S_NODES,
		K8S_NAMESPACES,
		K8S_PODS,
		K8S_REPLICATIONCONTROLLERS,
		K8S_SERVICES
	};

	typedef std::map<Component, std::string> component_map;
	typedef std::pair<std::string, std::string> k8s_pair_s;

	struct k8s_component
	{
		k8s_component(const std::string& name, const std::string& uid, const std::string& ns = "") : 
			m_name(name), m_uid(uid), m_ns(ns)
		{
		}

		std::string m_name;
		std::string m_uid;
		std::string m_ns;
		std::vector<k8s_pair_s> m_labels;
		std::vector<k8s_pair_s> m_selectors;
	};

	struct k8s_ns_s : public k8s_component
	{
		k8s_ns_s(const std::string& name, const std::string& uid, const std::string& ns = "") :
			k8s_component(name, uid, ns)
		{
		}
	};

	struct k8s_node_s : public k8s_component
	{
		k8s_node_s(const std::string& name, const std::string& uid, const std::string& ns = "") :
			k8s_component(name, uid, ns)
		{
		}
		std::vector<std::string> host_ips;
	};

	struct k8s_pod_s : public k8s_component
	{
		k8s_pod_s(const std::string& name, const std::string& uid, const std::string& ns = "") :
			k8s_component(name, uid, ns)
		{
		}
		std::vector<std::string> container_ids;
		std::string node_name;
		std::string host_ip;
		std::string internal_ip;
	};

	struct k8s_rc_s : public k8s_component
	{
		k8s_rc_s(const std::string& name, const std::string& uid, const std::string& ns = "") : 
			k8s_component(name, uid, ns)
		{
		}
	};

	struct k8s_service_s : public k8s_component
	{
		k8s_service_s(const std::string& name, const std::string& uid, const std::string& ns = "") : 
			k8s_component(name, uid, ns)
		{
		}
	};

	struct k8s_state_s
	{
		std::vector<k8s_ns_s> nss;
		std::vector<k8s_node_s> nodes;
		std::vector<k8s_pod_s> pods;
		std::vector<k8s_rc_s> rcs;
		std::vector<k8s_service_s> services;
	};

	void get_session();

	void init();

	bool send_request(Poco::Net::HTTPClientSession& session,
		Poco::Net::HTTPRequest& request,
		Poco::Net::HTTPResponse& response,
		const component_map::value_type& component);

	void add_object_entry(Component component, const std::string& name, k8s_pair_s&& p);

	// extracts labels or selectors
	void extract_object(Component component, const Json::Value& object, const std::string& name);

	void extract_nodes_addresses(const Json::Value& status);

	void extract_pods_data(const Json::Value& item);

	void extract_pod_containers(const Json::Value& item);

	void add_common_single_value(Component component, const std::string& name, const std::string& uid, const std::string& ns = "");

	void extract_data(const Json::Value& items, Component component);

	template <typename V, typename C>
	void populate_component(V& component, C* k8s_component, Component type)
	{
		draiosproto::k8s_common* common = k8s_component->mutable_common();
		common->set_name(component.m_name);
		common->set_uid(component.m_uid);
		const std::string ns = component.m_ns;
		if (!ns.empty())
		{
			common->set_namespace_(ns);
		}

		for (auto label : component.m_labels)
		{
			draiosproto::k8s_pair* lbl = common->add_labels();
			lbl->set_key(label.first);
			lbl->set_value(label.second);
		}

		for (auto selector : component.m_selectors)
		{
			draiosproto::k8s_pair* sel = common->add_selectors();
			sel->set_key(selector.first);
			sel->set_value(selector.second);
		}
	}

	void make_protobuf();

	void parse_json(const std::string& json, const component_map::value_type& component);

	Poco::URI                     m_uri;
	Poco::Net::HTTPCredentials*   m_credentials;
	Poco::Net::HTTPClientSession* m_session;
	draiosproto::k8s_state&       m_k8s_state;
	bool                          m_own_state;
	k8s_state_s                   m_state;
	static const component_map    m_components;
};

