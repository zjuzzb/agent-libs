//
// k8s.h
//
// extracts needed data from the k8s REST API interface
//

#pragma once

#include "json/json.h"
#include "k8s_component.h"
#include "k8s_net.h"
#include "draios.pb.h"
#include "google/protobuf/text_format.h"
#include <sstream>
#include <utility>
#include <mutex>

class k8s_dispatcher;

class k8s
{
public:
	k8s(const std::string& uri = "http://localhost:80",
		const std::string& api = "/api/v1/");

	k8s(draiosproto::metrics& metrics,
		const std::string& uri,
		const std::string& api = "/api/v1/");

	~k8s();

	const draiosproto::k8s_state& get_proto(bool watch = true);

	std::size_t count(k8s_component::type component) const;

	void on_watch_data(const k8s_net::event_args& msg);

private:
	void init();

	bool send_request(Poco::Net::HTTPClientSession& session,
		Poco::Net::HTTPRequest& request,
		Poco::Net::HTTPResponse& response,
		const k8s_component::component_map::value_type& component);

	// extracts labels or selectors
	void extract_object(k8s_component::type component, const Json::Value& object, const std::string& name);

	void extract_nodes_addresses(const Json::Value& status);

	void extract_pods_data(const Json::Value& item);

	void extract_pod_containers(const Json::Value& item);

	void extract_data(const Json::Value& items, k8s_component::type component);

	template <typename V, typename C>
	void populate_component(V& component, C* k8s_component, k8s_component::type type)
	{
		draiosproto::k8s_common* common = k8s_component->mutable_common();
		common->set_name(component.get_name());
		common->set_uid(component.get_uid());
		const std::string ns = component.get_namespace();
		if (!ns.empty())
		{
			common->set_namespace_(ns);
		}

		for (auto label : component.get_labels())
		{
			draiosproto::k8s_pair* lbl = common->add_labels();
			lbl->set_key(label.first);
			lbl->set_value(label.second);
		}

		for (auto selector : component.get_selectors())
		{
			draiosproto::k8s_pair* sel = common->add_selectors();
			sel->set_key(selector.first);
			sel->set_value(selector.second);
		}
	}

	void make_protobuf();

	void parse_json(const std::string& json, const k8s_component::component_map::value_type& component);

	// due to deleted default dispatcher constructor, g++ has trouble instantiating map with values,
	// so we have to go with the forward declaration above and pointers here ...
	typedef std::map<k8s_component::type, k8s_dispatcher*> dispatch_map;

	static dispatch_map make_dispatch_map(k8s_state_s& state);

	k8s_net                 m_net;
	draiosproto::k8s_state& m_proto;
	bool                    m_own_proto;
	k8s_state_s             m_state;
	dispatch_map            m_dispatch;
	std::mutex              m_mutex;

	static const k8s_component::component_map m_components;
};
