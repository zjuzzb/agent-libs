//
// k8s_delegator.cpp
//

#include "k8s_delegator.h"
#include "sinsp.h"
#include "sinsp_int.h"

// filters normalize state and event JSONs, so they can be processed generically:
// event is turned into a single-node array, state is turned into ADDED event

std::string k8s_delegator::EVENT_FILTER = "{"
	"  type: .type,"
	"  nodes:"
	"  ["
	"   .object | "
	"   {"
	"    name: .metadata.name,"
	"    timestamp: .metadata.creationTimestamp,"
	"    taints: [.spec.taints[]?.effect] | unique,"
	"    addresses: [.status.addresses[].address] | unique"
	"   }"
	"  ]"
	"}";

std::string k8s_delegator::STATE_FILTER = "{"
	" type: \"ADDED\","
	" nodes:"
	" ["
	"  .items[] | "
	"  {"
	"   name: .metadata.name,"
	"   timestamp: .metadata.creationTimestamp,"
	"   taints: [.spec.taints[]?.effect] | unique,"
	"   addresses: [.status.addresses[].address] | unique"
	"  }"
	" ]"
	"}";

k8s_delegator::k8s_delegator(sinsp* inspector,
	std::string url,
	int delegate_count,
	const std::string& http_version,
	ssl_ptr_t ssl,
	bt_ptr_t bt):
		k8s_handler("k8s_delegator", false, url, "/api/v1/nodes",
					STATE_FILTER, EVENT_FILTER, "",
					std::make_shared<k8s_handler::collector_t>(),
					http_version, 1000L, ssl, bt, true, true,
					std::make_shared<k8s_dummy_handler>(), false, ~0, nullptr),
		m_inspector(inspector),
		m_delegate_count(delegate_count)
{
}

k8s_delegator::~k8s_delegator()
{
}

void k8s_delegator::refresh_ipv4_list()
{
	m_local_ip_addrs.clear();
	if(m_inspector && m_inspector->m_network_interfaces)
	{
		for (const auto& iface : *m_inspector->m_network_interfaces->get_ipv4_list())
		{
			m_local_ip_addrs.emplace(iface.address());
		}
	}
}

k8s_delegator::node_ip_addr_list_t k8s_delegator::get_node_addresses(const Json::Value& addrs)
{
	node_ip_addr_list_t node_addrs;
	bool has_valid_ip = false;

	if(!addrs.isNull() && addrs.isArray())
	{
		for(const auto& addr : addrs)
		{
			if(addr.isConvertibleTo(Json::stringValue))
			{
				std::string address = addr.asString();
				if(is_ip_address(address) && (address != "127.0.0.1"))
				{
					node_addrs.insert(address);
					has_valid_ip = true;
				}
				else // likely not possible, but just in case ...
				{
					if(address != "127.0.0.1")
					{
						g_logger.log("K8s delegator: node address [" + address + "] "
									 "is not an IP address, ignoring.",
									 sinsp_logger::SEV_DEBUG);
					}
					else
					{
						g_logger.log("K8s delegator: ignored local node address [" + address + "] ",
									 sinsp_logger::SEV_INFO);
					}
				}
			}
			else
			{
				g_logger.log("K8s delegator: address not convertible to string.",
							 sinsp_logger::SEV_ERROR);
			}
		}
	}

	if (!has_valid_ip)
	{
		g_logger.log("K8s delegator: no valid node IP addresses found",
			     sinsp_logger::SEV_WARNING);
	}

	return node_addrs;
}

k8s_delegator::k8s_taint k8s_delegator::get_max_taint(const Json::Value& taints)
{
	k8s_taint max_taint = NO_TAINT;

	// Older k8s versions won't return
	if(taints.isNull() && !taints.isArray())
	{
		g_logger.log("K8s delegator: empty or invalid taint format",
			     sinsp_logger::SEV_DEBUG);
		return max_taint;
	}

	for(const auto& taint : taints)
	{
		if(taint.isConvertibleTo(Json::stringValue))
		{
			std::string taint_str = taint.asString();
			k8s_taint curr_taint = NO_TAINT;

			if (taint_str == "PreferNoSchedule")
			{
				curr_taint = PREFER_NOSCHEDULE;
			}
			else if (taint_str == "NoSchedule")
			{
				curr_taint = NOSCHEDULE;
			}
			else if (taint_str == "NoExecute")
			{
				curr_taint = NOEXECUTE;
			}

			if (curr_taint > max_taint)
			{
				max_taint = curr_taint;
			}
		}
		else
		{
			g_logger.log("K8s delegator: taint not convertible to string.",
				     sinsp_logger::SEV_ERROR);
		}
	}
	return max_taint;
}

bool k8s_delegator::add_node(time_t timestamp, const Json::Value& addrs,
			     const Json::Value& taints)
{
	node_ip_addr_list_t node_addrs = get_node_addresses(addrs);
	if(node_addrs.size() > 0)
	{
		k8s_taint max_taint = get_max_taint(taints);
		k8s_node_key node_key(timestamp, max_taint);
		for(auto it= m_nodes.begin(), end = m_nodes.end(); it != end; ++it)
		{
			if(it->second == node_addrs)
			{
				if (node_key == it->first)
				{
					return false;
				}
				else
				{
					m_nodes.erase(it);
				}
			}
		}

		m_nodes.insert({{timestamp, max_taint}, node_addrs});
		return true;
	}
	return false;
}

bool k8s_delegator::maybe_modify_node(time_t timestamp, const Json::Value& addrs,
				      const Json::Value& taints)
{
	node_ip_addr_list_t node_addrs = get_node_addresses(addrs);
	if (node_addrs.size() > 0)
	{
		k8s_taint max_taint = get_max_taint(taints);
		for(auto it= m_nodes.begin(), end = m_nodes.end(); it != end; ++it)
		{
			if(it->second == node_addrs
			   && it->first.get_ts() == timestamp
			   && it->first.get_max_taint() != max_taint)
			{
				m_nodes.erase(it);
				m_nodes.insert({{timestamp, max_taint}, node_addrs});
				return true;
			}
		}
	}
	return false;
}

bool k8s_delegator::remove_node(time_t timestamp, const Json::Value& addrs)
{
	node_ip_addr_list_t node_addrs = get_node_addresses(addrs);

	for(auto it= m_nodes.begin(), end = m_nodes.end(); it != end; ++it)
	{
		if(it->second == node_addrs)
		{
			// The taints may have changed but we ignore
			// them and delete from ts+addrs
			if(timestamp == it->first.get_ts())
			{
				m_nodes.erase(it);
				return true;
			}
		}
	}
	return false;
}

bool k8s_delegator::is_delegated(bool trace, bool log_delegated)
{
	refresh_ipv4_list(); // get current list of local IP addresses

	if(trace && g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log("This node has " + std::to_string(m_local_ip_addrs.size()) + " IP addresses", sinsp_logger::SEV_TRACE);
		std::ostringstream os;
		for(const auto& addr : m_local_ip_addrs)
		{
			os << addr << ", ";
		}
		g_logger.log(os.str(), sinsp_logger::SEV_TRACE);
	}

	auto it = m_nodes.cbegin();
	bool delegated = false;
	for (int ii = 1; ii <= m_delegate_count; ++ii)
	{
		if (it == m_nodes.end())
		{
			break;
		}

		std::ostringstream os;
		os << "Delegated node (" << ii << " of "
		   << m_delegate_count << "):";
		for(const auto& addr : it->second)
		{
			os << " " << addr;
			if(m_local_ip_addrs.find(addr) != m_local_ip_addrs.end())
			{
				g_logger.log("This node (" + std::to_string(ii) +
					     ") is delegated", sinsp_logger::SEV_DEBUG);
				delegated = true;
			}
		}
		g_logger.log(os.str(), log_delegated ? sinsp_logger::SEV_INFO : sinsp_logger::SEV_DEBUG);

		++it;
	}

	if (!delegated) {
		g_logger.log("This node is NOT delegated",
			     sinsp_logger::SEV_DEBUG);
	}
	return delegated;
}

bool k8s_delegator::handle_component(const Json::Value& json, const msg_data*)
{
	bool added = false;
	bool deleted = false;
	bool taint_modified = false;
	bool ret = true;

	const Json::Value& nodes = json["nodes"];
	if(!nodes.isNull() && nodes.isArray())
	{
		for(const auto& node : nodes)
		{
			const Json::Value& ts = node["timestamp"];
			if(!ts.isNull() && ts.isConvertibleTo(Json::stringValue))
			{
				std::string timestamp = ts.asString();
				time_t tm = get_epoch_utc_seconds(timestamp);
				const Json::Value& node_name = node["name"];
				std::string nname;
				if(!node_name.isNull() && node_name.isConvertibleTo(Json::stringValue))
				{
					nname = node_name.asString();
				}
				else
				{
					g_logger.log("K8s delegator: Couldn't determine node name (null or not a string).", sinsp_logger::SEV_WARNING);
				}
				std::string type = get_json_string(json, "type");
				added = (type == "ADDED");
				deleted = (type == "DELETED");
				if(added)
				{
					if(add_node(tm, node["addresses"], node["taints"]))
					{
						g_logger.log("K8s delegator: Added node to list: " + nname, sinsp_logger::SEV_DEBUG);
					}
					else
					{
						g_logger.log("K8s delegator: Node not added to list: " + nname, sinsp_logger::SEV_TRACE);
						ret = false;
					}
				}
				else if(deleted)
				{
					if(remove_node(tm, node["addresses"]))
					{
						g_logger.log("K8s delegator: Removed node from the list: " + nname, sinsp_logger::SEV_DEBUG);
					}
					else
					{
						g_logger.log("K8s delegator: Removed node event for non-existent node: " + nname, sinsp_logger::SEV_WARNING);
						ret = false;
					}
				}
				else if (type == "MODIFIED")
				{
					if (maybe_modify_node(tm, node["addresses"], node["taints"]))
					{
						taint_modified = true;
						g_logger.log("K8s delegator: Modified taint value for node: " + nname,
							     sinsp_logger::SEV_DEBUG);
					}
				}
			}
			else
			{
				g_logger.log("K8s delegator: timestamp is null or not string.", sinsp_logger::SEV_WARNING);
				ret = false;
			}
		} // end for nodes
	}
	else
	{
		g_logger.log("K8s delegator: nodes are empty or not an array.", sinsp_logger::SEV_WARNING);
		ret = false;
	}

	if(added || deleted || taint_modified)
	{
		std::string d;
		if(!is_delegated(true, true)) { d = "NOT "; }
		g_logger.log("This node is " + d + "delegated", sinsp_logger::SEV_INFO);
	}

	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log("NODES=" + std::to_string(m_nodes.size()), sinsp_logger::SEV_TRACE);
		for(const auto& node : m_nodes)
		{
			std::ostringstream os;
			for(const auto& n : node.second) { os << n << ", "; }
			g_logger.log(std::to_string(node.first.get_ts()) + ':' + os.str(), sinsp_logger::SEV_TRACE);
		}
	}
	return ret;
}

void k8s_delegator::handle_json(Json::Value&& root)
{
	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log(json_as_string(root), sinsp_logger::SEV_TRACE);
	}

	handle_component(root);
}
