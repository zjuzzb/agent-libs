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
					STATE_FILTER, EVENT_FILTER, std::make_shared<k8s_handler::collector_t>(),
					http_version, 1000L, ssl, bt),
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
				}
				else // likely not possible, but just in case ...
				{
					if(address != "127.0.0.1")
					{
						g_logger.log("K8s delegator: node address [" + address + "] "
									 "is not an IP address, ignoring.",
									 sinsp_logger::SEV_ERROR);
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
	return node_addrs;
}

bool k8s_delegator::add_node(time_t timestamp, const Json::Value& addrs)
{
	node_ip_addr_list_t node_addrs = get_node_addresses(addrs);
	if(node_addrs.size() > 0)
	{
		for(auto it= m_nodes.begin(), end = m_nodes.end(); it != end; ++it)
		{
			if(it->second == node_addrs)
			{
				if(timestamp == it->first) { return false; }
				else { m_nodes.erase(it); }
			}
		}

		m_nodes.insert({timestamp, node_addrs});
		return true;
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
			if(timestamp == it->first)
			{
				m_nodes.erase(it);
				return true;
			}
		}
	}
	return false;
}

bool k8s_delegator::is_delegated(bool trace)
{
	refresh_ipv4_list(); // get current list of local IP addresses
	int i = 1;

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

	for(node_map_t::const_iterator it = m_nodes.begin(),
		end = m_nodes.end(); it != end; ++it, ++i)
	{
		if(i > m_delegate_count) { break; }
		for(const auto& addr : it->second)
		{
			if(m_local_ip_addrs.find(addr) != m_local_ip_addrs.end())
			{
				return true;
			}
		}
	}
	return false;
}

bool k8s_delegator::handle_component(const Json::Value& json, const msg_data*)
{
	bool added = false;
	bool deleted = false;
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
					if(add_node(tm, node["addresses"]))
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

	if(added || deleted)
	{
		std::string d;
		if(!is_delegated(true)) { d = "NOT "; }
		g_logger.log("This node is " + d + "delegated", sinsp_logger::SEV_INFO);
	}

	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log("NODES=" + std::to_string(m_nodes.size()), sinsp_logger::SEV_TRACE);
		for(const auto& node : m_nodes)
		{
			std::ostringstream os;
			for(const auto& n : node.second) { os << n << ", "; }
			g_logger.log(std::to_string(node.first) + ':' + os.str(), sinsp_logger::SEV_TRACE);
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

	if(!handle_component(root))
	{
		g_logger.log("K8s delegator: error occurred while handling event.",
					 sinsp_logger::SEV_ERROR);
	}
}
