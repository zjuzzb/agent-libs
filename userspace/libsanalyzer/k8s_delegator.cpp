//
// k8s_delegator.cpp
//

#include "k8s_delegator.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "ifinfo.h"
#include <sstream>

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
	int timeout_ms,
	ssl_ptr_t ssl,
	bt_ptr_t bt,
	bool curl_debug): m_inspector(inspector),
		m_id("k8s_delegator"),
		m_collector(false),
		m_timeout_ms(timeout_ms),
		m_curl(url.append("/api/v1/nodes"), ssl, bt, timeout_ms, curl_debug),
		m_delegate_count(delegate_count)
{
	g_logger.log(std::string("Creating K8s delegator object for " + url), sinsp_logger::SEV_DEBUG);

	std::ostringstream os;
	sinsp_curl::check_error(m_curl.get_data(os));
	handler_t::json_ptr_t json = handler_t::try_parse(m_jq, os.str(), STATE_FILTER, "k8s_delegator", url);
	if(json)
	{
		handle_json(std::move(*json));
	}
	else
	{
		throw sinsp_exception("K8s delegator: could not get data from [" + url + ']');
	}
	m_http = std::make_shared<handler_t>(*this, "k8s_delegator",
										 url, "/api/v1/watch/nodes", http_version, timeout_ms,
										 ssl, bt);
	m_http->set_json_callback(&k8s_delegator::set_event_json);
	m_http->set_json_end("}\n");
	m_http->set_json_filter(EVENT_FILTER);
	m_collector.add(m_http);
	send_data_request();
}

k8s_delegator::~k8s_delegator()
{
}

void k8s_delegator::send_event_data_request()
{
	if(m_http)
	{
		m_http->send_request();
	}
	else
	{
		throw sinsp_exception("k8s_delegator event HTTP client is null.");
	}
}

void k8s_delegator::connect()
{
	if(!connect(m_http, &k8s_delegator::set_event_json, 1))
	{
		throw sinsp_exception("Connection to k8s_delegator API failed.");
	}
}

bool k8s_delegator::is_alive() const
{
	if(m_http && !m_http->is_connected())
	{
		g_logger.log("k8s_delegator state connection loss.", sinsp_logger::SEV_WARNING);
		return false;
	}
	return true;
}

void k8s_delegator::check_collector_status(int expected)
{
	if(!m_collector.is_healthy(expected))
	{
		throw sinsp_exception("k8s_delegator collector not healthy (has " + std::to_string(m_collector.subscription_count()) +
							  " connections, expected " + std::to_string(expected) + "); giving up on data collection in this cycle ...");
	}
}

void k8s_delegator::send_data_request(bool collect)
{
	if(m_events.size()) { return; }
	connect();
	send_event_data_request();
	g_logger.log("k8s_delegator event request sent.", sinsp_logger::SEV_DEBUG);
	if(collect) { collect_data(); }
}

void k8s_delegator::collect_data()
{
	if(m_collector.subscription_count())
	{
		m_collector.get_data();
		if(m_events.size())
		{
			for(auto evt : m_events)
			{
				if(evt && !evt->isNull())
				{
					handle_json(std::move(*evt));
				}
				else
				{
					g_logger.log(std::string("k8s_delegator event error: ") +
								(!evt ? "event is null." : (evt->isNull() ? "JSON is null." : "Unknown")),
								sinsp_logger::SEV_ERROR);
				}
			}
			m_events.clear();
		}
	}
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

bool k8s_delegator::is_ip_address(const std::string& addr)
{
	struct sockaddr_in serv_addr = {0};
	return inet_aton(addr.c_str(), &serv_addr.sin_addr);
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

k8s_delegator::ip_addr_list_t k8s_delegator::hostname_to_ip(const std::string& hostname)
{
	ip_addr_list_t ip_addrs;
	struct addrinfo *servinfo = 0;

	struct addrinfo hints = {0};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if((getaddrinfo(hostname.c_str(), NULL, &hints, &servinfo)) != 0)
	{
		g_logger.log("Can't determine IP address for hostname: " + hostname, sinsp_logger::SEV_WARNING);
		return ip_addrs;
	}

	for(struct addrinfo* p = servinfo; p != NULL; p = p->ai_next)
	{
		struct sockaddr_in* h = (struct sockaddr_in*)p->ai_addr;
		ip_addrs.emplace(inet_ntoa(h->sin_addr));
	}

	freeaddrinfo(servinfo);
	return ip_addrs;
}

void k8s_delegator::set_event_json(json_ptr_t json, const std::string&)
{
	if(json)
	{
		m_events.emplace_back(json);
	}
	else
	{
		g_logger.log("K8s: delegator received null JSON", sinsp_logger::SEV_ERROR);
	}
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

void k8s_delegator::handle_json(Json::Value&& root)
{
	if(g_logger.get_severity() >= sinsp_logger::SEV_TRACE)
	{
		g_logger.log(json_as_string(root), sinsp_logger::SEV_TRACE);
	}

	bool added = false;
	bool deleted = false;

	const Json::Value& nodes = root["nodes"];
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
				std::string type = get_json_string(root, "type");
				added = (type == "ADDED");
				deleted = (type == "DELETED");
				if(added)
				{
					if(add_node(tm, node["addresses"]))
					{ g_logger.log("K8s delegator: Added node to list: " + nname, sinsp_logger::SEV_DEBUG); }
					else
					{ g_logger.log("K8s delegator: Node not added to list: " + nname, sinsp_logger::SEV_TRACE); }
				}
				else if(deleted)
				{
					if(remove_node(tm, node["addresses"]))
					{ g_logger.log("K8s delegator: Removed node from the list: " + nname, sinsp_logger::SEV_DEBUG); }
					else
					{ g_logger.log("K8s delegator: Removed node event for non-existent node: " + nname, sinsp_logger::SEV_WARNING); }
				}
			}
			else
			{
				g_logger.log("K8s delegator: timestamp is null or not string.", sinsp_logger::SEV_WARNING);
			}
		} // end for nodes
	}
	else
	{
		g_logger.log("K8s delegator: nodes are empty or not an array.", sinsp_logger::SEV_WARNING);
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
}
