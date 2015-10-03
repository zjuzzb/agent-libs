//
// k8s_dispatcher.cpp
//

#include "k8s_dispatcher.h"
#include "json/json.h"
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iostream>

k8s_dispatcher::k8s_dispatcher(k8s_component::type t, k8s_state_s& state) :
	m_type(t),
	m_state(state)
{
}

void k8s_dispatcher::enqueue(const std::string& data)
{
	if (m_messages.size() == 0)
	{
		m_messages.push_back("");
	}

	std::string& msg = m_messages.back();
	std::string::size_type pos = msg.find_first_of('\n');
	if (pos != std::string::npos)
	{
		if (pos == msg.size() - 1) // last message was complete. this is a new message
		{
			m_messages.push_back(data);
		}
		else // EOL can be only at the end
		{
			throw std::invalid_argument("End of line character found in the string.");
		}
	}
	else // append
	{
		pos = data.find_first_of('\n');
		if (pos != std::string::npos)
		{
			msg += data.substr(0, pos);
			m_messages.push_back(data.substr(pos));
		}
		else
		{
			m_messages.push_back(data);
		}
	}
	dispatch(); // in separate thread?
}

bool k8s_dispatcher::is_valid(const std::string& msg)
{
	// zero-length message is valid because that's how it starts its life.
	// so, here we only check for messages that are single newline only
	// or those that are longer than one character and contain multiple newlines.

	if ((msg.size() == 1 && msg[0] == '\n') ||
		std::count(msg.begin(), msg.end(), '\n') > 1)
	{
		return false;
	}
	return true;
}

bool k8s_dispatcher::is_ready(const std::string& msg)
{
	// absurd minimum ( "{}\n" ) but it's hard to tell 
	// what minimal size is, so there
	if (msg.size() < 3) 
	{
		return false;
	}
	return msg[msg.size() - 1] == '\n';
}

k8s_dispatcher::msg_data k8s_dispatcher::get_msg_data(const std::string& json)
{
	msg_data data;
	Json::Value root;
	Json::Reader reader;
	if (reader.parse(json, root, false))
	{
		Json::Value evtype = root["type"];
		if (!evtype.isNull())
		{
			const std::string& et = evtype.asString();
			if (!et.empty())
			{
				if      (et[0] == 'A') { data.m_reason = COMPONENT_ADDED;    }
				else if (et[0] == 'M') { data.m_reason = COMPONENT_MODIFIED; }
				else if (et[0] == 'D') { data.m_reason = COMPONENT_DELETED;  }
				else if (et[0] == 'E') { data.m_reason = COMPONENT_ERROR;    }
			}
			else // can't do anything further without knowing the event type
			{
				return msg_data();
			}
		}
		Json::Value object = root["object"];
		if (!object.isNull() && object.isObject())
		{
			Json::Value meta = object["metadata"];
			if (!meta.isNull() && meta.isObject())
			{
				Json::Value name = meta["name"];
				if (!name.isNull())
				{
					data.m_name = name.asString();
				}
				Json::Value uid = meta["uid"];
				if (!uid.isNull())
				{
					data.m_uid = uid.asString();
				}
				Json::Value nspace = meta["namespace"];
				if (!nspace.isNull())
				{
					data.m_namespace = nspace.asString();
				}
			}
		}
	}
	else
	{
		std::ostringstream os;
		os << "JSON parsing failed for component: " << m_type;
		throw std::runtime_error(os.str());
	}
	return data;
}

void k8s_dispatcher::dispatch()
{
	for (list::iterator it = m_messages.begin(); it != m_messages.end();)
	{
		if (is_ready(*it))
		{
			// ADDED, MODIFIED, DELETED, or ERROR
			//std::cout << "JSON:[" << *it << ']' << std::flush;
			msg_data data = get_msg_data(*it);
			if (data.is_valid())
			{
				std::cout << '[' << to_reason_desc(data.m_reason) << ',' << data.m_name << ',' << data.m_uid << ',' << data.m_namespace << ']' << std::endl;
				switch (m_type)
				{
					case k8s_component::K8S_NODES:
						break;
					case k8s_component::K8S_NAMESPACES:
						break;
					case k8s_component::K8S_PODS:
						break;
					case k8s_component::K8S_REPLICATIONCONTROLLERS:
						break;
					case k8s_component::K8S_SERVICES:
						break;
					default:
					{
						std::ostringstream os;
						os << "Unknown component: " << static_cast<int>(m_type);
						throw std::invalid_argument(os.str());
					}
				}
				// TODO: update master state
			}
			else
			{
				// TODO: bad value found - discard silently?
				std::cout << "Bad message received." << std::endl;
			}
			it = m_messages.erase(it);
		}
		else
		{
			++it;
		}
	}
}

void k8s_dispatcher::handle(k8s_component::type type)
{
}
