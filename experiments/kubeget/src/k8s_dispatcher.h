//
// k8s_dispatcher.h
//
// kubernetes REST API notification abstraction
//

#pragma once

#include "k8s_component.h"
#include <deque>
#include <string>

class k8s_dispatcher
{
public:
	enum msg_reason
	{
		COMPONENT_ADDED,
		COMPONENT_MODIFIED,
		COMPONENT_DELETED,
		COMPONENT_ERROR,
		COMPONENT_UNKNOWN // only to mark bad event messages
	};

	struct msg_data
	{
		msg_reason  m_reason = COMPONENT_UNKNOWN;
		std::string m_name;
		std::string m_uid;
		std::string m_namespace;
		// TODO ...

		bool is_valid() const
		{
			return m_reason != COMPONENT_UNKNOWN;
		}
	};

	k8s_dispatcher() = delete;
	
	k8s_dispatcher(k8s_component::type t, k8s_state_s& state);

	void enqueue(const std::string& data);

private:
	const std::string& next_msg();
	
	msg_data get_msg_data(const std::string& json);

	bool is_valid(const std::string& msg);

	bool is_ready(const std::string& msg);

	void remove();

	void dispatch();

	void handle(k8s_component::type type);
	
	std::string to_reason_desc(msg_reason reason)
	{
		switch (reason)
		{
		case COMPONENT_ADDED:
			return "ADDED";
		case COMPONENT_MODIFIED:
			return "MODIFIED";
		case COMPONENT_DELETED:
			return "DELETED";
		case COMPONENT_ERROR:
			return "ERROR";
		case COMPONENT_UNKNOWN:
			return "UNKNOWN";
		default:
			return "";
		}
	}
	
	msg_reason to_reason(const std::string& desc)
	{
		if (desc == "ADDED") { return COMPONENT_ADDED; }
		else if (desc == "MODIFIED") { return COMPONENT_MODIFIED; }
		else if (desc == "DELETED") { return COMPONENT_DELETED; }
		else if (desc == "ERROR") { return COMPONENT_ERROR; }
		else if (desc == "UNKNOWN") { return COMPONENT_UNKNOWN; }
		throw std::invalid_argument(desc);
	}

	typedef std::deque<std::string> list;

	k8s_component::type m_type;
	list                m_messages;
	k8s_state_s&        m_state;
};


inline const std::string& k8s_dispatcher::next_msg()
{
	return m_messages.front();
}

inline void k8s_dispatcher::remove()
{
	m_messages.pop_front();
}