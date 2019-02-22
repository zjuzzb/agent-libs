#pragma once

#include "configuration.h"
#include "user_event.h"


class user_event_channel: public Poco::Channel
{
public:
	typedef std::unordered_map<string, string> tag_map_t;

	user_event_channel();
	void log(const Poco::Message& msg);

	user_event_queue::ptr_t get_event_queue();

protected:
	~user_event_channel();

private:

	void add(uint64_t timestamp,
			std::string&& name,
			std::string&& description,
			std::string&& scope,
			tag_map_t&& tags,
			uint32_t sev);

	user_event_queue::ptr_t m_event_queue;
};

inline void user_event_channel::log(const Message& msg)
{
	try
	{
		yaml_configuration yaml(msg.getText());
		uint64_t ts = yaml.get_scalar<uint64_t>("timestamp", msg.getTime().epochTime());
		uint32_t prio = yaml.get_scalar<uint32_t>("priority", static_cast<uint32_t>(msg.getPriority()));
		add(ts,
			yaml.get_scalar<string>("name"),
			yaml.get_scalar<string>("description", ""),
			yaml.get_scalar<string>("scope", ""),
			yaml.get_merged_map<string>("tags"),
			prio);
	}
	catch(YAML::ParserException& ex)
	{
		g_logger.log(std::string("YAML parsing exception in user event channel: ") + ex.what(), sinsp_logger::SEV_ERROR);
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Exception in user event channel: ") + ex.what(), sinsp_logger::SEV_ERROR);
	}
}

inline void user_event_channel::add(uint64_t timestamp,
									std::string&& name,
									std::string&& description,
									std::string&& scope,
									tag_map_t&& tags,
									uint32_t sev)
{
	m_event_queue->add(sinsp_user_event(timestamp, std::move(name),
						std::move(description), std::move(scope), std::move(tags), sev));
}

inline user_event_queue::ptr_t user_event_channel::get_event_queue()
{
	return m_event_queue;
}
