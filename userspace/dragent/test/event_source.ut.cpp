#include "event_source.h"
#include "sinsp.h"

#include <gtest.h>

class dummy_listener : public event_listener
{
public:
	void process_event(agent_event* evt)
	{
		m_event = *evt;
		m_event_received = true;
	}

	bool m_event_received = false;
	agent_event m_event;
};

class dummy_source : public event_source
{
public:
	void start() {}

	uint32_t send_event()
	{
		agent_event some_event;
		some_event.set_iosize(++m_count);
		process_event(&some_event);
		return m_count++;
	}

	uint32_t m_count = 0;
};

TEST(event_source, add_listeners)
{
	std::shared_ptr<dummy_listener> dl1 = std::make_shared<dummy_listener>();
	std::shared_ptr<dummy_listener> dl2 = std::make_shared<dummy_listener>();

	dummy_source ds;

	ASSERT_EQ(ds.get_event_listeners().size(), 0);

	ds.register_event_listener(dl1);
	ASSERT_EQ(ds.get_event_listeners().size(), 1);
	ASSERT_NE(ds.get_event_listeners().find(dl1), ds.get_event_listeners().end());

	ds.register_event_listener(dl2);
	ASSERT_EQ(ds.get_event_listeners().size(), 2);
	ASSERT_NE(ds.get_event_listeners().find(dl2), ds.get_event_listeners().end());
}

TEST(event_source, get_callbacks)
{
	std::shared_ptr<dummy_listener> dl1 = std::make_shared<dummy_listener>();
	std::shared_ptr<dummy_listener> dl2 = std::make_shared<dummy_listener>();

	dummy_source ds;

	ds.register_event_listener(dl1);
	ds.register_event_listener(dl2);

	uint32_t event_num = ds.send_event();
	ASSERT_TRUE(dl1->m_event_received);
	ASSERT_EQ(dl1->m_event.get_iosize(), event_num);
	ASSERT_TRUE(dl2->m_event_received);
	ASSERT_EQ(dl2->m_event.get_iosize(), event_num);
}
