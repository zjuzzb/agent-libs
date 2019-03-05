#include <gtest.h>
#include <string>
#include <vector>
#include <libsanalyzer/k8s_user_event_message_handler.h>
#include "user_event.h"
#include "user_event_channel.h"
#include <dragent/logger.h>


extern AutoPtr<user_event_channel> uec;

class test_helper {
public:
	static void set_filter(k8s_user_event_message_handler* handler,
			       user_event_filter_t* filter)
	{
		handler->m_event_filter = std::make_shared<user_event_filter_t>(filter);
	}
};

// dump an event into the k8s handler and ensure it comes out the other side
TEST(user_event_test, basic)
{
	auto handler = new k8s_user_event_message_handler(60, "/");
	auto filter = new user_event_filter_t();

	// don't care about type list since it's all
	user_event_meta_t::type_list_t type_list;
	user_event_meta_t all(user_event_meta_t::PERMIT_ALL, type_list);
	filter->add(all);
	test_helper::set_filter(handler, filter);

	sdc_internal::k8s_object object;
	object.set_kind("node");
	sdc_internal::k8s_user_event event;
	event.set_allocated_obj(&object);
	event.set_reason("why not?");
	event.set_last_timestamp(1);
	event.set_message("this had better work!");
	handler->handle_event(&event);

	// should get one event on the queue
	ASSERT_EQ(uec->get_event_queue(), 1);

	sinsp_user_event evt;
	uec->get_event_queue()->get(evt);
	ASSERT_EQ("why not?", evt.name());
	ASSERT_EQ("this had better work!", evt.description());

	delete handler;
	delete filter;
}
