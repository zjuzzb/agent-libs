/**
 * @file
 *
 * Unit test for user_event_logger.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "user_event_logger.h"
#include <gtest.h>
#include <memory>
#include <string>

namespace
{

class test_user_event_callback : public user_event_logger::callback
{
public:
	const static user_event_logger::severity DEFAULT_SEVERITY;

	test_user_event_callback():
		m_message(nullptr),
		m_severity(DEFAULT_SEVERITY)
	{ }

	void log(const sinsp_user_event& evt, user_event_logger::severity sev) override
	{
		m_message = &evt;
		m_severity = sev;
	}

	const sinsp_user_event* m_message;
	user_event_logger::severity m_severity;
};
const user_event_logger::severity test_user_event_callback::DEFAULT_SEVERITY = user_event_logger::SEV_EVT_DEBUG;

} // end namespace

class user_event_logger_test : public testing::Test
{
public:
	void TearDown() override
	{
		user_event_logger::register_callback(nullptr);
	}
};

/**
 * Ensure that the callback is initially a null object.
 */
TEST_F(user_event_logger_test, callback_is_initially_nullptr)
{
	ASSERT_TRUE(user_event_logger::get_callback().is_null());
}

/**
 * Ensure that registering a callback registers the callback.
 */
TEST_F(user_event_logger_test, register_real_callback)
{
	user_event_logger::callback::ptr_t cb = std::make_shared<test_user_event_callback>();
	user_event_logger::register_callback(cb);

	ASSERT_FALSE(user_event_logger::get_callback().is_null());
	ASSERT_EQ(cb.get(), &user_event_logger::get_callback());
}

/**
 * Ensure that registering nullptr as the callback results in a null object
 * callback.
 */
TEST_F(user_event_logger_test, register_nullptr_callback)
{
	user_event_logger::callback::ptr_t cb = std::make_shared<test_user_event_callback>();
	user_event_logger::register_callback(cb);
	user_event_logger::register_callback(nullptr);

	ASSERT_TRUE(user_event_logger::get_callback().is_null());
}

/**
 * Ensure that logs written to the user_event_logger with a registered
 * callback get delivered to the callback.
 */
TEST_F(user_event_logger_test, log_to_registered_callback)
{
	sinsp_user_event evt(
		time(nullptr),
		"some name",
		"some description",
		"some scope",
		{},
		sinsp_user_event::UNKNOWN_SEVERITY);

	std::shared_ptr<test_user_event_callback> cb = std::make_shared<test_user_event_callback>();
	user_event_logger::register_callback(cb);

	const user_event_logger::severity severity = user_event_logger::SEV_EVT_ERROR;

	user_event_logger::log(evt, severity);

	ASSERT_EQ(&evt, cb->m_message);
	ASSERT_EQ(severity, cb->m_severity);
}
