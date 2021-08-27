
#include "configuration.h"
#include "protocol.h"
#include "protocol_handler.h"
#include "sinsp_mock.h"
#include "sinsp_worker.h"
#include "watchdog_runnable_pool.h"

#include <gtest.h>
#include <sinsp_evt_clone.h>
#include <sinsp_evt_delay_filter.h>

using namespace test_helpers;

COMMON_LOGGER();

using match_results_t = std::shared_ptr<std::list<security_rules::match_result>>;

struct sinsp_delayed_evt_test: public ::testing::Test
{
	const int64_t tid = 0x100;
	const std::string exe = "my_exe";
	const std::string container_id = "123456";
	const std::string container_name = "my_container";

	sinsp_mock mock;

	bool flushed = false;
	std::function<void(gen_event*)>  f_clbk = [this](gen_event* evt)
		{ flushed = dynamic_cast<sinsp_evt_clone*>(evt) != nullptr; };

	std::function<
	    void(const gen_event*, const match_results_t&, const sinsp_threadinfo*, const std::string*)>
	    exp_clbk = [this](const gen_event* evt,
	                      const match_results_t& results,
	                      const sinsp_threadinfo* tinfo,
	                      const std::string* container_id_ptr)
	{ flushed = dynamic_cast<const sinsp_evt_clone*>(evt) != nullptr; };

	match_results_t results = match_results_t(new std::list<security_rules::match_result>());

	sinsp_evt_clone_registry registry;

	sinsp_threadinfo& tinfo;

	void SetUp() override
	{}
	void TearDown() override{}

	sinsp_delayed_evt_test()
	    : registry(f_clbk, exp_clbk, mock),
	      tinfo(mock.build_thread().tid(tid).exe(exe).commit())
	{
		mock.open();
		mock.get_thread_ref(tid)->m_ptid = 1;
		mock.build_event(tinfo).commit();
	}
};

// test registration
TEST_F(sinsp_delayed_evt_test, regiter_test)
{
	ASSERT_EQ(exe, tinfo.m_exe);

	sinsp_evt* event;
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));

	bool can_register = registry.can_register(event, &container_id);
	ASSERT_EQ(can_register, true);

	bool is_reg = registry.register_event(container_id, *event, results);
	ASSERT_EQ(is_reg, true);
}

// test expiration
TEST_F(sinsp_delayed_evt_test, event_expired_test)
{
	ASSERT_EQ(exe, tinfo.m_exe);

	sinsp_evt* event;
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));

	bool is_reg = registry.register_event(container_id, *event, results);
	ASSERT_EQ(is_reg, true);

	std::this_thread::sleep_for(std::chrono::milliseconds(900));
	registry.check_expired();
	ASSERT_EQ(flushed, true);
}

// test negative expiration, positive on container
TEST_F(sinsp_delayed_evt_test, container_test)
{
	mock.build_container(tinfo).id(container_id).name(container_name).commit();
	mock.build_event(tinfo).commit();

	auto cinfo = mock.m_container_manager.get_container(container_id);
	ASSERT_EQ(container_name, cinfo->m_name);

	auto* tinfo_ptr = &*mock.get_thread_ref(tid);
	ASSERT_EQ(container_id, tinfo_ptr->m_container_id);

	sinsp_evt* event;
	ASSERT_EQ(SCAP_SUCCESS, mock.next(&event));

	bool is_reg = registry.register_event(container_id, *event, results);
	ASSERT_EQ(is_reg, true);

	registry.check_expired();
	ASSERT_EQ(flushed, false);

	registry.on_new_container(*cinfo);
	ASSERT_EQ(flushed, true);
}

// test: not delaying events if actions are there
TEST_F(sinsp_delayed_evt_test, filter_test)
{
	mock.build_container(tinfo).id(container_id).name(container_name).commit();
	auto cinfo = mock.m_container_manager.get_container(container_id);
	ASSERT_EQ(container_name, cinfo->m_name);

	bool is_in = (sinsp_evt_delay_filter())
	             .should_delay(&container_id, *results, mock.m_container_manager);

	ASSERT_EQ(is_in, false); // due to container lookup=success


	draiosproto::action v2action;
	draiosproto::policy_v2 v2;
	v2.add_actions();
	v2.add_v2actions();

	results->emplace_back(security_rules::match_result());
	auto& result = results->back();

	result.m_policy = std::make_shared<security_policy_v2>(v2);

	is_in = (sinsp_evt_delay_filter())
		.should_delay(&container_id, *results, mock.m_container_manager);

	ASSERT_EQ(is_in, false);
}
