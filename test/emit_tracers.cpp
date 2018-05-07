#define VISIBILITY_PRIVATE

#include "sys_call_test.h"
#include "tracer_emitter.h"

class emit_tracer : public sys_call_test
{
protected:
	void do_emit_tracer(int depth, bool write_early);
};

void emit_tracer::do_emit_tracer(int depth, bool write_early)
{
	ASSERT_GE(depth, 1);
	ASSERT_LE(depth, 3);

	int callnum = 0;
	const int total_calls = 2 * depth;
	tracer_emitter::set_enabled(true);

	std::string parent_tag("parent_tracer");
	std::string child_tag("child_tracer");
	std::string gc_tag("grandchild_tracer");
	std::string agg_child_tag(parent_tag + "." + child_tag);
	std::string agg_gc_tag(agg_child_tag + "." + gc_tag);

	// Writing a tracer before running the callback causes the
	// /dev/null fd to be created in advance which changes whether
	// we get it from scanning /proc or from seeing the ::open()
	if (write_early) {
		tracer_emitter write_early("create_dev_null_fd");
	}

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return (m_tid_filter(evt) &&
			(evt->get_type() == PPME_TRACER_E ||
			 evt->get_type() == PPME_TRACER_X));
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		tracer_emitter parent(parent_tag);
		if (depth >= 2) {
			tracer_emitter child(child_tag, parent);
			if (depth >= 3) {
				tracer_emitter grandchild(gc_tag, child);
			}
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		callnum++;
		std::string evt_tag = param.m_evt->get_param_value_str("tags");
		if (callnum == 1 || callnum == total_calls) {
			EXPECT_EQ(parent_tag, evt_tag);
		}
		else if (depth >= 2 &&
			 (callnum == 2 || callnum == total_calls - 1))
		{
			EXPECT_EQ(agg_child_tag, evt_tag);
		}
		else if (depth >= 3 &&
			 (callnum == 3 || callnum == total_calls - 2))
		{
			EXPECT_EQ(agg_gc_tag, evt_tag);
		}
		else
		{
			FAIL() << "Unhandled call";
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});
	EXPECT_EQ(total_calls, callnum);
}

TEST_F(emit_tracer, solo)
{
	ASSERT_NO_FATAL_FAILURE(do_emit_tracer(1, false));
}
TEST_F(emit_tracer, solo_existing_fd)
{
	ASSERT_NO_FATAL_FAILURE(do_emit_tracer(1, true));
}

TEST_F(emit_tracer, child)
{
	ASSERT_NO_FATAL_FAILURE(do_emit_tracer(2, false));
}
TEST_F(emit_tracer, child_existing_fd)
{
	ASSERT_NO_FATAL_FAILURE(do_emit_tracer(2, true));
}

TEST_F(emit_tracer, grandchild)
{
	ASSERT_NO_FATAL_FAILURE(do_emit_tracer(3, false));
}
TEST_F(emit_tracer, grandchild_existing_fd)
{
	ASSERT_NO_FATAL_FAILURE(do_emit_tracer(3, true));
}
