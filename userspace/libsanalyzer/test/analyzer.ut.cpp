
#include <analyzer.h>
#include <run.h>
#include <sinsp_mock.h>
#include <gtest.h>

using namespace test_helpers;

TEST(analyzer_test, end_to_end_basic)
{
	sinsp_mock inspector;
	// Make some fake events
	uint64_t ts = 1095379199000000000ULL;
	inspector.build_event().tid(55).ts(ts).count(5).commit();
	inspector.build_event().tid(55).ts(ts).count(1000).commit();
	inspector.build_event().tid(75).count(1).commit();

	sinsp_analyzer analyzer(&inspector, "/" /*root dir*/);
	run_sinsp_with_analyzer(inspector, analyzer);

	// TODO bryan NOW WHAT?!?!?
}
