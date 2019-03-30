#include <gtest.h>
#include <analyzer.h>
#include "sinsp_mock.h"

using namespace test_helpers;

namespace {

void run_analyzer(sinsp_mock& inspector, sinsp_analyzer &analyzer)
{
	inspector.open();

	inspector.m_analyzer = &analyzer;
	analyzer.on_capture_start();

	// Calling sinsp::next will pass the events to the analyzer. Run this
	// until we are out of events.
	sinsp_evt *dummy;
	while (inspector.next(&dummy) != SCAP_EOF) {}
}

}

TEST(analyzer_test, end_to_end_basic)
{
	sinsp_mock inspector;
	// Make some fake events
	uint64_t ts = 1095379199000000000ULL;
	inspector.build_event().tid(55).ts(ts).count(5).commit();
	inspector.build_event().tid(55).ts(ts).count(1000).commit();
	inspector.build_event().tid(75).count(1).commit();

	sinsp_analyzer analyzer(&inspector, "/" /*root dir*/);
	run_analyzer(inspector, analyzer);

	// TODO bryan NOW WHAT?!?!?
}
