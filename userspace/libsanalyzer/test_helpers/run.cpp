
#include "run.h"
#include "sinsp_mock.h"
#include <analyzer.h>

namespace test_helpers
{

void run_sinsp_with_analyzer(sinsp_mock& inspector, sinsp_analyzer& analyzer)
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