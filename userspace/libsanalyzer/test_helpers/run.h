#pragma once

// forward declare
namespace test_helpers
{
class sinsp_mock;
}
class sinsp_analyzer;

namespace test_helpers
{

/**
 * Setup the given sinsp_mock in preparation for running. Must be done before
 * commiting events/threads.
 */
void init_sinsp_with_analyzer(sinsp_mock& inspector, sinsp_analyzer& analyzer);

/**
 * Use the given sinsp_mock to exercise the analyzer.
 *
 * All threads/events must be committed before running
 */
void run_sinsp_with_analyzer(sinsp_mock& inspector, sinsp_analyzer& analyzer);

}
