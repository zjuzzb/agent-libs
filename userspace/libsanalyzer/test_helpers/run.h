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
 * Use the given sinsp_mock to exercise the analyzer.
 */
void run_sinsp_with_analyzer(sinsp_mock& inspector, sinsp_analyzer& analyzer);

}
