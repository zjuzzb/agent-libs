#include <benchmark/benchmark.h>
#include <analyzer.h>
#include <run.h>
#include <sinsp_mock.h>

using namespace test_helpers;

namespace
{
uncompressed_sample_handler_dummy g_sample_handler;
audit_tap_handler_dummy g_audit_handler;
}

void one_hundred_thousand_reads(benchmark::State& state)
{
	for (auto _ : state)
	{
		sinsp_mock inspector;
		inspector.build_event().count(100000).type(PPME_SYSCALL_READ_E).commit();

		internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();

		sinsp_analyzer analyzer(&inspector,
					"/" /*root dir*/,
					int_metrics,
					g_sample_handler,
					g_audit_handler);

		run_sinsp_with_analyzer(inspector, analyzer);
	}
}
BENCHMARK(one_hundred_thousand_reads)->Unit(benchmark::kMillisecond);



