#include <benchmark/benchmark.h>
#include <analyzer.h>
#include <run.h>
#include <sinsp_mock.h>

using namespace test_helpers;

void one_hundred_thousand_reads(benchmark::State& state)
{
	for (auto _ : state)
	{
		sinsp_mock inspector;
		inspector.build_event().count(100000).type(PPME_SYSCALL_READ_E).commit();

		internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();
		sinsp_analyzer analyzer(&inspector, "/" /*root dir*/, int_metrics);

		run_sinsp_with_analyzer(inspector, analyzer);
	}
}
BENCHMARK(one_hundred_thousand_reads)->Unit(benchmark::kMillisecond);



