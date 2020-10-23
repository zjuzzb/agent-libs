#include <analyzer.h>
#include <benchmark/benchmark.h>
#include <run.h>
#include <sinsp_mock.h>

using namespace test_helpers;

namespace
{
sinsp_analyzer::flush_queue g_queue(2000);
audit_tap_handler_dummy g_audit_handler;
null_secure_audit_handler g_secure_audit_handler;
null_secure_profiling_handler g_secure_profiling_handler;
null_secure_netsec_handler g_secure_netsec_handler;
}  // namespace

void one_hundred_thousand_reads(benchmark::State& state)
{
	for (auto _ : state)
	{
		shared_ptr<sinsp_mock> inspector(new sinsp_mock());
		auto& tinfo = inspector->build_thread().commit();
		inspector->build_event(tinfo).count(100000).type(PPME_SYSCALL_READ_E).commit();

		internal_metrics::sptr_t int_metrics = std::make_shared<internal_metrics>();

		sinsp_analyzer analyzer(inspector.get(),
		                        "/" /*root dir*/,
		                        int_metrics,
		                        g_audit_handler,
		                        g_secure_audit_handler,
		                        g_secure_profiling_handler,
		                        g_secure_netsec_handler,
		                        &g_queue,
		                        []() -> bool { return true; });

		run_sinsp_with_analyzer(*inspector, analyzer);

		// For legacy reasons, the inspector must be deleted before the
		// analyzer.
		inspector.reset();
	}
}
BENCHMARK(one_hundred_thousand_reads)->Unit(benchmark::kMillisecond);
