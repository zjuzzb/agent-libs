/**
 * @file
 *
 * Unit tests for protobuf_metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "analyzer_callback_interface.h"
#include "protobuf_metric_serializer.h"
#include "analyzer_utils.h"
#include "capture_stats_source.h"
#include "internal_metrics.h"
#include "scoped_temp_directory.h"

#include <chrono>
#include <memory>
#include <gtest.h>

using libsanalyzer::metric_serializer;
using libsanalyzer::protobuf_metric_serializer;

namespace
{

/**
 * Helper realization of the capture_stats_source that returns pre-canned
 * results.
 */
class precanned_capture_stats_source : public capture_stats_source
{
public:
	/** Default number of captured events. */
	const static uint64_t DEFAULT_EVTS;

	/** Default number of dropped events. */
	const static uint64_t DEFAULT_DROPS;

	/** Default number of buffer drops. */
	const static uint64_t DEFAULT_DROPS_BUFFER;

	/** Default number of (PF?) drops. */
	const static uint64_t DEFAULT_DROPS_PF;

	/** Default number of bug drops. */
	const static uint64_t DEFAULT_DROPS_BUG;

	/** Default number of preemptions. */
	const static uint64_t DEFAULT_PREEMPTIONS;

	/** Default number of suppressed events. */
	const static uint64_t DEFAULT_SUPPRESSED;

	/** Default number of tids suppressed. */
	const static uint64_t DEFAULT_TIDS_SUPPRESSED;

	/**
	 * Initialize this precanned_capture_stats_source with the given
	 * initial values.
	 *
	 * @param[in] evts            The initial number of events
	 * @param[in] drops           The initial number of drops
	 * @param[in] drops_buffer    The initial number of buffer drops
	 * @param[in] drops_pf        The initial number of pf drops
	 * @param[in] drops_bug       The initial number of bug drops
	 * @param[in] preemptions     The initial number of preemptions
	 * @param[in] suppressed      The initial number of suppressed events
	 * @param[in] tids_suppressed The initial number of suppressed tids
	 */
	precanned_capture_stats_source(
			const uint64_t evts = DEFAULT_EVTS,
			const uint64_t drops = DEFAULT_DROPS,
			const uint64_t drops_buffer = DEFAULT_DROPS_BUFFER,
			const uint64_t drops_pf = DEFAULT_DROPS_PF,
			const uint64_t drops_bug = DEFAULT_DROPS_BUG,
			const uint64_t preemptions = DEFAULT_PREEMPTIONS,
			const uint64_t suppressed = DEFAULT_SUPPRESSED,
			const uint64_t tids_suppressed = DEFAULT_TIDS_SUPPRESSED):
		m_stats()
	{
		m_stats.n_evts = evts;
		m_stats.n_drops = drops;
		m_stats.n_drops_buffer = drops_buffer;
		m_stats.n_drops_pf = drops_pf;
		m_stats.n_drops_bug = drops_bug;
		m_stats.n_preemptions = preemptions;
		m_stats.n_suppressed = suppressed;
		m_stats.n_tids_suppressed = tids_suppressed;
	}

	/**
	 * Concrete realization of the get_capture_stats() API. Updates the
	 * given stats with the pre-canned stats.
	 *
	 * @param[out] stats The captured stats.
	 */
	void get_capture_stats(scap_stats* const stats) override
	{
		memcpy(stats, &m_stats, sizeof(m_stats));
	}

private:
	scap_stats m_stats;
};

//
// These are just dummy, made-up values for the sake of the test.  The
// rationale behind the choice of these values was (1) to have each be unique
// and (2) to have them be non-zero.
//
const uint64_t precanned_capture_stats_source::DEFAULT_EVTS = 42;
const uint64_t precanned_capture_stats_source::DEFAULT_DROPS = 5;
const uint64_t precanned_capture_stats_source::DEFAULT_DROPS_BUFFER = 2;
const uint64_t precanned_capture_stats_source::DEFAULT_DROPS_PF = 11;
const uint64_t precanned_capture_stats_source::DEFAULT_DROPS_BUG = 8;
const uint64_t precanned_capture_stats_source::DEFAULT_PREEMPTIONS = 17;
const uint64_t precanned_capture_stats_source::DEFAULT_SUPPRESSED = 6;
const uint64_t precanned_capture_stats_source::DEFAULT_TIDS_SUPPRESSED = 2;

/**
 * A dummy realization of the analyzer_callback_interface that saves the
 * values passed to sinsp_analyzer_data_ready.
 */
class dummy_analyzer_callback : public analyzer_callback_interface
{
public:
	/** The unset sentinel value for values of type uint64_t. */
	const static uint64_t UNSET_UINT64;

	/** The unset sentinel value for values of type uint32_t. */
	const static uint32_t UNSET_UINT32;

	/** The unset sentinel value for values of type double. */
	const static double UNSET_DOUBLE;

	/** The unset sentinel value for values of type draiosproto::metrics*. */
	static draiosproto::metrics* const UNSET_METRICS;

	/**
	 * Initialize this dummy handler to all unset sentinel values.
	 */
	dummy_analyzer_callback(const uint32_t sleep_time = 0):
		analyzer_callback_interface(),
		m_ts_ns(UNSET_UINT64),
		m_nevts(UNSET_UINT64),
		m_num_drop_events(UNSET_UINT64),
		m_metrics(UNSET_METRICS),
		m_sampling_ratio(UNSET_UINT32),
		m_analyzer_cpu_pct(UNSET_DOUBLE),
		m_flush_cpu_cpt(UNSET_DOUBLE),
		m_analyzer_flush_duration_ns(UNSET_UINT64),
		m_num_suppressed_threads(UNSET_UINT64),
		m_sleep_time(sleep_time),
		m_call_count(0)
	{ }

	/**
	 * Concrete realization of the sinsp_analyzer_data_ready() API.
	 * Saves all parameters to locals.
	 */
	void sinsp_analyzer_data_ready(const uint64_t ts_ns,
	                               const uint64_t nevts,
	                               const uint64_t num_drop_events,
	                               draiosproto::metrics* const metrics,
	                               const uint32_t sampling_ratio,
	                               const double analyzer_cpu_pct,
	                               const double flush_cpu_cpt,
	                               const uint64_t analyzer_flush_duration_ns,
	                               const uint64_t num_suppressed_threads) override
	{
		m_ts_ns = ts_ns;
		m_nevts = nevts;
		m_num_drop_events = num_drop_events;
		m_metrics = metrics;
		m_sampling_ratio = sampling_ratio;
		m_analyzer_cpu_pct = analyzer_cpu_pct;
		m_flush_cpu_cpt = flush_cpu_cpt;
		m_analyzer_flush_duration_ns = analyzer_flush_duration_ns;
		m_num_suppressed_threads = num_suppressed_threads;

		if(m_sleep_time != 0)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(m_sleep_time));
		}
		++m_call_count;
	}

	/**
	 * Concrete realization of the audit_tap_data_ready() API.  Currently
	 * does nothing.
	 */
	void audit_tap_data_ready(const uint64_t ts_ns,
	                          const tap::AuditLog* const audit_log) override
	{ }

	uint64_t m_ts_ns;
	uint64_t m_nevts;
	uint64_t m_num_drop_events;
	draiosproto::metrics* m_metrics;
	uint32_t m_sampling_ratio;
	double m_analyzer_cpu_pct;
	double m_flush_cpu_cpt;
	uint64_t m_analyzer_flush_duration_ns;
	uint64_t m_num_suppressed_threads;
	uint32_t m_sleep_time;
	std::atomic<uint8_t> m_call_count;
};



const uint64_t dummy_analyzer_callback::UNSET_UINT64 = std::numeric_limits<uint64_t>::max();
const uint32_t dummy_analyzer_callback::UNSET_UINT32 = std::numeric_limits<uint32_t>::max();
const double dummy_analyzer_callback::UNSET_DOUBLE = std::numeric_limits<double>::max();
draiosproto::metrics* const dummy_analyzer_callback::UNSET_METRICS = nullptr;

} // end namespace

/**
 * Ensure that a newly-constructed protobuf_metric_serializer is in the
 * expected initial state.
 */
TEST(protobuf_metric_serializer_test, initial_state)
{
	precanned_capture_stats_source stats_source;
	internal_metrics::sptr_t int_metrics(new internal_metrics());

	std::unique_ptr<protobuf_metric_serializer> s(
			new protobuf_metric_serializer(&stats_source,
			                               int_metrics,
			                               ""));

	ASSERT_EQ(0, s->get_prev_sample_evtnum());
	ASSERT_EQ(0, s->get_prev_sample_time());
	ASSERT_EQ(0, s->get_prev_sample_num_drop_events());
	ASSERT_TRUE(s->serialization_complete());
}

/**
 * Ensure that serialize() correctly serializes the data.
 */
TEST(protobuf_metric_serializer_test, serialize)
{
	test_helpers::scoped_temp_directory temp_dir;
	precanned_capture_stats_source stats_source;
	internal_metrics::sptr_t int_metrics(new internal_metrics());
	dummy_analyzer_callback analyzer_callback;

	const uint64_t TIMESTAMP = static_cast<uint64_t>(0x0000000000654321);
	const uint32_t SAMPLING_RATIO = 1;
	const double PREV_FLUSH_CPU_PCT = 0.01;
	const uint64_t INITIAL_PREV_FLUSH_DURATION_NS = 13;
	std::atomic<uint64_t> prev_flushes_duration_ns(INITIAL_PREV_FLUSH_DURATION_NS);
	std::atomic<bool> metrics_sent(false);
	const double CPU_LOAD = 0.12;
	const bool EXTRA_INTERNAL_METRICS = true;
	draiosproto::metrics metrics;

	metric_serializer::c_metrics_dir.set(temp_dir.get_directory());

	std::unique_ptr<protobuf_metric_serializer> s(
			new protobuf_metric_serializer(&stats_source,
			                               int_metrics,
			                               ""));

	s->set_sample_callback(&analyzer_callback);
	s->serialize(make_unique<metric_serializer::data>(
				precanned_capture_stats_source::DEFAULT_EVTS,
				TIMESTAMP,
				SAMPLING_RATIO,
				PREV_FLUSH_CPU_PCT,
				prev_flushes_duration_ns,
				metrics_sent,
				CPU_LOAD,
				EXTRA_INTERNAL_METRICS,
				metrics));


	// Wait for the async thread to complete the work.  If we have to wait
	// more that 5 seconds, something has gone badly wrong.
	const int FIVE_SECOND_IN_MS = 5 * 1000;
	for(int i = 0; !s->serialization_complete() && i < FIVE_SECOND_IN_MS; ++i)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	ASSERT_TRUE(s->serialization_complete());

	// The serializer should have updated its internal state
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_EVTS,
	          s->get_prev_sample_evtnum());
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_DROPS,
	          s->get_prev_sample_num_drop_events());
	ASSERT_EQ(TIMESTAMP,
	          s->get_prev_sample_time());

	// The serializer should have updated the internal metrics with the
	// values fetched from the status source.
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_EVTS,
	          int_metrics->get_n_evts());
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_DROPS,
	          int_metrics->get_n_drops());
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_DROPS_BUFFER,
	          int_metrics->get_n_drops_buffer());
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_PREEMPTIONS,
	          int_metrics->get_n_preemptions());
	ASSERT_EQ(static_cast<int>(PREV_FLUSH_CPU_PCT * 100),
	          int_metrics->get_fp());
	ASSERT_EQ(SAMPLING_RATIO, int_metrics->get_sr());
	ASSERT_EQ(0, int_metrics->get_fl());

	// The serializer should have recorded that the metrics were sent
	ASSERT_EQ(true, metrics_sent);

	// The serializer should have invoked the sinsp_analyzer_data_ready
	// callback
	ASSERT_EQ(TIMESTAMP, analyzer_callback.m_ts_ns);
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_EVTS,
	          analyzer_callback.m_nevts);
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_DROPS,
	          analyzer_callback.m_num_drop_events);
	ASSERT_NE(nullptr, analyzer_callback.m_metrics);
	ASSERT_EQ(SAMPLING_RATIO, analyzer_callback.m_sampling_ratio);
	ASSERT_DOUBLE_EQ(CPU_LOAD, analyzer_callback.m_analyzer_cpu_pct);
	ASSERT_DOUBLE_EQ(PREV_FLUSH_CPU_PCT, analyzer_callback.m_flush_cpu_cpt);
	ASSERT_EQ(INITIAL_PREV_FLUSH_DURATION_NS,
	          analyzer_callback.m_analyzer_flush_duration_ns);
	ASSERT_EQ(precanned_capture_stats_source::DEFAULT_TIDS_SUPPRESSED,
	          analyzer_callback.m_num_suppressed_threads);

	//
	// Since we enabled the config for logging, we can check to make sure
	// that the file was generated.  It should have been generated in our
	// temporary directory.
	//
	// generate_dam_filename() expects that the directory has the trailing
	// path delimiter, and get_metrics_directory() ensures that it is
	// there.
	//
	const std::string dam_file =
		protobuf_metric_serializer::generate_dam_filename(
				s->get_metrics_directory(),
				TIMESTAMP);

	//
	// We could parse this file, but I'm not sure what parser can consume
	// it.  For now, we'll just check (1) that it exists and (2) is not
	// empty.
	//
	struct stat statbuf = {};

	errno = 0;
	const int rc = stat(dam_file.c_str(), &statbuf);
	const int err = errno;

	ASSERT_EQ(0, rc);
	ASSERT_EQ(0, err);

	ASSERT_TRUE(S_ISREG(statbuf.st_mode));
	ASSERT_TRUE(statbuf.st_size > 0);
}

/**
 * Ensure that if we get a call to serialize() while the async
 * thread is still running, that the calling thread is blocked
 * until the async thread finishes.  Next, the calling thread
 * should get unblocked, and the async thread should handle the
 * new work.  In the end, the serializer should not drop any work.
 */
TEST(protobuf_metric_serializer_test, back_to_back_serialization)
{
	test_helpers::scoped_temp_directory temp_dir;
	precanned_capture_stats_source stats_source;
	internal_metrics::sptr_t int_metrics(new internal_metrics());
	const uint32_t sleep_time_ms = 3;
	dummy_analyzer_callback analyzer_callback(sleep_time_ms);

	const uint64_t TIMESTAMP = static_cast<uint64_t>(0x0000000000654321);
	const uint32_t SAMPLING_RATIO = 1;
	const double PREV_FLUSH_CPU_PCT = 0.01;
	const uint64_t INITIAL_PREV_FLUSH_DURATION_NS = 13;
	std::atomic<uint64_t> prev_flushes_duration_ns(INITIAL_PREV_FLUSH_DURATION_NS);
	std::atomic<bool> metrics_sent(false);
	const double CPU_LOAD = 0.12;
	const bool EXTRA_INTERNAL_METRICS = true;
	draiosproto::metrics metrics;

	// Update the configuration so that the serializer will emit the
	// metrics to file.  Use the configuration object mainly to get
	// the metrics directory with the required trailing path delimiter.
	metric_serializer::c_metrics_dir.set(temp_dir.get_directory());

	std::unique_ptr<protobuf_metric_serializer> s(
			new protobuf_metric_serializer(&stats_source,
			                               int_metrics,
			                               ""));

	s->set_sample_callback(&analyzer_callback);
	s->serialize(make_unique<metric_serializer::data>(
				precanned_capture_stats_source::DEFAULT_EVTS,
				TIMESTAMP,
				SAMPLING_RATIO,
				PREV_FLUSH_CPU_PCT,
				prev_flushes_duration_ns,
				metrics_sent,
				CPU_LOAD,
				EXTRA_INTERNAL_METRICS,
				metrics));

	s->serialize(make_unique<metric_serializer::data>(
				precanned_capture_stats_source::DEFAULT_EVTS,
				TIMESTAMP * 2, // make timestamp bigger
				SAMPLING_RATIO,
				PREV_FLUSH_CPU_PCT,
				prev_flushes_duration_ns,
				metrics_sent,
				CPU_LOAD,
				EXTRA_INTERNAL_METRICS,
				metrics));


	// Wait for the async thread to complete the work.  If we have to wait
	// more that 5 seconds, something has gone badly wrong.
	const int FIVE_SECOND_IN_MS = 5 * 1000;
	for(int i = 0;
	    !s->serialization_complete() &&
	    (analyzer_callback.m_call_count != 2) &&
	    (i < FIVE_SECOND_IN_MS);
	    ++i)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	ASSERT_TRUE(analyzer_callback.m_call_count == 2);
}
