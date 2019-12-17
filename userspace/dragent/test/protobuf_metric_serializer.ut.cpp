/**
 * @file
 *
 * Unit tests for protobuf_metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "protobuf_metric_serializer.h"
#include "analyzer_utils.h"
#include "capture_stats_source.h"
#include "scoped_temp_directory.h"
#include "uncompressed_sample_handler.h"
#include "scoped_config.h"
#include "analyzer_flush_message.h"
#include "dragent_message_queues.h"
#include "configuration.h"
#include "metrics_file_emitter.h"

#include <chrono>
#include <memory>
#include <thread>
#include <gtest.h>

using dragent::metric_serializer;
using dragent::protobuf_metric_serializer;

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
	precanned_capture_stats_source(const uint64_t evts = DEFAULT_EVTS,
	                               const uint64_t drops = DEFAULT_DROPS,
	                               const uint64_t drops_buffer = DEFAULT_DROPS_BUFFER,
	                               const uint64_t drops_pf = DEFAULT_DROPS_PF,
	                               const uint64_t drops_bug = DEFAULT_DROPS_BUG,
	                               const uint64_t preemptions = DEFAULT_PREEMPTIONS,
	                               const uint64_t suppressed = DEFAULT_SUPPRESSED,
	                               const uint64_t tids_suppressed = DEFAULT_TIDS_SUPPRESSED)
	    : m_stats()
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
	void get_capture_stats(scap_stats* const stats) const override
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
 * A dummy realization of the uncompressed_sample_handler that saves the
 * values passed to handle_uncompressed_sample.
 */
class dummy_sample_handler : public uncompressed_sample_handler
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
	dummy_sample_handler(const uint32_t sleep_time = 0)
	    : m_ts_ns(UNSET_UINT64), m_metrics(UNSET_METRICS), m_sleep_time(sleep_time), m_call_count(0)
	{
	}

	/**
	 * Concrete realization of the handle_uncompressed_sample() API.
	 * Saves all parameters to locals.
	 */
	std::shared_ptr<serialized_buffer> handle_uncompressed_sample(
	    const uint64_t ts_ns,
	    std::shared_ptr<draiosproto::metrics>& metrics,
	    uint32_t flush_interval,
	    std::shared_ptr<protobuf_compressor>& compressor) override
	{
		m_ts_ns = ts_ns;
		m_metrics = metrics;
		m_flush_interval = flush_interval;
		m_compressor = compressor;

		if (m_sleep_time != 0)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(m_sleep_time));
		}
		++m_call_count;
		auto ret = std::make_shared<serialized_buffer>();
		ret->ts_ns = ts_ns;
		ret->message_type = 255;
		return ret;
	}

	uint64_t get_last_loop_ns() const
	{
		return 0;
	}

	uint64_t m_ts_ns;
	std::shared_ptr<draiosproto::metrics> m_metrics;
	uint32_t m_sleep_time;
	uint32_t m_flush_interval;
	std::shared_ptr<protobuf_compressor> m_compressor;
	std::atomic<uint8_t> m_call_count;
};

const uint64_t dummy_sample_handler::UNSET_UINT64 = std::numeric_limits<uint64_t>::max();
const uint32_t dummy_sample_handler::UNSET_UINT32 = std::numeric_limits<uint32_t>::max();
const double dummy_sample_handler::UNSET_DOUBLE = std::numeric_limits<double>::max();
draiosproto::metrics* const dummy_sample_handler::UNSET_METRICS = nullptr;
const uint32_t max_queue_size = 32;
flush_queue g_fqueue(max_queue_size);
protocol_queue g_pqueue(max_queue_size);
}  // end namespace

/**
 * Ensure that a newly-constructed protobuf_metric_serializer is in the
 * expected initial state.
 */
TEST(protobuf_metric_serializer_test, initial_state)
{
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<precanned_capture_stats_source>();
	dummy_sample_handler dsh;

	auto compressor = null_protobuf_compressor::get();

	std::unique_ptr<protobuf_metric_serializer> s(
	    new protobuf_metric_serializer(stats_source,
	                                   "",
	                                   dsh,
	                                   &g_fqueue,
	                                   &g_pqueue,
	                                   compressor));

	ASSERT_EQ(0, s->get_num_serializations_completed());
}

/**
 * Ensure that serialize() correctly serializes the data.
 */
TEST(protobuf_metric_serializer_test, serialize)
{
	test_helpers::scoped_temp_directory temp_dir;
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<precanned_capture_stats_source>();
	dummy_sample_handler analyzer_callback;

	dragent_configuration::m_terminate = false;

	const uint64_t TIMESTAMP = static_cast<uint64_t>(0x0000000000654321);
	const uint32_t SAMPLING_RATIO = 1;
	const uint64_t INITIAL_PREV_FLUSH_DURATION_NS = 13;
	std::atomic<uint64_t> prev_flushes_duration_ns(INITIAL_PREV_FLUSH_DURATION_NS);
	std::atomic<bool> metrics_sent(false);
	const double CPU_LOAD = 0.12;

	metric_serializer::c_metrics_dir.set(temp_dir.get_directory());

	auto compressor = null_protobuf_compressor::get();

	std::unique_ptr<protobuf_metric_serializer> s(
	    new protobuf_metric_serializer(stats_source,
	                                   "",
	                                   analyzer_callback,
	                                   &g_fqueue,
	                                   &g_pqueue,
	                                   compressor));
	std::thread t([&s]()
	{ s->test_run(); });

	ASSERT_EQ(0, s->get_num_serializations_completed());

	s->serialize(std::make_shared<flush_data_message>(TIMESTAMP,
	                                                  &metrics_sent,
	                                                  make_unique<draiosproto::metrics>(),
	                                                  precanned_capture_stats_source::DEFAULT_EVTS,
	                                                  precanned_capture_stats_source::DEFAULT_DROPS,
	                                                  CPU_LOAD,
	                                                  SAMPLING_RATIO,
	                                                  0));

	// Wait for the async thread to complete the work.  If we have to wait
	// more that 5 seconds, something has gone badly wrong.
	const int FIVE_SECOND_IN_MS = 5 * 1000;
	for (int i = 0; s->get_num_serializations_completed() == 0 && i < FIVE_SECOND_IN_MS; ++i)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// The serializer should have recorded that the metrics were sent
	ASSERT_EQ(true, metrics_sent);

	// The serializer should have invoked the handle_uncompressed_sample
	// callback
	ASSERT_EQ(TIMESTAMP, analyzer_callback.m_ts_ns);
	ASSERT_NE(nullptr, analyzer_callback.m_metrics);

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
	    dragent::metrics_file_emitter::generate_dam_filename(s->get_metrics_directory(), TIMESTAMP);

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
	ASSERT_GT(statbuf.st_size, 0);

	s->stop();
	t.join();
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
	std::shared_ptr<const capture_stats_source> stats_source =
	    std::make_shared<precanned_capture_stats_source>();
	const uint32_t sleep_time_ms = 3;
	dummy_sample_handler analyzer_callback(sleep_time_ms);

	dragent_configuration::m_terminate = false;

	const uint64_t TIMESTAMP = static_cast<uint64_t>(0x0000000000654321);
	const uint32_t SAMPLING_RATIO = 1;
	const uint64_t INITIAL_PREV_FLUSH_DURATION_NS = 13;
	std::atomic<uint64_t> prev_flushes_duration_ns(INITIAL_PREV_FLUSH_DURATION_NS);
	std::atomic<bool> metrics_sent(false);
	const double CPU_LOAD = 0.12;

	// Update the configuration so that the serializer will emit the
	// metrics to file.  Use the configuration object mainly to get
	// the metrics directory with the required trailing path delimiter.
	metric_serializer::c_metrics_dir.set(temp_dir.get_directory());

	auto compressor = null_protobuf_compressor::get();

	std::unique_ptr<protobuf_metric_serializer> s(
	    new protobuf_metric_serializer(stats_source,
	                                   "",
	                                   analyzer_callback,
	                                   &g_fqueue,
	                                   &g_pqueue,
	                                   compressor));
	std::thread t([&]()
	{ ASSERT_NO_THROW(s->test_run()); });

	s->serialize(std::make_shared<flush_data_message>(TIMESTAMP,
	                                                  &metrics_sent,
	                                                  make_unique<draiosproto::metrics>(),
	                                                  precanned_capture_stats_source::DEFAULT_EVTS,
	                                                  precanned_capture_stats_source::DEFAULT_DROPS,
	                                                  CPU_LOAD,
	                                                  SAMPLING_RATIO,
	                                                  0));

	s->serialize(std::make_shared<flush_data_message>(TIMESTAMP * 2,  // make timestamp bigger
	                                                  &metrics_sent,
	                                                  make_unique<draiosproto::metrics>(),
	                                                  precanned_capture_stats_source::DEFAULT_EVTS,
	                                                  precanned_capture_stats_source::DEFAULT_DROPS,
	                                                  CPU_LOAD,
	                                                  SAMPLING_RATIO,
	                                                  0));

	// Wait for the async thread to complete the work.  If we have to wait
	// more that 5 seconds, something has gone badly wrong.
	const int FIVE_SECOND_IN_MS = 5 * 1000;
	for (int i = 0; s->get_num_serializations_completed() < 2 && i < FIVE_SECOND_IN_MS; ++i)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	ASSERT_EQ(2, analyzer_callback.m_call_count);
	ASSERT_EQ(2, s->get_num_serializations_completed());

	s->stop();
	t.join();
}

// basic test to catch a bug found during development. if no dir set, don't flush
TEST(protobuf_metric_serializer_test, no_flush_to_file)
{
	dragent::metrics_file_emitter mfe;
	ASSERT_FALSE(mfe.emit_metrics_to_file(std::make_shared<flush_data_message>(
	    0, nullptr, make_unique<draiosproto::metrics>(), 0, 0, 0, 0, 0)));
	ASSERT_FALSE(mfe.emit_metrics_to_json_file(std::make_shared<flush_data_message>(
	    0, nullptr, make_unique<draiosproto::metrics>(), 0, 0, 0, 0, 0)));
}

using namespace dragent;

namespace
{
uncompressed_sample_handler_dummy g_sample_handler;
}

/**
 * Ensure that the constructed object is in the expected initial state.
 */
TEST(protobuf_metric_serializer_test, more_initial_state)
{
	test_helpers::scoped_config<std::string> config("metricsfile.location", "");
	std::shared_ptr<capture_stats_source> stats_source = nullptr;

	auto compressor = null_protobuf_compressor::get();

	std::unique_ptr<protobuf_metric_serializer> s(
	    new protobuf_metric_serializer(stats_source,
	                                   ".",
	                                   g_sample_handler,
	                                   &g_fqueue,
	                                   &g_pqueue,
	                                   compressor));

	ASSERT_NE(s.get(), nullptr);

	// non-null metrics dir implies emit to file
	ASSERT_FALSE(s->get_emit_metrics_to_file());
}

/**
 * ensure we deal with configuring the metrics directory correctly
 */
TEST(protobuf_metric_serializer_test, configuration)
{
	const std::string root_dir = "/foo";
	const std::string metrics_directory = "/tmp";
	test_helpers::scoped_config<std::string> config("metricsfile.location", metrics_directory);

	std::shared_ptr<capture_stats_source> stats_source = nullptr;

	auto compressor = null_protobuf_compressor::get();
	auto new_compressor = gzip_protobuf_compressor::get(-1);

	std::unique_ptr<protobuf_metric_serializer> s(
	    new protobuf_metric_serializer(stats_source,
	                                   root_dir,
	                                   g_sample_handler,
	                                   &g_fqueue,
	                                   &g_pqueue,
	                                   compressor));

	// Make sure that update_configuration() updates the values
	ASSERT_TRUE(s->get_emit_metrics_to_file());
	ASSERT_EQ("/foo/tmp/", s->get_metrics_directory());

	// Check that the set_metrics_directory API works
	s->set_metrics_directory("/bar/");
	ASSERT_TRUE(s->get_emit_metrics_to_file());
	ASSERT_EQ("/bar/", s->get_metrics_directory());

	// Check that we can disable it
	s->set_metrics_directory("");
	ASSERT_FALSE(s->get_emit_metrics_to_file());
	ASSERT_EQ("", s->get_metrics_directory());

	// Check that we can change the compression
	bool ret = s->set_compression(new_compressor);
	ASSERT_TRUE(ret);
}
