/**
 * @file
 *
 * Interface to protobuf_metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "metric_serializer.h"
#include "dragent_message_queues.h"
#include "watchdog_runnable.h"
#include "protobuf_compression.h"

#include <condition_variable>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <memory>
#include "metrics_file_emitter.h"

class capture_stats_source;
struct scap_stats;

namespace dragent
{

/**
 * A concrete metric_serializer for asynchronously writing metrics in
 * protobuf format to the back-end.
 */
class protobuf_metric_serializer : public metric_serializer, public dragent::watchdog_runnable
{
	const uint64_t DEFAULT_MQUEUE_READ_TIMEOUT_MS = 300;

public:
	/**
	 * Initialize this protobuf_metric_serializer.
	 *
	 * NOTE: The constructor starts the serialization thread. The serializer
	 * is active and ready to serialize upon construction.
	 *
	 * @param[in] stats_source     The source from which to fetch stats.
	 * @param[in] root_dir         The root dir base of the application
	 * @param[in] sample_handler   The serialization handler
	 * @param[in] input_queue      The queue for incoming unserialized data
	 * @param[in] output_queue     The queue for outgoing serialized data
	 * @param[in] compressor       The compressor for the serialized protobufs
	 */
	protobuf_metric_serializer(std::shared_ptr<const capture_stats_source> stats_source,
	                           const std::string& root_dir,
	                           uncompressed_sample_handler& sample_handler,
	                           flush_queue* input_queue,
	                           protocol_queue* output_queue,
	                           std::shared_ptr<protobuf_compressor>& compressor);

	~protobuf_metric_serializer() override;

	/**
	 * Concrete realization of the serialize() API that perform an async,
	 * protobuf-based serialization.
	 */
	void serialize(flush_data&& data) override;

	void drain() const override;

	void stop() override;

	//
	// The following APIs are not part of the metric_serializer interface
	// and should not be used directly by client code.  They are intended
	// to provide visibility to the unit test (the only thing other than
	// the factory that should know about a concrete
	// protobuf_metric_serializer).
	//

	/** Returns the number of serializations this serializer has done */
	uint64_t get_num_serializations_completed() const;

	/**
	 * Get the dam filename.
	 *
	 * @param[in] directory the directory in which the file will exist.
	 *                      This must include the trailing directory
	 *                      delimiter.
	 * @param[in] timestamp The timestamp base for the filename.
	 */
	static std::string generate_dam_filename(const std::string& directory, uint64_t timestamp);

	bool get_emit_metrics_to_file() const override;
	std::string get_metrics_directory() const override;
	void set_metrics_directory(const std::string&) override;
	bool set_compression(std::shared_ptr<protobuf_compressor> compressor) override;

#ifdef SYSDIG_TEST
	void test_run()
	{
		do_run();
	}
#endif
private:
	/**
	 * Reset m_data and notify any threads waiting for it to become
	 * empty.
	 */
	void clear_data();

	/**
	 * This will block waiting for work, do that work, then block
	 * again waiting for work. This method will terminate when the
	 * protobuf_metric_serializer is destroyed or stop() is called.
	 */
	void do_run() override;

	/**
	 * This is the meat of the serialization work.
	 */
	void do_serialization(flush_data& data);

	/**
	 * Writes the dam file during serialization.
	 */
	void emit_metrics_to_file(const flush_data& data);

	/**
	 * Writes the metrics to individual JSON files during serialization.
	 */
	void emit_metrics_to_json_file(const flush_data& data) const;

	std::atomic<bool> m_stop_thread;

	std::shared_ptr<const capture_stats_source> m_capture_stats_source;
	uint64_t m_serializations_completed;

	metrics_file_emitter m_file_emitter;

	std::shared_ptr<protobuf_compressor> m_compressor;

	std::thread m_thread;  // Must be last
};

}  // end namespace dragent
