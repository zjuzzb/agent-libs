/**
 * @file
 *
 * Interface to protobuf_metric_serializer.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "metric_serializer.h"

#include <condition_variable>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

class capture_stats_source;
struct scap_stats;

namespace libsanalyzer
{

/**
 * A concrete metric_serializer for asynchronously writing metrics in
 * protobuf format to the back-end.
 */
class protobuf_metric_serializer : public metric_serializer
{
public:
	/**
	 * Initialize this protobuf_metric_serializer.
	 *
	 * @param[in] stats_source     The source from which to fetch stats.
	 * @param[in] internal_metrics The internal_metrics that might be
	 *                             serialized.
	 * @param[in] root_dir The root dir base of the application 
	 */
	protobuf_metric_serializer(capture_stats_source* stats_source,
	                           const internal_metrics::sptr_t& internal_metrics,
				   const std::string& root_dir);

	~protobuf_metric_serializer() override;

	/**
	 * Concrete realization of the serialize() API that perform an async,
	 * protobuf-based serialization.
	 */
	void serialize(std::unique_ptr<data>&& data) override;

	void drain() const override;

	//
	// The following APIs are not part of the metric_serializer interface
	// and should not be used directly by client code.  They are intended
	// to provide visibility to the unit test (the only thing other than
	// the factory that should know about a concrete
	// protobuf_metric_serializer).
	//

	/** Returns the previous sample event number. */
	uint64_t get_prev_sample_evtnum() const;

	/** Returns the previous sample time. */
	uint64_t get_prev_sample_time() const;

	/** Returns the number of dropped events in the previous sample. */
	uint64_t get_prev_sample_num_drop_events() const;

	/**
	 * Returns true if there is no async serialization in progress.
	 */
	bool serialization_complete() const;

	/**
	 * Get the dam filename.
	 *
	 * @param[in] directory the directory in which the file will exist.
	 *                      This must include the trailing directory
	 *                      delimiter.
	 * @param[in] timestamp The timestamp base for the filename.
	 */
	static std::string generate_dam_filename(const std::string& directory,
	                                         uint64_t timestamp);

private:
	/**
	 * Reset m_data and notify any threads waiting for it to become
	 * empty.
	 */
	void clear_data();

	/**
	 * A protobuf_metric_serializer will start a new thread on creation
	 * with this method as that thread's entry point.  This will block
	 * waiting for work, do that work, then block again waiting for work.
	 * This method will terminate when the protobuf_metric_serializer
	 * is destroyed.
	 */
	void serialization_thread();

	/**
	 * This is the meat of the serialization work.
	 */
	void do_serialization();

	/**
	 * Helper method that invokes the callback during serialization.
	 */
	void invoke_callback(const scap_stats& st,
	                     uint64_t nevts,
	                     uint64_t num_dropped_events);

	/**
	 * Writes the dam file during serialization.
	 */
	void emit_metrics_to_file();

	/**
	 * Writes the metrics to individual JSON files during serialization.
	 */
	void emit_metrics_to_json_file() const;

	std::unique_ptr<data> m_data;
	mutable std::mutex m_data_mutex;
	std::condition_variable m_data_available_condition;
	std::condition_variable m_serialization_complete_condition;
	std::atomic<bool> m_stop_thread;

	capture_stats_source* m_capture_stats_source;
	std::ofstream m_protobuf_file;
	uint64_t m_prev_sample_evtnum;
	uint64_t m_prev_sample_time;
	uint64_t m_prev_sample_num_drop_events;

	std::thread m_thread; // Must be last
};

} // end namespace libsanalyzer
