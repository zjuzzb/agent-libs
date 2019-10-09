/**
 * @file
 *
 * Interface to metric_serializer -- an abstract base class for analyzer
 * metric serialization.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include "blocking_queue.h"
#include "protocol.h"
#include "type_config.h"
#include "uncompressed_sample_handler.h"
#include "analyzer_flush_message.h"
#include "dragent_message_queues.h"

namespace draiosproto { class metrics; }

class test_helper;

namespace dragent
{

/**
 * Abstract base class for analyzer metric serialization.
 */
class metric_serializer
{
public:
	/**
	 * Sentinel event number that indicates that a serialization operation
	 * was not triggered by an event.
	 */
	const static uint64_t NO_EVENT_NUMBER;
	typedef flush_data data;

	/**
	 * Initialize this metric_serializer.
	 *
	 * @param[in] root_dir         The root dir base of the application
	 * @param[in] sample_handler   The object which performs the serialization
	 * @param[in] input_queue      The queue on which flush data are received
	 * @param[in] output_queue     The queue to which serialized data are written
	 */
	metric_serializer(const std::string& root_dir,
	                  uncompressed_sample_handler& sample_handler,
	                  flush_queue* input_queue,
	                  protocol_queue* output_queue);

	virtual ~metric_serializer() = default;

	/**
	 * Enqueue the data item onto the serialization queue.
	 *
	 * @param[in] data The data to serialize.
	 */
	virtual void serialize(data&& data) = 0;

	/**
	 * Wait for any potentially async serialization operations to complete.
	 */
	virtual void drain() const = 0;

	/**
	 * Shut down the serializer
	 */
	virtual void stop() = 0;

	/**
	 * Returns true if this metric_serializer is configured to emit
	 * metrics to file, false otherwise.
	 */
	bool get_emit_metrics_to_file() const;

	/**
	 * Returns the path to the directory into which this metric_serializer
	 * will write metrics to file.  This method's return value is
	 * meaningful only when get_emit_metrics_to_file() returns true.
	 */
	std::string get_metrics_directory() const;

	/**
	 * set the absolute path to the metrics directory.
	 *
	 * Setting this to "" terminates logging to file.
	 * The directory will be created if it does not exist.
	 */
	void set_metrics_directory(const std::string&);

private:
	mutable std::mutex m_metrics_dir_mutex;
	std::string m_root_dir;
	std::string m_metrics_dir;

protected:
	uncompressed_sample_handler& m_uncompressed_sample_handler;
	flush_queue* m_input_queue;
	protocol_queue* m_output_queue;

public: // configs
	static type_config<std::string> c_metrics_dir;

	friend class ::test_helper;
};

} // end namespace dragent
