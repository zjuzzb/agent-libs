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
#include "protocol.h"
#include "protobuf_compression.h"
#include "type_config.h"
#include "uncompressed_sample_handler.h"
#include "analyzer_flush_message.h"
#include "dragent_message_queues.h"

namespace draiosproto
{
class metrics;
}

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
	virtual void serialize(flush_data&& data) = 0;

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
	virtual bool get_emit_metrics_to_file() const = 0;

	/**
	 * Returns the path to the directory into which this metric_serializer
	 * will write metrics to file.  This method's return value is
	 * meaningful only when get_emit_metrics_to_file() returns true.
	 */
	virtual std::string get_metrics_directory() const = 0;

	/**
	 * Set the absolute path to the metrics directory.
	 *
	 * Setting this to "" terminates logging to file.
	 * The directory will be created if it does not exist.
	 */
	virtual void set_metrics_directory(const std::string&) = 0;

	/**
	 * Sets the compressor for this serializer.
	 *
	 * Returns true if the compressor is valid, false otherwise.
	 */
	virtual bool set_compression(std::shared_ptr<protobuf_compressor> compressor) = 0;

protected:
	uncompressed_sample_handler& m_uncompressed_sample_handler;
	flush_queue* m_input_queue;
	protocol_queue* m_output_queue;

public:  // configs
	static type_config<std::string> c_metrics_dir;

	friend class ::test_helper;
};

}  // end namespace dragent
