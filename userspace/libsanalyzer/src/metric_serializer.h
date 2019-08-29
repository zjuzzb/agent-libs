/**
 * @file
 *
 * Interface to metric_serializer -- an abstract base class for analyzer
 * metric serialization.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#pragma once

#include "internal_metrics.h"
#include <atomic>
#include <memory>
#include <mutex>
#include "type_config.h"
#include "uncompressed_sample_handler.h"

namespace draiosproto { class metrics; }

class test_helper;

namespace libsanalyzer
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

	/**
	 * Enable clients of the serialize() API to pass in data in the form
	 * in which we'll store it.  Client code should not use this class
	 * outside of calls to serialize().
	 */
	class data
	{
	public:
		data(uint64_t evt_num,
		     uint64_t ts,
		     uint32_t sampling_ratio,
		     double prev_flush_cpu_pct,
		     uint64_t prev_flushes_duration_ns,
		     std::atomic<bool>& metrics_sent,
		     double my_cpuload,
		     const draiosproto::metrics& metrics);

		const uint64_t m_evt_num;
		const uint64_t m_ts;
		const uint32_t m_sampling_ratio;
		const double m_prev_flush_cpu_pct;
		const uint64_t m_prev_flushes_duration_ns;
		std::atomic<bool>& m_metrics_sent;
		const double m_my_cpuload;
		std::shared_ptr<draiosproto::metrics> m_metrics;
	};


	/**
	 * Initialize this metric_serializer.
	 *
	 * @param[in] internal_metrics The internal metrics to serialize.
	 * @param[in] root_dir    The root dir base of the application
	 * @param[in] sample_handler the object implementing the function
	 *            "handle_uncompressed_sample" to be invoked when sample processing
	 *            is completed
	 */
	metric_serializer(const internal_metrics::sptr_t& internal_metrics,
			  const std::string& root_dir,
			  uncompressed_sample_handler& sample_handler);

	virtual ~metric_serializer() = default;

	/**
	 * Start the serialization process for the given data.  This process
	 * may be performed asynchronously, client code must handle async
	 * updates to anything passed by reference to data's constructor.
	 *
	 * @param[in] data The data to serialize.
	 */
	virtual void serialize(std::unique_ptr<data>&& data) = 0;

	/**
	 * Wait for any potentially async serialization operations to complete.
	 */
	virtual void drain() const = 0;

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
	internal_metrics::sptr_t m_internal_metrics;
	uncompressed_sample_handler& m_uncompressed_sample_handler;

public: // configs
	static type_config<std::string> c_metrics_dir;

	friend class ::test_helper;
};

} // end namespace libsanalyzer
