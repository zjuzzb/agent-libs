#pragma once

#include <stdint.h>
#include <memory>
#include "protocol.h"

namespace draiosproto
{
class metrics;
}

/**
 * virtual class that defines the API invoked when the uncompressed protobuf for a given sample
 * is fully populated. Courtesy default implementations are provided
 */
class uncompressed_sample_handler
{
public:
	/**
	 * call when the uncompressed protobuf is fully populated and ready to be
	 * compressed or otherwise processed
	 *
	 * @param[in] ts_ns timestamp of the sample, in ns
	 * @param[in] metrics the protobuf containing the uncompressed data for this sample
	 *
	 * @return The processed protobuf
	 */
	virtual std::shared_ptr<serialized_buffer> handle_uncompressed_sample(uint64_t ts_ns,
	                    std::shared_ptr<draiosproto::metrics>& metrics) = 0;

	/**
	 * returns the timestamp of the last invokation of handle_uncompressed_sample
	 */
	virtual uint64_t get_last_loop_ns() const = 0;
};

class uncompressed_sample_handler_dummy : public uncompressed_sample_handler
{
public:
	virtual std::shared_ptr<serialized_buffer> handle_uncompressed_sample(uint64_t ts_ns,
	                    std::shared_ptr<draiosproto::metrics>& metrics)
	{
		return nullptr;
	}

	virtual uint64_t get_last_loop_ns() const
	{
		return 0;
	}
};
