#pragma once

#include "protobuf_compression.h"
#include "protocol.h"
#include <chrono>
#include <memory>

class aggregation_interval_source
{
public:
	virtual ~aggregation_interval_source() = default;

	virtual std::chrono::seconds get_negotiated_aggregation_interval() const = 0;
};

class compression_method_source
{
public:
	virtual ~compression_method_source() = default;

	virtual std::shared_ptr<protobuf_compressor>& get_negotiated_compression_method() = 0;
};
