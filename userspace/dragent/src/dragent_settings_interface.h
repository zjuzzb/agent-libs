#pragma once

#include "handshake.pb.h"
#include "protobuf_compression.h"
#include "protocol.h"
#include <chrono>
#include <functional>
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

class metric_limit_source
{
public:
	virtual ~metric_limit_source() = default;

	using callback = std::function<void(bool has_limit, draiosproto::custom_metric_limit_value value)>;

	void register_metric_limit_destination(const callback &cb)
	{
		m_destination = cb;
	}

protected:
	void set_metric_limit(draiosproto::handshake_v1_response &resp)
	{
		if (nullptr == m_destination) 
		{
			return;
		}

		if (resp.has_custom_metric_limit()) 
		{
			m_destination(true, resp.custom_metric_limit());
		}
		else
		{
			m_destination(false, draiosproto::custom_metric_limit_value::CUSTOM_METRIC_DEFAULT);
		}
	}


private:
	callback m_destination;

};
