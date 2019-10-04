#pragma once

#include "draios.proto.h"

// in order to override any of the generated function,
// 1) create the impl class that derives from the generated aggregator
// 2) write the allocator, and override any functions you need to
// 3) override the appropriate builder function in the builder_impl below


class process_details_message_aggregator_impl : public process_details_message_aggregator
{
public:
	process_details_message_aggregator_impl(const message_aggregator_builder& builder)
		: process_details_message_aggregator(builder)
	{}

private:
	// args need to be treated like a list, not a set, so needs special handling
	virtual void aggregate_args(const draiosproto::process_details& input,
				    draiosproto::process_details& output);

	// backend always sets container id, even if not set in input, so we do, too
	virtual void aggregate_container_id(const draiosproto::process_details& input,
					    draiosproto::process_details& output);
};

// for any message type which we've overridden, we have to override it's builder
// function as well
class message_aggregator_builder_impl : public message_aggregator_builder
{
	virtual agent_message_aggregator<draiosproto::process_details>& build_process_details() const;
};
