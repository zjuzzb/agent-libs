#include "aggregator_overrides.h"

// unlike almost every other repeated non-message field, this is a list, not
// a set. It is also a primary key. So in this case, the first time we call
// into it, copy the list. Then don't do anything further times, as the lists
// would have to be equal anyway (because it's a primary key)
void process_details_message_aggregator_impl::aggregate_args(const draiosproto::process_details& input,
							     draiosproto::process_details& output)
{
	if (output.args().size() == 0)
	{
		for (auto i : input.args())
		{
			output.add_args(i);
		}
	}
}

void process_details_message_aggregator_impl::aggregate_container_id(const draiosproto::process_details& input,
								     draiosproto::process_details& output)
{
	if (!output.has_container_id())
	{
		output.set_container_id("");

	}
	process_details_message_aggregator::aggregate_container_id(input, output);
}

agent_message_aggregator<draiosproto::process_details>&
message_aggregator_builder_impl::build_process_details() const
{
	return *(new process_details_message_aggregator_impl(*this));
}
