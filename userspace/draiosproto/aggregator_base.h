#pragma once
#include <stdint.h>
#include "draios.pb.h"
#include "common.pb.h"

class message_aggregator_builder;

template <typename message_type>
class agent_message_aggregator {
protected:
	const message_aggregator_builder& m_builder;
public:
	agent_message_aggregator(const message_aggregator_builder& builder)
		: m_builder(builder)
	{
	}
	
	virtual ~agent_message_aggregator()
	{
	}

	virtual void aggregate(const message_type& input,
			       message_type& output) = 0;

	virtual void reset() = 0;

	// input type should be some numeric type
	// output type should be one of the aggregations types
	template <typename input_type, typename output_type>
	static void default_aggregate_value(input_type input,
					    output_type& output)
	{
		if (input > output.max() || output.weight() == 0)
		{
			output.set_max(input);
		}
		if (input < output.min() || output.weight() == 0)
		{
			output.set_min(input);
		}
		output.set_sum(input + output.sum());
		output.set_weight(output.weight() + 1);
	}

	// input should be indexable container of numeric types
	// output should be indexable container of aggregation types
	template <typename input_type, typename output_type>
	static void default_aggregate_list(input_type input,
					   output_type& output)
	{
		while (output.max().size() < input.size())
		{
			output.add_max(0);
			output.add_sum(0);
			output.add_min(0);
		}

		for (uint32_t i = 0; i < input.size(); i++)
		{
			if (input[i] > output.max()[i] || output.weight() == 0)
			{
				(*output.mutable_max())[i] = input[i];
			}
			if (input[i] < output.min()[i] || output.weight() == 0)
			{
				(*output.mutable_min())[i] = input[i];
			}
			(*output.mutable_sum())[i] += input[i];
		}
		output.set_weight(output.weight() + 1);
	}
};
