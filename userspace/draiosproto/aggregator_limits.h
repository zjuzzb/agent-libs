#pragma once
#include "draios.proto.h"

#include <functional>
#include <list>

namespace aggregator_limits_comparators
{
bool status_code_details_comparator(const draiosproto::status_code_details& lhs,
                                    const draiosproto::status_code_details& rhs);
bool status_code_details_reverse_comparator(const draiosproto::status_code_details& lhs,
                                            const draiosproto::status_code_details& rhs);

bool container_priority_comparator(const draiosproto::container& lhs,
                                   const draiosproto::container& rhs);
bool program_priority_comparator(const draiosproto::program& lhs, const draiosproto::program& rhs);

template<typename message>
void file_stat_limiter(
    message& output,
    uint32_t limit,
    std::function<google::protobuf::RepeatedPtrField<draiosproto::file_stat>*(message&)>
        field_extractor);

template<typename message, typename field>
void app_metric_limiter(message& output, uint32_t limit);

template<typename proto, typename tiebreak = const std::string&>
class message_comparator
{
public:
	message_comparator(std::function<uint64_t(const proto&)> value_extractor,
	                   std::function<tiebreak(const proto&)> tiebreaker_extractor)
	    : m_value_extractor(value_extractor),
	      m_tiebreaker_extractor(tiebreaker_extractor)
	{
	}

	bool operator()(const proto& lhs, const proto& rhs)
	{
		uint64_t lhs_value = m_value_extractor(lhs);
		uint64_t rhs_value = m_value_extractor(rhs);
		if (lhs_value != rhs_value)
		{
			return lhs_value > rhs_value;
		}
		return m_tiebreaker_extractor(rhs) > m_tiebreaker_extractor(lhs);
	}
	std::function<uint64_t(const proto&)> m_value_extractor;
	std::function<tiebreak(const proto&)> m_tiebreaker_extractor;
};

template<typename message, typename field, typename tiebreak = const std::string&>
void multi_compare_limiter(
    message& output,
    uint32_t limit,
    std::function<google::protobuf::RepeatedPtrField<field>*(message&)> field_extractor,
    std::list<message_comparator<field, tiebreak> > comparators,
    uint32_t start_index = 0)
{
	if (limit >= field_extractor(output)->size())
	{
		return;
	}

	uint32_t limit_each = limit / comparators.size();
	uint32_t index = start_index;

	for (auto i : comparators)
	{
		uint32_t start_offset = index * limit_each;
		uint32_t end_offset = (index + 1) * limit_each;

		std::partial_sort(field_extractor(output)->begin() + start_offset,
		                  field_extractor(output)->begin() + end_offset,
		                  field_extractor(output)->end(),
		                  i);

		index++;
	}
	field_extractor(output)->DeleteSubrange(
	    start_index + limit,
	    field_extractor(output)->size() - (start_index + limit));
}
}  // namespace aggregator_limits_comparators
