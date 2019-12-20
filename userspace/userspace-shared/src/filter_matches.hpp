#include <fnmatch.h>

template<typename filter_param>
bool all_filter<filter_param>::matches(const filter_param& arg,
				       bool& exclude,
				       bool& high_priority,
				       std::string* reason) const
{
	exclude = this->exclude_on_match();
	high_priority = false;
	if (reason) {
		*reason = "all";
	}
	return true;
}

template<typename filter_param>
bool equal_filter<filter_param>::matches(const filter_param& arg,
					 bool& exclude,
					 bool& high_priority,
					 std::string* reason) const
{
	if (arg == m_arg)
	{
		exclude = this->exclude_on_match();
		high_priority = true;
		if (reason) {
			*reason = "equality match";
		}
		return true;
	}

	return false;
}

template<typename filter_param>
bool regex_filter<filter_param>::matches(const filter_param& arg,
					 bool& exclude,
					 bool& high_priority,
					 std::string* reason) const
{
	const std::string& str_arg = m_extractor(arg);

	if (m_regex.match(str_arg))
	{
		exclude = this->exclude_on_match();
		high_priority = true;
		if (reason) {
			*reason = str_arg + " matches regex " + m_pattern;
		}
		return true;
	}

	return false;
}

template<typename filter_param>
bool wildcard_filter<filter_param>::matches(const filter_param& arg,
					    bool& exclude,
					    bool& high_priority,
					    std::string* reason) const
{
	const std::string& str_arg = m_extractor(arg);

	if (!fnmatch(m_pattern.c_str(), str_arg.c_str(), FNM_EXTMATCH))
	{
		exclude = this->exclude_on_match();
		high_priority = true;
		if (reason) {
			*reason = str_arg + " matches wildcard " + m_pattern;
		}
		return true;
	}

	return false;
}

template<typename filter_param>
bool priority_filter<filter_param>::matches(const filter_param& arg,
					    bool& exclude,
					    bool& high_priority,
					    std::string* reason) const
{
	uint32_t rule_num;
	return matches(arg, exclude, high_priority, reason, rule_num);
}

template<typename filter_param>
bool priority_filter<filter_param>::matches(const filter_param& arg,
					    bool& exclude,
					    bool& high_priority,
					    std::string* reason,
					    uint32_t& rule_number) const
{
	rule_number = 0;
	for (const auto& i : m_sub_filters)
	{
		bool high_priority_temp;
		bool exclude_temp;

		if (i->matches(arg, exclude_temp, high_priority_temp, reason))
		{
			high_priority = high_priority_temp;
			exclude = exclude_temp;
			return true;
		}
		rule_number++;
	}

	return false;
}

template<typename filter_param>
bool and_filter<filter_param>::matches(const filter_param& arg,
				       bool& exclude,
				       bool& high_priority,
				       std::string* reason) const
{
	high_priority = true;
	if (reason) {
		*reason = "and filter matches:";
	}

	for (const auto& i : m_sub_filters)
	{
		bool exclude_temp;
		bool high_priority_temp;
		std::string reason_temp;

		// short circuit if we can
		if (!i->matches(arg, exclude_temp, high_priority_temp, reason ? &reason_temp : nullptr))
		{
			return false;
		}

		high_priority &= high_priority_temp;
		if (reason) {
			*reason += reason_temp + ";";
		}
	}

	exclude = this->exclude_on_match();
	return true;
}
