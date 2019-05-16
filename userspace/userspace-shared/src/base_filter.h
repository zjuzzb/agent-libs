#pragma once
#include <Poco/RegularExpression.h>
#include <string>
#include <list>
#include <memory>

/**
 * allows filtering on an arbitrary set of types and rules.
 *
 * @tparam filter_param is an arbitrary data type that will be passed in. It must
 * contain all the data necessary in order to complete the matching for
 * a given filter. It should also implement to_string.
 */ 
template<typename filter_param>
class base_filter {
public:
	/**
	 * @param exclude_on_match determines the behavior of the filter if
	 *	  there is a positive match. If true, filter will return false on match
	 *	  else it will return true.
	 */
	base_filter(bool exclude_on_match)
		: m_exclude_on_match(exclude_on_match)
	{
	}

	/**
	 * indicates whether the data stored in arg matches the filter
	 *
	 * returns true if there is a match, or false otherwise
	 * 
	 * @param[out] exclude indicates whether this filter is set to exclude on match
	 *
	 * @param[out] high_priority indicates whether the match is high_priority
	 *             as defined by the implementation. Undefined if function returns
	 *             false
	 *
	 * @param[out] reason a string indicating the reason a match occurred. May not be
	 *	       populated if a match did not occur
	 */
	virtual bool matches(const filter_param& arg,
			     bool& exclude,
			     bool& high_prioriy,
			     std::string& reason) const = 0;

	/**
	 * indicates whether this filter should set exclude to true in the case of
	 * a match
	 */
	bool exclude_on_match() const
	{
		return m_exclude_on_match;
	}

private:
	const bool m_exclude_on_match;
};

/**
 * courtesy filter which always returns true at low priority
 */
template<typename filter_param>
class all_filter : public base_filter<filter_param>
{
public:
	all_filter(bool exclude_on_match)
		: base_filter<filter_param>(exclude_on_match)
	{
	}

	bool matches(const filter_param& arg,
		     bool& exclude,
		     bool& high_prioriy,
		     std::string& reason) const;
};

/**
 * courtesy filter which compares objects for equality
 *
 * returns high priority
 */
template<typename filter_param>
class equal_filter : public base_filter<filter_param>
{
public:
	equal_filter(bool exclude_on_match,
		     const filter_param& arg)
		: base_filter<filter_param>(exclude_on_match),
	          m_arg(arg)
	{
	}

	bool matches(const filter_param& arg,
		     bool& exclude,
		     bool& high_priority,
		     std::string& reason) const;

private:
	filter_param m_arg;
};

/**
 * courtesy filter which applies regex comparison for a string
 *
 * returns high priority
 */
template<typename filter_param>
class regex_filter : public base_filter<filter_param>
{
public:
	regex_filter(bool exclude_on_match,
		     const std::string& pattern,
		     std::function<const std::string&(const filter_param&)> extractor)
		: base_filter<filter_param>(exclude_on_match),
		  m_pattern(pattern),
		  m_regex(pattern),
		  m_extractor(extractor)
	{
	}


		bool matches(const filter_param& arg,
		     bool& exclude,
		     bool& high_priority,
		     std::string& reason) const;

private:
	std::string m_pattern;
	Poco::RegularExpression m_regex;
	std::function<const std::string&(const filter_param&)> m_extractor;
};

/**
 * courtesy filter for wildcard matches
 *
 * returns high priority
 */
template<typename filter_param>
class wildcard_filter : public base_filter<filter_param>
{
public:
	wildcard_filter(bool exclude_on_match,
			const std::string& pattern,
			std::function<const std::string&(const filter_param&)> extractor)
		: base_filter<filter_param>(exclude_on_match),
		  m_pattern(pattern),
		  m_extractor(extractor)
	{
	}


	bool matches(const filter_param& arg,
		     bool& exclude,
		     bool& high_priority,
		     std::string& reason) const;

private:
	std::string m_pattern;
	std::function<const std::string&(const filter_param&)> m_extractor;
};


/**
 * courtesy filter which returns the FIRST match of a set of filters, and inherits
 * it's priority/exclusion/reason.
 */
template<typename filter_param>
class priority_filter: public base_filter<filter_param>
{
public:
	priority_filter(const std::list<std::shared_ptr<base_filter<filter_param>>>& sub_filters)
		: base_filter<filter_param>(false),
		  m_sub_filters(sub_filters)
	{
	}

	bool matches(const filter_param& arg,
		     bool& exclude,
		     bool& high_priority,
		     std::string& reason) const;

	/**
	 * courtesy function which returns the number of the rule which matches, as
	 * determined by the order of the rules when the filter was initially created
	 *
	 * @param[out] rule_number the index of the rule which ultimately matched for this
	 *             filter. Undefined if no match is made.
	 */
	bool matches(const filter_param& arg,
		     bool& exclude,
		     bool& high_priority,
		     std::string& reason,
		     uint32_t& rule_number) const;

private:
	std::list<std::shared_ptr<base_filter<filter_param>>> m_sub_filters;
};

/**
 * courtesy filter which returns true if all of a set of filters are true
 *
 * considered high priority if all of the matching filters are high priority
 * exclude on match of sub-filters is overwritten by configured value.
 *
 * An and filter with no conditions always is met with high priority.
 *
 * reason string is concatenation of reasons of all subfilters
 */
template<typename filter_param>
class and_filter : public base_filter<filter_param>
{
public:
	and_filter(bool exclude_on_match,
		   const std::list<std::shared_ptr<base_filter<filter_param>>>& sub_filters)
		: base_filter<filter_param>(exclude_on_match),
		  m_sub_filters(sub_filters)
	{
	}

	bool matches(const filter_param& arg,
		     bool& exclude,
		     bool& high_priority,
		     std::string& reason) const;
private:
	std::list<std::shared_ptr<base_filter<filter_param>>> m_sub_filters;
};

#include "filter_matches.hpp"
