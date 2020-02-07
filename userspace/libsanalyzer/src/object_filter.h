#pragma once
#include "analyzer_thread.h"
#include "base_filter.h"
#include "object_filter_config.h"
#include "sinsp.h"

#include <vector>

class infrastructure_state;

/**
 * filter args object contains all the fields that are required by any of the valid
 * filters for a process
 */
class process_filter_args
{
public:
	process_filter_args(const THREAD_TYPE* tinfo,
	                    const THREAD_TYPE* mtinfo,
	                    const sinsp_container_info* container,
	                    const infrastructure_state* is)
	    : m_tinfo(tinfo),
	      m_mtinfo(mtinfo),
	      m_container(container),
	      m_is(is)
	{
	}

	const THREAD_TYPE* m_tinfo;
	const THREAD_TYPE* m_mtinfo;
	const sinsp_container_info* m_container;
	const infrastructure_state* m_is;
};

/**
 * top-level class for defining a filter of most of our metadata objects, namely containers and
 *processes.
 *
 * It is defined by a set of filter_rules which each specify a set of conditions. A rule is
 *considered met
 * if all of its conditions are met, and only the first met rule is considered. Each rule is
 *associated
 * with an inclusion or exclusion which determines the value returned during the match.
 *
 * The match is considered generic only if all conditions in the matching rule are considered
 *generic.
 */
class object_filter
{
public:
	object_filter(const std::string& name) : m_name(name){};

	/**
	 * apply a match against the 4 provided arguments. If any sub-filter requires info from
	 * a field which has no been provided, that sub-filter will not match.
	 *
	 * @param[out] indicates whether the match was generic. see specific sub-filters
	 *             for descriptions of how they behave.
	 *             (mostly just "all" filter returns generic, the rest don't)
	 * @param[out] returns a pointer to the rule which defines the filter which
	 *             ultimately matched
	 */
	bool matches(const THREAD_TYPE* tinfo,
	             const THREAD_TYPE* mtinfo,
	             const sinsp_container_info* container,
	             const infrastructure_state* is,
	             bool* generic_match,
	             const object_filter_config::filter_rule** match_rule,
	             std::string* reason) const;

	/**
	 * create the filter defined by the given rules. May be called multiple times.
	 * If the vector is empty, an "all" filter is created
	 */
	void set_rules(const std::vector<object_filter_config::filter_rule>& rules);

	/**
	 * get a callback to reg for each rule which was used to configure
	 * this filter. See comment below for further explanation
	 */
	void register_annotations(std::function<void(const std::string&)> reg) const;

private:
	std::shared_ptr<priority_filter<process_filter_args>> m_filter;

	std::string m_name;
	/**
	 * How this generally works is
	 * - config creates list of rules
	 * - filters created from set of rules
	 * - external dependencies call in, and ask for a callback to be immediately
	 *   made for each rule.
	 *
	 * This flow is not ideal, but until we those dependencies can get their information
	 * directly from the filters, we'll have to cache the initial set of rules.
	 */
	std::vector<object_filter_config::filter_rule> m_rules;

	friend class test_helper;
};

/**
 * checks whether tinfo contains any ports which match the configured
 * port filter rules
 *
 * The rules work as follows:
 * -each rule can either match a range of ports, or an explicit set of ports
 * -if the rule indicates "include", we add ports to a matched set
 * -if the rule doesn't indicate "include", we prevent inclusion in the matched set
 * -rules are given priority based on their order
 *
 *  This should be replaced by a priority filter in the future
 *
 *  This filter always returns a high_priority result and never excludes.
 */
template<typename filter_param>
class port_filter : public base_filter<filter_param>
{
public:
	port_filter(const std::vector<object_filter_config::port_filter_rule>& ports)
	    : base_filter<filter_param>(false),
	      m_ports(ports)
	{
	}

	bool matches(const filter_param& arg,
	             bool& exclude,
	             bool& high_priority,
	             std::string* reason) const final;

	static std::set<uint16_t> filter_ports(
	    const std::set<uint16_t>& sports,
	    const std::vector<object_filter_config::port_filter_rule>& rules);

private:
	std::vector<object_filter_config::port_filter_rule> m_ports;
};

/**
 * checks whether the provided m_tinfo->m_comm is a wildcard match with provided pattern
 *
 * This filter always returns a high_priority result and never excludes.
 */
template<typename filter_param>
class process_name_filter : public wildcard_filter<filter_param>
{
public:
	process_name_filter(const std::string& pattern)
	    : wildcard_filter<filter_param>(false,
	                                    pattern,
	                                    [](const process_filter_args& arg) -> const std::string& {
		                                    return arg.m_tinfo ? arg.m_tinfo->m_comm : no_data;
	                                    })
	{
	}

	static std::string no_data;
};

/**
 * checks whether the provided m_tinfo->m_exe contains the specified patter, or any arg is a
 *wildcard match
 *
 * This filter always returns a high_priority result and never excludes.
 */
template<typename filter_param>
class process_cmd_line_filter : public base_filter<filter_param>
{
public:
	process_cmd_line_filter(const std::string& pattern)
	    : base_filter<filter_param>(false),
	      m_pattern(pattern)
	{
	}

	bool matches(const filter_param& arg,
	             bool& exclude,
	             bool& high_priority,
	             std::string* reason) const final;

private:
	std::string m_pattern;
};

/**
 * checks whether the container name in the provided args matches the specified wildcard
 *
 * This filter always returns a high_priority result and never excludes.
 */
template<typename filter_param>
class container_name_filter : public wildcard_filter<filter_param>
{
public:
	container_name_filter(const std::string& pattern)
	    : wildcard_filter<filter_param>(false,
	                                    pattern,
	                                    [](const process_filter_args& arg) -> const std::string& {
		                                    return arg.m_container ? arg.m_container->m_name
		                                                           : no_data;
	                                    })
	{
	}

	static std::string no_data;
};

template<typename filter_param>
class container_image_filter : public wildcard_filter<filter_param>
{
public:
	container_image_filter(const std::string& pattern)
	    : wildcard_filter<filter_param>(false,
	                                    pattern,
	                                    [](const process_filter_args& arg) -> const std::string& {
		                                    return arg.m_container ? arg.m_container->m_image
		                                                           : no_data;
	                                    })
	{
	}

	static std::string no_data;
};

/**
 * checks whether the container tag map contains a given label, and whether the value of that label
 *matches a pattern
 *
 * This filter always returns a high_priority result and never excludes.
 */
template<typename filter_param>
class container_label_filter : public base_filter<filter_param>
{
public:
	container_label_filter(const std::string& label, const std::string& pattern)
	    : base_filter<filter_param>(false),
	      m_label(label),
	      m_pattern(pattern)
	{
	}

	bool matches(const filter_param& arg,
	             bool& exclude,
	             bool& high_priority,
	             std::string* reason) const final;

private:
	std::string m_label;
	std::string m_pattern;
};

/**
 * checks whether the infrastructure state representation of a container has the appropriate
 *tag/value pair
 *
 * This filter always returns a high_priority result and never excludes.
 */
template<typename filter_param>
class tag_filter : public base_filter<filter_param>
{
public:
	tag_filter(const std::string& label, const std::string& pattern)
	    : base_filter<filter_param>(false),
	      m_label(label),
	      m_pattern(pattern)
	{
	}

	bool matches(const filter_param& arg,
	             bool& exclude,
	             bool& high_priority,
	             std::string* reason) const final;

private:
	std::string m_label;
	std::string m_pattern;
};

/**
 * checks whether the given app check exists
 *
 * This filter always returns a high_priority result and never excludes.
 */
template<typename filter_param>
class app_check_filter : public base_filter<filter_param>
{
public:
	app_check_filter(const std::string& pattern)
	    : base_filter<filter_param>(false),
	      m_pattern(pattern)
	{
	}

	bool matches(const filter_param& arg,
	             bool& exclude,
	             bool& high_priority,
	             std::string* reason) const final;

private:
	std::string m_pattern;
};
