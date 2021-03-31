#ifndef CYGWING_AGENT
#pragma once

#include <utility>
#include <string>

#include "draios.pb.h"


typedef google::protobuf::RepeatedPtrField<draiosproto::scope_predicate> scope_predicates;

bool operator==(const scope_predicates &a,
		const scope_predicates &b);

class scope_resolver_iface
{
public:
	// <kind, UID> strings
	using uid_t = std::pair<std::string, std::string>;

	using tags_map = std::map<std::string, std::string>;

	// Check the uid against the scope predicates in predicates
	// and return whether or not the uid matches the predicates.
	virtual bool match_scope(const uid_t &uid, const scope_predicates &predicates) = 0;

	// Helper function to check a set of scope predicates against a target value
	static bool match_predicate(const draiosproto::scope_predicate& p, const std::string& value);

	// Helper function to check agent.tag.xxx scope predicates in
	// the provided set of predicates against a map of
	// agent.tag.xx -> value. all predicates that are not
	// agent.tag.xxx are copied to a new set of scope predicates and returned.
	static bool match_agent_tag_predicates(const scope_predicates &predicates,
					       const tags_map &agent_tags,
					       scope_predicates &remaining_predicates);
};

#endif // CYGWING_AGENT
