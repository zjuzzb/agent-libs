#pragma once

#include "draios.pb.h"
#include "infra_utils_details.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/util/message_differencer.h>

#include <deque>
#include <string>
#include <type_traits>
#include <vector>

namespace test
{

/*!
 * This class provides a method for creating multiple events (i.e. container_groups as they are
 * built in cointerface), and a method for forming the dragent output out of the events elaboration
 * (i.e. a k8s_state structure). Moreover, a method for check proto messages equality is provided
 */
class infra_util
{
public:
	// event_tuple_t is used as parameter type in create_many_events method
	using event_tuple_t = std::tuple<std::string,                      /* event kind */
	                                 std::string,                      /* event id */
	                                 std::string,                      /* namespace */
	                                 draiosproto::congroup_event_type, /* event type */
	                                 std::vector<std::pair<std::string, std::string>>, /* parents */
	                                 std::vector<std::pair<std::string, std::string>> /* children */
	                                 >;

	// expected_tuple_t is used as parameter type in create_expected
	template<typename T>
	using expected_tuple_t =
	    std::tuple<T, /* one of k8s_pod, k8s_replica_sets, etc...*/
	               std::string /* object id*/,
	               std::string,                                     /* namespace */
	               std::string,                                     /* node (where it applies */
		       std::string,                                     /* object name */
	               std::vector<std::pair<std::string, std::string>> /* parents */
	               >;

	// Instead of declaring directly expected_tuple_t, use make_expected_tuple, for
	// leveraging type deduction.
	template<typename PROTO>
	static expected_tuple_t<PROTO> make_expected_tuple(
	    PROTO,
	    const std::string& id,
	    const std::string& namespace_,
	    const std::string& node,
	    const std::string& name,
	    const std::vector<std::pair<std::string, std::string>>& parents);

	// Create as many as you want cointerface events. Each event is represented by
	// an event_typle_t entry
	template<typename... Args>
	static std::deque<draiosproto::congroup_update_event> create_many_events(Args... args);

	// Specialization for implementing variadic template
	template<typename First, typename... Others>
	static std::deque<draiosproto::congroup_update_event> create_many_events(First first,
	                                                                         Others... others);
	// Specialization for implementing variadic template
	template<typename First>
	static std::deque<draiosproto::congroup_update_event> create_many_events(First first);

	// Create a k8s_state object as an expected value in tests.
	// Input are as many as you want objects of type k8s_pod, k8s_deployment, k8s_namespace, etc...
	template<typename... Args>
	static draiosproto::k8s_state create_expected(Args...);

	// Specialization for implementing variadic template
	template<typename F, typename... Others>
	static draiosproto::k8s_state create_expected(F&& first, Others&&... others);

	// Specialization for implementing variadic template
	template<typename F>
	static draiosproto::k8s_state create_expected(F&& first);

	// Compare two generic protobuf messages
	template<typename PROTO>
	static bool check_equality(const PROTO& msg_actual, const PROTO& msg_expected);

	template<typename F, typename... Args>
	static void remove_parent(F& msg, Args...);

	template<typename F, typename first, typename... Others>
	static void remove_parent(F& msg, const first&, const Others&...);

	template<typename F, typename first>
	static void remove_parent(F& msg, const first&);

private:
	template<typename T>
	static void add_obj_to_state(draiosproto::k8s_state& state, const T& obj);

	template<typename T>
	static void set_namespace(T& t, const std::string& ns)
	{
		return details::set_namespace<T>(t, ns);
	}

	template<typename T>
	static void set_node(T& t, const std::string& ns)
	{
		return details::set_node(t, ns);
	}

	template<typename T>
	static void set_restart_rate(T& t)
	{
		details::set_restart_rate(t);
	}

	static draiosproto::container_group create_cg(
	    const std::string& kind,
	    const std::string& id,
	    const std::string& ns_name,
	    std::vector<std::pair<std::string, std::string>> parents,
	    std::vector<std::pair<std::string, std::string>> children);

	static draiosproto::congroup_update_event create_event(
	    const std::string& kind,
	    const std::string& id,
	    const std::string& ns_name,
	    draiosproto::congroup_event_type type,
	    std::vector<std::pair<std::string, std::string>>& parents,
	    std::vector<std::pair<std::string, std::string>>& children);
};

template<typename PROTO>
infra_util::expected_tuple_t<PROTO> infra_util::make_expected_tuple(
    PROTO,
    const std::string& id,
    const std::string& namespace_,
    const std::string& node,
    const std::string& name,
    const std::vector<std::pair<std::string, std::string>>& parents)
{
	return expected_tuple_t<PROTO>(PROTO(), id, namespace_, node, name, parents);
}

template<typename T>
void infra_util::add_obj_to_state(draiosproto::k8s_state& state, const T& obj)
{
	return details::add_obj_to_state(state, obj);
}

template<typename First, typename... Others>
std::deque<draiosproto::congroup_update_event> infra_util::create_many_events(First first,
                                                                              Others... others)
{
	auto vc = create_many_events(first);
	auto ovc = create_many_events(others...);

	for (const auto& el : vc)
	{
		ovc.push_front(el);
	}

	return ovc;
}

template<typename First>
std::deque<draiosproto::congroup_update_event> infra_util::create_many_events(First first)
{
	std::deque<draiosproto::congroup_update_event> ret;

	ret.push_front(create_event(std::get<0>(first),
	                            std::get<1>(first),
	                            std::get<2>(first),
	                            std::get<3>(first),
	                            std::get<4>(first),
	                            std::get<5>(first)));
	return ret;
}

template<typename PROTO>
bool infra_util::check_equality(const PROTO& msg_actual, const PROTO& msg_expected)
{
	google::protobuf::util::MessageDifferencer differencer;

	draiosproto::k8s_common common;
	differencer.TreatAsSet(common.GetDescriptor()->FindFieldByName("parents"));

	return differencer.Compare(msg_actual, msg_expected);
}

template<typename F, typename... Others>
draiosproto::k8s_state infra_util::create_expected(F&& first, Others&&... others)
{
	auto state1 = create_expected(std::forward<F>(first));
	auto state2 = create_expected(std::forward<Others>(others)...);

	draiosproto::k8s_state ret;
	ret.MergeFrom(state1);
	ret.MergeFrom(state2);

	return ret;
}

template<typename F>
draiosproto::k8s_state infra_util::create_expected(F&& first)
{
	draiosproto::k8s_state ret;

	using PROTO = typename std::remove_reference<decltype(std::get<0>(first))>::type;
	PROTO msg;
	msg.mutable_common()->set_uid(std::get<1>(first));

	if(std::get<4>(first) != "")
	{
		msg.mutable_common()->set_name(std::get<4>(first));
	}
	
	infra_util::set_namespace(msg, std::get<2>(first));
	infra_util::set_node(msg, std::get<3>(first));
	infra_util::set_restart_rate(msg);

	for (const auto& parent : std::get<5>(first))
	{
		auto* p = msg.mutable_common()->mutable_parents()->Add();
		p->set_key(parent.first);
		p->set_value(parent.second);
	}

	add_obj_to_state(ret, msg);
	return ret;
}

template<typename F, typename first, typename... Others>
void infra_util::remove_parent(F& msg, const first& f, const Others&... others)
{
	remove_parent(msg, f);
	remove_parent(msg, others...);
}

template<typename F, typename first>
void infra_util::remove_parent(F& msg, const first& f)
{
	details::parent_remover<F>::remove(msg, f);
}

}  // namespace test
