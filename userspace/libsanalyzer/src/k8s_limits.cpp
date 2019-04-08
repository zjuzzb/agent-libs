#include "k8s_limits.h"

k8s_limits::k8s_limits(const filter_vec_t& filters,
			   uint32_t max_entries,
			   uint64_t expire_seconds)
	: user_configured_limits(filters,
				 "K8S",
				 log_flags<k8s_limits>::m_log,
				 log_flags<k8s_limits>::m_enable_log,
				 log_flags<k8s_limits>::m_last,
				 log_flags<k8s_limits>::m_running,
				 max_entries,
				 expire_seconds),
	  m_filter_vec_is_empty(false)
{
}

k8s_limits::k8s_limits()
	: k8s_limits(filter_vec_t({}))
{
}

void k8s_limits::sanitize_filters()
{
}


bool k8s_limits::allow(const std::string& target,
			 std::string& filter,
			 int* pos,
			 const std::string& type)
{
	return get_filters().empty() ? true : user_configured_limits::allow(target, filter, pos, type);
}

void k8s_limits::init(const filter_vec_t& filters,
		      uint32_t max_entries,
		      uint64_t expire_seconds)
{
	user_configured_limits::set_filters(filters);
	set_cache_max_entries(max_entries);
	set_purge_seconds(expire_seconds);
}

void k8s_limits::purge_tags(draiosproto::container_group& congroup)
{
	using proto_map_t = std::remove_pointer<decltype(congroup.mutable_tags())>::type;

	auto purge = [this](proto_map_t& map)
	{
		std::string filter;

		for(auto it = std::begin(map), last = std::end(map); it!=last;)
		{
			if(!allow(it->first, filter))
			{
				it = map.erase(it);
			}
			else
			{
				it++;
			}
		}
	};

	ASSERT(congroup.mutable_tags() != nullptr);
	ASSERT(congroup.mutable_internal_tags() != nullptr)
	purge(*congroup.mutable_tags());
	purge(*congroup.mutable_internal_tags());
}

INITIALIZE_LOG(k8s_limits);


