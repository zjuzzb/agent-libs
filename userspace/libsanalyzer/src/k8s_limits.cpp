#include "k8s_limits.h"

#include "draios.pb.h"

k8s_limits::k8s_limits(filter_vec_t filters,
			   uint32_t max_entries,
			   uint64_t expire_seconds)
	: user_configured_limits(std::move(filters),
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

k8s_limits::sptr_t k8s_limits::build(
	filter_vec_t filters,
	bool log_enabled,
	uint32_t max_entries,
	uint64_t expire_seconds)
{
	if(log_enabled)
	{
		user_configured_limits::enable_logging<k8s_limits>();
	}
	if(!filters.empty() && !k8s_limits::first_includes_all(filters))
	{
		return std::make_shared<k8s_limits>(std::move(filters), max_entries, expire_seconds);
	}
	return nullptr;
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


