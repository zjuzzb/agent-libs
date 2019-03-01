#pragma once

#include "draios.pb.h"
#include "filter_limits.h"


class k8s_limits : public user_configured_limits
{
public:
	k8s_limits(const filter_vec_t& filters,
		   uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
		   uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	k8s_limits();

	void init(const filter_vec_t& filters,
		  uint32_t max_entries = user_configured_limits::MAX_ENTRIES,
		  uint64_t expire_seconds = user_configured_limits::EXPIRE_SECONDS);

	virtual void sanitize_filters() override;

	bool allow(const std::string& target,
		   std::string& filter,
		   int* pos = nullptr,
		   const std::string& type = "");

	void purge_tags(draiosproto::container_group& congroup);

	DEFINE_LOG("Labels");
	DEFINE_LOG_ENABLED(k8s_limits);
private:
	bool m_filter_vec_is_empty;
};
