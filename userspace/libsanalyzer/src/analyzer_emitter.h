#pragma once
#include <unordered_set>

/**
 * analyzer emitter namespace holds types that are required by analyzer during flush.
 *
 * This may progress to a class which holds transient data during flush to align
 * with other *_emitter class philosophies.
 */
namespace analyzer_emitter {
enum flush_flags
{
	DF_NONE = 0,
	DF_FORCE_FLUSH,
	DF_FORCE_NOFLUSH,
	DF_FORCE_FLUSH_BUT_DONT_EMIT,
	DF_TIMEOUT,
	DF_EOF,
};

using progtable_t = std::unordered_set<sinsp_threadinfo*,
				       sinsp_threadinfo::hasher,
				       sinsp_threadinfo::comparer>;

using progtable_by_container_t = unordered_map<string, vector<sinsp_threadinfo*>>;
}
