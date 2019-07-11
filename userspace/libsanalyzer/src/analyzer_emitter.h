#pragma once
#include <unordered_set>

/**
 * analyzer emitter namespace holds types that are required by analyzer during flush.
 *
 * This may progress to a class which holds transient data during flush to align
 * with other *_emitter class philosophies.
 */
namespace analyzer_emitter {
/**
 * When subsampling, the kernel module sends a PPME_DROP_{E_X} event when we start dropping.
 * When this happens, we flush with the FORCE_FLUSH flush before the end of the interval.
 * Then at the end of the interval we flush with the BUT_DONT_EMIT flag. This lets us clean up
 * buffers so that the next flush doesn't take into account incomplete data. However, there are
 * many parts of the code that where we explicitly don't clean up the data because we know it's
 * safe to keep and send in the next flush.
 *
 * See https://github.com/draios/agent/pull/1360#issuecomment-487236553 for more information.
 */
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
