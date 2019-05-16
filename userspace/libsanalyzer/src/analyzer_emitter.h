#pragma once

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
}
