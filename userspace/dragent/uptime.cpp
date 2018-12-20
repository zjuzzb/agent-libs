#include <chrono>

namespace
{

const std::chrono::time_point<std::chrono::steady_clock> STEADY_START = std::chrono::steady_clock::now();

const std::chrono::time_point<std::chrono::steady_clock>& getStart()
{
	// This is kept inside a function so that clients don't need
	// to worry about static initialization order. This will get
	// initialized on first call.
	const static std::chrono::time_point<std::chrono::steady_clock> STEADY_START =
		std::chrono::steady_clock::now();
	return STEADY_START;
}

// Forcing getStart to get called at static init time to initialize
// STEADY_START. This shouldn't be used.
const std::chrono::time_point<std::chrono::steady_clock>& DO_NOT_USE = getStart();


} // anonymous namespace

namespace dragent
{

namespace uptime
{

// static
uint64_t milliseconds()
{
	auto diff = std::chrono::steady_clock::now() - getStart();
	return std::chrono::duration_cast<std::chrono::milliseconds>(diff).count();
}

} // namespace uptime

} // namespace dragent
