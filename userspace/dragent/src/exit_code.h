
#include "Poco/Util/Application.h"

namespace dragent
{

/**
 * List of reasons that the dragent application can exit. Some
 * of these may no longer be used. Where applicable, these map 
 * to Poco codes. 
 * These map to the behavior of monitor. 
 */
namespace exit_code
{
	/// The EXIT_OK code will allow for a clean exit, but we 
	/// transform it to SHUT_DOWN to better indicate how the error 
	/// is handled by monitor. 
	const uint8_t SHUT_DOWN = Poco::Util::Application::EXIT_OK;
	/// The EXIT_SOFTWARE code is for an internal error, but we 
	/// transform it to RESTART to better indicate how the error is 
	/// handled by monitor. 
	const uint8_t RESTART = Poco::Util::Application::EXIT_SOFTWARE;
	const uint8_t DONT_RESTART = 17;
	const uint8_t CONFIG_UPDATE = 18;
	const uint8_t DONT_SEND_LOG_REPORT = 19;
}

}
