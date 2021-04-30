#include <string>

/**
 * Utilities for accessing network endpoints
 */
namespace network_utils {

/**
 * Simple transfer of string data from a server.
 */
std::string curl_get(const std::string &uri, const std::string &buffer);

}
