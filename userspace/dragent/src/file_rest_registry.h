#pragma once
#include <list>
#include <map>
#include <string>

namespace dragent {

/**
 * Helper to handle a list of paths keyed by filename.
 */
class file_rest_registry
{
public:
	using file_list = std::list<std::string>;
	file_rest_registry(const file_list& paths);

	/**
	 * Open the given file and return and string.
	 */
	const std::string get_content_as_string(const std::string& file_name);

	/**
	 * Return a list of keys.
	 */
	file_list get_file_name_list();

private:
	using path_map = std::map<std::string, std::string>;
	path_map m_paths;
};

} // namespace dragent
