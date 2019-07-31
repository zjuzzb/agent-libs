/**
 * @file
 *
 * Implementation of file_rest_registry.
 *
 * @copyright Copyright (c) 2019 Sysdig Inc., All Rights Reserved
 */
#include "file_rest_registry.h"
#include <rest_exception.h>
#include <rest_util.h>
#include <common_logger.h>
#include <fstream>
#include <Poco/Net/HTTPResponse.h>
#include <streambuf>
#include <string>

COMMON_LOGGER();

namespace dragent {

file_rest_registry::file_rest_registry(const file_list& provided)
{
	file_list tracked = { "/opt/draios/etc/dragent.yaml" };

	// This only happens in test code
	std::copy(provided.begin(), provided.end(), std::front_inserter(tracked));

	for(const std::string& path : tracked)
	{
		std::string file_name = librest::post_last_slash(path);
		m_paths[file_name] = path;
	}
}

const std::string file_rest_registry::get_content_as_string(const std::string& file_name)
{
	path_map::const_iterator found = m_paths.find(file_name);
	if (found == m_paths.end())
	{
		THROW_REST_ERROR(Poco::Net::HTTPResponse::HTTPStatus::HTTP_NOT_FOUND,
				 "File %s in cannot be returned",
				 file_name.c_str());
	}

	std::ifstream stream(found->second);
	std::string content((std::istreambuf_iterator<char>(stream)),
			    std::istreambuf_iterator<char>());

	return content;
}

file_rest_registry::file_list file_rest_registry::get_file_name_list()
{
	file_list file_names;

	for(path_map::value_type &item : m_paths)
	{
		std::ifstream f(item.second.c_str());
		if(f.good())
		{
			file_names.push_back(item.first);
		}
	}
	return file_names;
}

}
