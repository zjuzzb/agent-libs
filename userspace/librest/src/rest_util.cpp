#include "rest_util.h"

namespace librest
{

std::string post_last_slash(const std::string& uri)
{
	const std::size_t last_slash = uri.rfind("/");
	std::string value;

	if (last_slash != std::string::npos)
	{
		value = uri.substr(last_slash + 1);
	}

	return value;
}

}
