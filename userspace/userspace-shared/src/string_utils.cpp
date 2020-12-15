
#include "string_utils.h"
#include <algorithm>

namespace 
{

// trim from start
std::string& ltrim(std::string &s)
{
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), not1(std::ptr_fun<int, int>(isspace))));
	return s;
}

// trim from end
std::string& rtrim(std::string &s)
{
	s.erase(std::find_if(s.rbegin(), s.rend(), not1(std::ptr_fun<int, int>(isspace))).base(), s.end());
	return s;
}

}

namespace string_utils
{

void trim(std::string &value)
{
	(void)ltrim(rtrim(value));
}

}
