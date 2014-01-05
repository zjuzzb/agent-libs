#include <iostream>
#include <fstream>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>

#include <sinsp.h>
#include "chisel.h"

///////////////////////////////////////////////////////////////////////////////
// String trimming
///////////////////////////////////////////////////////////////////////////////
//
// trim from start
//
static inline std::string &ltrim(std::string &s) 
{
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	return s;
}

//
// trim from end
//
static inline std::string &rtrim(std::string &s) 
{
	s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}

//
// trim from both ends
//
static inline std::string &trim(std::string &s) 
{
	return ltrim(rtrim(s));
}

///////////////////////////////////////////////////////////////////////////////
// chisel implementation
///////////////////////////////////////////////////////////////////////////////
chisel::chisel(sinsp* inspector, string filename)
{
	m_inspector = inspector;
	load(filename);
}

void chisel::load(string filename)
{
	string line;
	ifstream is(filename);

	if(is.is_open())
	{
		while(getline(is, line))
		{
			string prefix;

			//
			// Skip empty lines
			//
			if(line.size() == 0)
			{
				continue;
			}

			//
			// Skip comments
			//
			if(line[0] == '#')
			{
				continue;
			}

			prefix = "description:";

			if(line.compare(0, prefix.size(), prefix) == 0)
			{
				m_description = trim(line.substr(prefix.size(), string::npos));
			}
		}

		is.close();
	}
	else
	{
		throw sinsp_exception("can't open file " + filename);
	}
}

void chisel::run(sinsp_evt* evt)
{
}
