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
string &ltrim(string &s) 
{
	s.erase(s.begin(), find_if(s.begin(), s.end(), not1(ptr_fun<int, int>(isspace))));
	return s;
}

//
// trim from end
//
string &rtrim(string &s) 
{
	s.erase(find_if(s.rbegin(), s.rend(), not1(ptr_fun<int, int>(isspace))).base(), s.end());
	return s;
}

//
// trim from both ends
//
string &trim(string &s) 
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
				string val = line.substr(prefix.size(), string::npos);
				m_description = trim(val);
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
