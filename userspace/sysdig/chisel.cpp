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
		uint32_t j;

		//
		// Bring the file into a string
		//
		string docstr((istreambuf_iterator<char>(is)),
			istreambuf_iterator<char>());

		//
		// Parse the json
		//
		Json::Reader reader;
		bool parsingSuccessful = reader.parse(docstr, m_root);
		if(!parsingSuccessful)
		{
			throw sinsp_exception("Failed to parse configuration\n" + 
				reader.getFormattedErrorMessages());
		}

		//
		// Extract the info
		//
		m_description = m_root["info"]["description"].asString();
		const Json::Value args = m_root["info"]["arguments"];
		
		for(j = 0; j < args.size(); j++)
		{
			string s = args[j]["name"].asString();
			int a= 0;
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
