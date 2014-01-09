#pragma once

#include <json/json.h>

class chisel
{
public:
	chisel(sinsp* inspector, string filename);
	void load(string filename);
	void run(sinsp_evt* evt);

private:
	sinsp* m_inspector;
	string m_description;
	Json::Value m_root;
	sinsp_filter* m_filter;
	sinsp_dumper* m_dumper;
};