#pragma once

class chisel
{
public:
	chisel(sinsp* inspector, string filename);
	void load(string filename);
	void run(sinsp_evt* evt);

private:
	sinsp* m_inspector;
	string m_description;
	sinsp_filter* m_filter;
	sinsp_dumper* m_dumper;
};