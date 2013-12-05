#pragma once

class sinsp_filter_check;

class SINSP_PUBLIC sinsp_evt_formatter
{
public:
	sinsp_evt_formatter(const string& fmt, sinsp* inspector);
	void tostring(sinsp_evt* evt, OUT string* res);

private:
	void set_format(const string& fmt);
	vector<sinsp_filter_check*> m_tokens;
	sinsp* m_inspector;
};
