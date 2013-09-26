#pragma once

//
// The main analyzer class
//
class sinsp_procparser
{
public:
	sinsp_procparser();

	static void get_cpu_loads(OUT vector<uint32_t>* loads);
};
