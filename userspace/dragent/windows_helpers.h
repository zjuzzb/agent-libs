#pragma once

class windows_helpers
{
public:
	static string get_machine_uid();
	static string get_machine_first_mac_address();
	static string get_executable_parent_dir();
	bool is_parent_service_running();

private:
	string m_service_file_name;
};
