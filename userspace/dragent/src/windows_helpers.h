#pragma once

class windows_helpers
{
public:
	static std::string get_machine_uid();
	static std::string get_machine_first_mac_address();
	static std::string get_executable_parent_dir();
	bool is_parent_service_running();

private:
	std::string m_service_file_name;
};
