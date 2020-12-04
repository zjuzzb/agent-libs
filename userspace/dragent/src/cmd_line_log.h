#pragma once
#include <string>

namespace command_line
{

class cmd_line_log
{
public:
	cmd_line_log();
	~cmd_line_log();

	std::string get_last_log();
	std::string get_last_error();

private:
	std::string get_last_lines(int linecount);
	static const std::uint32_t LINE_COUNT = 50;
};

}
