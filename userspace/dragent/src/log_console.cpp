#include "log_console.h"
#include "command_line_error.h"
#include "command_line_manager.h"
#include "common_logger.h"

#include <vector>
#include <algorithm>
#include <fstream>

COMMON_LOGGER();

namespace
{

const std::uint32_t DEFAULT_LINE_COUNT = 50;
const std::uint32_t MAX_LINE_COUNT = 5000;

std::string get_last_lines(const std::string&file, int line_count)
{
	size_t const granularity = 100 * line_count;
	std::ifstream source(file.c_str(), std::ios_base::in);
	source.seekg(0, std::ios_base::end);
	size_t size = static_cast<size_t>(source.tellg());
	std::vector<char> buffer(0);
	int newline_count = 0;
	while (source
	       && buffer.size() != size
	       && newline_count < line_count)
	{
		buffer.resize(std::min(buffer.size() + granularity, size));
		source.seekg(-static_cast<std::streamoff>(buffer.size()),
			     std::ios_base::end);
		source.read(buffer.data(), buffer.size());
		newline_count = std::count(buffer.begin(), buffer.end(), '\n');
	}
	std::vector<char>::iterator start = buffer.begin();
	while (newline_count > line_count)
	{
		start = std::find(start, buffer.end(), '\n') + 1;
		--newline_count;
	}
	std::vector<char>::iterator end = remove(start, buffer.end(), '\r');
	return std::string(start, end);
}

}

namespace log_console
{

void init( const std::string &file)
{
	command_line_manager::command_info cmd_info;
	cmd_info.short_description = "Display the end of the agent log";
	cmd_info.long_description = "Display the end of the agent log.\n\n"
				     "agent tail-log -> Display the last 50 log lines\n"
				     "agent tail-log -lines 200 -> Display the last 200 log lines";
	cmd_info.type = command_line_manager::content_type::TEXT;
	cmd_info.handler = [file](const command_line_manager::argument_list& args)
			   {
				   int count = 0;

				   for (const auto &arg : args)
				   {
					   if (arg.first != "lines" && arg.first != "n")
					   {
						   THROW_CLI_ERROR("tail-log command does not support the following argument: %s", arg.first.c_str());
					   }
				   }
				   if (args.size() > 1)
				   {
					   THROW_CLI_ERROR("tail-log command supports only the \"lines\" argument");
				   }

				   if (args.size() == 1)
				   {
					   count = std::atoi(args[0].second.c_str());
				   }
				   count = count == 0 ? DEFAULT_LINE_COUNT : count;
				   return get_last_lines(file, count);
			   };

	command_line_manager::instance().register_command("agent tail-log", cmd_info);
}

}

