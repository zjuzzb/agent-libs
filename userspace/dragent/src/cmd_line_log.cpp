#include "cmd_line_log.h"
#include "command_line_manager.h"
#include "common_logger.h"

#include <vector>
#include <algorithm>
#include <fstream>

COMMON_LOGGER();

command_line::cmd_line_log::cmd_line_log()
{
	command_line_manager::command_info cmd_info;
	cmd_info.description = "Dump the agent log";
	cmd_info.long_description = "Dump the agent log";
	cmd_info.type = command_line_manager::content_type::TEXT;
	cmd_info.handler = [this](const command_line_manager::argument_list& args)
			   {
				   return get_last_log();
			   };

	command_line_manager::instance().register_command("log dump", cmd_info);
}

command_line::cmd_line_log::~cmd_line_log()
{
}

std::string command_line::cmd_line_log::get_last_log()
{
	return get_last_lines(LINE_COUNT);
}


std::string command_line::cmd_line_log::get_last_lines(int line_count)
{
	static const std::string filename = "/opt/draios/logs/draios.log";
	size_t const granularity = 100 * line_count;
	std::ifstream source( filename.c_str(), std::ios_base::in );
	source.seekg( 0, std::ios_base::end );
	size_t size = static_cast<size_t>( source.tellg() );
	std::vector<char> buffer(0);
	int newline_count = 0;
	while ( source
		&& buffer.size() != size
		&& newline_count < line_count ) {
		buffer.resize( std::min( buffer.size() + granularity, size ) );
		source.seekg( -static_cast<std::streamoff>( buffer.size() ),
			      std::ios_base::end );
		source.read( buffer.data(), buffer.size() );
		newline_count = std::count( buffer.begin(), buffer.end(), '\n');
	}
	std::vector<char>::iterator start = buffer.begin();
	while ( newline_count > line_count ) {
		start = std::find( start, buffer.end(), '\n' ) + 1;
		-- newline_count;
	}
	std::vector<char>::iterator end = remove( start, buffer.end(), '\r' );

	std::string tmp =  std::string( start, end );

	// Super workaround (I won't sleep for had written this)
	std::string ret = "<p>";

	for(auto c : tmp)
	{
		if(c == '\n')
		{
			ret += "<br/>";
		}
		ret.push_back(c);
	}
	ret += "</p>";

	return ret;


}

