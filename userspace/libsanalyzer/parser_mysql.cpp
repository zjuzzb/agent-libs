#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_mysql.h"

#ifdef HAS_ANALYZER

sinsp_mysql_parser::sinsp_mysql_parser()
{
}

sinsp_protocol_parser::msg_type sinsp_mysql_parser::should_parse(char* buf, uint32_t buflen)
{
	return sinsp_protocol_parser::MSG_NONE;
}

bool sinsp_mysql_parser::parse_request(char* buf, uint32_t buflen)
{
	return false;
}

bool sinsp_mysql_parser::parse_response(char* buf, uint32_t buflen)
{
	return false;
}

#endif // HAS_ANALYZER
