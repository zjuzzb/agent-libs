#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_mysql.h"

#ifdef HAS_ANALYZER

sinsp_mysql_parser::sinsp_mysql_parser()
{
}

sinsp_protocol_parser::msg_type sinsp_mysql_parser::should_parse(sinsp_fdinfo_t* fdinfo, 
																 sinsp_partial_transaction::direction dir,
																 bool is_switched,
																 char* buf, uint32_t buflen)
{
	if(fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_IN ||
		fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_OUT)
	{
		if(buflen >= 5)
		{
			return sinsp_protocol_parser::MSG_REQUEST;
		}
	}
	else if(fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_OUT ||
		fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_IN)
	{
		if(is_switched)
		{
			return sinsp_protocol_parser::MSG_RESPONSE;
		}
	}

	return sinsp_protocol_parser::MSG_NONE;
}

bool sinsp_mysql_parser::parse_request(char* buf, uint32_t buflen)
{
	m_is_req_valid = true;
	return false;
}

bool sinsp_mysql_parser::parse_response(char* buf, uint32_t buflen)
{
	return false;
}

#endif // HAS_ANALYZER
