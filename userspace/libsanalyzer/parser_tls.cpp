//
// Created by Luca Marturana on 14/09/15.
//

#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "parser_tls.h"

sinsp_protocol_parser::msg_type sinsp_tls_parser::should_parse(sinsp_fdinfo_t *fdinfo,
															   sinsp_partial_transaction::direction dir,
															   bool is_switched, char *buf, uint32_t buflen)
{
	if((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_IN) ||
	   (fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_OUT))
	{
		if(!m_is_req_valid)
		{
			return sinsp_protocol_parser::MSG_REQUEST;
		}
	}
	else if((fdinfo->is_role_server() && dir == sinsp_partial_transaction::DIR_OUT) ||
			(fdinfo->is_role_client() && dir == sinsp_partial_transaction::DIR_IN))
	{
		if(!m_is_valid)
		{
			return sinsp_protocol_parser::MSG_RESPONSE;
		}
	}
	return sinsp_protocol_parser::MSG_NONE;
}

bool sinsp_tls_parser::parse_request(char *buf, uint32_t buflen)
{
	m_is_valid = false;
	m_is_req_valid = (buf[0] == 0x17);
	return m_is_req_valid;
}

bool sinsp_tls_parser::parse_response(char *buf, uint32_t buflen)
{
	m_is_valid = (buf[0] == 0x17);
	return m_is_valid;
}

sinsp_protocol_parser::proto sinsp_tls_parser::get_type()
{
	return sinsp_protocol_parser::PROTO_TLS;
}