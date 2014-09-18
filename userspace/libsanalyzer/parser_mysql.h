#ifdef HAS_ANALYZER

#pragma once

///////////////////////////////////////////////////////////////////////////////
// HTTP parser
///////////////////////////////////////////////////////////////////////////////
class sinsp_mysql_parser : sinsp_protocol_parser
{
public:
	sinsp_mysql_parser();
	sinsp_protocol_parser::msg_type should_parse(char* buf, uint32_t buflen);
	bool parse_request(char* buf, uint32_t buflen);
	bool parse_response(char* buf, uint32_t buflen);

	char* m_query;

private:
};

#endif // HAS_ANALYZER
