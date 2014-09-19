#ifdef HAS_ANALYZER

#pragma once

#define HTTP_GET_STR "GET "
#define HTTP_OPTIONS_STR "OPTI"
#define HTTP_HEAD_STR "HEAD"
#define HTTP_POST_STR "POST"
#define HTTP_PUT_STR "PUT "
#define HTTP_DELETE_STR "DELE"
#define HTTP_TRACE_STR "TRAC"
#define HTTP_CONNECT_STR "CONN"
#define HTTP_RESP_STR "HTTP/"

///////////////////////////////////////////////////////////////////////////////
// HTTP parser
///////////////////////////////////////////////////////////////////////////////
class sinsp_http_parser : sinsp_protocol_parser
{
public:
	enum http_method
	{
		UM_NONE = 'n',
		UM_GET = 'g',
		UM_POST = 'p',
		UM_OPTIONS = 'o',
		UM_HEAD = 'h',
		UM_PUT = 'P',
		UM_DELETE = 'd',
		UM_TRACE = 't',
		UM_CONNECT = 'c'
	};

	sinsp_http_parser();
	~sinsp_http_parser();
	sinsp_protocol_parser::msg_type should_parse(sinsp_fdinfo_t* fdinfo, 
		sinsp_partial_transaction::direction dir, 
		bool is_switched,
		char* buf, uint32_t buflen);
	bool parse_request(char* buf, uint32_t buflen);
	bool parse_response(char* buf, uint32_t buflen);

	char* m_path;
	char* m_url;
	char* m_agent;
	char* m_content_type;
	int32_t m_status_code;
	http_method m_method;

private:
	inline char* check_and_extract(char* buf, uint32_t buflen, char* tosearch, uint32_t tosearchlen, OUT uint32_t* reslen);
	inline void extend_req_buffer_len(uint32_t len);
	inline void req_assign(char** dest, char* src, uint32_t len);
	inline void extend_resp_buffer_len(uint32_t len);
	inline void resp_assign(char** dest, char* src, uint32_t len);

	char* m_req_storage;
	uint32_t m_req_storage_size;
	uint32_t m_req_storage_pos;
	char m_req_initial_storage[256];

	char* m_resp_storage;
	uint32_t m_resp_storage_size;
	uint32_t m_resp_storage_pos;
	char m_resp_initial_storage[32];
};

#endif // HAS_ANALYZER
