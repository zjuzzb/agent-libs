#ifdef HAS_ANALYZER

#pragma once

#include "protostate.h"

#define HTTP_GET_STR "GET "
#define HTTP_OPTIONS_STR "OPTI"
#define HTTP_HEAD_STR "HEAD"
#define HTTP_POST_STR "POST"
#define HTTP_PUT_STR "PUT "
#define HTTP_DELETE_STR "DELE"
#define HTTP_TRACE_STR "TRAC"
#define HTTP_CONNECT_STR "CONN"
#define HTTP_RESP_STR "HTTP/"

class sinsp_http_parser : public sinsp_protocol_parser
{
public:
	enum class http_method
	{
		NONE = 'n',
		GET = 'g',
		POST = 'p',
		OPTIONS = 'o',
		HEAD = 'h',
		PUT = 'P',
		DELETE = 'd',
		TRACE = 't',
		CONNECT = 'c'
	};

	sinsp_http_parser();
	~sinsp_http_parser();
	sinsp_protocol_parser::msg_type should_parse(sinsp_fdinfo_t* fdinfo, 
						     sinsp_partial_transaction::direction dir,
						     bool is_switched,
						     const char* buf,
						     uint32_t buflen) override;
	bool parse_request(const char* buf, uint32_t buflen) override;
	bool parse_response(const char* buf, uint32_t buflen) override;
	proto get_type() override;

	struct Result {
		// request
		const char* path = nullptr;
		const char* url = nullptr;
		const char *agent = nullptr;
		http_method method = http_method::NONE;
		// response
		const char* content_type = nullptr;
		int32_t status_code = 0;
	};
	const Result& result() { return m_result; }

private:
	inline const char* check_and_extract(const char* buf, uint32_t buflen,
					     char* tosearch,
					     uint32_t tosearchlen,
					     OUT uint32_t* reslen);
	inline void extend_req_buffer_len(uint32_t len);
	inline void req_assign(const char** dest, const char* src, uint32_t len);
	inline void extend_resp_buffer_len(uint32_t len);
	inline void resp_assign(const char** dest, const char* src, uint32_t len);

	char* m_req_storage;
	uint32_t m_req_storage_size;
	uint32_t m_req_storage_pos;
	char m_req_initial_storage[256];

	char* m_resp_storage;
	uint32_t m_resp_storage_size;
	uint32_t m_resp_storage_pos;
	char m_resp_initial_storage[32];

	Result m_result;

 	friend class sinsp_protostate_test_per_container_distribution_Test;
	friend class sinsp_protostate_test_top_call_should_be_present_Test;

};

#endif // HAS_ANALYZER
