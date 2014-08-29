#pragma once
#include "parser_http.h"

class analyzer_file_stat
{
public:
	analyzer_file_stat():
		m_time_ns(0),
		m_bytes(0),
		m_errors(0),
		m_open_count(0),
		m_exclude_from_sample(true)
	{
	}

	static bool cmp_bytes(const analyzer_file_stat* src, const analyzer_file_stat* dst)
	{
		ASSERT(src);
		ASSERT(dst);
		return src->m_bytes > dst->m_bytes;
	}

	static bool cmp_time(const analyzer_file_stat* src, const analyzer_file_stat* dst)
	{
		ASSERT(src);
		ASSERT(dst);
		return src->m_time_ns > dst->m_time_ns;
	}

	static bool cmp_errors(const analyzer_file_stat* src, const analyzer_file_stat* dst)
	{
		ASSERT(src);
		ASSERT(dst);
		return src->m_errors > dst->m_errors;
	}

	static bool cmp_open_count(const analyzer_file_stat* src, const analyzer_file_stat* dst)
	{
		ASSERT(src);
		ASSERT(dst);
		return src->m_open_count > dst->m_open_count;
	}

	string m_name;
	uint64_t m_time_ns;
	uint32_t m_bytes;
	uint32_t m_errors;
	uint32_t m_open_count;
	bool m_exclude_from_sample;
};

///////////////////////////////////////////////////////////////////////////////
// The DPI-based protocol detector
///////////////////////////////////////////////////////////////////////////////
class sinsp_proto_detector
{
public:
	sinsp_proto_detector();

	inline sinsp_partial_transaction::type detect_proto(sinsp_partial_transaction *trinfo,
		char* buf, uint32_t buflen)
	{
/*
		//
		// Make sure there are at least 4 bytes
		//
		if(buflen > 4)
		{
			if(*(uint32_t*)buf == m_http_get_intval ||
					*(uint32_t*)buf == m_http_post_intval ||
					*(uint32_t*)buf == m_http_put_intval ||
					*(uint32_t*)buf == m_http_delete_intval ||
					*(uint32_t*)buf == m_http_trace_intval ||
					*(uint32_t*)buf == m_http_connect_intval ||
					*(uint32_t*)buf == m_http_options_intval ||
					(*(uint32_t*)buf == m_http_resp_intval && buf[4] == '/'))
			{
				trinfo->m_protoparser = (sinsp_protocol_parser*)new sinsp_http_parser();
				return sinsp_partial_transaction::TYPE_HTTP;
			}
		}
*/
		return sinsp_partial_transaction::TYPE_IP;
	}

	bool parse_request(char* buf, uint32_t buflen);

	string m_url;
	string m_agent;

private:
	uint32_t m_http_options_intval;
	uint32_t m_http_get_intval;
	uint32_t m_http_head_intval;
	uint32_t m_http_post_intval;
	uint32_t m_http_put_intval;
	uint32_t m_http_delete_intval;
	uint32_t m_http_trace_intval;
	uint32_t m_http_connect_intval;
	uint32_t m_http_resp_intval;
};

///////////////////////////////////////////////////////////////////////////////
// This class listens on FD activity and performs advanced analysis
///////////////////////////////////////////////////////////////////////////////
class sinsp_analyzer_fd_listener : public sinsp_fd_listener
{
public:
	sinsp_analyzer_fd_listener(sinsp* inspector, sinsp_analyzer* analyzer);

	// XXX this functions have way too many parameters. Fix it.
	void on_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
	void on_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
	void on_connect(sinsp_evt *evt, uint8_t* packed_data);
	void on_accept(sinsp_evt *evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo_t* new_fdinfo);
	void on_file_create(sinsp_evt* evt, const string& fullpath);
	void on_error(sinsp_evt* evt);
	void on_erase_fd(erase_fd_params* params);
	void on_socket_shutdown(sinsp_evt *evt);

	bool patch_network_role(sinsp_threadinfo* ptinfo, 
		sinsp_fdinfo_t* pfdinfo,
		bool incoming);

	unordered_map<string, analyzer_file_stat> m_files_stat;

private:
	analyzer_file_stat* get_file_stat(const string& name);

	sinsp* m_inspector; 
	sinsp_analyzer* m_analyzer;
	sinsp_proto_detector m_proto_detector;
};
