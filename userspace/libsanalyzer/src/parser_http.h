#pragma once

#include "feature_manager.h"
#include "protocol_manager.h"
#include "protocol_state.h"

#include <Poco/RegularExpression.h>

#define HTTP_GET_STR "GET "
#define HTTP_OPTIONS_STR "OPTI"
#define HTTP_HEAD_STR "HEAD"
#define HTTP_POST_STR "POST"
#define HTTP_PUT_STR "PUT "
#define HTTP_DELETE_STR "DELE"
#define HTTP_TRACE_STR "TRAC"
#define HTTP_CONNECT_STR "CONN"
#define HTTP_RESP_STR "HTTP/"

// The static singleton that does basic http protocol things
class protocol_http : public protocol_base, public feature_base
{
private:
	static protocol_http* s_protocol_http;

public:
	protocol_http();

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

	static protocol_http& instance();

	bool is_protocol(sinsp_evt* evt,
	                 sinsp_partial_transaction* trinfo,
	                 sinsp_partial_transaction::direction trdir,
	                 const uint8_t* buf,
	                 uint32_t buflen,
	                 uint16_t serverport) const override;

	static inline bool is_absoluteURI(const char* URI, uint32_t len);
	static inline bool decompose_URI(const char* URI_in,
	                                 uint32_t URI_len,
	                                 const char** host_out,
	                                 uint32_t& host_len,
	                                 const char** path_out,
	                                 uint32_t& path_len);
};

// The representation of a single HTTP transaction
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

	struct Result
	{
		// request
		const char* path = nullptr;
		const char* url = nullptr;
		const char* agent = nullptr;
		http_method method = http_method::NONE;
		// response
		const char* content_type = nullptr;
		int32_t status_code = 0;
	};
	const Result& result() { return m_result; }

private:
	inline const char* check_and_extract(const char* buf,
	                                     uint32_t buflen,
	                                     char* tosearch,
	                                     uint32_t tosearchlen,
	                                     OUT uint32_t* reslen);
	inline void extend_req_buffer_len(uint32_t len);
	inline void req_assign(const char** dest, const char* src, uint32_t len);
	inline void extend_resp_buffer_len(uint32_t len);
	inline void req_build_url(const char** dest, const char* url, uint32_t url_len, char method);
	inline void resp_assign(const char** dest, const char* src, uint32_t len);
	inline bool is_absoluteURI(const char* URI, uint32_t len);
	inline bool decompose_URI(const char* URI_in,
	                          uint32_t URI_len,
	                          const char** host_out,
	                          uint32_t& host_len,
	                          const char** path_out,
	                          uint32_t& path_len);

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

	friend class test_helper;
};

class sinsp_url_group
{
public:
	sinsp_url_group(const std::string& pattern)
	    : m_pattern(pattern, Poco::RegularExpression::RE_CASELESS)
	{
	}

	///
	/// determine whether a url, represented by a string, is a member of this group
	/// @param url  string representation of the url to match
	/// @returns    whether the url is a member of the group
	///
	bool contains(std::string url) const { return m_pattern.match(url); }

private:
	Poco::RegularExpression m_pattern;
};

class sinsp_url_details : public sinsp_request_details
{
public:
	sinsp_url_details() : sinsp_request_details(), m_matched(false), m_url_groups() {}

	/// takes a URL, and if we haven't compared it to all known URL groups, does so
	/// @param groups the list of groups to match against
	/// @param url the string of the url we want to match
	///
	/// we have to pass in the URL explicitly since it isn't stored as part of
	/// url_details
	void match_url_if_unmatched(
	    const std::map<std::string, std::shared_ptr<sinsp_url_group>>& groups,
	    const std::string& url)
	{
		if (m_matched)
		{
			return;
		}
		for (const auto& group : groups)
		{
			if (group.second->contains(url))
			{
				add_group(group.second);
			}
		}

		m_matched = true;
	}

	/// adds a group to this URL. Since URL groups are currently static, this
	/// is a permanent action
	void add_group(const std::shared_ptr<sinsp_url_group>& group) { m_url_groups.insert(group); }

	std::unordered_set<std::shared_ptr<sinsp_url_group>>* get_group_list() { return &m_url_groups; }

private:
	bool m_matched;  // indicates whether this URL has already been matched against existing
	                 // URL groups

	// set of groups this URL matches
	std::unordered_set<std::shared_ptr<sinsp_url_group>> m_url_groups;
};

// The persistent data storing all http transactions seen by a given object (process, container,
// etc.)
class sinsp_http_state : public protocol_state
{
public:
	// constructor mainly to call clear so we can initialize the URL groups
	sinsp_http_state() { clear(); }

	void clear()
	{
		m_server_urls.clear();
		m_client_urls.clear();
		m_server_status_codes.clear();
		m_client_status_codes.clear();
		m_server_totals = sinsp_request_details();
		m_client_totals = sinsp_request_details();
	}

	bool has_data() { return !m_server_status_codes.empty() || !m_client_status_codes.empty(); }
	void add(sinsp_http_state* other);

	void update(sinsp_partial_transaction* tr,
	            uint64_t time_delta,
	            bool is_server,
	            uint32_t truncation_size);

	void to_protobuf(draiosproto::http_info* protobuf_msg, uint32_t sampling_ratio, uint32_t limit);
	void coalesce_protobuf(draiosproto::http_info* protobuf_msg, uint32_t sampling_ratio);

private:
	friend class sinsp_http_marker;
	void url_table_to_protobuf(draiosproto::http_info* protobuf_msg,
	                           std::unordered_map<std::string, sinsp_url_details>* table,
	                           bool is_server,
	                           uint32_t sampling_ratio,
	                           uint32_t limit);

	void status_code_table_to_protobuf(draiosproto::http_info* protobuf_msg,
	                                   std::unordered_map<uint32_t, sinsp_request_details>* table,
	                                   bool is_server,
	                                   uint32_t sampling_ratio,
	                                   uint32_t limit);

	std::unordered_map<std::string, sinsp_url_details> m_server_urls;
	std::unordered_map<std::string, sinsp_url_details> m_client_urls;
	std::unordered_map<uint32_t, sinsp_request_details> m_server_status_codes;
	std::unordered_map<uint32_t, sinsp_request_details> m_client_status_codes;
	sinsp_request_details m_server_totals;
	sinsp_request_details m_client_totals;

	friend class sinsp_protostate;
};
