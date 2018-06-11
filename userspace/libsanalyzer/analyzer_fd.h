#pragma once

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
// This class listens on FD activity and performs advanced analysis
///////////////////////////////////////////////////////////////////////////////
class sinsp_analyzer_fd_listener : public sinsp_fd_listener
{
public:
	sinsp_analyzer_fd_listener(sinsp* inspector, sinsp_analyzer* analyzer);

	// XXX this functions have way too many parameters. Fix it.
	void on_read(sinsp_evt *evt, int64_t tid, int64_t fd, sinsp_fdinfo_t* fdinfo, char *data, uint32_t original_len, uint32_t len);
	void on_write(sinsp_evt *evt, int64_t tid, int64_t fd, sinsp_fdinfo_t* fdinfo, char *data, uint32_t original_len, uint32_t len);
	void on_rw_error(sinsp_evt *evt, int64_t fd, sinsp_fdinfo_t* fdinfo);
	void on_sendfile(sinsp_evt *evt, int64_t fdin, uint32_t len);
	void on_connect(sinsp_evt *evt, uint8_t* packed_data);
	void on_accept(sinsp_evt *evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo_t* new_fdinfo);
	void on_file_open(sinsp_evt* evt, const string& fullpath, uint32_t flags);
	void on_error(sinsp_evt* evt);
	void on_erase_fd(erase_fd_params* params);
	void on_socket_shutdown(sinsp_evt *evt);
	void on_execve(sinsp_evt *evt);
	void on_clone(sinsp_evt* evt, sinsp_threadinfo* newtinfo);
	void on_bind(sinsp_evt *evt);
	bool patch_network_role(sinsp_threadinfo* ptinfo,
		sinsp_fdinfo_t* pfdinfo,
		bool incoming);

	unordered_map<string, analyzer_file_stat> m_files_stat;

private:
	inline bool should_report_network(sinsp_fdinfo_t* fdinfo);
	analyzer_file_stat* get_file_stat(const sinsp_threadinfo* tinfo, const string& name);
	void flush_transaction(erase_fd_params* params);

	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	sinsp_proto_detector m_proto_detector;
	sinsp_configuration* m_sinsp_config;
};
