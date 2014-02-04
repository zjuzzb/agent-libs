#pragma once

class sinsp_analyzer_fd_listener : public sinsp_fd_listener
{
public:
	sinsp_analyzer_fd_listener(sinsp* inspector, sinsp_analyzer* analyzer);

	// XXX this functions have way too many parameters. Fix it.
	void on_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
	void on_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
	void on_connect(sinsp_evt *evt, uint8_t* packed_data);
	void on_accept(sinsp_evt *evt, int64_t newfd, uint8_t* packed_data, sinsp_fdinfo_t* new_fdinfo);
	void on_erase_fd(erase_fd_params* params);
	void on_socket_shutdown(sinsp_evt *evt);

private:
	bool set_role_by_guessing(sinsp_threadinfo* ptinfo, sinsp_fdinfo_t* pfdinfo, bool incoming);
	sinsp* m_inspector; 
	sinsp_analyzer* m_analyzer;
};
