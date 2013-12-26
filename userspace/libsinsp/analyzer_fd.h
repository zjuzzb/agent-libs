#pragma once

class sinsp_analyzer_fd_listener : public sinsp_fd_listener
{
public:
	sinsp_analyzer_fd_listener(sinsp* inspector, sinsp_analyzer* analyzer);

	// XXX this functions have way too many parameters. Fix it.
	void on_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
	void on_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
	void on_connect(sinsp_evt *evt, uint8_t family, uint8_t* packed_data);
	void on_accept(sinsp_evt *evt);

private:
	sinsp* m_inspector; 
	sinsp_analyzer* m_analyzer;
};
