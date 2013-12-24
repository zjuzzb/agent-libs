#pragma once

class sinsp_analyzer_rw_listener : public sinsp_rw_listener
{
public:
	void on_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
	void on_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len);
};
