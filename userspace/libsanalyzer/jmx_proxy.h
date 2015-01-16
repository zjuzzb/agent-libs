#pragma once

#include "third-party/jsoncpp/json/json.h"
#include <utility>

class jmx_proxy
{
public:
	jmx_proxy(const std::pair<int, int>& fds);

	void send_get_metrics();
	void read_metrics();

private:
	// Input and output of the subprocess
	// so we'll write on input and read from
	// output
	int input_fd;
	int output_fd;
	Json::Reader json_reader;
};