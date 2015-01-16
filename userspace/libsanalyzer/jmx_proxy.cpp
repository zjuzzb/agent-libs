#include "jmx_proxy.h"
#include <unistd.h>

jmx_proxy::jmx_proxy(const std::pair<int, int>& fds):
	input_fd(fds.first),
	output_fd(fds.second)
{
}

void jmx_proxy::send_get_metrics()
{
	static const std::string command("getMetrics\n");
	write(input_fd, command.c_str(), command.size());
}