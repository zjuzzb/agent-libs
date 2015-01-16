#include <unistd.h>
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "logger.h"
#include "fcntl.h"
#include "jmx_proxy.h"

jmx_proxy::jmx_proxy(const std::pair<int, int>& fds):
	input_fd(fds.first),
	output_fd(fds.second)
{
	int flags = fcntl(output_fd, F_GETFL, 0);
	fcntl(output_fd, F_SETFL, flags | O_NONBLOCK);
}

void jmx_proxy::send_get_metrics()
{
	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending get metric command to JMX");
	static const std::string command("getMetrics\n");
	write(input_fd, command.c_str(), command.size());
}

void jmx_proxy::read_metrics()
{
	static char buffer[200];
	int bytes_read = read(output_fd, buffer, 1000);
	buffer[bytes_read] = '\0';
	if(bytes_read > 0)
		g_logger.format(sinsp_logger::SEV_DEBUG, "Read from JMX metrics: %s", buffer);
}