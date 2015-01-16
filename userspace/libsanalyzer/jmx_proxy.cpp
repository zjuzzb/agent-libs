#include <unistd.h>
#include "sinsp.h"
#include "sinsp_int.h"
#include "analyzer_int.h"
#include "logger.h"
#include "fcntl.h"
#include "jmx_proxy.h"

jmx_proxy::jmx_proxy(const std::pair<FILE*, FILE*>& fds):
	m_input_fd(fds.first),
	m_output_fd(fds.second)
{
}

void jmx_proxy::send_get_metrics()
{
	g_logger.format(sinsp_logger::SEV_DEBUG, "Sending get metric command to JMX");
	fprintf(m_input_fd, "getMetrics\n");
	fflush(m_input_fd);
}

void jmx_proxy::read_metrics()
{
	char buffer[1000];
	fd_set readset;

	int output_fd_int = fileno(m_output_fd);
	FD_ZERO(&readset);
	FD_SET(output_fd_int, &readset);
	struct timeval timeout;
	memset(&timeout, 0, sizeof(struct timeval));
	int result = select(output_fd_int+1, &readset, NULL, NULL, &timeout);
	if (result > 0)
	{
		fgets(buffer, 1000, m_output_fd);
		g_logger.format(sinsp_logger::SEV_DEBUG, "Received JMX metrics: %s", buffer);
	}
	else
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "JMX metrics are not ready");
	}
}