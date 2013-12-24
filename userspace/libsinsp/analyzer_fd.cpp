#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "../../driver/ppm_ringbuffer.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "parsers.h"
#include "connectinfo.h"
#include "metrics.h"
#include "analyzer.h"
#include "draios.pb.h"
#include "delays.h"
#include "scores.h"
#include "procfs_parser.h"
#include "sinsp_errno.h"
#include "sched_analyzer.h"
#include "proto_header.h"
#include "analyzer_fd.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_percpu_delays implementation
///////////////////////////////////////////////////////////////////////////////
void sinsp_analyzer_rw_listener::on_read(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len)
{
	int a = 0;
}

void sinsp_analyzer_rw_listener::on_write(sinsp_evt *evt, int64_t tid, int64_t fd, char *data, uint32_t original_len, uint32_t len)
{
	int a = 0;
}
