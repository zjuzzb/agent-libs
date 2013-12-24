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
#include "analyzer_thread.h"

analyzer_threadtable_listener::analyzer_threadtable_listener(sinsp* inspector, sinsp_analyzer* analyzer)
{
	m_inspector = inspector; 
	m_analyzer = analyzer;
}

void analyzer_threadtable_listener::on_thread_created(sinsp_threadinfo* tinfo)
{
	tinfo->m_ainfo = new thread_analyzer_info();
	tinfo->m_ainfo->init(m_inspector, tinfo);
}

void analyzer_threadtable_listener::on_thread_destroyed(sinsp_threadinfo* tinfo)
{
	if(tinfo->m_ainfo)
	{
		tinfo->m_ainfo->destroy();
		delete tinfo->m_ainfo;
	}
}
