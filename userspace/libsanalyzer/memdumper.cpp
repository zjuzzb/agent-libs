#include <iostream>
#include <sinsp.h>
#include <sinsp_int.h>
#include "utils.h"
#ifdef HAS_ANALYZER
#include "draios.pb.h"
#include "analyzer_int.h"
#include "analyzer.h"
#endif
#include <memdumper.h>

extern sinsp_evttables g_infotables;

sinsp_memory_dumper::sinsp_memory_dumper(sinsp* inspector)
{
	m_inspector = inspector;
	m_active_state = &m_states[0];
	m_file_id = 0;
	m_f = NULL;
	m_disabled = false;
}

void sinsp_memory_dumper::init(uint64_t bufsize)
{
	uint64_t bsize = bufsize / 2;

	m_states[0].init(m_inspector, bsize);
	m_states[1].init(m_inspector, bsize);

	m_inspector->m_is_dumping = true;

	try
	{
		m_active_state->m_dumper->open("", false, true);
		m_active_state->m_has_data = true;
	}
	catch(sinsp_exception e)
	{
		lo(sinsp_logger::SEV_ERROR, "capture memory buffer too small to store process information. Memory dump disabled. Current size: %" PRIu64, 
			bsize);

		m_disabled = true;
	}

	char tbuf[32768];
	struct timeval ts;
	gettimeofday(&ts, NULL);
	time_t rawtime = (time_t)ts.tv_sec;
	struct tm* time_info = gmtime(&rawtime);
	snprintf(tbuf, sizeof(tbuf), "%.2d-%.2d_%.2d_%.2d_%.2d_%.6d",
		time_info->tm_mon + 1,
		time_info->tm_mday,
		time_info->tm_hour,
		time_info->tm_min,
		time_info->tm_sec,
		(int)ts.tv_usec);

	string fname = string("sd_dump_") + tbuf + ".scap";

	m_f = fopen(fname.c_str(), "wb");
	if(m_f == NULL)
	{
		lo(sinsp_logger::SEV_ERROR, "cannot open file %s", fname.c_str());
	}
}

sinsp_memory_dumper::~sinsp_memory_dumper()
{
	if(m_f != NULL)
	{
		fclose(m_f);
	}
}

void sinsp_memory_dumper::close()
{
	switch_states();
	m_inspector->m_is_dumping = false;
}

void sinsp_memory_dumper::to_file(string name, uint64_t ts_ns)
{
	char tbuf[32768];

	lo(sinsp_logger::SEV_INFO, "saving dump %s", name.c_str());

//	struct timeval ts;
//	gettimeofday(&ts, NULL);
//	time_t rawtime = (time_t)ts.tv_sec;
	time_t rawtime = (time_t)ts_ns / 1000000000;
	struct tm* time_info = gmtime(&rawtime);
	snprintf(tbuf, sizeof(tbuf), "%.2d-%.2d_%.2d_%.2d_%.2d_%.6d",
		time_info->tm_mon + 1,
		time_info->tm_mday,
		time_info->tm_hour,
		time_info->tm_min,
		time_info->tm_sec,
		(int)(ts_ns % 1000000000));

	string fname = string("sd_dump_") + name + "_" + tbuf + ".scap";

	FILE* fp = fopen(fname.c_str(), "wb");
	if(fp == NULL)
	{
		lo(sinsp_logger::SEV_ERROR, 
			"cannot open file %s, dump will not happen", fname.c_str());
		return;
	}

	sinsp_memory_dumper_state* m_inactive_state =
		(m_active_state == &m_states[0])? &m_states[1] : &m_states[0];

	flush_state_to_disk(fp, m_inactive_state, false);
	flush_state_to_disk(fp, m_active_state, true);

	fclose(fp);
}

void sinsp_memory_dumper::flush_state_to_disk(FILE* fp, 
	sinsp_memory_dumper_state* state,
	bool is_last_event_complete)
{
	if(state->m_has_data)
	{
		uint64_t datalen;

		if(is_last_event_complete)
		{
			datalen = state->m_dumper->written_bytes();
		}
		else
		{
			datalen = state->m_last_valid_bufpos - state->m_buf;
		}

		m_file_id++;

		if(fp != NULL)
		{
			fwrite(state->m_buf, datalen, 1, fp);
		}

		/*
		uint64_t dlen = 400 * 1024 * 1024;
		printf("YYY\n");

		if(compr(state->m_buf + datalen + 1,
			&dlen, state->m_buf, datalen, 1) != SCAP_SUCCESS)
		{
			printf("FAILED\n");
		}
		printf("XXX %ld %ld\n", datalen, dlen);

		fwrite(state->m_buf + datalen + 1, dlen, 1, f);
		*/
	}
}

void sinsp_memory_dumper::switch_states()
{
	//
	// The buffer is full, swap the states
	//
	if(m_active_state == &m_states[0])
	{
		m_active_state = &m_states[1];
	}
	else
	{
		m_active_state = &m_states[0];
	}

	//
	// Save the capture to disk
	//
	//flush_state_to_disk(m_f, m_active_state, false);

	//
	// Close and reopen the new state
	//
	m_active_state->m_dumper->close();

	try
	{
		m_active_state->m_dumper->open("", false, true);
		m_active_state->m_has_data = true;
	}
	catch(sinsp_exception e)
	{
		lo(sinsp_logger::SEV_ERROR, "capture memory buffer too small to store process information. Memory dump disabled. Current size: " + 
			m_active_state->m_bufsize);

		m_disabled = true;
	}
}

void sinsp_memory_dumper::process_event(sinsp_evt *evt)
{
	//
	// Capture is disabled if there was not enough memory to dump the thread table.
	//
	if(m_disabled)
	{
		return;
	}

	try
	{
		m_active_state->m_last_valid_bufpos = m_active_state->m_dumper->get_memory_dump_cur_buf();
		m_active_state->m_dumper->dump(evt);
	}
	catch(sinsp_exception e)
	{
		switch_states();
		m_active_state->m_dumper->dump(evt);
	}
}
