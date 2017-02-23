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

sinsp_memory_dumper::sinsp_memory_dumper(sinsp* inspector, bool capture_dragent_events)
{
	m_inspector = inspector;
	m_active_state = &m_states[0];
	m_file_id = 0;
	m_f = NULL;
	m_cf = NULL;
	m_disabled = false;
	m_switches_to_go = 0;
	m_saturation_inactivity_start_time = 0;

#if defined(HAS_CAPTURE)
	m_capture_dragent_events = capture_dragent_events;
	if(!capture_dragent_events)
	{
		m_sysdig_pid = m_inspector->m_sysdig_pid;
	}
#endif
}

void sinsp_memory_dumper::init(uint64_t bufsize, 
	uint64_t max_disk_size,
	uint64_t saturation_inactivity_pause_ns)
{
	lo(sinsp_logger::SEV_INFO, "memdump: initializing memdumper, bufsize=%" PRIu64 ", max_disk_size=%" PRIu64 ", saturation_inactivity_pause_ns=%" PRIu64,
		bufsize,
		max_disk_size,
		saturation_inactivity_pause_ns);

	m_max_disk_size = max_disk_size;
	m_saturation_inactivity_pause_ns = saturation_inactivity_pause_ns;

	//
	// Let the inspector know that we're dumping
	//
	m_inspector->m_is_dumping = true;

	//
	// Initialize the buffers
	//
	m_bsize = bufsize / 2;

	m_states[0].init(m_inspector, m_bsize);
	m_states[1].init(m_inspector, m_bsize);

	//
	// Initialize the dumprt
	//
	try
	{
		m_active_state->m_dumper->open("", true, true);
		m_active_state->m_has_data = true;
	}
	catch(sinsp_exception e)
	{
		lo(sinsp_logger::SEV_ERROR, "memdump: capture memory buffer too small to store process information. Memory dump disabled. Current size: %" PRIu64, 
			m_bsize);

		m_disabled = true;
	}

/*
	//
	// Initialize the dump file
	//
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
		lo(sinsp_logger::SEV_ERROR, "memdump: cannot open file %s", fname.c_str());
	}
*/
	m_f = NULL;	

	//
	// Initialize the notification event
	//
	m_notification_scap_evt = (scap_evt*)m_notification_scap_evt_storage;
	m_notification_scap_evt->type = PPME_NOTIFICATION_E;
	m_notification_evt.m_poriginal_evt = NULL;
	m_notification_evt.m_pevt = m_notification_scap_evt;
	m_notification_evt.m_inspector = m_inspector;
}

sinsp_memory_dumper::~sinsp_memory_dumper()
{
	if(m_f != NULL)
	{
		fclose(m_f);
	}

	if(m_cf != NULL)
	{
		fclose(m_cf);
	}
}

void sinsp_memory_dumper::close()
{
	switch_states(0);
	m_inspector->m_is_dumping = false;
}

void sinsp_memory_dumper::to_file_multi(string name, uint64_t ts_ns)
{
	char tbuf[512];

	m_switches_to_go = 2;

	if(m_cf != NULL)
	{
		return;
	}

	if((m_saturation_inactivity_start_time != 0) && 
		(ts_ns - m_saturation_inactivity_start_time) < m_saturation_inactivity_pause_ns)
	{
		return;
	}

	time_t rawtime = (time_t)ts_ns / 1000000000;
	struct tm* time_info = gmtime(&rawtime);
	snprintf(tbuf, sizeof(tbuf), "%.2d-%.2d_%.2d_%.2d_%.2d_%.6d",
		time_info->tm_mon + 1,
		time_info->tm_mday,
		time_info->tm_hour,
		time_info->tm_min,
		time_info->tm_sec,
		(int)(ts_ns % 1000000000));

	string fname = string("/tmp/sd_dump_") + name + "_" + tbuf + ".scap";

	lo(sinsp_logger::SEV_INFO, "memdump: saving dump %s", fname.c_str());

	m_cf = fopen(fname.c_str(), "wb");
	if(m_cf == NULL)
	{
		lo(sinsp_logger::SEV_ERROR, 
			"memdump: cannot open file %s, dump will not happen", fname.c_str());
		return;
	}

	sinsp_memory_dumper_state* inactive_state =
		(m_active_state == &m_states[0])? &m_states[1] : &m_states[0];

	flush_state_to_disk(m_cf, inactive_state, false);
//	flush_state_to_disk(m_cf, m_active_state, true);

//	fclose(m_cf);
//	m_cf = NULL;

	m_cur_dump_size = m_bsize;
}

void sinsp_memory_dumper::apply_job_filter(string intermediate_filename, 
	sinsp_memory_dumper_job* job)
{
	int32_t res;
	sinsp_evt* ev;

	sinsp inspector;
	inspector.set_hostname_and_port_resolution_mode(false);

	try
	{
		inspector.open(intermediate_filename);
	}
	catch(...)
	{
		job->m_lasterr = inspector.getlasterr();
		job->m_state = sinsp_memory_dumper_job::ST_DONE_ERROR;
		return;
	}

	if(job->m_filterstr != "")
	{
		string flt = "(" + job->m_filterstr + ") or evt.type=notification";
		inspector.set_filter(flt);
	}

	while(1)
	{
		res = inspector.next(&ev);

		if(res == SCAP_EOF || job->m_state == sinsp_memory_dumper_job::ST_STOPPPED)
		{
			break;
		}
		else if(res == SCAP_TIMEOUT)
		{
			continue;
		}
		else if(res != SCAP_SUCCESS && res != SCAP_TIMEOUT)
		{
			//
			// There was an error. Just stop here and log the error
			//
			job->m_state = sinsp_memory_dumper_job::ST_DONE_ERROR;
			job->m_lasterr = "apply_job_filter error reading events from file " + intermediate_filename;
			ASSERT(false);
			break;
		}

		if(job->m_start_time != 0 && ev->get_ts() < job->m_start_time)
		{
			continue;
		}

		if(job->m_dumper == NULL)
		{
			job->m_dumper = new sinsp_dumper(&inspector);
			try
			{
				job->m_dumper->open(job->m_filename, false, true);
			}
			catch(...)
			{
				job->m_lasterr = inspector.getlasterr();
				job->m_state = sinsp_memory_dumper_job::ST_DONE_ERROR;
				return;
			}
		}

		job->m_dumper->dump(ev);
	}

	inspector.close();
}

sinsp_memory_dumper_job* sinsp_memory_dumper::add_job(uint64_t ts, string filename, string filter, 
	uint64_t delta_time_past_ns, uint64_t delta_time_future_ns)
{
	struct timeval tm;
	gettimeofday(&tm, NULL);

	sinsp_memory_dumper_job* job = new sinsp_memory_dumper_job();
	m_jobs.push_back(job);

	string fname = "/tmp/dragent_i_" + to_string(tm.tv_sec) + to_string(tm.tv_usec);

	FILE* tfp = fopen(fname.c_str(), "wb");
	if(tfp == NULL)
	{
		job->m_state = sinsp_memory_dumper_job::ST_DONE_ERROR;
		job->m_lasterr = "can't open temporary file " + fname;
		return job;
	}

	sinsp_memory_dumper_state* inactive_state =
		(m_active_state == &m_states[0])? &m_states[1] : &m_states[0];

	flush_state_to_disk(tfp, inactive_state, false);
	flush_state_to_disk(tfp, m_active_state, false);

	fclose(tfp);

	job->m_start_time = 
		delta_time_past_ns != 0? ts - delta_time_past_ns : 0;
	job->m_end_time = ts + delta_time_future_ns;
	job->m_filename = filename;

	if(filter != "")
	{
		job->m_filterstr = filter;

		try
		{
			sinsp_filter_compiler compiler(m_inspector, filter);
			job->m_filter = compiler.compile();
		}
		catch(...)
		{
			job->m_state = sinsp_memory_dumper_job::ST_DONE_ERROR;
			job->m_lasterr = "error compiling capture job filter";
			return job;
		}
	}

	apply_job_filter(fname, job);

	unlink(fname.c_str());

	//
	// If no capture in the future is required, the job can stop here
	//
	if(delta_time_future_ns == 0)
	{
		job->m_state = sinsp_memory_dumper_job::ST_DONE_OK;
	}

	return job;
}

void sinsp_memory_dumper::remove_job(sinsp_memory_dumper_job* job)
{
	m_jobs.erase(std::remove(m_jobs.begin(), m_jobs.end(), job), m_jobs.end());
	delete job;
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

void sinsp_memory_dumper::switch_states(uint64_t ts)
{
	//
	// Save the capture to disk
	//
	if(m_cf)
	{
		flush_state_to_disk(m_cf, m_active_state, false);
		m_cur_dump_size += m_bsize;
		m_switches_to_go--;

		bool toobig = (m_cur_dump_size >= m_max_disk_size);

		if(m_switches_to_go == 0 ||
			toobig)
		{
			fclose(m_cf);
			m_cf = NULL;

			if(toobig)
			{
				m_saturation_inactivity_start_time = ts;	
				lo(sinsp_logger::SEV_INFO, "memdump: dump closed because too big, m_max_disk_size=%" PRIu64 ", waiting %" PRIu64 " ns", 
					m_max_disk_size,
					m_saturation_inactivity_pause_ns);
			}
			else
			{
				lo(sinsp_logger::SEV_INFO, "memdump: dump closed");
			}
		}
	}

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
		lo(sinsp_logger::SEV_ERROR, "memdump: capture memory buffer too small to store process information. Memory dump disabled. Current size: " + 
			m_active_state->m_bufsize);

		m_disabled = true;
	}
}

void sinsp_memory_dumper::push_notification(uint64_t ts, uint64_t tid, string id, string description)
{
	m_notification_scap_evt->ts = ts;
	m_notification_scap_evt->tid = tid;

	uint16_t *lens = (uint16_t *)(m_notification_scap_evt_storage + sizeof(struct ppm_evt_hdr));
	uint16_t idlen = id.length() + 1;
	uint16_t desclen = description.length() + 1;
	lens[0] = idlen;
	lens[1] = desclen;

	memcpy((m_notification_scap_evt_storage + sizeof(struct ppm_evt_hdr) + 4), 
		id.c_str(), 
		idlen);

	memcpy((m_notification_scap_evt_storage + sizeof(struct ppm_evt_hdr) + 4 + idlen), 
		description.c_str(), 
		desclen);

	m_notification_scap_evt->len = sizeof(scap_evt) + sizeof(uint16_t) + 4 + idlen + desclen + 1;

	process_event(&m_notification_evt);
	m_active_state->m_last_valid_bufpos = m_active_state->m_dumper->get_memory_dump_cur_buf();
}
