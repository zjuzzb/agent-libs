#pragma once

class sinsp_memory_dumper_state
{
public:
	sinsp_memory_dumper_state()
	{
		m_dumper = NULL;
		m_buf = NULL;
		m_has_data = false;
	}

	~sinsp_memory_dumper_state()
	{
		if(m_dumper != NULL)
		{
			delete m_dumper;
		}

		if(m_buf != NULL)
		{
			free(m_buf);
		}
	}

	void init(sinsp* inspector, uint64_t bufsize)
	{
		m_buf = (uint8_t*)malloc(bufsize);
		if(m_buf == NULL)
		{
			throw sinsp_exception("unable to allocate the buffer for the sysdig memory dump");
		}

		m_bufsize = bufsize;

		try
		{
			m_dumper = new sinsp_dumper(inspector, m_buf, m_bufsize);
		}
		catch(sinsp_exception e)
		{
			throw sinsp_exception(
				"capture memory buffer too small to store process information. Current size: " + 
				to_string(m_bufsize));
		}
	}

	sinsp_dumper* m_dumper;
	uint8_t* m_buf;
	uint64_t m_bufsize;
	bool m_has_data;
	uint8_t* m_last_valid_bufpos;
};

class sinsp_memory_dumper_job
{
public:
	sinsp_memory_dumper_job()
	{
		m_fp = NULL;
		m_start_time = 0;
		m_size_past = 0;
		m_size_future = 0;
		m_time_past = 0;
		m_time_future = 0;
	}

	FILE* m_fp;
	uint64_t m_start_time;
	uint64_t m_size_past;
	uint64_t m_size_future;
	uint64_t m_time_past;
	uint64_t m_time_future;
};

class sinsp_memory_dumper
{
public:
	sinsp_memory_dumper(sinsp* inspector);
	~sinsp_memory_dumper();
	void init(uint64_t bufsize, uint64_t max_disk_size, uint64_t saturation_inactivity_pause_ns);
	void close();
	void to_file_multi(string name, uint64_t ts_ns);
	void start_job(sinsp_evt *evt, string filename, string filter, uint64_t max_size, 
		uint64_t delta_time_past_ns, uint64_t delta_time_future_ns);
	inline void process_event(sinsp_evt *evt)
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
			ASSERT(evt != NULL);
			switch_states(evt->get_ts());
			m_active_state->m_dumper->dump(evt);
		}
	}
	void push_notification(sinsp_evt *evt, string id, string description);

private:
	void flush_state_to_disk(FILE* fp, 
		sinsp_memory_dumper_state* state,
		bool is_last_event_complete);
	void switch_states(uint64_t ts);
	void apply_job_filter(string outfilename, string infilename, string filter, uint64_t start_time, uint64_t end_time, uint64_t max_size);

	scap_threadinfo* m_scap_proclist;
	sinsp* m_inspector;

	sinsp_memory_dumper_state m_states[2];
	sinsp_memory_dumper_state* m_active_state;
	uint32_t m_file_id;
	FILE* m_f;
	FILE* m_cf;
	bool m_disabled;
	sinsp_evt m_notification_evt;
	uint8_t m_notification_scap_evt_storage[4096];
	scap_evt* m_notification_scap_evt;
	uint32_t m_switches_to_go;
	uint32_t m_cur_dump_size;
	uint32_t m_max_disk_size;
	uint64_t m_bsize;
	uint64_t m_saturation_inactivity_pause_ns;
	uint64_t m_saturation_inactivity_start_time;
	vector<sinsp_memory_dumper_job> m_jobs;
};
