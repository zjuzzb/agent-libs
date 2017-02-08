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
	enum state
	{
		ST_INPROGRESS = 0,
		ST_DONE_OK = 1,
		ST_DONE_ERROR = 2,
		ST_STOPPPED = 3,
	};

	sinsp_memory_dumper_job()
	{
		m_start_time = 0;
		m_end_time = 0;
		m_state = ST_INPROGRESS;
		m_dumper = NULL;
		m_filter = NULL;
	}

	~sinsp_memory_dumper_job()
	{
		if(m_dumper)
		{
			delete m_dumper;
		}

		if(m_filter)
		{
			delete m_filter;
		}
	}

	inline void dump(sinsp_evt* evt)
	{
		if(m_state == ST_INPROGRESS)
		{
			if(evt->m_pevt->ts > m_end_time)
			{
				m_state = ST_DONE_OK;
				return;
			}

			if(m_filter != NULL && m_filter->run(evt) == false)
			{
				if(evt->get_type() != PPME_NOTIFICATION_E)
				{
					return;
				}
			}

			m_dumper->dump(evt);
		}
	}

	inline bool is_done()
	{
		return m_state != ST_INPROGRESS;
	}

	void stop()
	{
		m_state = ST_STOPPPED;
	}

	uint64_t m_start_time;
	uint64_t m_end_time;
	string m_filterstr;
	string m_filename;
	state m_state;
	string m_lasterr;
	sinsp_dumper* m_dumper;
	sinsp_filter* m_filter;
};

class sinsp_memory_dumper
{
public:
	sinsp_memory_dumper(sinsp* inspector);
	~sinsp_memory_dumper();
	void init(uint64_t bufsize, uint64_t max_disk_size, uint64_t saturation_inactivity_pause_ns);
	void close();
	void to_file_multi(string name, uint64_t ts_ns);
	sinsp_memory_dumper_job* add_job(uint64_t ts, string filename, string filter, 
		uint64_t delta_time_past_ns, uint64_t delta_time_future_ns);
	void remove_job(sinsp_memory_dumper_job* job);
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

			for(auto it = m_jobs.begin(); it != m_jobs.end(); ++it)
			{
				(*it)->dump(evt);
			}
		}
		catch(sinsp_exception e)
		{
			ASSERT(evt != NULL);
			switch_states(evt->get_ts());
			m_active_state->m_dumper->dump(evt);
		}
	}
	void push_notification(sinsp_evt *evt, string id, string description);
	inline vector<sinsp_memory_dumper_job*>* get_jobs()
	{
		return &m_jobs;
	}

private:
	void flush_state_to_disk(FILE* fp, 
		sinsp_memory_dumper_state* state,
		bool is_last_event_complete);
	void switch_states(uint64_t ts);
	void apply_job_filter(string intemrdiate_filename, sinsp_memory_dumper_job* job);

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
	vector<sinsp_memory_dumper_job*> m_jobs;
};
