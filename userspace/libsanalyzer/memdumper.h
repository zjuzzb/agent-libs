#pragma once

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <atomic>

#include "Poco/Mutex.h"
#include "Poco/ScopedLock.h"

#include "sinsp_int.h"

class sinsp_memory_dumper_state
{
public:
	sinsp_memory_dumper_state()
	{
		m_dumper = NULL;
		m_shm_fd = 0;
		m_shm_name = "";
	}

	~sinsp_memory_dumper_state()
	{
		if(m_dumper != NULL)
		{
			delete m_dumper;
		}

		::close(m_shm_fd);

		if(shm_unlink(m_shm_name.c_str()) != 0)
		{
			throw sinsp_exception(string("unable to remove the shared memory region for the sysdig memory dump: ") + strerror(errno));
		}
	}

	void close()
	{
		m_dumper->close();
	}

	bool open(sinsp *inspector, std::string &errstr)
	{
		if (lseek(m_shm_fd, SEEK_SET, 0) != 0)
		{
			errstr = "could not reset shared memory segment";
			return false;
		}

		try
		{
			// NOTE: Compression is intentionally disabled. In
			// addition to being a better tradeoff of cpu time vs
			// space savings, the file offsets used in
			// inspector.get_bytes_read()/m_dumper->written_bytes()
			// only match up when using pass-through uncompressed
			// files. Otherwise, you have to perform an lseek
			// system call every time you check the offsets.
			m_dumper->fdopen(m_shm_fd, false, true);
		}
		catch(sinsp_exception e)
		{
			errstr = "capture memory buffer too small to store process information. Current size: " +
				m_bufsize;
			return false;
		}

		return true;
	}

	void init(sinsp* inspector, uint64_t bufsize, string shm_name)
	{
		m_shm_name = shm_name;

		// Try to remove the shared memory segment first.
		shm_unlink(m_shm_name.c_str());

		m_shm_fd = shm_open(m_shm_name.c_str(), O_RDWR | O_CREAT | O_EXCL, S_IRWXU);
		if(m_shm_fd == -1)
		{
			throw sinsp_exception(string("unable to allocate the shared memory region for the sysdig memory dump: ") + strerror(errno));
		}

		if(ftruncate(m_shm_fd, bufsize) != 0)
		{
			throw sinsp_exception(string("unable to initialize the shared memory region for the sysdig memory dump: ") + strerror(errno));
		}

		try
		{
			m_dumper = new sinsp_dumper(inspector);
		}
		catch(sinsp_exception e)
		{
			throw sinsp_exception(
				"capture memory buffer too small to store process information. Current size: " +
				to_string(m_bufsize));
		}
	}

	// Returns the number of bytes written.
	inline uint64_t flush()
	{
		Poco::ScopedLock<Poco::FastMutex> lck(m_dumper_mtx);
		m_dumper->flush();

		return m_dumper->written_bytes();
	}

        std::string m_shm_name;
	sinsp_dumper* m_dumper;
	int m_shm_fd;
	uint64_t m_bufsize;

	// Mutex that protects access to this state's dumper
	Poco::FastMutex m_dumper_mtx;
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
		m_n_events = 0;
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

			m_n_events++;

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
	uint64_t m_n_events;
};

class sinsp_memory_dumper
{
public:
	sinsp_memory_dumper(sinsp* inspector, bool capture_dragent_events);
	~sinsp_memory_dumper();
	void init(uint64_t bufsize, uint64_t max_disk_size, uint64_t saturation_inactivity_pause_ns);
	void close();
	void to_file_multi(string name, uint64_t ts_ns);

	// Write a file on disk that contains the result of applying
	// the filter to the events in the memory buffer. If track_job
	// is true, also create internal state to track this memory
	// dumper job going forward.
	// Returns an object containing details on what occurred. If
	// track_job is false, the caller should delete this
	// object. Otherwise, the caller should pass it to remove_job
	// later.
	//
	// If membuf_mtx is non-NULL, lock the mutex before the job has
	// fully read the memory buffer, to guarantee that
	// process_event will stop adding new events to the
	// buffer. The caller will unlock the mutex when the job has
	// been added to the list of jobs.

	sinsp_memory_dumper_job* add_job(uint64_t ts, string filename, string filter,
					 uint64_t delta_time_past_ns, uint64_t delta_time_future_ns,
					 bool track_job, Poco::Mutex *membuf_mtx);

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
#if defined(HAS_CAPTURE)
			if(!m_capture_dragent_events)
			{
				//
				// The custom notification events emitted by the memdumper have inspector = NULL
				//
				if(evt->m_pevt->type != PPME_NOTIFICATION_E)
				{
					sinsp_threadinfo* tinfo = evt->get_thread_info();
					if(tinfo &&	tinfo->m_pid == m_sysdig_pid)
					{
						return;
					}
				}
			}
#endif

			{
				Poco::ScopedLock<Poco::FastMutex> lck((*m_active_state)->m_dumper_mtx);
				(*m_active_state)->m_dumper->dump(evt);
			}

			for(auto it = m_jobs.begin(); it != m_jobs.end(); ++it)
			{
				(*it)->dump(evt);
			}
		}
		catch(sinsp_exception e)
		{
			ASSERT(evt != NULL);
			switch_states(evt->get_ts());
			{
				Poco::ScopedLock<Poco::FastMutex> lck((*m_active_state)->m_dumper_mtx);
				(*m_active_state)->m_dumper->dump(evt);
			}
		}
	}
	void push_notification(uint64_t ts, uint64_t tid, string id, string description);
	inline vector<sinsp_memory_dumper_job*>* get_jobs()
	{
		return &m_jobs;
	}

private:
	void switch_states(uint64_t ts);
	bool read_membuf_using_inspector(sinsp &inspector, const std::shared_ptr<sinsp_memory_dumper_state> &state, sinsp_memory_dumper_job* job);
	void apply_job_filter(const std::shared_ptr<sinsp_memory_dumper_state> &state, sinsp_memory_dumper_job* job, Poco::Mutex *membuf_mtx);

	typedef std::list<std::shared_ptr<sinsp_memory_dumper_state>> memdump_state;

	scap_threadinfo* m_scap_proclist;
	sinsp* m_inspector;

	memdump_state m_states;
	memdump_state::iterator m_active_state;
	memdump_state::const_reverse_iterator m_reader_state;
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
#if defined(HAS_CAPTURE)
	bool m_capture_dragent_events;
	int64_t m_sysdig_pid;
#endif
	// Mutex that protects access to the list of states
	Poco::FastMutex m_state_mtx;
};
