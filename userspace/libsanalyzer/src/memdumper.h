#pragma once

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <atomic>

#include "Poco/Mutex.h"
#include "Poco/ScopedLock.h"

#include "analyzer_utils.h"
#include "sinsp_int.h"

class sinsp_memory_dumper_state
{
public:
	sinsp_memory_dumper_state(sinsp* inspector, uint64_t bufsize, std::string shm_name)
		: m_inspector(inspector),
		m_shm_name(shm_name),
		m_shm_fd(0),
		m_bufsize(bufsize),
		m_begin_ts(0),
		m_end_ts(0)
	{
	}

	~sinsp_memory_dumper_state()
	{
		close();

		if(m_shm_fd != 0)
		{
			::close(m_shm_fd);
		}

		if(shm_unlink(m_shm_name.c_str()) != 0)
		{
			glogf(sinsp_logger::SEV_CRITICAL, "unable to remove the shared memory region %s: %s",
			      m_shm_name.c_str(),
			      strerror(errno));
		}
	}

	void close()
	{
		m_dumper = NULL;
		m_shm_fd = 0;
	}

	bool open(std::string &errstr)
	{
		shm_unlink(m_shm_name.c_str());

		m_shm_fd = shm_open(m_shm_name.c_str(), O_RDWR | O_CREAT | O_EXCL, S_IRWXU);
		if(m_shm_fd == -1)
		{
			errstr = std::string("could not reset shared memory segment: ") + strerror(errno);
			return false;
		}

		try
		{
			m_dumper = make_unique<sinsp_dumper>(m_inspector);

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
				std::to_string(m_bufsize);
			return false;
		}

		m_begin_ts = m_end_ts = 0;

		return true;
	}

	bool is_open()
	{
		return (m_dumper && m_dumper->is_open());
	}

	// Returns the number of bytes written.
	inline uint64_t flush()
	{
		Poco::ScopedLock<Poco::FastMutex> lck(m_dumper_mtx);
		m_dumper->flush();

		return m_dumper->written_bytes();
	}

	inline void dump(sinsp_evt *evt)
	{
		Poco::ScopedLock<Poco::FastMutex> lck(m_dumper_mtx);

		if(m_begin_ts == 0)
		{
			m_begin_ts = evt->get_ts();
		}

		m_end_ts = evt->get_ts();

		m_dumper->dump(evt);
	}

	sinsp *m_inspector;
        std::string m_shm_name;
	std::unique_ptr<sinsp_dumper> m_dumper;
	int m_shm_fd;
	uint64_t m_bufsize;

	// Reflects the timerange covered by events in this memory state.
	uint64_t m_begin_ts;
	uint64_t m_end_ts;

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

			if(m_filter != NULL)
			{
				m_filter->run(evt);
			}

			bool do_drop;
			(void) evt->get_dump_flags(&do_drop);
			if(do_drop)
			{
				return;
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
	std::string m_filterstr;
	std::string m_filename;
	state m_state;
	std::string m_lasterr;
	sinsp_dumper* m_dumper;
	sinsp_filter* m_filter;
	uint64_t m_n_events;
};

class sinsp_memory_dumper
{
public:
	sinsp_memory_dumper(sinsp* inspector);
	~sinsp_memory_dumper();
	void init(uint64_t bufsize, uint64_t max_disk_size, uint64_t max_init_attempts);
	void close();

	// Write a file on disk that contains the result of applying
	// the filter to the events in the memory buffer. If track_job
	// is true, also create internal state to track this memory
	// dumper job going forward.
	// Returns an object containing details on what occurred.
	// The caller should delete this object.
	//
	// If membuf_mtx is non-NULL, lock the mutex before the job has
	// fully read the memory buffer, to guarantee that
	// process_event will stop adding new events to the
	// buffer. The caller will unlock the mutex when the job has
	// been added to the list of jobs.

	sinsp_memory_dumper_job* add_job(uint64_t ts, std::string filename, std::string filter,
					 uint64_t delta_time_past_ns, uint64_t delta_time_future_ns,
					 Poco::Mutex *membuf_mtx);

	inline void process_event(sinsp_evt *evt)
	{
		//
		// Capture is disabled if there was not enough memory to dump the thread table.
		//
		if(m_disabled)
		{
			return;
		}

		// If a delayed state switch is needed, see if it is
		// ready and if so switch states. Otherwise, skip the
		// event.
		if(m_delayed_switch_states_needed)
		{
			if(m_delayed_switch_states_ready)
			{
				switch_states(evt->get_ts());

				// If after switching, memdump is
				// disabled, just return.
				if(m_disabled)
				{
					return;
				}
			}
			else
			{
				m_delayed_switch_states_missed_events++;
				return;
			}
		}

		try
		{
			(*m_active_state)->dump(evt);

			// If we've written at least m_bsize bytes to the active state, switch states.
			if((*m_active_state)->m_dumper->next_write_position() >= (*m_active_state)->m_bufsize)
			{
				switch_states(evt->get_ts());

				// If after switching, memdump is
				// disabled, just return.
				if(m_disabled)
				{
					return;
				}
			}
		}
		catch(sinsp_exception e)
		{
			ASSERT(evt != NULL);
			switch_states(evt->get_ts());

			// If after switching, memdump is
			// disabled, just return.
			if(m_disabled)
			{
				return;
			}

			{
				Poco::ScopedLock<Poco::FastMutex> lck((*m_active_state)->m_dumper_mtx);
				(*m_active_state)->m_dumper->dump(evt);
			}
		}
	}

	inline bool is_enabled()
	{
		return !m_disabled;
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
	std::atomic<bool> m_reader_active;
	uint32_t m_file_id;
	FILE* m_f;
	FILE* m_cf;
	bool m_disabled;
	uint32_t m_switches_to_go;
	uint32_t m_cur_dump_size;
	uint32_t m_max_disk_size;
	uint64_t m_bsize;

	std::atomic<bool> m_delayed_switch_states_needed;
	std::atomic<bool> m_delayed_switch_states_ready;
	uint64_t m_delayed_switch_states_missed_events;

	// Mutex that protects access to the list of states
	Poco::FastMutex m_state_mtx;

	char m_errbuf[256];
};
