#pragma once

#include "main.h"
#include "configuration.h"
#include "sinsp_data_handler.h"

class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};

class sinsp_worker
{
public:
	class dump_job_request
	{
	public:
		enum request_type {
			JOB_START,
			JOB_STOP
		};

		dump_job_request():
			m_duration_ns(0),
			m_max_size(0)
		{
		}

		request_type m_request_type;
		string m_token;
		uint64_t m_duration_ns;
		uint64_t m_max_size;
		string m_filter;
	};

	sinsp_worker(dragent_configuration* configuration, protocol_queue* queue);
	~sinsp_worker();

	void init();
	captureinfo do_inspect();
	void queue_job_request(SharedPtr<dump_job_request> job_request);

private:
	class dump_job_state
	{
	public:
		dump_job_state():
			m_dumper(NULL),
			m_filter(NULL),
			m_start_ns(0),
			m_duration_ns(0),
			m_max_size(0),
			m_fp(NULL),
			m_file_size(0),
			m_delete_file_when_done(true),
			m_send_file(true),
			m_n_events(0),
			m_last_chunk_offset(0),
			m_last_chunk_idx(0),
			m_terminated(false),
			m_error(false)
		{
		}

		~dump_job_state()
		{			
			if(m_dumper)
			{
				delete m_dumper;
				m_dumper = NULL;
			}

			if(m_filter)
			{
				delete m_filter;
				m_filter = NULL;
			}

			if(m_fp)
			{
				fclose(m_fp);
				m_fp = NULL;
			}

			if(m_delete_file_when_done && !m_file.empty())
			{
				File f(m_file);
				if(f.exists())
				{
					f.remove();
				}
			}
		}

		string m_token;
		sinsp_dumper* m_dumper;
		sinsp_filter* m_filter;
		uint64_t m_start_ns;
		uint64_t m_duration_ns;
		uint64_t m_max_size;
		string m_file;
		FILE* m_fp;
		uint64_t m_file_size;
		bool m_delete_file_when_done;
		bool m_send_file;
		uint64_t m_n_events;
		uint64_t m_last_chunk_offset;
		uint64_t m_last_chunk_idx;
		string m_last_chunk;
		bool m_terminated;
		bool m_error;
	};

	void prepare_response(const string& token, draiosproto::dump_response* response);
	bool queue_response(const draiosproto::dump_response& response);
	void send_error(const string& token, const string& error);
	void send_dump_chunks(dump_job_state* job);
	void run_jobs(sinsp_evt* ev);
	void process_job_requests(uint64_t ts);
	void flush_jobs();
	void stop_job(dump_job_state* job);
	void start_job(const dump_job_request& request, uint64_t ts);
	void read_chunk(dump_job_state* job);

	static const string m_name;
	static const uint64_t m_max_chunk_size = 100 * 1024;

	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	sinsp_data_handler m_sinsp_handler;
	blocking_queue<SharedPtr<dump_job_request>> m_dump_job_requests;
	vector<SharedPtr<dump_job_state>> m_running_dump_jobs;
	int64_t m_dragent_pid;
};
