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
		dump_job_request(uint64_t duration_ns, const string& filter):
			m_duration_ns(duration_ns),
			m_filter(filter)
		{
		}

		uint64_t m_duration_ns;
		string m_filter;
	};

	sinsp_worker(dragent_configuration* configuration, protocol_queue* queue);
	~sinsp_worker();

	void init();
	captureinfo do_inspect();
	void schedule_dump_job(SharedPtr<dump_job_request> job_request);

private:
	class dump_job_state
	{
	public:
		dump_job_state():
			m_dumper(NULL),
			m_filter(NULL),
			m_start_ns(0),
			m_duration_ns(0),
			m_delete_file_when_done(true),
			m_send_file_when_done(true),
			m_n_events(0)
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

			if(m_delete_file_when_done && !m_file.empty())
			{
				File f(m_file);
				if(f.exists())
				{
					f.remove();
				}
			}
		}

		sinsp_dumper* m_dumper;
		sinsp_filter* m_filter;
		uint64_t m_start_ns;
		uint64_t m_duration_ns;
		string m_file;
		bool m_delete_file_when_done;
		bool m_send_file_when_done;
		uint64_t m_n_events;
	};

	void prepare_response(draiosproto::dump_response* response);
	void queue_response(const draiosproto::dump_response& response);
	void send_error(const string& error);
	void send_file(const string& filename);
	static std::streamsize copy_file(FileInputStream* istr, std::string* str);
	void run_dump_jobs(sinsp_evt* ev);
	void start_new_jobs(uint64_t ts);

	static const string m_name;
	static const uint64_t m_max_dump_file_size = MAX_SERIALIZATION_BUF_SIZE_BYTES * 0.9;

	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	sinsp_data_handler m_sinsp_handler;
	blocking_queue<SharedPtr<dump_job_request>> m_dump_job_requests;
	vector<SharedPtr<dump_job_state>> m_running_dump_jobs;
};
