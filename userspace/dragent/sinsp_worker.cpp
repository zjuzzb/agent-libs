#include "sinsp_worker.h"

#include "logger.h"
#include "error_handler.h"

const string sinsp_worker::m_name = "sinsp_worker";

sinsp_worker::sinsp_worker(dragent_configuration* configuration, protocol_queue* queue):
	m_configuration(configuration),
	m_queue(queue),
	m_inspector(NULL),
	m_analyzer(NULL),
	m_sinsp_handler(configuration, queue),
	m_dump_job_requests(10),
	m_dragent_pid(0),
	m_last_loop_ns(0)
{
}

sinsp_worker::~sinsp_worker()
{
	if(m_inspector != NULL)
	{
		delete m_inspector;
	}

	if(m_analyzer != NULL)
	{
		delete m_analyzer;
	}
}

void sinsp_worker::init()
{
	m_inspector = new sinsp();
	m_analyzer = new sinsp_analyzer(m_inspector);
	m_inspector->m_analyzer = m_analyzer;

	m_dragent_pid = getpid();

	//
	// sysdig that comes with dragent is always installed in /usr
	//
	m_inspector->add_chisel_dir("/usr" CHISELS_INSTALLATION_DIR, false);

	m_inspector->set_debug_mode(true);

	//
	// Attach our transmit callback to the analyzer
	//
	m_inspector->m_analyzer->set_sample_callback(&m_sinsp_handler);

	//
	// Plug the sinsp logger into our one
	//
	m_inspector->set_log_callback(dragent_logger::sinsp_logger_callback);
	if(!m_configuration->m_metrics_dir.empty())
	{
		//
		// Create the metrics directory if it doesn't exist
		//
		File md(m_configuration->m_metrics_dir);
		md.createDirectories();
		m_analyzer->get_configuration()->set_emit_metrics_to_file(true);
		m_analyzer->get_configuration()->set_metrics_directory(m_configuration->m_metrics_dir);
	}
	else
	{
		g_log->information("metricsfile.location not specified, metrics won't be saved to disk.");
	}

	//
	// The machine id is the MAC address of the first physical adapter
	//
	m_analyzer->get_configuration()->set_machine_id(m_configuration->m_machine_id);

	//
	// The customer id is currently specified by the user
	//
	if(m_configuration->m_customer_id.empty())
	{
		g_log->error("customerid not specified.");
	}

	m_analyzer->get_configuration()->set_customer_id(m_configuration->m_customer_id);

	//
	// Configure compression in the protocol
	//
	m_analyzer->get_configuration()->set_compress_metrics(m_configuration->m_compression_enabled);

	//
	// Configure connection aggregation
	//
	m_analyzer->get_configuration()->set_aggregate_connections_in_proto(!m_configuration->m_emit_full_connections);

	if(m_configuration->m_subsampling_ratio != 1)
	{
		g_log->information("Enabling dropping mode, ratio=" + NumberFormatter::format(m_configuration->m_subsampling_ratio));
		m_inspector->start_dropping_mode(m_configuration->m_subsampling_ratio);
	}

	if(m_configuration->m_drop_upper_treshold != 0)
	{
		g_log->information("Drop upper treshold=" + NumberFormatter::format(m_configuration->m_drop_upper_treshold));
		m_analyzer->get_configuration()->set_drop_upper_threshold(m_configuration->m_drop_upper_treshold);
	}

	if(m_configuration->m_drop_lower_treshold != 0)
	{
		g_log->information("Drop lower treshold=" + NumberFormatter::format(m_configuration->m_drop_lower_treshold));
		m_analyzer->get_configuration()->set_drop_lower_threshold(m_configuration->m_drop_lower_treshold);
	}

	if(m_configuration->m_host_custom_name != "")
	{
		g_log->information("Setting custom name=" + m_configuration->m_host_custom_name);
		m_analyzer->get_configuration()->set_host_custom_name(m_configuration->m_host_custom_name);
	}

	if(m_configuration->m_host_tags != "")
	{
		g_log->information("Setting tags=" + m_configuration->m_host_tags);
		m_analyzer->get_configuration()->set_host_tags(m_configuration->m_host_tags);
	}

	if(m_configuration->m_host_custom_map != "")
	{
		g_log->information("Setting custom map=" + m_configuration->m_host_custom_map);
		m_analyzer->get_configuration()->set_host_custom_map(m_configuration->m_host_custom_map);
	}

	if(m_configuration->m_hidden_processes != "")
	{
		g_log->information("Setting hidden processes=" + m_configuration->m_hidden_processes);
		m_analyzer->get_configuration()->set_hidden_processes(m_configuration->m_hidden_processes);
	}

	if(m_configuration->m_host_hidden)
	{
		g_log->information("Setting host hidden");
		m_analyzer->get_configuration()->set_host_hidden(m_configuration->m_host_hidden);
	}
	
	if(m_configuration->m_autodrop_enabled)
	{
		g_log->information("Setting autodrop");
		m_analyzer->get_configuration()->set_autodrop_enabled(true);
	}

	m_analyzer->get_configuration()->set_version(AGENT_VERSION);
	
	//
	// Start the capture with sinsp
	//
	g_log->information("Opening the capture source");
	if(m_configuration->m_input_filename != "")
	{
		m_inspector->open(m_configuration->m_input_filename);
	}
	else
	{
		m_inspector->open("");
	}

	aws_metadata metadata;
	if(m_configuration->get_aws_metadata(&metadata))
	{
		sinsp_ipv4_ifinfo aws_interface(metadata.m_public_ipv4, metadata.m_public_ipv4, metadata.m_public_ipv4, "aws");
		m_inspector->import_ipv4_interface(aws_interface);
	}
}

void sinsp_worker::run()
{
	uint64_t nevts = 0;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;
	uint64_t last_job_check_ns = 0;

	m_pthread_id = pthread_self();

	g_log->information("sinsp_worker: Starting");

	init();

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration->m_evtcnt != 0 && nevts == m_configuration->m_evtcnt)
		{
			dragent_configuration::m_terminate = true;
			break;
		}

		res = m_inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			m_last_loop_ns = dragent_configuration::get_current_time_ns();
			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			cerr << "res = " << res << endl;
			throw sinsp_exception(m_inspector->getlasterr().c_str());
		}

		//
		// Update the time 
		//
		ts = ev->get_ts();
		m_last_loop_ns = ts;

		if(ts - last_job_check_ns > 1000000000)
		{
			last_job_check_ns = ts;

			process_job_requests(ts);

			//
			// Also, just every second, cleanup the old ones
			// Why every second? Because the sending queue might be
			// full and we still send each one every second
			//
			flush_jobs(ts);
		}

		run_jobs(ev);

		//
		// Update the event count
		//
		++nevts;
	}

	g_log->information("sinsp_worker: Terminating");
}

void sinsp_worker::queue_job_request(SharedPtr<dump_job_request> job_request)
{
	g_log->information("Scheduling job request " + job_request->m_token);

	if(!m_dump_job_requests.put(job_request))
	{
		send_error(job_request->m_token, "Maximum number of requests reached");
	}
}

void sinsp_worker::prepare_response(const string& token, draiosproto::dump_response* response)
{
	response->set_timestamp_ns(dragent_configuration::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->m_machine_id);
	response->set_token(token);
}

bool sinsp_worker::queue_response(const draiosproto::dump_response& response, protocol_queue::item_priority priority)
{
	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		draiosproto::message_type::DUMP_RESPONSE, 
		response, 
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return true;
	}

	while(!m_queue->put(buffer, priority))
	{
		g_log->error("Queue full");
		return false;
	}

	return true;
}

void sinsp_worker::run_jobs(sinsp_evt* ev)
{
	for(vector<SharedPtr<dump_job_state>>::iterator it = m_running_dump_jobs.begin();
		it != m_running_dump_jobs.end(); ++it)
	{
		SharedPtr<dump_job_state> job = *it;

		if(job->m_terminated)
		{
			continue;
		}

		//
		// We don't want dragent to show up in captures
		//
		sinsp_threadinfo* tinfo = ev->get_thread_info();
		uint16_t etype = ev->get_type();

		if(tinfo &&
			tinfo->m_pid == m_dragent_pid &&
			etype != PPME_SCHEDSWITCH_1_E && 
			etype != PPME_SCHEDSWITCH_6_E)
		{
			continue;
		}

		if(job->m_max_size && 
			job->m_file_size > job->m_max_size)
		{
			stop_job(job);
			continue;
		}

		if(job->m_duration_ns && 
			ev->get_ts() - job->m_start_ns > job->m_duration_ns)
		{
			stop_job(job);
			continue;
		}

		if(job->m_filter)
		{
			if(!job->m_filter->run(ev))
			{
				continue;
			}
		}

		job->m_dumper->dump(ev);
		++job->m_n_events;
	}
}

void sinsp_worker::stop_job(dump_job_state* job)
{
	ASSERT(!job->m_terminated);
	job->m_terminated = true;

	g_log->information("Job " + job->m_token + " stopped, captured events: " 
		+ NumberFormatter::format(job->m_n_events));

	//
	// Stop the job, but don't delete it yet, there might be
	// a bunch of pending chunks
	//
	delete job->m_dumper;
	job->m_dumper = NULL;
}

void sinsp_worker::send_error(const string& token, const string& error)
{
	g_log->error(error);
	draiosproto::dump_response response;
	prepare_response(token, &response);
	response.set_error(error);
	queue_response(response, protocol_queue::BQ_PRIORITY_HIGH);	
}

void sinsp_worker::send_dump_chunks(dump_job_state* job)
{
	ASSERT(job->m_last_chunk_offset <= job->m_file_size);
	while(job->m_last_chunk_offset < job->m_file_size &&
		(job->m_terminated ||
		job->m_file_size - job->m_last_chunk_offset > m_max_chunk_size))
	{
		if(job->m_last_chunk.empty())
		{
			read_chunk(job);
		}

		uint32_t progress = 0;
		ASSERT(job->m_file_size > 0);
		if(job->m_file_size > 0)
		{
			progress = (job->m_last_chunk_offset * 100) / job->m_file_size;
		}

		g_log->information(m_name + ": " + job->m_file + ": Sending chunk " 
			+ NumberFormatter::format(job->m_last_chunk_idx) + " of size " 
			+ NumberFormatter::format(job->m_last_chunk.size())
			+ ", progress " + NumberFormatter::format(progress) + "%%");

		draiosproto::dump_response response;
		prepare_response(job->m_token, &response);
		response.set_content(job->m_last_chunk);
		response.set_chunk_no(job->m_last_chunk_idx);

		ASSERT(job->m_last_chunk_offset + job->m_last_chunk.size() <= job->m_file_size);
		if(job->m_last_chunk_offset + job->m_last_chunk.size() >= job->m_file_size)
		{
			response.set_final_chunk(true);
		}
		
		if(!queue_response(response, protocol_queue::BQ_PRIORITY_LOW))
		{
			g_log->error(m_name + ": " + job->m_file + ": Queue full while sending chunk " 
				+ NumberFormatter::format(job->m_last_chunk_idx) + ", will retry in 1 second");
			return;
		}

		++job->m_last_chunk_idx;
		job->m_last_chunk_offset += job->m_last_chunk.size();
		job->m_last_chunk.clear();
	}
}

void sinsp_worker::read_chunk(dump_job_state* job)
{
	Buffer<char> buffer(16384);
	uint64_t chunk_size = m_max_chunk_size;
	bool eof = false;

	while(!eof && chunk_size)
	{
		size_t to_read = min<u_int64_t>(buffer.size(), chunk_size); 
		ASSERT(job->m_fp);
		size_t res = fread(buffer.begin(), 1, to_read, job->m_fp);
		if(res != to_read)
		{
			if(feof(job->m_fp))
			{
				g_log->information(m_name + ": " + job->m_file + ": EOF");
				eof = true;
			}
			else if(ferror(job->m_fp))
			{
				g_log->error(m_name + ": ferror while reading " + job->m_file);
				job->m_error = true;
				send_error(job->m_token, "ferror while reading " + job->m_file);
				ASSERT(false);
				return;
			} else {
				g_log->error(m_name + ": unknown error while reading " + job->m_file);
				job->m_error = true;
				send_error(job->m_token, "unknown error while reading " + job->m_file);
				ASSERT(false);
				return;
			}
		}

		chunk_size -= res;
		job->m_last_chunk.append(buffer.begin(), res);
	}
}

void sinsp_worker::process_job_requests(uint64_t ts)
{
	if(dragent_configuration::m_signal_dump)
	{
		dragent_configuration::m_signal_dump = false;
		SharedPtr<dump_job_state> job_state(new dump_job_state());

		job_state->m_dumper = new sinsp_dumper(m_inspector);
		job_state->m_file = m_configuration->m_dump_dir + "dump.scap";
		g_log->information("Starting dump job " + job_state->m_token 
			+ " in " + job_state->m_file);
		job_state->m_dumper->open(job_state->m_file, true);

		job_state->m_duration_ns = 20000000000LL;
		job_state->m_start_ns = ts;
		job_state->m_delete_file_when_done = false;
		job_state->m_send_file = false;

		m_running_dump_jobs.push_back(job_state);
	}

	SharedPtr<dump_job_request> request;
	while(m_dump_job_requests.get(&request, 0))
	{
		switch(request->m_request_type)
		{
		case dump_job_request::JOB_START:
			start_job(*request, ts);
			break;
		case dump_job_request::JOB_STOP:
			{
				bool found = false;

				for(vector<SharedPtr<dump_job_state>>::iterator it = m_running_dump_jobs.begin();
					it != m_running_dump_jobs.end(); ++it)
				{
					if((*it)->m_token == request->m_token)
					{
						stop_job(*it);
						found = true;
						break;
					}
				}

				if(!found)
				{
					g_log->error("Can't find job " + request->m_token);
				}

				break;
			}
		default:
			ASSERT(false);
		}
	}
}

void sinsp_worker::start_job(const dump_job_request& request, uint64_t ts)
{
	SharedPtr<dump_job_state> job_state(new dump_job_state());

	if(!request.m_filter.empty())
	{
		try
		{
			job_state->m_filter = new sinsp_filter(m_inspector, request.m_filter);
		}
		catch(sinsp_exception& e)
		{
			send_error(request.m_token, e.what());
			return;
		}
	}

	job_state->m_token = request.m_token;
	job_state->m_dumper = new sinsp_dumper(m_inspector);
	job_state->m_file = m_configuration->m_dump_dir + request.m_token + ".scap";
	g_log->information("Starting dump job in " + job_state->m_file + 
		", filter '" + request.m_filter + "'");
	job_state->m_dumper->open(job_state->m_file, true);

	job_state->m_fp = fopen(job_state->m_file.c_str(), "r");
	if(job_state->m_fp == NULL)
	{
		send_error(request.m_token, strerror(errno));
		return;
	}

	job_state->m_duration_ns = request.m_duration_ns;
	job_state->m_max_size = request.m_max_size;
	job_state->m_start_ns = ts;

	m_running_dump_jobs.push_back(job_state);
}

void sinsp_worker::flush_jobs(uint64_t ts)
{
	vector<SharedPtr<dump_job_state>>::iterator it = m_running_dump_jobs.begin();

	while(it != m_running_dump_jobs.end())
	{
		SharedPtr<dump_job_state> job = *it;

		if(ts - job->m_last_keepalive_ns > m_keepalive_interval_ns)
		{
			job->m_last_keepalive_ns = ts;
			draiosproto::dump_response response;
			prepare_response(job->m_token, &response);
			response.set_keep_alive(true);
			g_log->information("Job " + job->m_token + ": sending keepalive"); 
			queue_response(response, protocol_queue::BQ_PRIORITY_HIGH);
		}

		struct stat st;
		if(stat(job->m_file.c_str(), &st) != 0)
		{
			g_log->error("Error checking file size");
			send_error(job->m_token, "Error checking file size");
			job->m_error = true;
			ASSERT(false);
		}

		job->m_file_size = st.st_size;

		if(!job->m_error && job->m_send_file)
		{
			send_dump_chunks(job);
		}

		if(job->m_error)
		{
			g_log->information("Job " + job->m_token 
				+ ": in error state, deleting"); 
			it = m_running_dump_jobs.erase(it);
		}
		else if(job->m_terminated &&
			(!job->m_send_file ||
			job->m_last_chunk_offset >= job->m_file_size))
		{
			ASSERT(job->m_last_chunk_offset <= job->m_file_size);
			g_log->information("Job " + job->m_token 
				+ ": sent all chunks to backend, deleting"); 
			it = m_running_dump_jobs.erase(it);
		}
		else
		{
			++it;
		}
	}
}
