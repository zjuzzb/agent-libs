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
	m_dump_job_requests(10)
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

	//
	// sysdig that comes with dragent is always installed in /usr
	//
	m_inspector->add_chisel_dir("/usr" CHISELS_INSTALLATION_DIR);

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

captureinfo sinsp_worker::do_inspect()
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	uint64_t ts;
	uint64_t deltats = 0;
	uint64_t firstts = 0;
	uint64_t last_job_check_ns = 0;

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration->m_evtcnt != 0 && retval.m_nevts == m_configuration->m_evtcnt)
		{
			dragent_configuration::m_terminate = true;
			break;
		}

		res = m_inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
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

		if(ts - last_job_check_ns > 1000000000)
		{
			last_job_check_ns = ts;

			//
			// Check every second if we have a new job
			//
			start_new_jobs(ts);
		}

		run_dump_jobs(ev);

		//
		// Update the event count
		//
		retval.m_nevts++;

		if(firstts == 0)
		{
			firstts = ts;
		}

		deltats = ts - firstts;
	}

	retval.m_time = deltats;
	return retval;
}

void sinsp_worker::schedule_dump_job(SharedPtr<dump_job_request> job_request)
{
	g_log->information("Scheduling dump job");

	if(!m_dump_job_requests.put(job_request))
	{
		send_error(job_request->m_token, "Maximum number of dump jobs reached");
	}
}

void sinsp_worker::prepare_response(const string& token, draiosproto::dump_response* response)
{
	response->set_timestamp_ns(dragent_configuration::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->m_machine_id);
	response->set_token(token);
}

void sinsp_worker::queue_response(const draiosproto::dump_response& response)
{
	SharedPtr<protocol_queue_item> buffer = dragent_protocol::message_to_buffer(
		draiosproto::message_type::DUMP_RESPONSE, 
		response, 
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	while(!m_queue->put(buffer))
	{
		g_log->error("Queue full, discarding file");
	}
}

void sinsp_worker::run_dump_jobs(sinsp_evt* ev)
{
	vector<SharedPtr<dump_job_state>>::iterator it = m_running_dump_jobs.begin();

	while(it != m_running_dump_jobs.end())
	{
		SharedPtr<dump_job_state> job = *it;

		bool terminate = false;

		if(job->m_dumper->written_bytes() > m_max_dump_file_size)
		{
			terminate = true;
		}

		if(ev->get_ts() - job->m_start_ns > job->m_duration_ns)
		{
			terminate = true;
		}

		if(terminate)
		{
			g_log->information("Job completed, captured events: " 
				+ NumberFormatter::format(job->m_n_events));

			it = m_running_dump_jobs.erase(it);

			//
			// Stop the job
			//
			delete job->m_dumper;
			job->m_dumper = NULL;

			if(job->m_send_file_when_done)
			{
				send_file(job->m_token, job->m_file);
			}
		}
		else
		{
			++it;
			
			if(job->m_filter)
			{
				if(!job->m_filter->run(ev))
				{
					continue;
				}
			}

			++job->m_n_events;
			job->m_dumper->dump(ev);
		}
	}
}

void sinsp_worker::send_error(const string& token, const string& error)
{
	g_log->error(error);
	draiosproto::dump_response response;
	prepare_response(token, &response);
	response.set_error(error);
	queue_response(response);	
}

void sinsp_worker::send_file(const string& token, const string& filename)
{
	FileInputStream file(filename);
	string sfile;

	uint32_t nread = copy_file(&file, &sfile);
	
	g_log->information(m_name + ": " + filename + ": File size: " + NumberFormatter::format(nread));

	draiosproto::dump_response response;
	prepare_response(token, &response);
	response.set_content(sfile);
	queue_response(response);
}

std::streamsize sinsp_worker::copy_file(FileInputStream* istr, std::string* str)
{
	Buffer<char> buffer(8192);
	std::streamsize len = 0;
	
	istr->read(buffer.begin(), buffer.size());
	std::streamsize n = istr->gcount();

	while(n > 0)
	{
		len += n;
		str->append(buffer.begin(), static_cast<std::string::size_type>(n));

		if(len > MAX_SERIALIZATION_BUF_SIZE_BYTES)
		{
			g_log->information("File too big, truncating to " + NumberFormatter::format(len));
			break;
		}

		if(istr)
		{
			istr->read(buffer.begin(), buffer.size());
			n = istr->gcount();
		}
		else 
		{
			n = 0;
		}
	}

	return len;
}

void sinsp_worker::start_new_jobs(uint64_t ts)
{
	if(dragent_configuration::m_signal_dump)
	{
		dragent_configuration::m_signal_dump = false;
		SharedPtr<dump_job_state> job_state(new dump_job_state());

		job_state->m_dumper = new sinsp_dumper(m_inspector);
		job_state->m_file = m_configuration->m_dump_dir + "dump.scap";
		g_log->information("Starting dump job in " + job_state->m_file);
		job_state->m_dumper->open(job_state->m_file);

		job_state->m_duration_ns = 20000000000LL;
		job_state->m_start_ns = ts;
		job_state->m_delete_file_when_done = false;
		job_state->m_send_file_when_done = false;

		m_running_dump_jobs.push_back(job_state);
	}

	SharedPtr<dump_job_request> request;
	while(m_dump_job_requests.get(&request, 0))
	{
		SharedPtr<dump_job_state> job_state(new dump_job_state());

		if(!request->m_filter.empty())
		{
			try
			{
				job_state->m_filter = new sinsp_filter(m_inspector, request->m_filter);
			}
			catch(sinsp_exception& e)
			{
				send_error(request->m_token, e.what());
				return;
			}
		}

		job_state->m_token = request->m_token;
		job_state->m_dumper = new sinsp_dumper(m_inspector);
		job_state->m_file = TemporaryFile::tempName(m_configuration->m_dump_dir) + ".scap";
		g_log->information("Starting dump job in " + job_state->m_file + 
			", filter '" + request->m_filter + "'");
		job_state->m_dumper->open(job_state->m_file);

		job_state->m_duration_ns = request->m_duration_ns;
		job_state->m_start_ns = ts;

		m_running_dump_jobs.push_back(job_state);
	}
}
