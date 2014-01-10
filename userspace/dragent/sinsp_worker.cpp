#include "sinsp_worker.h"

#include "logger.h"
#include "error_handler.h"

const string sinsp_worker::m_name = "sinsp_worker";

sinsp_worker::sinsp_worker(dragent_configuration* configuration, dragent_queue* queue):
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

	if(m_configuration->m_dropping_mode)
	{
		g_log->information("Enabling dropping mode");
		m_inspector->start_dropping_mode(4);
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
		string error = "Maximum number of dump jobs reached";
		g_log->error(error);
		draiosproto::dump_response response;
		prepare_response(&response);
		response.set_error(error);
		queue_response(response);
	}
}

void sinsp_worker::prepare_response(draiosproto::dump_response* response)
{
	response->set_timestamp_ns(dragent_configuration::get_current_time_ns());
	response->set_customer_id(m_configuration->m_customer_id);
	response->set_machine_id(m_configuration->m_machine_id);
}

void sinsp_worker::queue_response(const draiosproto::dump_response& response)
{
	SharedPtr<dragent_queue_item> buffer = dragent_protocol::message_to_buffer(
		dragent_protocol::PROTOCOL_MESSAGE_TYPE_DUMP_RESPONSE, 
		response, 
		m_configuration->m_compression_enabled);

	if(buffer.isNull())
	{
		g_log->error("NULL converting message to buffer");
		return;
	}

	while(!m_queue->put(buffer))
	{
		g_log->error(m_name + ": Queue full, waiting");
		Thread::sleep(1000);

		if(dragent_configuration::m_terminate)
		{
			break;
		}
	}
}

void sinsp_worker::run_dump_jobs(sinsp_evt* ev)
{
	vector<SharedPtr<dump_job_state>>::iterator it = m_running_dump_jobs.begin();

	while(it != m_running_dump_jobs.end())
	{
		SharedPtr<dump_job_state> job = *it;

		if(ev->get_ts() - job->m_start_ns > job->m_duration_ns)
		{
			g_log->information("Job completed");

			it = m_running_dump_jobs.erase(it);

			//
			// Stop the job
			//
			delete job->m_dumper;
			job->m_dumper = NULL;

			send_file();
		}
		else
		{
			if(job->m_filter)
			{
				if(!job->m_filter->run(ev))
				{
					continue;
				}
			}

			job->m_dumper->dump(ev);

			++it;
		}
	}
}

void sinsp_worker::send_file()
{
	FileInputStream file(m_configuration->m_dump_file);
	string sfile;

	uint32_t nread = copy_file(&file, &sfile);
	
	g_log->information(m_name + ": File size: " + NumberFormatter::format(nread));

	draiosproto::dump_response response;
	prepare_response(&response);
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

		if(len > MAX_SERIALIZATION_BUF_SIZE_BYTES * 0.9)
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
	SharedPtr<dump_job_request> request;
	while(m_dump_job_requests.get(&request, 0))
	{
		g_log->information("Starting dump job");
		SharedPtr<dump_job_state> job_state(new dump_job_state());

		if(!request->m_filter.empty())
		{
			job_state->m_filter = new sinsp_filter(m_inspector, request->m_filter);
		}

		job_state->m_dumper = new sinsp_dumper(m_inspector);
		job_state->m_dumper->open(m_configuration->m_dump_file);

		job_state->m_duration_ns = request->m_duration_ns;
		job_state->m_start_ns = ts;

		m_running_dump_jobs.push_back(job_state);
	}
}
