#include "sinsp_worker.h"

#include "logger.h"
#include "error_handler.h"

sinsp_worker::sinsp_worker(dragent_configuration* configuration, dragent_queue* queue):
	m_configuration(configuration),
	m_inspector(NULL),
	m_analyzer(NULL),
	m_sinsp_handler(configuration, queue)
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

	while(!dragent_configuration::m_terminate)
	{
		if(m_configuration->m_evtcnt != 0 && retval.m_nevts == m_configuration->m_evtcnt)
		{
			dragent_configuration::m_terminate = true;
			break;
		}

		if(m_configuration->m_dump_in_progress)
		{
			if(!dragent_configuration::m_dump_enabled)
			{
				g_log->information("Stopping dump");
				m_configuration->m_dump_in_progress = false;
				m_inspector->autodump_stop();
				m_configuration->m_dump_completed.set();
			}
		}
		else
		{
			if(dragent_configuration::m_dump_enabled)
			{
				g_log->information("Starting dump");
				m_configuration->m_dump_in_progress = true;
				m_configuration->m_dump_completed.reset();
				m_inspector->autodump_start(m_configuration->m_dump_file);
			}
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
		// Update the event count
		//
		retval.m_nevts++;

		//
		// Update the time 
		//
		ts = ev->get_ts();

		if(firstts == 0)
		{
			firstts = ts;
		}

		deltats = ts - firstts;
	}

	retval.m_time = deltats;
	return retval;
}
