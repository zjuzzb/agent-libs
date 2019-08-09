#include <thread>
#include <memory>
#include <atomic>

#include <Poco/Glob.h>
#include <Poco/Thread.h>
#include <Poco/NullChannel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>
#include <Poco/ErrorHandler.h>

#include <gtest.h>

#include <sinsp.h>

#include <capture_job_handler.h>
#include <sinsp_worker.h>
#include <configuration.h>
#include <protocol.h>
#include "security_config.h"

using namespace std;
namespace security_config = libsanalyzer::security_config;

class memdump_error_handler : public Poco::ErrorHandler
{
public:
	memdump_error_handler() {};

	void exception(const Poco::Exception& exc) {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got Poco::Exception " << exc.displayText();
	}

	void exception(const std::exception& exc) {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got std::exception " << exc.what();
	}

	void exception() {
		dragent_configuration::m_terminate = true;
		FAIL() << "Got unknown exception";
	}
};

// Performs a role similar to sinsp_worker, but much simpler. Only
// contains the inspector loop and capture job management.
namespace {
class test_sinsp_worker : public Runnable
{
public:
	typedef struct {
		bool successful;
		string errstr;
	} dump_response_t;

	test_sinsp_worker(shared_ptr<blocking_queue<std::shared_ptr<capture_job_handler::dump_job_request>>> &dump_job_requests,
			  shared_ptr<blocking_queue<dump_response_t>> &dump_job_responses,
			  capture_job_handler *capture_job_handler)
		: m_ready(false),
		  m_job_requests_interval(100000000),
		  m_dump_job_requests(dump_job_requests),
		  m_dump_job_responses(dump_job_responses),
		  m_capture_job_handler(capture_job_handler)
	{
		m_inspector = make_unique<sinsp>();

		m_inspector->set_debug_mode(true);
		m_inspector->set_internal_events_mode(true);
		m_inspector->set_hostname_and_port_resolution_mode(false);

		m_inspector->open("");
	}

	~test_sinsp_worker()
	{
		m_inspector->set_log_callback(0);
	}

	const sinsp* get_inspector() const
	{
		return m_inspector.get();
	}

	void process_job_requests()
	{
		string errstr;

		std::shared_ptr<capture_job_handler::dump_job_request> request;
		while(m_dump_job_requests->get(&request, 0))
		{
			string errstr;

			g_log->debug("sinsp_worker: dequeued dump request token=" + request->m_token);

			if(m_capture_job_handler->queue_job_request(m_inspector.get(), request, errstr))
			{
				dump_response_t res = {true, ""};

				ASSERT_TRUE(m_dump_job_responses->put(res));
			}
			else
			{
				dump_response_t res = {false, errstr};

				ASSERT_TRUE(m_dump_job_responses->put(res));
			}
		}
	}

	bool queue_job_request(std::shared_ptr<capture_job_handler::dump_job_request> job_request, std::string &errstr)
	{
		if(!m_dump_job_requests->put(job_request))
		{
			errstr = "Could add to job request queue";
			return false;

		}
		dump_response_t res;
		if (!m_dump_job_responses->get(&res, 5000))
		{
			errstr = "Could not receive response from job response queue";
			return false;
		}

		errstr = res.errstr;
		return res.successful;
	}

	void run()
	{
		g_log->information("test_sinsp_worker: Starting");

		while(!dragent_configuration::m_terminate)
		{
			int32_t res;
			sinsp_evt* ev;

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

			m_job_requests_interval.run([this]()
                        {
				process_job_requests();
			}, ev->get_ts());

			m_capture_job_handler->process_event(ev);
			if(!m_ready)
			{
				g_log->information("test_sinsp_worker: ready");
				m_ready = true;
			}
		}

		scap_stats st;
		m_inspector->get_capture_stats(&st);

		g_log->information("sinsp_worker: Terminating. events=" + to_string(st.n_evts) + " dropped=" + to_string(st.n_drops + st.n_drops_buffer));
	}

	atomic<bool> m_ready;
private:
	run_on_interval m_job_requests_interval;
	shared_ptr<blocking_queue<shared_ptr<capture_job_handler::dump_job_request>>> m_dump_job_requests;
	shared_ptr<blocking_queue<dump_response_t>> m_dump_job_responses;
	capture_job_handler *m_capture_job_handler;
	unique_ptr<sinsp> m_inspector;
};
}

class memdump_test : public testing::Test
{
protected:

	void SetUpCaptures(bool capture_dragent_events, uint32_t max_captures=10)
	{
		// With the 10k packet size and our relatively slow
		// reading of responses, we need a bigger than normal
		// queue length.
		m_queue = new protocol_queue(1000);

		// dragent_configuration::init() takes an app, but I
		// don't see it used anywhere.
		m_configuration.init(NULL, false);
		dragent_configuration::m_terminate = false;

		m_configuration.m_capture_dragent_events  = capture_dragent_events;
		m_configuration.m_memdump_enabled = true;
		security_config::set_enabled(false);
		m_configuration.m_max_sysdig_captures = max_captures;
		m_configuration.m_autodrop_enabled = false;
		m_configuration.m_memdump_max_init_attempts = 10;

		// The (global) logger only needs to be set up once
		if(!g_log)
		{
			AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));

			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));

			// To enable debug logging, change the tailing -1 to Message::Priority::PRIO_DEBUG
			Logger &loggerc = Logger::create("DraiosLogC", formatting_channel_console, -1);

			AutoPtr<Channel> null_channel(new Poco::NullChannel());
			Logger &nullc = Logger::create("NullC", null_channel, -1);

			g_log = std::unique_ptr<common_logger>(new common_logger(&nullc, &loggerc));
		}

		m_capture_job_handler = new capture_job_handler(&m_configuration, m_queue, &m_enable_autodrop);
		m_dump_job_requests = make_shared<blocking_queue<shared_ptr<capture_job_handler::dump_job_request>>>(1);
		m_dump_job_responses = make_shared<blocking_queue<test_sinsp_worker::dump_response_t>>(1);
		m_sinsp_worker = new test_sinsp_worker(m_dump_job_requests, m_dump_job_responses, m_capture_job_handler);
		m_capture_job_handler->init(m_sinsp_worker->get_inspector());

		Poco::ErrorHandler::set(&m_error_handler);

		ThreadPool::defaultPool().start(*m_capture_job_handler, "capture_job_handler");
		ThreadPool::defaultPool().start(*m_sinsp_worker, "test_sinsp_worker");

		// Wait for the test_sinsp_worker to be ready.
		while(!m_sinsp_worker->m_ready)
		{
			Poco::Thread::sleep(100);
		}
	}

	virtual void SetUp()
	{
		SetUpCaptures(true);
	}

	virtual void TearDown()
	{
		m_capture_job_handler->m_force_cleanup = true;
		dragent_configuration::m_terminate = true;

		ThreadPool::defaultPool().joinAll();
		ThreadPool::defaultPool().stopAll();

		delete m_sinsp_worker;
		delete m_capture_job_handler;
		delete m_queue;

		// Remove any existing trace files. This shouldn't
		// strictly be necessary but just making sure.
		std::set<string> traces;
		Poco::Glob::glob(string("/tmp/") + memdump_test::agent_dump_token + "*", traces);

		for(auto file : traces)
		{
			ASSERT_EQ(unlink(file.c_str()), 0);
		}
	}

	string make_token(const string &tag)
	{
		return memdump_test::agent_dump_token + ":" + tag;
	}

	string extract_tag(const string &token)
	{
		size_t idx = token.find_first_of(":");
		ASSERT(idx != string::npos);
		return token.substr(idx+1);
	}

	// Parse a generic queue item into a dump response object.
	void parse_dump_response(std::shared_ptr<protocol_queue_item> item, draiosproto::dump_response &response)
	{
		dragent_protocol::buffer_to_protobuf(
				(uint8_t *) item->buffer.data() + sizeof(dragent_protocol_header),
				(uint32_t) item->buffer.size()-sizeof(dragent_protocol_header),
				&response);

		g_log->debug("Dump response token=" + response.token()
			     + " chunk_no=" + to_string(response.chunk_no())
			     + " final=" + (response.final_chunk() ? "yes" : "no")
			     + " size="	+ to_string((response.has_content() ? response.content().size() : 0))
			     + " final_size= " + to_string((response.has_final_size_bytes() ? response.final_size_bytes() : 0)));
	}

	// Read messages until all the all the dumps in the set tags
	// are complete. Fill in responses with the response message
	// for each tag.
	void wait_dump_complete(const set<string> &tags)
	{
		g_log->debug("Waiting for all dump files to be sent...");

		set<string> remaining = tags;

		// We'll attempt to read capture contents for up to 60 seconds.
		for(time_t now = time(NULL); time(NULL) < now + 60;)
		{
			std::shared_ptr<protocol_queue_item> buf;
			draiosproto::dump_response response;
			if(!m_queue->get(&buf, 100))
			{
				continue;
			}

			ASSERT_NO_FATAL_FAILURE(parse_dump_response(buf, response));

			// We stop if error is non-empty or if
			// final_chunk is set to true
			ASSERT_STREQ(response.error().c_str(), "");

			if(response.final_chunk()) {
				string tag = extract_tag(response.token());

				remaining.erase(tag);
				if (remaining.size() == 0)
				{
					return;
				}
			}
		}

		FAIL() << "All captures did not complete within 60 seconds";
	}

	std::shared_ptr<capture_job_handler::dump_job_request> generate_dump_request(const string &tag,
										     bool filter_events,
										     bool defer_send,
										     uint32_t before_ms, uint32_t after_ms)
	{
		std::shared_ptr<capture_job_handler::dump_job_request> req = std::make_shared<capture_job_handler::dump_job_request>();
		req->m_start_details = make_unique<capture_job_handler::start_job_details>();
		req->m_request_type = capture_job_handler::dump_job_request::JOB_START;
		req->m_start_details->m_delete_file_when_done = false;
		req->m_start_details->m_send_file = true;
		// Only measure our own process to get semi-consistent trace sizes
		if(filter_events)
		{
			req->m_start_details->m_filter = "proc.name=tests";
		}
		req->m_start_details->m_send_initial_keepalive = true;
		req->m_start_details->m_defer_send = defer_send;
		req->m_start_details->m_duration_ns = after_ms * 1000000LL;
		req->m_start_details->m_past_duration_ns = before_ms * 1000000LL;
		req->m_start_details->m_max_size = 0;
		req->m_token = make_token(tag);

		return req;
	}

	void send_dump_request(const string &tag,
			       uint32_t before_ms, uint32_t after_ms,
			       bool filter_events,
			       bool defer_send,
			       bool wait_for_start)
	{
		std::shared_ptr<protocol_queue_item> buf;
		string errstr;
		draiosproto::dump_response response;

		std::shared_ptr<capture_job_handler::dump_job_request> req = generate_dump_request(tag, filter_events, defer_send,
												   before_ms, after_ms);

		g_log->debug("Queuing job request tag=" + tag);
		ASSERT_TRUE(m_sinsp_worker->queue_job_request(req, errstr))
			<< string("Could not queue job request: ") + errstr;

		// Wait for the initial (keepalive) response to arrive
		// from the queue. That way we know the capture has
		// started.
		if(wait_for_start)
		{
			ASSERT_EQ(m_queue->get(&buf, 5000), true);
			ASSERT_NO_FATAL_FAILURE(parse_dump_response(buf, response));
			ASSERT_EQ(response.keep_alive(), true)
				<< "Response from capture job handler did not have keep_alive=true. Full response="
				<< response.DebugString();
		}
	}

	void send_stop(const string &tag, bool remove_unsent_job)
	{
		string errstr;

		std::shared_ptr<capture_job_handler::dump_job_request> req = std::make_shared<capture_job_handler::dump_job_request>();

		req->m_stop_details = make_unique<capture_job_handler::stop_job_details>();

		req->m_request_type = capture_job_handler::dump_job_request::JOB_STOP;
		req->m_token = make_token(tag);

		req->m_stop_details->m_remove_unsent_job = remove_unsent_job;

		g_log->debug("Queuing job request stop tag=" + tag);

		ASSERT_TRUE(m_sinsp_worker->queue_job_request(req, errstr))
			<< string("Could not queue job request: ") << errstr;
	}

	void send_dump_start(const string &tag)
	{
		string errstr;

		std::shared_ptr<capture_job_handler::dump_job_request> req = std::make_shared<capture_job_handler::dump_job_request>();

		req->m_request_type = capture_job_handler::dump_job_request::JOB_SEND_START;
		req->m_token = make_token(tag);

		g_log->debug("Queuing job request send_start tag=" + tag);

		ASSERT_TRUE(m_sinsp_worker->queue_job_request(req, errstr))
			<< "Could not queue job request: " << errstr;
	}

	// Open a filename with a known fixed pattern + unique
	// tag. In read_trace, we'll look for all file opens
	// matching the pattern and compare the tags to ensure the
	// right files were found in the trace.
	void open_test_file(const string &tag)
	{
		g_log->debug("Writing test file with tag: " + tag);

		string filename = memdump_test::test_filename_pat + ":" + tag;
		FILE *f = fopen(filename.c_str(), "r");
		if(f)
		{
			fclose(f);
		}
	}

        // Create a thread that does the following:
        //  - open a file with a known filename for reading
        //  - Request an event dump from the capture_job_handler, looking
        //    for file open events. If before == true, the past duration
        //    will be non-zero.
        //  - wait for a keep-alive message for the dump we started
        //  - open a different file with a known filename for reading
        //  - wait for the dump to complete
	void perform_single_dump(bool dump_before, bool filter_events)
	{
		open_test_file("before");

		// When limiting by size, we don't limit by time.
		ASSERT_NO_FATAL_FAILURE({
				send_dump_request("single",
						  (dump_before ? 1000 : 0),
						  3000,
						  filter_events,
						  false,
						  true);
					});

		open_test_file("after");

		wait_dump_complete(set<string>{string("single")});
	}

	// Interleave a stream of file opens and dump requests. The
	// file opens and dump requests are spaced such that each dump
	// should capture the preceding, current, and following file
	// open.
	void perform_overlapping_dumps(uint32_t total)
	{
		std::shared_ptr<protocol_queue_item> buf;
		set<string> active_dumps;

		for(uint32_t i=0; i < total; i++)
		{
			if(i > 0)
			{
				// Schedule each capture for 1.5 seconds before and
				// after. This should capture the immediately preceding
				// and following file open.

				ASSERT_NO_FATAL_FAILURE({
						send_dump_request(to_string(i), 1500, 1500, false, false, false);
					});
				active_dumps.insert(to_string(i));

			}

			open_test_file(to_string(i));

			Poco::Thread::sleep(1000);
		}

		wait_dump_complete(active_dumps);
	}

	// Request 11 dumps back to back. We expect the first 10 to
	// succeed and the 11th to fail with a "max outstanding
	// captures" message.
	void perform_too_many_dumps(bool back_in_time)
	{
		string errstr;
		std::shared_ptr<protocol_queue_item> buf;

		for(uint32_t i=0; i < 10; i++)
		{
			g_log->debug("Queuing request for capture " + to_string(i));
			std::shared_ptr<capture_job_handler::dump_job_request> req = generate_dump_request(to_string(i), true, false,
													   (back_in_time ? 500 : 0), 30000);
			ASSERT_TRUE(m_sinsp_worker->queue_job_request(req, errstr))
				<< "Could not queue job request: " << errstr;
		}

		// Sleep 5 seconds to make sure the capture job handler
		// has picked up all the requests and started the
		// jobs.
		g_log->debug("Waiting 5 seconds for all jobs to start");
		sleep(5);

		g_log->debug("Starting capture over limit (should fail)");
		std::shared_ptr<capture_job_handler::dump_job_request> req = generate_dump_request(to_string(10), true, false,
												   (back_in_time ? 3000 : 0), 30000);
		ASSERT_FALSE(m_sinsp_worker->queue_job_request(req, errstr));

		ASSERT_STREQ(errstr.c_str(), "maximum number of outstanding captures (10) reached");
	}

	// Read through the trace file with the provided tag. We
	// expect all tags in the set expected to be in the trace file.
	void read_trace(const string &tag, const set<string> &expected)
	{
		std::unique_ptr<sinsp> inspector = make_unique<sinsp>();
		set<string> found;
		sinsp_evt_formatter open_name(inspector.get(), "%evt.arg.name");
		string filter = string("evt.is_open_read=true and evt.arg.name startswith ")
			+ memdump_test::test_filename_pat;

		g_log->debug("Searching through trace file with tag=" + tag + " with filter " + filter);

		inspector->set_hostname_and_port_resolution_mode(false);

		inspector->set_filter(filter);

		try
		{
			string dump_file = string("/tmp/") + make_token(tag) + ".scap";
			inspector->open(dump_file);
		}
		catch(sinsp_exception e)
		{
			FAIL() << "Could not open dump file: " << e.what();
			return;
		}

		while(1)
		{
			int32_t res;
			sinsp_evt* evt;
			res = inspector->next(&evt);

			if(res == SCAP_EOF)
			{
				break;
			}
			else if(res == SCAP_TIMEOUT)
			{
				continue;
			}
			else if(res != SCAP_SUCCESS && res != SCAP_TIMEOUT)
			{
				FAIL() << "Got unexpected error from inspector->next(): " << res;
				break;
			}

			string filename;
			open_name.tostring(evt, &filename);

			// Extract the tag from the filename
			string tag = extract_tag(filename);
			found.insert(tag);
			g_log->debug("Found file open for filename " + filename + " tag=" + tag);
		}

		if (expected != found)
		{
			ostringstream os;

			os << "Expected tags in trace file for tag " << tag << " do not match actual tags.";

			os << " Expected: (";
			for(auto tag : expected)
			{
				os << " " << tag;
			}

			os << ") Found: (";
			for(auto tag : found)
			{
				os << " " << tag;
			}

			os << ")";

			FAIL() << os.str();
		}
	}

	sinsp *m_inspector;
	test_sinsp_worker *m_sinsp_worker;
	capture_job_handler *m_capture_job_handler;
	dragent_configuration m_configuration;
	protocol_queue *m_queue;
	shared_ptr<blocking_queue<shared_ptr<capture_job_handler::dump_job_request>>> m_dump_job_requests;
	shared_ptr<blocking_queue<test_sinsp_worker::dump_response_t>> m_dump_job_responses;
	atomic<bool> m_enable_autodrop;
	memdump_error_handler m_error_handler;

	string test_filename_pat = "/tmp/memdump_agent_test";
	string agent_dump_token = "agent-dump-events";
};

class memdump_no_dragent_events_test : public memdump_test
{
protected:
	virtual void SetUp()
	{
		SetUpCaptures(false);
	}
};

class memdump_max_one_capture_test : public memdump_test
{
protected:
	virtual void SetUp()
	{
		SetUpCaptures(true, 1);
	}
};


TEST_F(memdump_test, standard_dump)
{
	// Set the dump chunk size to something very small so
	// we get frequent dump_response messages.
	m_capture_job_handler->set_dump_chunk_size(10240);

	ASSERT_NO_FATAL_FAILURE(perform_single_dump(false, true));

	// At this point, /tmp/agent-dump-events.scap should exist and
	// contain an open event for the after file, but not the before file.
	ASSERT_NO_FATAL_FAILURE(read_trace("single", set<string>{string("after")}));
}

TEST_F(memdump_test, back_in_time_dump)
{
	// Set the dump chunk size to something very small so
	// we get frequent dump_response messages.
	m_capture_job_handler->set_dump_chunk_size(10240);

	ASSERT_NO_FATAL_FAILURE(perform_single_dump(true, true));

	// At this point, /tmp/agent-dump-events.scap should exist and
	// contain an open event for both the before and after files
	ASSERT_NO_FATAL_FAILURE(read_trace("single",set<string>{string("before"), string("after")}));
}

TEST_F(memdump_test, overlapping_dumps)
{
	ASSERT_NO_FATAL_FAILURE(perform_overlapping_dumps(10));

	// For a tag i, we expect to see the prior, current, and
	// following tags in the trace file.
	for(unsigned int i=1; i < 9; i++)
	{
		ASSERT_NO_FATAL_FAILURE({
				read_trace(to_string(i), set<string>{to_string(i-1), to_string(i), to_string(i+1)});
			});
	}
}

TEST_F(memdump_test, max_outstanding_dumps_back_in_time)
{
	ASSERT_NO_FATAL_FAILURE(perform_too_many_dumps(true));
}

TEST_F(memdump_test, max_outstanding_dumps)
{
	ASSERT_NO_FATAL_FAILURE(perform_too_many_dumps(false));
}

TEST_F(memdump_no_dragent_events_test, verify_no_dragent_events)
{
	ASSERT_NO_FATAL_FAILURE(perform_single_dump(true, false));

	std::unique_ptr<sinsp> inspector = make_unique<sinsp>();
	string filter = "proc.name=tests";
	g_log->debug("Searching through trace file for any events with proc.name=tests");

	inspector->set_hostname_and_port_resolution_mode(false);

	inspector->set_filter(filter);

	try
	{
		string dump_file = string("/tmp/agent-dump-events:single.scap");
		inspector->open(dump_file);
	}
	catch(sinsp_exception e)
	{
		FAIL() << "Could not open dump file: " << e.what();
		return;
	}

	sinsp_evt_formatter *formatter = new sinsp_evt_formatter(inspector.get(), std::string("*%evt.num %evt.outputtime %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info"));

	while(1)
	{
		std::string evstr;

		int32_t res;
		sinsp_evt* evt;
		res = inspector->next(&evt);

		if(res == SCAP_EOF)
		{
			break;
		}
		else if(res == SCAP_TIMEOUT)
		{
			continue;
		}
		else if(res != SCAP_SUCCESS && res != SCAP_TIMEOUT)
		{
			FAIL() << "Got unexpected error from inspector->next(): " << res << ", last error: " << inspector->getlasterr();
			break;
		}

		formatter->tostring(evt, &evstr);
		g_log->debug(evstr);

		// If we got any event other than a notification event, this is a failure.
		if(evt->get_type() != PPME_NOTIFICATION_E)
		{
			FAIL() << "Got event other than notification event for test program: " + evstr;
		}
	}
	delete(formatter);
}

TEST_F(memdump_test, delayed_capture_start)
{
	// We start a capture, wait 10 seconds, and then send a second
	// message telling the capture to start sending. The
	// connection manager should not receive any capture chunks
	// before the time at which we tell it to start sending.
	ASSERT_NO_FATAL_FAILURE({
			send_dump_request("delayed", 1000, 3000,
					  false,
					  true,
					  true);
		});

	// Poll waiting for the capture to finish.
	sleep(10);

	// Verify that the connection manager has not received any
	// capture chunks.
	std::shared_ptr<protocol_queue_item> buf;
	ASSERT_EQ(m_queue->get(&buf, 1000), false);

	ASSERT_NO_FATAL_FAILURE(perform_single_dump(false, true));

	// Tell the capture to start sending
	send_dump_start("delayed");

	// Verify that all of the capture was sent.
	wait_dump_complete(set<string>{string("delayed")});
}


TEST_F(memdump_max_one_capture_test, stop_delayed_capture)
{
	// We start a capture, wait 10 seconds, and then stop it
	// without ever sending a start_job message. The connection
	// manager should not receive any capture chunks.
	ASSERT_NO_FATAL_FAILURE({
			send_dump_request("aborted", 1000, 3000,
					  false,
					  true,
					  true);
		});

	send_stop("aborted", true);

	// Poll waiting for the capture to finish. This ensures that
	// it completes on its own and would otherwise get stuck
	// waiting for job_start()
	sleep(10);

	// Verify that the connection manager has not received any
	// capture chunks.
	std::shared_ptr<protocol_queue_item> buf;
	ASSERT_EQ(m_queue->get(&buf, 1000), false);

	// Start another capture. This would only work if sending the
	// stop above actually cleans up the capture.
	ASSERT_NO_FATAL_FAILURE(perform_single_dump(false, true));

	// At this point, /tmp/agent-dump-events.scap should exist and
	// contain an open event for the after file, but not the before file.
	ASSERT_NO_FATAL_FAILURE(read_trace("single", set<string>{string("after")}));

}
