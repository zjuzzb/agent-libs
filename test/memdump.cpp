#include <thread>
#include <memory>

#include <Poco/Glob.h>
#include <Poco/Thread.h>
#include <Poco/NullChannel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>

#include <gtest.h>

#include <sinsp.h>

#include <sinsp_worker.h>
#include <configuration.h>
#include <protocol.h>

using namespace std;

class memdump_test : public testing::Test
{
protected:

	virtual void SetUp()
	{
		m_queue = new protocol_queue(10);

		// dragent_configuration::init() takes an app, but I
		// don't see it used anywhere.
		m_configuration.init(NULL);
		dragent_configuration::m_terminate = false;

		m_configuration.m_capture_dragent_events  = true;
		m_configuration.m_memdump_enabled = true;

		m_sinsp_worker = new sinsp_worker(&m_configuration, m_queue);

		// The (global) logger only needs to be set up once
		if(!g_log)
		{
			AutoPtr<Formatter> formatter(new PatternFormatter("%Y-%m-%d %H:%M:%S.%i, %P, %p, %t"));

			AutoPtr<Channel> console_channel(new ConsoleChannel());
			AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));
			Logger &loggerc = Logger::create("DraiosLogC", formatting_channel_console, -1);

			AutoPtr<Channel> null_channel(new Poco::NullChannel());
			Logger &nullc = Logger::create("NullC", null_channel, -1);

			g_log = new dragent_logger(&nullc, &loggerc, &nullc);
		}

	}

	virtual void TearDown()
	{
		delete m_sinsp_worker;
		delete m_queue;

		// Remove any existing trace files
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

	// Wait for the next message of the provided type
	void queue_fetch(uint8_t messagetype, SharedPtr<protocol_queue_item> &item)
	{
		// The sinsp_worker may send a variety of messages
		// (e.g. metrics, dump responses, etc). so try up to
		// 50 times to get a message of the type we want.
		for(uint32_t attempts = 0; attempts < 50; attempts++)
		{
			ASSERT_TRUE(m_queue->get(&item, 5000));

			dragent_protocol_header *hdr = (dragent_protocol_header*) item->data();

			g_log->debug("Got message type=" + to_string(hdr->messagetype));

			if(hdr->messagetype != messagetype)
			{
				continue;
			}

			return;
		}

		FAIL() << "Did not receive message with type " << to_string(messagetype) << " after 50 attempts";
	}

	// Parse a generic queue item into a dump response object.
	void parse_dump_response(SharedPtr<protocol_queue_item> item, draiosproto::dump_response &response)
	{
		ASSERT_TRUE(dragent_protocol::buffer_to_protobuf((uint8_t *) item->data() + sizeof(dragent_protocol_header),
								 (uint32_t) item->size()-sizeof(dragent_protocol_header),
								 &response));

		g_log->debug("Dump response token=" + response.token()
			     + " chunk_no=" + to_string(response.chunk_no())
			     + " final=" + (response.final_chunk() ? "yes" : "no")
			     + " size="	+ to_string((response.has_content() ? response.content().size() : 0))
			     + " final_size= " + to_string((response.has_final_size_bytes() ? response.final_size_bytes() : 0)));
	}

	// Read messages until all the all the dumps in the set tags
	// are complete. Fill in responses with the response message
	// for each tag.
	void wait_dump_complete(const set<string> &tags, map<string,
				draiosproto::dump_response> &responses)
	{
		set<string> remaining = tags;

		// We'll try up to 5000 messages (at 1k chunk size,
		// 5M) before giving up.
		for(uint32_t attempts = 0; attempts < 1000; attempts++)
		{
			SharedPtr<protocol_queue_item> buf;
			draiosproto::dump_response response;
			queue_fetch(draiosproto::DUMP_RESPONSE, buf);

			parse_dump_response(buf, response);

			// We stop if error is non-empty or if
			// final_chunk is set to true
			if(response.error().size() != 0 ||
			   response.final_chunk()) {
				string tag = extract_tag(response.token());

				remaining.erase(tag);
				responses.insert(pair<string,draiosproto::dump_response>(tag,response));
				if (remaining.size() == 0)
				{
					return;
				}
			}
		}

		FAIL() << "Did not receive dump_responses containg all tags after 1000 attempts";
	}

	void send_dump_request(const string &tag,
			       uint32_t before_ms, uint32_t after_ms,
			       bool wait_for_response=true,
			       uint32_t max_size=0)
	{
		SharedPtr<protocol_queue_item> buf;
		draiosproto::dump_response response;

		SharedPtr<sinsp_worker::dump_job_request> req = new sinsp_worker::dump_job_request();
		req->m_request_type = sinsp_worker::dump_job_request::JOB_START;
		req->m_delete_file_when_done = false;
		req->m_send_file = true;
		// Only measure our own process to get semi-consistent trace sizes
		req->m_filter = "proc.name=tests";
		req->m_duration_ns = after_ms * 1000000LL;
		req->m_past_duration_ns = before_ms * 1000000LL;
		req->m_max_size = max_size;
		req->m_token = make_token(tag);

		g_log->debug("Queuing job request tag=" + tag);
		m_sinsp_worker->queue_job_request(req);

		if(wait_for_response)
		{
			// Wait for the response to the dump
			// request. This typically has no data and
			// should not be a final response.
			queue_fetch(draiosproto::DUMP_RESPONSE, buf);
			parse_dump_response(buf, response);
			ASSERT_STREQ(response.error().c_str(), "");
			ASSERT_FALSE(response.final_chunk());
		}
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
        //  - Wait for a metrics message. This will let us know
        //    that the sinsp_worker is running.
        //  - open a file with a known filename for reading
        //  - Request an event dump from the sinsp_worker, looking
        //    for file open events. If before == true, the past duration
        //    will be non-zero.
        //  - wait for a keep-alive message for the dump we started
        //  - open a different file with a known filename for reading
        //  - wait for the dump to complete
        //  - Request the sinsp_worker shut down by setting m_terminate = true
	void perform_single_dump(bool dump_before, bool limit_size)
	{
		m_dump_client = std::thread([dump_before, limit_size, this]() {
			SharedPtr<protocol_queue_item> buf;
			draiosproto::dump_response response;

			queue_fetch(draiosproto::METRICS, buf);

			open_test_file("before");

			// When limiting by size, we don't limit by time.
			send_dump_request("single",
					  (dump_before ? 1000 : 0),
					  (limit_size ? 10000 : 1000),
					  true,
					  (limit_size ? 1 : 0));

			if(limit_size) {
				// Wait for the first chunk of real
				// data. This, combined with the 1
				// byte size limit above, ensures that
				// any actions we perform *after* this
				// time will not be included in the
				// sysdig capture.
				queue_fetch(draiosproto::DUMP_RESPONSE, buf);
				parse_dump_response(buf, response);
				ASSERT_STREQ(response.error().c_str(), "");
			}

			open_test_file("after");

			if (!response.final_chunk()) {
				map<string, draiosproto::dump_response> responses;

				wait_dump_complete(set<string>{string("single")}, responses);
				response = responses[string("single")];
			}

			ASSERT_STREQ(response.error().c_str(), "");
			ASSERT_TRUE(response.final_chunk());
			dragent_configuration::m_terminate = true;
		});
	}

	// Interleave a stream of file opens and dump requests. The
	// file opens and dump requests are spaced such that each dump
	// should capture the preceding, current, and following file
	// open.
	void perform_overlapping_dumps(uint32_t total)
	{
		m_dump_client = std::thread([total, this]() {
			SharedPtr<protocol_queue_item> buf;
			map<string,draiosproto::dump_response> responses;

			queue_fetch(draiosproto::METRICS, buf);

			set<string> active_dumps;

			// Try to align the times at which we request
			// dumps with the times at which the
			// sinsp_worker is checking for job requests.
			uint64_t next_job_check_ns = m_sinsp_worker->get_last_job_check_ns() + ONE_SECOND_IN_NS;
			uint64_t cur_ns = sinsp_utils::get_current_time_ns();
			ASSERT_GT(next_job_check_ns, cur_ns);
			int64_t sleep_ms = (next_job_check_ns - cur_ns)/1000000 - 100;
			if(sleep_ms > 0)
			{
				g_log->debug("Sleeping " + to_string(sleep_ms) + " ms to align dump requests and checks");
				Poco::Thread::sleep(sleep_ms);
			}

			for(uint32_t i=0; i < total; i++)
			{
				if(i > 0)
				{
					// Schedule each capture for 1.5 seconds before and
					// after. This should capture the immediately preceding
					// and following file open.

					send_dump_request(to_string(i), 1500, 1500, false);
					active_dumps.insert(to_string(i));

				}

				open_test_file(to_string(i));

				Poco::Thread::sleep(1000);
			}

			wait_dump_complete(active_dumps, responses);

			for(auto &pair : responses)
			{
				ASSERT_STREQ(pair.second.error().c_str(), "");
				ASSERT_TRUE(pair.second.final_chunk());
			}
			dragent_configuration::m_terminate = true;
		});
	}

	// Request 11 dumps, delay_ms apart. We expect the first 10 to
	// succeed and the 11th to fail. delay_ms varies to allow for
	// slightly different error paths.
	void perform_too_many_dumps(uint32_t delay_ms, const char *errstr)
	{
		m_dump_client = std::thread([delay_ms, errstr, this]() {
			set<string> active_dumps;
			map<string,draiosproto::dump_response> responses;

			for(uint32_t i=0; i < 11; i++)
			{
				send_dump_request(to_string(i), 3000, 3000, false);
				active_dumps.insert(to_string(i));

				Poco::Thread::sleep(delay_ms);
			}

			wait_dump_complete(active_dumps, responses);

			for(uint32_t i = 0; i < 10; i++)
			{
				EXPECT_STREQ(responses[to_string(i)].error().c_str(), "");
			}

			ASSERT_STREQ(responses[to_string(10)].error().c_str(), errstr);

			dragent_configuration::m_terminate = true;
		});
	}

	// Read through the trace file with the provided tag. We
	// expect all tags in the set expected to be in the trace file.
	void read_trace(const string &tag, const set<string> &expected)
	{
		sinsp inspector;
		set<string> found;
		sinsp_evt_formatter open_name(&inspector, "%evt.arg.name");
		string filter = string("evt.type=open and evt.dir=< and evt.is_open_read=true and fd.name startswith")
			+ memdump_test::test_filename_pat;

		g_log->debug("Searching through trace file with tag=" + tag + " with filter " + filter);

		inspector.set_hostname_and_port_resolution_mode(false);

		inspector.set_filter(filter);

		try
		{
			string dump_file = string("/tmp/") + make_token(tag) + ".scap";
			inspector.open(dump_file);
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
			res = inspector.next(&evt);

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
				FAIL() << "Got unexpected error from inspector.next(): " << res;
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
	sinsp_analyzer *m_analyzer;
	sinsp_worker *m_sinsp_worker;
	dragent_configuration m_configuration;
	protocol_queue *m_queue;

	std::thread m_dump_client;

	string test_filename_pat = "/tmp/memdump_agent_test";
	string agent_dump_token = "agent-dump-events";
};

/* FIXME: put these back 
TEST_F(memdump_test, standard_dump)
{
	// Set the dump chunk size to something very small so
	// we get frequent dump_response messages.
	m_sinsp_worker->set_dump_chunk_size(1024);

	perform_single_dump(false, false);

	m_sinsp_worker->run();

	m_dump_client.join();

	// At this point, /tmp/agent-dump-events.scap should exist and
	// contain an open event for the after file, but not the before file.
	read_trace("single", set<string>{string("after")});
}

TEST_F(memdump_test, back_in_time_dump)
{
	// Set the dump chunk size to something very small so
	// we get frequent dump_response messages.
	m_sinsp_worker->set_dump_chunk_size(1024);

	perform_single_dump(true, false);

	m_sinsp_worker->run();

	m_dump_client.join();

	// At this point, /tmp/agent-dump-events.scap should exist and
	// contain an open event for both the before and after files
	read_trace("single", set<string>{string("before"), string("after")});
}

TEST_F(memdump_test, overlapping_dumps)
{
	perform_overlapping_dumps(10);

	m_sinsp_worker->run();

	m_dump_client.join();

	// For a tag i, we expect to see the prior, current, and
	// following tags in the trace file.
	for(unsigned int i=1; i < 9; i++)
	{
		read_trace(to_string(i), set<string>{to_string(i-1), to_string(i), to_string(i+1)});
	}
}

TEST_F(memdump_test, max_outstanding_dumps)
{
	perform_too_many_dumps(200, "maximum number of outstanding captures (10) reached");

	m_sinsp_worker->run();

	m_dump_client.join();
}

TEST_F(memdump_test, request_queue_full)
{
	perform_too_many_dumps(1, "Maximum number of requests reached");

	m_sinsp_worker->run();

	m_dump_client.join();
} */
