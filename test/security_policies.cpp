#include <memory>

#include <Poco/NullChannel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/Formatter.h>

#include <gtest.h>

#include <sinsp.h>

#include <sinsp_worker.h>
#include <configuration.h>
#include <protocol.h>

using namespace std;

class security_policy_error_handler : public Poco::ErrorHandler
{
public:
	security_policy_error_handler() {};

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


class security_policies_test : public testing::Test
{
protected:

	virtual void SetUp()
	{
		// With the 10k packet size and our relatively slow
		// reading of responses, we need a bigger than normal
		// queue length.
		m_queue = new protocol_queue(1000);
		m_policy_events = new synchronized_policy_events(100);

		// dragent_configuration::init() takes an app, but I
		// don't see it used anywhere.
		m_configuration.init(NULL, false);
		dragent_configuration::m_terminate = false;

		m_configuration.m_capture_dragent_events  = true;
		m_configuration.m_memdump_enabled = false;
		m_configuration.m_security_enabled = true;
		m_configuration.m_max_sysdig_captures = 10;
		m_configuration.m_autodrop_enabled = false;
		m_configuration.m_security_policies_file = "./resources/security_policies_message.txt";
		m_configuration.m_security_throttled_report_interval_ns = 1000000000;

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

			g_log = new dragent_logger(&nullc, &loggerc, &nullc);
		}

		m_capture_job_handler = new capture_job_handler(&m_configuration, m_queue, &m_enable_autodrop);
		m_sinsp_worker = new sinsp_worker(&m_configuration, m_queue, &m_enable_autodrop, m_policy_events, m_capture_job_handler);
		m_sinsp_worker->init();
		m_capture_job_handler->init(m_sinsp_worker->get_inspector());

		Poco::ErrorHandler::set(&m_error_handler);

		ThreadPool::defaultPool().start(*m_capture_job_handler, "capture_job_handler");
		ThreadPool::defaultPool().start(*m_sinsp_worker, "sinsp_worker");
	}

	virtual void TearDown()
	{
		dragent_configuration::m_terminate = true;

		ThreadPool::defaultPool().stopAll();

		delete m_sinsp_worker;
		delete m_capture_job_handler;
		delete m_queue;
		delete m_policy_events;
	}

	// Wait for the next message of the provided type
	void queue_fetch(uint8_t messagetype, std::shared_ptr<protocol_queue_item> &item)
	{
		// The capture_job_handler may send a variety of messages
		// (e.g. metrics, dump responses, etc). so try up to
		// 50 times to get a message of the type we want.
		for(uint32_t attempts = 0; attempts < 50; attempts++)
		{
			ASSERT_TRUE(m_queue->get(&item, 5000));

			dragent_protocol_header *hdr = (dragent_protocol_header*) item->buffer.data();

			g_log->debug("Got message type=" + to_string(hdr->messagetype));

			if(hdr->messagetype != messagetype)
			{
				continue;
			}

			return;
		}

		FAIL() << "Did not receive message with type " << to_string(messagetype) << " after 50 attempts";
	}


	sinsp *m_inspector;
	sinsp_analyzer *m_analyzer;
	sinsp_worker *m_sinsp_worker;
	capture_job_handler *m_capture_job_handler;
	dragent_configuration m_configuration;
	protocol_queue *m_queue;
	atomic<bool> m_enable_autodrop;
	synchronized_policy_events *m_policy_events;
	security_policy_error_handler m_error_handler;
};

TEST_F(security_policies_test, events_flood)
{
	std::shared_ptr<protocol_queue_item> item;

	// Repeatedly try to read /etc/shadow. This will result in a flood of policy events.

	// What we want to see is the following:
	//  - 1 policy event message, containing all the policy events that make it through the token bucket.
	//  - Between 8-12 throttled policy event messages. These should be sent
	//    every second while the opens are occurring.
	//  - The total count of events across both messages should equal the number of reads we did.
	//  - There should be a steady stream of metrics events without any big delays.

	queue_fetch(draiosproto::METRICS, item);

	g_log->debug("Reading /etc/sample-sensitive-file.txt 1000 times");
	for(uint32_t i = 0; i < 1000; i++)
	{
		int fd = open("/etc/sample-sensitive-file.txt", O_RDONLY);
		close(fd);

		Poco::Thread::sleep(10);
	}

	// Sleep 2 seconds. This ensures that the final throttled
	// policy events message was sent.
	Poco::Thread::sleep(2000);

	uint64_t last_metrics_ts = 0;
	int32_t policy_event_count = 0;
	int32_t throttled_policy_event_count = 0;
	int32_t metrics_count = 0;
	int32_t event_count = 0;

	// We'll stop when the queue is empty. This way we'll get all
	// metrics and policy event messages sent while the above
	// opens were occurring.
	while (m_queue->get(&item, 0))
	{
		const uint8_t *buf;
		uint32_t size;
		draiosproto::metrics metrics;
		draiosproto::throttled_policy_events tpe;

		dragent_protocol_header *hdr = (dragent_protocol_header*) item->buffer.data();
		buf = (const uint8_t *) (item->buffer.data() + sizeof(dragent_protocol_header));
		size = ntohl(hdr->len) - sizeof(dragent_protocol_header);

		g_log->debug("Got message type=" + to_string(hdr->messagetype));

		switch (hdr->messagetype)
		{

		case draiosproto::message_type::METRICS:
			metrics_count++;
			ASSERT_TRUE(dragent_protocol::buffer_to_protobuf(buf, size, &metrics));
			if(last_metrics_ts == 0)
			{
				last_metrics_ts = metrics.timestamp_ns();
			}
			else
			{
				ASSERT_LT(metrics.timestamp_ns()-last_metrics_ts, 1.5 * ONE_SECOND_IN_NS);
				ASSERT_GT(metrics.timestamp_ns()-last_metrics_ts, 0.5 * ONE_SECOND_IN_NS);
				last_metrics_ts = metrics.timestamp_ns();
			}

			break;

		case draiosproto::message_type::THROTTLED_POLICY_EVENTS:
			throttled_policy_event_count++;
			ASSERT_TRUE(dragent_protocol::buffer_to_protobuf(buf, size, &tpe));
			event_count += tpe.events(0).count();

			break;

		default:
			FAIL() << "Received unknown message " << hdr->messagetype;
		}
	}

	// Now read all events from m_policy_events.
	draiosproto::policy_events pe;

	while (m_policy_events->get(pe))
	{
		g_log->debug("Read policy event with " + to_string(pe.events_size()) + " events");
		policy_event_count++;
		event_count += pe.events_size();
	}

	g_log->debug("Num metrics messages:"  + to_string(metrics_count));
	g_log->debug("Num policy_event messages:"  + to_string(policy_event_count));
	g_log->debug("Num throttled_policy_event messages: " + to_string(throttled_policy_event_count));
	g_log->debug("Num events: " + to_string(event_count));

	ASSERT_GT(metrics_count, 10);
	ASSERT_EQ(policy_event_count, 1);
	ASSERT_GE(throttled_policy_event_count, 8);
	ASSERT_LE(throttled_policy_event_count, 13);
	ASSERT_EQ(event_count, 1000);
}
