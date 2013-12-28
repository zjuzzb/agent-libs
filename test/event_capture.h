#ifndef EVENT_CAPTURE_H
#define EVENT_CAPTURE_H

#include <functional>
#include <Poco/Thread.h>
#include <Poco/Event.h>
#include <Poco/RunnableAdapter.h>
#include <unistd.h>
#include <sinsp.h>
#include <analyzer.h>
#include <gtest.h>
#include <inttypes.h>


using namespace std;

class callback_param
{
public:
	sinsp_evt *m_evt;
	sinsp *m_inspector;
};

typedef function<bool (sinsp_evt *evt) > event_filter_t;
typedef function<void (const callback_param &param) > captured_event_callback_t;
typedef function<void (sinsp* inspector) > run_callback_t;

class event_capture
{
public:

	void capture();

	void stop_capture()
	{
		m_stopped = true;
	}

	void wait_for_capture_start()
	{
		m_capture_started.wait();
	}

	void wait_for_capture_stop()
	{
		m_capture_stopped.wait();
	}

	static void run(run_callback_t run_function,
	                captured_event_callback_t captured_event_callback,
	                event_filter_t filter)
	{
		sinsp_configuration configuration;
		run(run_function, captured_event_callback, filter, configuration);
	}

	static void run(run_callback_t run_function,
	                captured_event_callback_t captured_event_callback)
	{
		event_filter_t no_filter = [](sinsp_evt *)
		{
			return true;
		};
		sinsp_configuration configuration;
		run(run_function, captured_event_callback, no_filter, configuration);
	}

	static void run(
	    run_callback_t run_function,
	    captured_event_callback_t captured_event_callback,
	    event_filter_t filter,
	    const sinsp_configuration& configuration,
	    analyzer_callback_interface* analyzer_callback = NULL)
	{
		event_capture capturing;
		capturing.m_captured_event_callback = captured_event_callback;
		capturing.m_filter = filter;
		capturing.m_configuration = configuration;
		capturing.m_analyzer_callback = analyzer_callback;

		Poco::RunnableAdapter<event_capture> runnable(capturing, &event_capture::capture);
		Poco::Thread thread;
		thread.start(runnable);
		capturing.wait_for_capture_start();
		if(!capturing.m_start_failed)
		{
			run_function(capturing.m_inspector);
			capturing.stop_capture();
			capturing.wait_for_capture_stop();
			//    capturing.re_read_dump_file();
		}
		else
		{
			GTEST_MESSAGE_(capturing.m_start_failure_message.c_str(), ::testing::TestPartResult::kFatalFailure);
		}
	}

private:
	event_capture() : m_stopped(false), m_start_failed(false)
	{
	}

	void re_read_dump_file()
	{
		try
		{
			sinsp inspector;
			sinsp_evt *event;

			inspector.open(m_dump_filename);
			uint32_t res;
			do
			{
				res = inspector.next(&event);
			}
			while(res == SCAP_SUCCESS);
			ASSERT_EQ((int)SCAP_EOF, (int)res);
		}
		catch(sinsp_exception &e)
		{
			FAIL() << "caught exception " << e.what();
		}
	}

	bool handle_event(sinsp_evt *event)
	{
		if(::testing::Test::HasNonfatalFailure())
		{
			return true;
		}
		bool res = true;
		if(m_filter(event))
		{
			try
			{
				m_param.m_evt = event;
				m_captured_event_callback(m_param);
			}
			catch(...)
			{
				res = false;
			}
		}
		if(!res || ::testing::Test::HasNonfatalFailure())
		{
			cerr << "failed on event " << event->get_num() << endl;
		}
		return res;
	}

	Poco::Event m_capture_started;
	Poco::Event m_capture_stopped;
	bool m_stopped;
	event_filter_t m_filter;
	captured_event_callback_t m_captured_event_callback;
	sinsp_configuration m_configuration;
	bool m_start_failed;
	string m_start_failure_message;
	string m_dump_filename;
	callback_param m_param;
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	analyzer_callback_interface* m_analyzer_callback;
};


#endif  /* EVENT_CAPTURE_H */

