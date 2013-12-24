#pragma once

class dumper_worker : public Runnable
{
public:
	dumper_worker(blocking_queue* queue, uint64_t duration_ns):
		m_queue(queue),
		m_duration_ms(duration_ns / 1000000)
	{
	}

	void run()
	{
		g_log->information("Running dumper for " + NumberFormatter::format(m_duration_ms) + " ms");
		g_toggle_capture = true;
		Thread::sleep(m_duration_ms);
		g_toggle_capture = true;
		g_log->information("Capture completed, sending file");
		delete this;
	}

private:
	blocking_queue* m_queue;
	uint64_t m_duration_ms;
};
