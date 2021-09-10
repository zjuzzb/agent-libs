#pragma once

/**
 * Often we need to run something on an interval
 * usually we need to store last_run_ts compare to now
 * and run it
 * This micro-class makes this easier
 *
 * This class implementation is a blatant copy from
 * run_on_interval class in libsanalyzer.
 */
class interval_runner
{
public:
	inline interval_runner(uint64_t interval, uint64_t threshold = 0);

	template<typename Callable>
	inline void run(const Callable& c, uint64_t now);
	uint64_t interval() const { return m_interval; }
	void interval(uint64_t i) { m_interval = i; }
	void threshold(uint64_t t) { m_threshold = t; }
private:
	uint64_t m_last_run_ns;
	uint64_t m_interval;
	uint64_t m_threshold;
};

interval_runner::interval_runner(uint64_t interval, uint64_t threshold):
		m_last_run_ns(0),
		m_interval(interval),
		m_threshold(threshold)
{
}

template<typename Callable>
void interval_runner::run(const Callable& c, uint64_t now)
{
	if(now - m_last_run_ns + m_threshold > m_interval)
	{
		c();
		m_last_run_ns = now;
	}
}
