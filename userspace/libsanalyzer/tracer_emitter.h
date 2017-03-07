#pragma once
#include <string>

// XXX LIMITED TO sinsp_analyzer::flush() CURRENTLY
// BECAUSE IT'S NOT THREADSAFE!
// This class allows the caller to output sysdig tracers
// to /dev/null.
class tracer_emitter
{
public:
	tracer_emitter(std::string tag);
	tracer_emitter(std::string tag, const tracer_emitter &parent);
	tracer_emitter() = delete;
	tracer_emitter(const tracer_emitter&) = delete;
	tracer_emitter& operator=(const tracer_emitter&) = delete;
	~tracer_emitter();

	void start();
	void stop();

private:
	void write_tracer(const bool enter);
	const std::string& tag() const { return m_tag; }

	std::string m_tag;
	bool m_exit_written = false;
};
