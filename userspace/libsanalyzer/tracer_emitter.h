#pragma once
#include <string>

class tracer_writer
{
public:
	tracer_writer() {}
	~tracer_writer();

	int write(const std::string &trc);

private:
	void close_fd();

	int m_fd = -1;
};

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
