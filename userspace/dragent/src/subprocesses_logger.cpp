#include "subprocesses_logger.h"
#include "common_logger.h"
#include "utils.h"
#include "dragent.h"

using namespace std;

// On systems with kernel < 2.6.35 we don't have this flag
// so define it and compile our code anyway as we need it when
// running on most recent kernels
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

pipe_manager::pipe_manager()
{
	// Create pipes
	int ret = pipe(m_inpipe);
	if(ret != 0)
	{
		// We don't have logging enabled when this constructor is called
		cerr << "Cannot create pipe()" << endl;
	}
	ret = pipe(m_outpipe);
	if(ret != 0)
	{
		cerr << "Cannot create pipe()" << endl;
	}
	ret = pipe(m_errpipe);
	if(ret != 0)
	{
		cerr << "Cannot create pipe()" << endl;
	}

	// transform to FILE*
	m_input_fd = fdopen(m_inpipe[PIPE_WRITE], "w");
	m_output_fd = fdopen(m_outpipe[PIPE_READ], "r");
	m_error_fd = fdopen(m_errpipe[PIPE_READ], "r");

	// Use non blocking io
	enable_nonblocking(m_outpipe[PIPE_READ]);
	enable_nonblocking(m_errpipe[PIPE_READ]);
	enable_nonblocking(m_inpipe[PIPE_WRITE]);

	// We need bigger buffers on pipes, for example for JMX data
	m_inpipe_size = fcntl(m_inpipe[PIPE_READ], F_SETPIPE_SZ, PIPE_BUFFER_SIZE);
	m_outpipe_size = fcntl(m_outpipe[PIPE_WRITE], F_SETPIPE_SZ, PIPE_BUFFER_SIZE);
}

pipe_manager::~pipe_manager()
{
	close(m_inpipe[PIPE_READ]);
	if(m_input_fd) { fclose(m_input_fd); }
	close(m_outpipe[PIPE_WRITE]);
	if(m_output_fd) { fclose(m_output_fd); }
	close(m_errpipe[PIPE_WRITE]);
	if(m_error_fd) { fclose(m_error_fd); }
}

void pipe_manager::attach_child_stdio()
{
	dup2(m_outpipe[PIPE_WRITE], STDOUT_FILENO);
	dup2(m_errpipe[PIPE_WRITE], STDERR_FILENO);
	dup2(m_inpipe[PIPE_READ], STDIN_FILENO);
	// Close the other part of the pipes
	fclose(m_input_fd); m_input_fd = 0;
	fclose(m_output_fd); m_output_fd = 0;
	fclose(m_error_fd); m_error_fd = 0;
}

void pipe_manager::enable_nonblocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

errpipe_manager::errpipe_manager()
{
	// Create pipes
	int ret = pipe(m_pipe);
	if(ret != 0)
	{
		// We don't have logging enabled when this constructor is called
		cerr << "Cannot create pipe()" << endl;
	}

	// transform to FILE*
	m_file = fdopen(m_pipe[PIPE_READ], "r");

	// Use non blocking io
	enable_nonblocking(m_pipe[PIPE_READ]);
}

errpipe_manager::~errpipe_manager()
{
	close(m_pipe[PIPE_WRITE]);
	if(m_file)
	{
		fclose(m_file);
	}
}

void errpipe_manager::attach_child()
{
	dup2(m_pipe[PIPE_WRITE], STDERR_FILENO);
	// Close the other part of the pipes
	fclose(m_file);
	m_file = 0;
}

void errpipe_manager::enable_nonblocking(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

void sdjagent_parser::operator()(const string& data)
{
	// Parse log level and use it
	Json::Value sdjagent_log;
	bool parsing_ok = m_json_reader.parse(data, sdjagent_log, false);
	if(parsing_ok && sdjagent_log.isObject())
	{
		unsigned pid = sdjagent_log["pid"].asUInt();
		string log_level = sdjagent_log["level"].asString();
		string log_message = "sdjagent[" + to_string(pid) + "]: " + sdjagent_log["message"].asString();
		if(log_level == "SEVERE")
		{
			g_log->error(log_message);
		}
		else if(log_level == "WARNING")
		{
			g_log->warning(log_message);
		}
		else if(log_level == "INFO")
		{
			g_log->information(log_message);
		}
		else
		{
			g_log->debug(log_message);
		}
	}
	else
	{
		if (data.length() == subprocesses_logger::READ_BUFFER_SIZE)
		{
			// Likely, the message is longer than the read buffer and got chopped off
			g_log->debug("sdjagent, " + data);
		}
		else
		{
			g_log->error("sdjagent, " + data);
		}
	}
}

void cointerface_parser::operator()(const string& data)
{
	// Parse log level and use it
	Json::Value cointerface_log;
	bool parsing_ok = m_json_reader.parse(data, cointerface_log, false);
	if(parsing_ok &&
	   cointerface_log.isObject() &&
	   cointerface_log.isMember("pid") &&
	   cointerface_log.isMember("level") &&
	   cointerface_log.isMember("message"))
	{
		unsigned pid = cointerface_log["pid"].asUInt();
		string log_level = cointerface_log["level"].asString();
		string log_message = "cointerface[" + to_string(pid) + "]: " + cointerface_log["message"].asString();
		if(log_level == "trace")
		{
			g_log->trace(log_message);
		} else if(log_level == "debug")
		{
			g_log->debug(log_message);
		} else if(log_level == "info")
		{
			g_log->information(log_message);
		} else if(log_level == "warn")
		{
			g_log->warning(log_message);
		} else if(log_level == "error")
		{
			g_log->error(log_message);
		} else if(log_level == "critical")
		{
			g_log->critical(log_message);
		} else {
			// Shouldn't happen, but just in case
			assert(false);
			g_log->critical("Unparsable log level: " + data);
		}
	}
	else
	{
		assert(false);
		g_log->critical("Cointerface, unparsable log message: " + data);
	}
}

sdchecks_parser::sdchecks_parser()
	: m_last_pid_str("0")
	, m_last_sev(Poco::Message::Priority::PRIO_ERROR)
{
}

void sdchecks_parser::operator()(const string& line)
{
	auto parsed_log = sinsp_split(line, ':');
	// TODO: switch to json logging to avoid parsing issues
	// using this project for example: https://github.com/madzak/python-json-logger
	if(parsed_log.size() >= 3 &&
		!parsed_log.at(0).empty() &&
		isdigit(parsed_log.at(0).at(0)))
	{
		auto level = parsed_log.at(1);
		auto message = "sdchecks[" + parsed_log.at(0) + "] " + parsed_log.at(2);
		m_last_pid_str = parsed_log.at(0);

		for(auto it = parsed_log.begin()+3; it < parsed_log.end(); ++it)
		{
			message += ":" + *it;
		}
		if(level == "DEBUG")
		{
			m_last_sev = Poco::Message::Priority::PRIO_DEBUG;
		}
		else if(level == "INFO")
		{
			m_last_sev = Poco::Message::Priority::PRIO_INFORMATION;
		}
		else if(level == "WARNING")
		{
			m_last_sev = Poco::Message::Priority::PRIO_WARNING;
		}
		else
		{
			m_last_sev = Poco::Message::Priority::PRIO_ERROR;
		}
		g_log->log(message, m_last_sev);
	}
	else
	{
		// Assuming continuation from previous log
		g_log->log("sdchecks[" + m_last_pid_str + "] " + line, m_last_sev);
	}
}

sinsp_logger_parser::sinsp_logger_parser(const string& procname, bool default_is_error):
	m_prefix(procname + ": "),
	m_default_is_error(default_is_error)
{

}

void sinsp_logger_parser::operator()(const string& s)
{
	// Right now we are using default sinsp stderror logger
	// it does not send priority so we are using a simple heuristic
	if(s.find("Error") != string::npos)
	{
		g_log->error(m_prefix + s);
	}
	else if(s.find("Warning") != string::npos)
	{
		g_log->warning(m_prefix +s);
	}
	else if(s.find("Info") != string::npos)
	{
		g_log->information(m_prefix +s);
	}
	else if (m_default_is_error)
	{
		g_log->error(m_prefix + s);
	}
	else
	{
		g_log->debug(m_prefix + s);
	}
}

subprocesses_logger::log_state::log_state()
	: m_parser_f(nullptr),
	  m_curbuf(make_shared<string>()),
	  m_state(nullptr)

{
}

subprocesses_logger::log_state::log_state(function<void(const string&)> parser, watchdog_state *state)
	: m_parser_f(parser),
	  m_curbuf(make_shared<string>()),
	  m_state(state)
{
}

subprocesses_logger::log_state::~log_state()
{
}

sinsp_encoded_parser::sinsp_encoded_parser(const string& procname):
	m_prefix(procname + ": ")
{
}

void sinsp_encoded_parser::operator()(const string& s)
{
	sinsp_logger::severity sev;
	size_t sev_len = sinsp_logger::decode_severity(s, sev);
	if (sev_len <= 0)
	{
		g_log->error(m_prefix + "unparsable log message: " + s);
		return;
	}
	assert(s.length() > sev_len);
	Poco::Message::Priority priority = Poco::Message::Priority::PRIO_TRACE;

	switch(sev)
	{
	case sinsp_logger::SEV_FATAL:
		priority = Poco::Message::Priority::PRIO_FATAL;
		break;

	case sinsp_logger::SEV_CRITICAL:
		priority = Poco::Message::Priority::PRIO_CRITICAL;
		break;

	case sinsp_logger::SEV_ERROR:
		priority = Poco::Message::Priority::PRIO_ERROR;
		break;

	case sinsp_logger::SEV_WARNING:
		priority = Poco::Message::Priority::PRIO_WARNING;
		break;

	case sinsp_logger::SEV_NOTICE:
		priority = Poco::Message::Priority::PRIO_NOTICE;
		break;

	case sinsp_logger::SEV_INFO:
		priority = Poco::Message::Priority::PRIO_INFORMATION;
		break;

	case sinsp_logger::SEV_DEBUG:
		priority = Poco::Message::Priority::PRIO_DEBUG;
		break;

	case sinsp_logger::SEV_TRACE:
		priority = Poco::Message::Priority::PRIO_TRACE;
		break;
	}

	g_log->log(m_prefix + s.substr(sev_len), priority);
}

const unsigned subprocesses_logger::READ_BUFFER_SIZE = 4096;

subprocesses_logger::subprocesses_logger(dragent_configuration *configuration, log_reporter* reporter) :
		dragent::watchdog_runnable("subprocesses_logger"),
		m_configuration(configuration),
		m_log_reporter(reporter)
{
}

void subprocesses_logger::add_logfd(FILE *fd, function<void(const string&)> &&parser, watchdog_state* state)
{
	log_state st(parser, state);
	m_error_fds.emplace(fd, st);
}

void subprocesses_logger::do_run()
{
	g_log->information("subprocesses_logger: Starting");

	if(m_error_fds.empty())
	{
		g_log->information("subprocesses_logger: no log fds, closing");
		return;
	}

	while(heartbeat())
	{
		int max_fd = 0;
		fd_set readset_w;
		FD_ZERO(&readset_w);
		for(const auto& fds : m_error_fds)
		{
			auto fd = fileno(fds.first);
			FD_SET(fd, &readset_w);
			max_fd = std::max(fd, max_fd);
		}
		struct timeval timeout_w = { 0 };
		timeout_w.tv_sec = 1;

		int result = select(max_fd+1, &readset_w, NULL, NULL, &timeout_w);

		if(result > 0 )
		{
			for(const auto& fds : m_error_fds)
			{
				if(FD_ISSET(fileno(fds.first), &readset_w))
				{
					char buffer[READ_BUFFER_SIZE];

					ssize_t bytes_read = 0;

					do {
						bytes_read = read(fileno(fds.first), buffer, sizeof(buffer));
						if(bytes_read > 0)
						{
							fds.second.m_curbuf->append(buffer, bytes_read);
						}
					} while (bytes_read > 0);

					// EAGAIN is expected as the fd is nonblocking
					if(bytes_read == -1 && errno != EAGAIN)
					{
						g_log->error(string("Could not read from subprocess logger fd: ") + strerror(errno));
					}

					// For each complete line in the buffer, pass it to the right parser
					for(auto pos = fds.second.m_curbuf->find_first_of("\n");
					    pos != string::npos;
					    pos = fds.second.m_curbuf->find_first_of("\n"))
					{
						string data(*(fds.second.m_curbuf), 0, pos);

						fds.second.m_curbuf->erase(0, pos+1);

						trim(data);
						if(fds.second.m_state != nullptr && data.find("HB,") == 0)
						{
							// This is a heartbeat message, so parse and store values
							// for watchdog, format: HB,pid,memory_used,last_loop_ts
							StringTokenizer tokenizer(data, ",");
							if(tokenizer.count() > 3)
							{
								fds.second.m_state->reset(stoul(tokenizer[1]),
											  stoul(tokenizer[2]),
											  stoul(tokenizer[3]));
							}
							g_log->debug("Received [" + fds.second.m_state->name() + "] heartbeat: " + data);
						}
						else
						{
							fds.second.m_parser_f(data);
						}
					}
				}
			}
		}
		if(dragent_configuration::m_send_log_report)
		{
			m_log_reporter->send_report(sinsp_utils::get_current_time_ns());
			dragent_configuration::m_send_log_report = false;
		}
	}
}
