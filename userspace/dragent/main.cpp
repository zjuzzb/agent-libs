#include "main.h"
#ifndef _WIN32
#include <execinfo.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
#include <fstream>

#define AGENT_PRIORITY 19

static Logger* g_log = NULL;

//
// Signal management
//
static bool g_terminate = false;

static void g_monitor_signal_callback(int sig)
{
	exit(EXIT_SUCCESS);
}

static void g_signal_callback(int sig)
{
	g_terminate = true;
}

#ifndef _WIN32
static const int g_crash_signals[] = 
{
	SIGSEGV,
	SIGABRT,
	SIGFPE,
	SIGILL,
	SIGBUS
};

static void g_crash_handler(int sig)
{
	static int NUM_FRAMES = 10;

	if(g_log)
	{
		g_log->error("Received signal " + NumberFormatter::format(sig));

		void *array[NUM_FRAMES];

		int frames = backtrace(array, NUM_FRAMES);
		
		char **strings = backtrace_symbols(array, frames);
		
		if(strings != NULL)
		{
			for(int32_t j = 0; j < frames; ++j)
			{
				g_log->error(strings[j]);
			}

			free(strings);
		}
	}

	signal(sig, SIG_DFL);
	raise(sig);
}

static bool initialize_crash_handler()
{
	stack_t stack;

	memset(&stack, 0, sizeof(stack));
	stack.ss_sp = malloc(SIGSTKSZ);
	stack.ss_size = SIGSTKSZ;

	if(sigaltstack(&stack, NULL) == -1)
	{
		free(stack.ss_sp);
		return false;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);

	for(uint32_t j = 0; j < sizeof(g_crash_signals) / sizeof(g_crash_signals[0]); ++j)
	{
		sigaddset(&sa.sa_mask, g_crash_signals[j]);
	}

	sa.sa_handler = g_crash_handler;
	sa.sa_flags = SA_ONSTACK;

	for(uint32_t j = 0; j < sizeof(g_crash_signals) / sizeof(g_crash_signals[0]); ++j)
	{
		if(sigaction(g_crash_signals[j], &sa, NULL) != 0)
		{
			return false;
		}
	}

	return true;
}

static void run_monitor(const string& pidfile)
{
	signal(SIGINT, g_monitor_signal_callback);
	signal(SIGTERM, g_monitor_signal_callback);

	//
	// Start the monitor process
	// 
	int result = fork();

	if(result < 0)
	{
		exit(EXIT_FAILURE);
	}

	if(result)
	{
		//
		// Father. It will be the monitor process
		//
		while(true)
		{
			int status = 0;

			wait(&status);

			if(!WIFEXITED(status) || (WIFEXITED(status) && WEXITSTATUS(status) != 0))
			{
				//
				// Since both child and father are run with --daemon option,
				// Poco can get confused and can delete the pidfile even if
				// the monitor doesn't die.
				//
				if(!pidfile.empty())
				{
					std::ofstream ostr(pidfile);
					if(ostr.good())
					{
						ostr << Poco::Process::id() << std::endl;
					}
				}

				//
				// Sleep for a bit and run another dragent
				//
				sleep(1);

				result = fork();
				if(result == 0)
				{
					break;
				}

				if(result < 0)
				{
					exit(EXIT_FAILURE);
				}
			}
			else
			{
				exit(EXIT_SUCCESS);
			}
		}
	}

	//
	// We want to terminate when the monitor is killed by init
	//
	prctl(PR_SET_PDEATHSIG, SIGTERM);
}
#endif

///////////////////////////////////////////////////////////////////////////////
// Log management
///////////////////////////////////////////////////////////////////////////////

void g_logger_callback(char* str, uint32_t sev)
{
	switch(sev)
	{
	case sinsp_logger::SEV_DEBUG:
		g_log->debug(str);
		break;
	case sinsp_logger::SEV_INFO:
		g_log->information(str);
		break;
	case sinsp_logger::SEV_WARNING:
		g_log->warning(str);
		break;
	case sinsp_logger::SEV_ERROR:
		g_log->error(str);
		break;
	case sinsp_logger::SEV_CRITICAL:
		g_log->critical(str);
		break;
	default:
		ASSERT(false);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Capture information class
///////////////////////////////////////////////////////////////////////////////
class captureinfo
{
public:
	captureinfo()
	{
		m_nevts = 0;
		m_time = 0;
	}

	uint64_t m_nevts;
	uint64_t m_time;
};

///////////////////////////////////////////////////////////////////////////////
// A simple class to store an analyzer sample when the backend is not reachable
///////////////////////////////////////////////////////////////////////////////
class sample_store
{
public:
	sample_store()
	{
		m_buf = NULL;
		m_buflen = 0;
	}

	sample_store(char* buf, uint32_t buflen)
	{
		m_buf = new char[buflen];
		memcpy(m_buf, buf, buflen);
		m_buflen = buflen;
	}

	~sample_store()
	{
		if(m_buf)
		{
			delete [] m_buf;
		}
	}

	char* m_buf;
	uint32_t m_buflen;
};

///////////////////////////////////////////////////////////////////////////////
// The main application class
///////////////////////////////////////////////////////////////////////////////
class dragent_app: 
	public Poco::Util::ServerApplication,
	public analyzer_callback_interface
{
public:
	dragent_app(): m_help_requested(false)
	{
		m_evtcnt = 0;
		m_socket = NULL;
		m_sa = NULL;
		m_customerid = "<invalid>";
	}
	
	~dragent_app()
	{
	}

protected:
	void initialize(Application& self)
	{
		m_serverport = 0;

		//
		// load the configuration file.
		// First try the local dir
		//
		try
		{
			loadConfiguration("dragent.properties"); 
		}
		catch(...)
		{
			//
			// Then try /opt/draios
			//
			try
			{
				Path p;
				p.parseDirectory("/opt/draios");
				p.setFileName("dragent.properties");
				loadConfiguration(p.toString()); 
			}
			catch(...)
			{
			}
		}

		ServerApplication::initialize(self);
	}
		
	void uninitialize()
	{
		ServerApplication::uninitialize();
	}

	void defineOptions(OptionSet& options)
	{
		ServerApplication::defineOptions(options);
		
		options.addOption(
			Option("help", "h", "display help information on command line arguments")
				.required(false)
				.repeatable(false));

		options.addOption(
			Option("consolepriority", "", "min priotity of the log messages that go on console. Can be 'error', 'warning', 'info' or 'debug'.")
				.required(false)
				.repeatable(false)
				.argument("priority"));

		options.addOption(
			Option("filepriority", "", "min priotity of the log messages that go on file. Can be 'error', 'warning', 'info' or 'debug'.")
				.required(false)
				.repeatable(false)
				.argument("priority"));

		options.addOption(
			Option("readfile", "r", "file to open.")
				.required(false)
				.repeatable(false)
				.argument("filename"));

		options.addOption(
			Option("evtcount", "c", "numer of events after which the capture stops.")
				.required(false)
				.repeatable(false)
				.argument("count"));

		options.addOption(
			Option("customerid", "i", "force the customer id.")
				.required(false)
				.repeatable(false)
				.argument("id"));

		options.addOption(
			Option("writefile", "w", "specify this flag to save all the capture events to the 'filename' file.")
				.required(false)
				.repeatable(false)
				.argument("filename"));

		options.addOption(
			Option("srvaddr", "", "the address of the server to connect to.")
				.required(false)
				.repeatable(false)
				.argument("address"));

		options.addOption(
			Option("srvport", "", "the TCP port to use.")
				.required(false)
				.repeatable(false)
				.argument("port"));
	}

	void handleOption(const std::string& name, const std::string& value)
	{
		ServerApplication::handleOption(name, value);

		if(name == "help")
		{
			m_help_requested = true;
		}
		else if(name == "consolepriority")
		{
			if(value == "error")
			{
				m_min_console_priority = Message::PRIO_ERROR;
			}
			else if(value == "warning")
			{
				m_min_console_priority = Message::PRIO_WARNING;
			}
			else if(value == "info")
			{
				m_min_console_priority = Message::PRIO_INFORMATION;
			}
			else if(value == "debug")
			{
				m_min_console_priority = Message::PRIO_DEBUG;
			}
			else
			{
				printf("invalid consolepriority. Accepted values are: 'error', 'warning', 'info' or 'debug'.");
				exit(0);
			}
		}
		else if(name == "filepriority")
		{
			if(value == "error")
			{
				m_min_file_priority = Message::PRIO_ERROR;
			}
			else if(value == "warning")
			{
				m_min_file_priority = Message::PRIO_WARNING;
			}
			else if(value == "info")
			{
				m_min_file_priority = Message::PRIO_INFORMATION;
			}
			else if(value == "debug")
			{
				m_min_file_priority = Message::PRIO_DEBUG;
			}
			else
			{
				printf("invalid filepriority. Accepted values are: 'error', 'warning', 'info' or 'debug'.");
				exit(0);
			}
		}
		else if(name == "readfile")
		{
			m_filename = value;
		}
		else if(name == "evtcount")
		{
			m_evtcnt = NumberParser::parse64(value);
		}
		else if(name == "customerid")
		{
			m_customerid = value;
		}
		else if(name == "writefile")
		{
			m_writefile = value;
		}
		else if(name == "srvaddr")
		{
			m_serveraddr = value;
		}
		else if(name == "srvport")
		{
			m_serverport = (uint16_t)NumberParser::parse(value);
		}
		else if(name == "pidfile")
		{
			m_pidfile = value;
		}
	}

	void displayHelp()
	{
		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS");
		helpFormatter.setHeader("Draios Agent.");
		helpFormatter.format(std::cout);
	}

	///////////////////////////////////////////////////////////////////////////
	// Event processing loop.
	// We don't do much other than consuming the events and updating a couple
	// of counters.
	///////////////////////////////////////////////////////////////////////////
	captureinfo do_inspect()
	{
		captureinfo retval;
		int32_t res;
		sinsp_evt* ev;
		uint64_t ts;
		uint64_t deltats = 0;
		uint64_t firstts = 0;

		while(1)
		{
			if((m_evtcnt != 0 && retval.m_nevts == m_evtcnt) || g_terminate)
			{
				break;
			}

			res = m_inspector.next(&ev);

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
				throw sinsp_exception(m_inspector.getlasterr().c_str());
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

	///////////////////////////////////////////////////////////////////////////
	// This function is called every time the sinsp analyzer has a new sample ready
	///////////////////////////////////////////////////////////////////////////
	void sinsp_analyzer_data_ready(uint64_t ts_ns, char* buffer)
	{
		uint32_t j;

		ASSERT(m_sa != NULL);
		uint32_t* buflen = (uint32_t*)buffer;
		uint32_t size = *buflen + sizeof(uint32_t);

		//
		// Turn the length into network byte order
		//
		*buflen = htonl(*buflen);

		try
		{
			//
			// If the connection was lost, try to reconnect and send the unsent samples
			//
			uint32_t store_size = m_unsent_samples.size();

			ASSERT(store_size < MAX_SAMPLE_STORE_SIZE);

			if(store_size != 0)
			{
				ASSERT(m_socket == NULL);

				m_socket = new Poco::Net::StreamSocket(*m_sa);

				g_log->error(string("server connection recovered. Sending ") +
					NumberFormatter::format(store_size) + " buffered samples");

				for(j = 0; j < store_size; j++)
				{
					m_socket->sendBytes(m_unsent_samples[j]->m_buf, m_unsent_samples[j]->m_buflen);
					delete m_unsent_samples[j];
				}
			}

			m_unsent_samples.clear();

			//
			// Send the current sample
			//
			m_socket->sendBytes(buffer, size);
		}
		catch(Poco::IOException& e)
		{
			if(e.code() == POCO_EWOULDBLOCK)
			{
				//
				// Send buffer full.
				// Keeping processing the data in libsinsp to minimize event drops is
				// more important than dropping the sample, therefore we don't block
				// and keep going.
				//
				g_log->error(string("sample drop. TS:") + NumberFormatter::format(ts_ns) + 
					", cause:socket buffer full, len:" + NumberFormatter::format(size));
				return;
			}
			else
			{
				//
				// Looks like we lost the connection to the backend.
				// If there's space, make a copy of this sample so we can try to send it later.
				//
				if(m_unsent_samples.size() == 0)
				{
					g_log->error("lost server connection");
					if(m_socket != NULL)
					{
						delete m_socket;
						m_socket = NULL;
					}
					else
					{
						ASSERT(false);
					}
				}

				if(m_unsent_samples.size() < MAX_SAMPLE_STORE_SIZE)
				{
					sample_store* sstore = new sample_store(buffer, size);
					m_unsent_samples.push_back(sstore);
				}

				return;
			}
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// MAIN
	///////////////////////////////////////////////////////////////////////////
	int main(const std::vector<std::string>& args)
	{
		if(m_help_requested)
		{
			displayHelp();
			return Application::EXIT_OK;
		}

#ifndef _WIN32
		if(config().getBool("application.runAsDaemon", false))
		{
			run_monitor(m_pidfile);
		}
#endif

		if(signal(SIGINT, g_signal_callback) == SIG_ERR)
		{
			ASSERT(false);
		}

		if(signal(SIGTERM, g_signal_callback) == SIG_ERR)
		{
			ASSERT(false);
		}

#ifndef _WIN32
		if(initialize_crash_handler() == false)
		{
			ASSERT(false);
		}
#endif

		//
		// Create the logs directory if it doesn't exist
		//
		string logdir = config().getString("logfile.location", "logs");
		File d(logdir);
		d.createDirectories();
		Path p;
		p.parseDirectory(logdir);
		p.setFileName("draios.log");
		string logsdir = p.toString();

		//
		// Setup the logging
		//
		AutoPtr<SplitterChannel> splitterChannel(new SplitterChannel());

		AutoPtr<Channel> consoleChannel(new ConsoleChannel());
		AutoPtr<FileChannel> rotatedFileChannel(new FileChannel(logsdir));

		rotatedFileChannel->setProperty("rotation", "10M");
		rotatedFileChannel->setProperty("purgeCount", "5");
		rotatedFileChannel->setProperty("archive", "timestamp");

		splitterChannel->addChannel(consoleChannel);
		splitterChannel->addChannel(rotatedFileChannel);


		AutoPtr<Formatter> formatter(new PatternFormatter("%h-%M-%S.%i, %p, %t"));
		AutoPtr<Channel> formattingChannel(new FormattingChannel(formatter, splitterChannel));

		Logger& logger = Logger::create("TestLog", formattingChannel, Message::PRIO_DEBUG);
		g_log = &logger;

		g_log->information("Agent starting");

		if(config().getBool("application.runAsDaemon", false))
		{
#ifndef _WIN32
			if(nice(AGENT_PRIORITY) == -1)
			{
				ASSERT(false);
				g_log->error("Cannot set priority: " + string(strerror(errno)));
			}

			//
			// Since 2.6.36, the previous code is not enough since
			// the kernel will make the nice level of the process effective
			// only within the process group, which is useless.
			// I found out the following hack by looking in the kernel source
			//
			ofstream autogroup_file("/proc/" + NumberFormatter::format(getpid()) + "/autogroup", std::ofstream::out);
			if(autogroup_file.is_open())
			{
				autogroup_file << AGENT_PRIORITY;
				if(autogroup_file.fail())
				{
					g_log->warning("Cannot set the autogroup priority");
				}

				autogroup_file.close();
			}
			else
			{
				g_log->warning("Cannot open the autogroup file");
			}
#endif
		}

		//
		// Create the metrics directory if it doesn't exist
		//
		string metricsdir = config().getString("metricsfile.location", "metrics");
		File md(metricsdir);
		md.createDirectories();

		//
		// From now on we can get exceptions
		//
		try
		{
			//
			// Connect to the server
			//
			if(m_serveraddr == "")
			{
				m_serveraddr = config().getString("server.address", "");
			}

			if(m_serverport == 0)
			{
				m_serverport = config().getInt("server.port", 0);
			}

			if(m_serveraddr != "" && m_serverport != 0)
			{
				m_sa = new Poco::Net::SocketAddress(m_serveraddr, m_serverport);
				m_socket = new Poco::Net::StreamSocket(*m_sa);
				
				//
				// Set the send buffer size for the socket
				//
				m_socket->setSendBufferSize(config().getInt("transmitbuffer.size", DEFAULT_DATA_SOCKET_BUF_SIZE));

				//
				// Put the socket in nonblocking mode
				//
				m_socket->setBlocking(false);
				
				//
				// Attach our transmit callback to the analyzer
				//
				m_inspector.set_analyzer_callback(this);
			}

			//
			// Plug the sinsp logger into our one
			//
			m_inspector.set_log_callback(g_logger_callback);
			if(config().hasOption("metricsfile.location"))
			{
				m_inspector.get_configuration()->set_emit_metrics_to_file(true);
				m_inspector.get_configuration()->set_metrics_directory(metricsdir);
			}
			else
			{
				g_log->information("metricsfile.location not specified, metrics won't be saved to disk.");
			}

			//
			// The machine id is the MAC address of the first physical adapter
			//
			m_inspector.get_configuration()->set_machine_id(Environment::nodeId());

			//
			// The customer id is currently specified by the user
			//
			if(config().hasOption("customerid"))
			{
				m_customerid = config().getString("customerid");
			}
			else
			{
				g_log->error("customerid not specified.");
			}

			m_inspector.get_configuration()->set_customer_id(m_customerid);

			//
			// Start the capture with sinsp
			//
			g_log->information("Opening the capture source");
			if(m_filename != "")
			{
				m_inspector.open(m_filename);
			}
			else
			{
				m_inspector.open("");
			}

			bool dropping_mode = config().getBool("droppingmode.enabled", false);
			if(dropping_mode)
			{
				g_log->information("Enabling dropping mode");
				m_inspector.start_dropping_mode();
			}

			if(m_writefile != "")
			{
				m_inspector.start_dump(m_writefile);
			}

			//
			// Start consuming the captured events
			//
			do_inspect();
		}
		catch(sinsp_exception& e)
		{
			g_log->error(e.what());
			return Application::EXIT_SOFTWARE;
		}
		catch(Poco::Exception& e)
		{

			g_log->error(e.displayText());
			return Application::EXIT_SOFTWARE;
		}
		catch(...)
		{
			g_log->error("Application::EXIT_SOFTWARE\n");
			return Application::EXIT_SOFTWARE;
		}

		g_log->information("Application::EXIT_OK\n");
		return Application::EXIT_OK;
	}
	
private:
	bool m_help_requested;
	Message::Priority m_min_console_priority;
	Message::Priority m_min_file_priority;
	sinsp m_inspector;
	string m_filename;
	uint64_t m_evtcnt;
	string m_customerid;
	string m_writefile;
	string m_serveraddr;
	uint16_t m_serverport;
	string m_pidfile;
	Poco::Net::SocketAddress* m_sa;
	Poco::Net::StreamSocket* m_socket;
	vector<sample_store*> m_unsent_samples;
};


int main(int argc, char** argv)
{
	dragent_app app;
	return app.run(argc, argv);
}
