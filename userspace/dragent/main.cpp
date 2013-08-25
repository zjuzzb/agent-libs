#include "main.h"
#ifndef _WIN32
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

//
// Signal management
//
static bool g_terminate = false;

static void signal_callback(int signal)
{
	g_terminate = true;
}

#ifndef _WIN32
static void run_monitor()
{
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

//
// Log management
//
Logger* g_log = NULL;

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

//
// Capture information class
//
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

//
// The main application class
//
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
			Option("idcustomer", "i", "force the cusomer id.")
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
	void sinsp_analyzer_data_ready(char* buffer)
	{
		ASSERT(m_sa != NULL);
		ASSERT(m_socket != NULL);
		uint32_t* buflen = (uint32_t*)buffer;
		uint32_t size = *buflen + sizeof(uint32_t);

		*buflen = htonl(*buflen);
		//m_socket->sendBytes(&buflen, sizeof(uint32_t));
		m_socket->sendBytes(buffer, size);
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
			run_monitor();
		}
#endif

		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			ASSERT(false);
			return EXIT_FAILURE;
		}

		if(signal(SIGTERM, signal_callback) == SIG_ERR)
		{
			ASSERT(false);
			return EXIT_FAILURE;
		}

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


		AutoPtr<Formatter> formatter(new PatternFormatter("%h-%M-%S.%i, %l, %t"));
		AutoPtr<Channel> formattingChannel(new FormattingChannel(formatter, splitterChannel));

		Logger& logger = Logger::create("TestLog", formattingChannel, Message::PRIO_DEBUG);
		g_log = &logger;

		g_log->information("Agent starting");

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
				m_socket->setBlocking(false);
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

			//
			//
			//
			if(m_writefile != "")
			{
				m_inspector.start_dump(m_writefile);
			}

			//
			// Start consuming the captured events
			//
			do_inspect();
		}
		catch(sinsp_exception e)
		{
			g_log->error(e.what());
			return Application::EXIT_SOFTWARE;
		}
		catch(Poco::Exception e)
		{
			g_log->error(e.displayText());
			return Application::EXIT_SOFTWARE;
		}
		catch(...)
		{
			g_log->error("Application::EXIT_SOFTWARE\n");
			return Application::EXIT_SOFTWARE;
		}

		g_log->error("Application::EXIT_OK\n");
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
	Poco::Net::SocketAddress* m_sa;
	Poco::Net::StreamSocket* m_socket;
};


int main(int argc, char** argv)
{
	dragent_app app;
	return app.run(argc, argv);
}
