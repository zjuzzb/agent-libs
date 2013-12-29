#include "main.h"
#ifndef _WIN32
#include <execinfo.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
#include <fstream>

#include "configuration.h"
#include "../libsanalyzer/proto_header.h"

#define AGENT_PRIORITY 19
#define SOCKETBUFFER_STORAGE_SIZE (2 * 1024 * 1024)

dragent_logger* g_log = NULL;

//
// Signal management
//
static bool g_terminate = false;
static bool g_toggle_capture = false;

static void g_monitor_signal_callback(int sig)
{
	exit(EXIT_SUCCESS);
}

static void g_signal_callback(int sig)
{
	g_terminate = true;
}

static void g_usr_signal_callback(int sig)
{
	g_toggle_capture = true;
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
	signal(SIGUSR1, SIG_IGN);

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

//
// SSL callback: since the SSL is managed by ELB, he sends an encrypted alert type 21 when
// no instances are available in the backend. Of course Poco is bugged and doesn't recognize
// that, so we need to abort the connection ourselves otherwise we'll keep talking to noone:
// https://forums.aws.amazon.com/message.jspa?messageID=453844
//
static bool g_ssl_alert_received = false;

#ifndef _WIN32
static void g_ssl_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
	//
	// Code borrowed from s_cb.c in openssl
	//
	if(write_p == 0 &&
		content_type == 21 &&
		len == 2 &&
		((const unsigned char*)buf)[1] == 0)
	{
		g_ssl_alert_received = true;
	}
}
#endif

///////////////////////////////////////////////////////////////////////////////
// Log management
///////////////////////////////////////////////////////////////////////////////

void g_logger_callback(char* str, uint32_t sev)
{
	ASSERT(g_log != NULL);

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
		m_socketbufferptr = NULL;
		m_socketbuflen = 0;
		m_socketbuffer_storage = NULL;
		m_capturing = false;
		m_inspector = new sinsp();
		m_analyzer = new sinsp_analyzer(m_inspector);
		m_inspector->m_analyzer = m_analyzer;

#ifndef _WIN32
		Poco::Net::initializeSSL();
#endif
	}
	
	~dragent_app()
	{
		if(m_sa)
		{
			delete m_sa;
			m_sa = NULL;
		}

		if(m_socket)
		{
			delete m_socket;
			m_socket = NULL;
		}

		if(m_socketbuffer_storage)
		{
			delete [] m_socketbuffer_storage;
			m_socketbuffer_storage = NULL;
		}

#ifndef _WIN32
		Poco::Net::uninitializeSSL();
#endif

		if(g_log != NULL)
		{
			delete g_log;
		}

		if(m_inspector != NULL)
		{
			delete m_inspector;
		}

		if(m_analyzer != NULL)
		{
			delete m_analyzer;
		}
	}

protected:
	void initialize(Application& self)
	{
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
			Option("consolepriority", "", "min priority of the log messages that go on console. Can be 'error', 'warning', 'info' or 'debug'.")
				.required(false)
				.repeatable(false)
				.argument("priority"));

		options.addOption(
			Option("filepriority", "", "min priority of the log messages that go on file. Can be 'error', 'warning', 'info' or 'debug'.")
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
			m_configuration.m_min_console_priority = dragent_configuration::string_to_priority(value);
		}
		else if(name == "filepriority")
		{
			m_configuration.m_min_file_priority = dragent_configuration::string_to_priority(value);
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
			m_configuration.m_customer_id = value;
		}
		else if(name == "writefile")
		{
			m_writefile = value;
		}
		else if(name == "srvaddr")
		{
			m_configuration.m_server_addr = value;
		}
		else if(name == "srvport")
		{
			m_configuration.m_server_port = (uint16_t)NumberParser::parse(value);
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

			if(g_toggle_capture)
			{
				g_toggle_capture = false;

				if(m_capturing)
				{
					g_log->information("Received SIGUSR1, Stopping dump");
					m_capturing = false;
					m_inspector->stop_dump();
				}
				else
				{
					g_log->information("Received SIGUSR1, Starting dump");
					m_capturing = true;
					m_inspector->start_dump(m_configuration.m_dump_file);
				}
			}

			res = m_inspector->next(&ev);

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
				throw sinsp_exception(m_inspector->getlasterr().c_str());
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

	void transmit_buffer(char* buffer, uint32_t buflen)
	{
		m_socketbufferptr = buffer;
		m_socketbuflen = buflen;

		while(true)
		{
			//
			// Do a fake read to make sure openssl reads the stream from
			// the server and detects any pending alerts
			//
			try 
			{
				char buf;
				m_socket->receiveBytes(&buf, 1);
			}
			catch(Poco::TimeoutException&)
			{
				//
				// Poco signals a NONBLOCKING read that would block with
				// an exception
				//
			}

			if(g_ssl_alert_received)
			{
				throw sinsp_exception("Received SSL alert, terminating the connection");
			}

			int32_t res = m_socket->sendBytes(m_socketbufferptr, m_socketbuflen);
			if(res == (int32_t) m_socketbuflen)
			{
				//
				// Transmission finished
				//
				m_socketbuflen = 0;
				break;
			}
			else if(res <= 0)
			{
				ASSERT(false); // sendBytes() throws exception, doesn't return < 0
				//
				// There's no way we can easily recover from this, at least when we're
				// in the middle of a multi-segment send. We just die so the backend
				// resets its state and doesn't expect the rest of the buffer.
				//
				throw sinsp_exception("socket transmission error");
			}
			else
			{
				m_socketbufferptr += res;
				m_socketbuflen -= res;
			}
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// This function is called every time the sinsp analyzer has a new sample ready
	///////////////////////////////////////////////////////////////////////////
	void sinsp_analyzer_data_ready(uint64_t ts_ns, char* buffer)
	{
		uint32_t j;

		ASSERT(m_sa != NULL);
		sinsp_sample_header* hdr = (sinsp_sample_header*)buffer;
		uint32_t size = hdr->m_sample_len;
		uint32_t* pbuflen = &hdr->m_sample_len;

		//
		// Turn the length into network byte order
		//
		*pbuflen = htonl(*pbuflen);

		try
		{
			//
			// First of all, check if there's a partially sent buffer and try
			// to send it
			//
			if(m_socketbuflen != 0)
			{
				transmit_buffer(m_socketbufferptr, m_socketbuflen);
			}

			m_is_partial_buffer_stored = false;

			//
			// If the connection was lost, try to reconnect and send the unsent samples
			//
			uint32_t store_size = m_unsent_samples.size();

			ASSERT(store_size < MAX_SAMPLE_STORE_SIZE);

			if(store_size != 0)
			{
				ASSERT(m_socket == NULL);
				ASSERT(m_socketbuflen == 0);

				create_socket();

				g_log->error(string("server connection recovered. Sending ") +
					NumberFormatter::format(store_size) + " buffered samples");

				for(j = 0; j < store_size; j++)
				{
					transmit_buffer(m_unsent_samples[j]->m_buf, m_unsent_samples[j]->m_buflen);
					delete m_unsent_samples[j];
				}
			}

			m_unsent_samples.clear();

			//
			// Send the current sample
			//
			transmit_buffer(buffer, size);
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
				
				ASSERT(m_socketbuflen);

				if(m_is_partial_buffer_stored == false)
				{
					//
					// a buffer coming from sinsp could only be partially sent. We need to
					// copy it so we can finsh sending it later.
					//
					if(m_socketbuflen > SOCKETBUFFER_STORAGE_SIZE)
					{
						//
						// There's no way we can easily recover from this, at least when we're
						// in the middle of a multi-segment send. We just die so the backend
						// resets its state and doesn't expect the rest of the buffer.
						//
						throw sinsp_exception("transmit storage exhausted");
					}

					memcpy(m_socketbuffer_storage, 
						m_socketbufferptr,
						m_socketbuflen);

					m_socketbufferptr = m_socketbuffer_storage;

					m_is_partial_buffer_stored = true;
				}
				else
				{
					g_log->error(string("sample drop. TS:") + NumberFormatter::format(ts_ns) + 
						", cause:socket buffer full, len:" + NumberFormatter::format(size));						
				}

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
						m_socketbuflen = 0;
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

	void create_socket()
	{
#ifndef _WIN32
		if(m_configuration.m_ssl_enabled)
		{
			m_socket = new Poco::Net::SecureStreamSocket(*m_sa, m_configuration.m_server_addr);
			((Poco::Net::SecureStreamSocket*) m_socket)->verifyPeerCertificate();

			g_log->information("SSL identity verified");
		}
		else
#endif
		{
			m_socket = new Poco::Net::StreamSocket(*m_sa);
		}

		//
		// Set the send buffer size for the socket
		//
		m_socket->setSendBufferSize(m_configuration.m_transmitbuffer_size);

		//
		// Put the socket in nonblocking mode
		//
		m_socket->setBlocking(false);
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

		if(signal(SIGINT, g_signal_callback) == SIG_ERR)
		{
			ASSERT(false);
		}

		if(signal(SIGTERM, g_signal_callback) == SIG_ERR)
		{
			ASSERT(false);
		}

		if(signal(SIGUSR1, g_usr_signal_callback) == SIG_ERR)
		{
			ASSERT(false);
		}

		if(initialize_crash_handler() == false)
		{
			ASSERT(false);
		}
#endif

		m_configuration.init(this);

		//
		// Create the logs directory if it doesn't exist
		//
		File d(m_configuration.m_log_dir);
		d.createDirectories();
		Path p;
		p.parseDirectory(m_configuration.m_log_dir);
		p.setFileName("draios.log");
		string logsdir = p.toString();

		//
		// Setup the logging
		//
		AutoPtr<Channel> console_channel(new ConsoleChannel());
		AutoPtr<FileChannel> file_channel(new FileChannel(logsdir));

		file_channel->setProperty("rotation", "10M");
		file_channel->setProperty("purgeCount", "5");
		file_channel->setProperty("archive", "timestamp");

		AutoPtr<Formatter> formatter(new PatternFormatter("%h-%M-%S.%i, %p, %t"));

		AutoPtr<Channel> formatting_channel_file(new FormattingChannel(formatter, file_channel));
		AutoPtr<Channel> formatting_channel_console(new FormattingChannel(formatter, console_channel));

		Logger& loggerf = Logger::create("DraiosLogF", formatting_channel_file, m_configuration.m_min_file_priority);
		Logger& loggerc = Logger::create("DraiosLogC", formatting_channel_console, m_configuration.m_min_console_priority);
		
		if(m_configuration.m_min_console_priority != -1)
		{
			g_log = new dragent_logger(&loggerf, &loggerc);
		}
		else
		{
			g_log = new dragent_logger(&loggerf, NULL);
		}

		g_log->information("Agent starting");

		m_configuration.print_configuration();

#if 0
		if(m_configuration.m_daemon)
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
#endif
		//
		// Allocate the buffer for partial socket sends
		//
		m_socketbuffer_storage = new char[SOCKETBUFFER_STORAGE_SIZE];

		//
		// From now on we can get exceptions
		//
		try
		{
			//
			// Connect to the server
			//
			if(m_configuration.m_server_addr != "" && m_configuration.m_server_port != 0)
			{
				m_sa = new Poco::Net::SocketAddress(m_configuration.m_server_addr, m_configuration.m_server_port);

#ifndef _WIN32
				if(m_configuration.m_ssl_enabled)
				{
					g_log->information("SSL enabled, initializing context");

					Poco::Net::Context::Ptr ptrContext = new Poco::Net::Context(
						Poco::Net::Context::CLIENT_USE, 
						"", 
						"", 
						m_configuration.m_ssl_ca_certificate, 
						Poco::Net::Context::VERIFY_STRICT, 
						9, 
						false, 
						"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

					Poco::Net::SSLManager::instance().initializeClient(0, 0, ptrContext);

					SSL_CTX* ssl_ctx = ptrContext->sslContext();
					if(ssl_ctx)
					{
						SSL_CTX_set_msg_callback(ssl_ctx, g_ssl_callback);
					}
				}
#endif				

				create_socket();

				//
				// Attach our transmit callback to the analyzer
				//
				m_inspector->m_analyzer->set_sample_callback(this);
			}

			//
			// Plug the sinsp logger into our one
			//
			m_inspector->set_log_callback(g_logger_callback);
			if(!m_configuration.m_metrics_dir.empty())
			{
				//
				// Create the metrics directory if it doesn't exist
				//
				File md(m_configuration.m_metrics_dir);
				md.createDirectories();
				m_analyzer->get_configuration()->set_emit_metrics_to_file(true);
				m_analyzer->get_configuration()->set_metrics_directory(m_configuration.m_metrics_dir);
			}
			else
			{
				g_log->information("metricsfile.location not specified, metrics won't be saved to disk.");
			}

			//
			// The machine id is the MAC address of the first physical adapter
			//
			m_analyzer->get_configuration()->set_machine_id(Environment::nodeId());

			//
			// The customer id is currently specified by the user
			//
			if(m_configuration.m_customer_id.empty())
			{
				g_log->error("customerid not specified.");
			}

			m_analyzer->get_configuration()->set_customer_id(m_configuration.m_customer_id);

			//
			// Configure compression in the protocol
			//
			m_analyzer->get_configuration()->set_compress_metrics(m_configuration.m_compression_enabled);

			//
			// Configure connection aggregation
			//
			m_analyzer->get_configuration()->set_aggregate_connections_in_proto(!m_configuration.m_emit_full_connections);

			//
			// Start the capture with sinsp
			//
			g_log->information("Opening the capture source");
			if(m_filename != "")
			{
				m_inspector->open(m_filename);
			}
			else
			{
				m_inspector->open("");
			}

			aws_metadata metadata;
			if(m_configuration.get_aws_metadata(&metadata))
			{
				sinsp_ipv4_ifinfo aws_interface(metadata.m_public_ipv4, metadata.m_public_ipv4, metadata.m_public_ipv4, "aws");
				m_inspector->import_ipv4_interface(aws_interface);
			}

			if(m_configuration.m_dropping_mode)
			{
				g_log->information("Enabling dropping mode");
				m_inspector->start_dropping_mode();
			}

			if(m_writefile != "")
			{
				m_inspector->start_dump(m_writefile);
				m_capturing = true;
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
	sinsp* m_inspector;
	sinsp_analyzer* m_analyzer;
	string m_filename;
	uint64_t m_evtcnt;
	string m_writefile;
	bool m_capturing;
	string m_pidfile;
	Poco::Net::SocketAddress* m_sa;
	Poco::Net::StreamSocket* m_socket;
	char* m_socketbufferptr;
	char* m_socketbuffer_storage;
	bool m_is_partial_buffer_stored;
	uint32_t m_socketbuflen;
	vector<sample_store*> m_unsent_samples;
	dragent_configuration m_configuration;
};


int main(int argc, char** argv)
{
	dragent_app app;
	return app.run(argc, argv);
}
