#ifndef SYS_CALL_TEST_H
#define	SYS_CALL_TEST_H

#include <Poco/Net/SSLManager.h>
#include <Poco/Net/KeyConsoleHandler.h>
#include <Poco/Net/AcceptCertificateHandler.h>


#include "event_capture.h"
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <list>
#include <gtest.h>
#include <tuple>
#include "ppm_events_public.h"

#define UNIT_TEST_BINARY

using Poco::SharedPtr;
using Poco::Net::X509Certificate;
using Poco::Net::PrivateKeyPassphraseHandler;
using Poco::Net::InvalidCertificateHandler;


class proc;
class args;

typedef std::list<Poco::ProcessHandle> process_handles_t;
typedef std::list<proc> process_list_t;
bool ends_with(std::string const &s, std::string const &ending);
void run_processes(process_list_t & processes);
void wait_for_message(Poco::Pipe & pipe, const char *msg);
void wait_for_process_start(Poco::Pipe & pipe);
void wait_for_all(process_handles_t & handles);
uint32_t parse_ipv4_addr(const char *dotted_notation);
uint32_t get_server_address();
std::tuple<Poco::ProcessHandle,Poco::Pipe*> start_process(proc* process);
std::tuple<Poco::ProcessHandle,Poco::Pipe*,Poco::Pipe*> start_process_sync(proc* process);

class proc_started_filter
{
public:
    bool operator()(sinsp_evt *evt)
    {
        if(!m_child_ready && evt->get_type() == PPME_SYSCALL_WRITE_X)
        {
            auto buffer = evt->get_param_value_str("data", false);
            if(buffer.find("STARTED") != std::string::npos)
            {
                m_child_ready = true;
            }
        }
        return m_child_ready;
    }
private:
    bool m_child_ready{false};
};

class sys_call_test : public testing::Test
{
public:
	static void SetUpTestCase()
	{
		// Set up in-process HTTPS server
		SharedPtr<PrivateKeyPassphraseHandler> pph = new Poco::Net::KeyConsoleHandler(true);
		SharedPtr<InvalidCertificateHandler> pich = new Poco::Net::AcceptCertificateHandler(false);

		Poco::Net::initializeSSL();
		// First init with a null context pointer to avoid crashing in the context creation
		Poco::Net::SSLManager::instance().initializeServer(pph, pich, nullptr);

		// Now create a server context and init again
		auto sctxt = new Poco::Net::Context(Poco::Net::Context::SERVER_USE,
										   "key.pem", // Privatekeyfile
										   "certificate.pem", // Certificatefile
										   "", // CA location
										   Poco::Net::Context::VERIFY_NONE);
		Poco::Net::SSLManager::instance().initializeServer(pph, pich, sctxt);
	}

	static void TearDownTestCase()
	{
		Poco::Net::uninitializeSSL();
	}

protected:
    void SetUp()
    {
        m_tid = getpid();
        m_tid_filter = [this] (sinsp_evt * evt) {
            return evt->get_tid() == m_tid;
        };
    };
    
    __pid_t m_tid;
    event_filter_t m_tid_filter;
    proc_started_filter m_proc_started_filter;
};

#ifdef __x86_64__

using sys_call_test32 = sys_call_test;

#endif

class args
{
public:
    args& operator<< (const std::string& arg) {
        m_data.push_back(arg);
        return *this;
    }
    
    operator Poco::Process::Args() const {
        return m_data;
    }
private:
    Poco::Process::Args m_data;
};

class proc
{
public:
    proc(const std::string & command, const Poco::Process::Args & arguments)
    {
        m_command = command;
        m_arguments = arguments;
    }
    
    const std::string & get_command()
    {
        return m_command;
    }
    
    const Poco::Process::Args & get_arguments()
    {
        return m_arguments;
    }
    
private:
    std::string m_command;
    Poco::Process::Args m_arguments;
};

#endif	/* SYS_CALL_TEST_H */

