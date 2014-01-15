
#include "event_capture.h"
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <list>
#include <gtest.h>
#include <tuple>
#include "ppm_events_public.h"

#ifndef SYS_CALL_TEST_H
#define	SYS_CALL_TEST_H

using namespace std;

class proc;
class args;

typedef list<Poco::ProcessHandle> process_handles_t;
typedef list<proc> process_list_t;
bool ends_with(std::string const &s, std::string const &ending);
void run_processes(process_list_t & processes);
void wait_for_process_start(Poco::Pipe & pipe);
void wait_for_all(process_handles_t & handles);
uint32_t parse_ipv4_addr(const char *dotted_notation);
uint32_t get_server_address();
tuple<Poco::ProcessHandle,Poco::Pipe*> start_process(proc* process);

class sys_call_test : public testing::Test
{

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
};

class args
{
public:
    args& operator<< (const string& arg) {
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
    proc(const string & command, const Poco::Process::Args & arguments)
    {
        m_command = command;
        m_arguments = arguments;
    }
    
    const string & get_command()
    {
        return m_command;
    }
    
    const Poco::Process::Args & get_arguments()
    {
        return m_arguments;
    }
    
private:
    string m_command;
    Poco::Process::Args m_arguments;
};

#endif	/* SYS_CALL_TEST_H */

