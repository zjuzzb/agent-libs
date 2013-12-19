#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#include <iostream>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#pragma warning(disable: 4996)
#include <io.h>
#include <stdlib.h>
#include <crtdbg.h>
#else
#include <unistd.h>
#endif

#include <assert.h>

#ifndef _WIN32
#include "Poco/Net/Context.h"
#include "Poco/Net/PrivateKeyPassphraseHandler.h"
#include "Poco/Net/SecureStreamSocket.h"
#include "Poco/Net/SSLManager.h"
#endif
#include "Poco/Net/SocketReactor.h"
#include "Poco/Net/SocketAcceptor.h"
#include "Poco/Net/SocketNotification.h"
#include "Poco/Net/StreamSocket.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/NObserver.h"
#include "Poco/Exception.h"
#include "Poco/Thread.h"
#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/Option.h"
#include "Poco/Util/OptionSet.h"
#include "Poco/Util/HelpFormatter.h"
#include "Poco/AutoPtr.h"
#include "Poco/ConsoleChannel.h"
#include "Poco/SplitterChannel.h"
#include "Poco/FileChannel.h"
#include "Poco/PatternFormatter.h"
#include "Poco/FormattingChannel.h"
#include "Poco/Message.h"
#include "Poco/Mutex.h"
#include "Poco/Logger.h"
#include "Poco/File.h"
#include "Poco/NumberParser.h"
#include "Poco/NumberFormatter.h"
#include "Poco/Path.h"
#include "Poco/Environment.h"
#include "Poco/Process.h"
#include "Poco/Semaphore.h"
#include "Poco/Runnable.h"

#include <sinsp.h>

using Poco::Net::SocketReactor;
using Poco::Net::SocketAcceptor;
using Poco::Net::SocketAddress;
using Poco::Net::ReadableNotification;
using Poco::Net::ShutdownNotification;
using Poco::Net::ServerSocket;
using Poco::Net::StreamSocket;
using Poco::NObserver;
using Poco::AutoPtr;
using Poco::Thread;
using Poco::Util::ServerApplication;
using Poco::Util::Application;
using Poco::Util::LayeredConfiguration;
using Poco::Util::Option;
using Poco::Util::OptionSet;
using Poco::Util::HelpFormatter;
using Poco::AutoPtr;
using Poco::Channel;
using Poco::ConsoleChannel;
using Poco::SplitterChannel;
using Poco::FileChannel;
using Poco::FormattingChannel;
using Poco::Formatter;
using Poco::PatternFormatter;
using Poco::Logger;
using Poco::Message;
using Poco::File;
using Poco::NumberParser;
using Poco::NumberFormatter;
using Poco::Path;
using Poco::Environment;
using Poco::Mutex;
using Poco::Semaphore;
using Poco::Runnable;

#ifdef _DEBUG
#define ASSERT(X) \
	if(!(X)) \
	{ \
		if(g_log) \
		{ \
			g_log->error(Poco::format("ASSERTION %s at %s:%d", string(#X), string(__FILE__), __LINE__)); \
		} \
		assert(X); \
	} 
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

class dragent_logger
{
public:
	dragent_logger(Logger* file_log, Logger* console_log)
	{
		m_file_log = file_log;
		m_console_log = console_log;
	}

	void debug(string str)
	{
		m_file_log->debug(str);
		if(m_console_log != NULL)
		{
			m_console_log->debug(str);
		}
	}

	void information(string str)
	{
		m_file_log->information(str);
		if(m_console_log != NULL)
		{
			m_console_log->information(str);
		}
	}

	void warning(string str)
	{
		m_file_log->warning(str);
		if(m_console_log != NULL)
		{
			m_console_log->warning(str);
		}
	}

	void error(string str)
	{
		m_file_log->error(str);
		if(m_console_log != NULL)
		{
			m_console_log->error(str);
		}
	}

	void critical(string str)
	{
		m_file_log->critical(str);
		if(m_console_log != NULL)
		{
			m_console_log->critical(str);
		}
	}

private:
	Logger* m_file_log;
	Logger* m_console_log;
};

extern dragent_logger* g_log;
