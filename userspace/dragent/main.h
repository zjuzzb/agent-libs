#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <sinsp.h>
#include <analyzer.h>
#include <iostream>
#include <fstream>
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
#include "Poco/ErrorHandler.h"
#include "Poco/SharedPtr.h"
#include "Poco/ThreadPool.h"
#include "Poco/Event.h"
#include "Poco/Buffer.h"
#include "Poco/StreamCopier.h"
#include "Poco/FileStream.h"
#include "Poco/TemporaryFile.h"
#include "Poco/Process.h"
#include "Poco/Pipe.h"
#include "Poco/PipeStream.h"
#include "Poco/StringTokenizer.h"

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
using Poco::SharedPtr;
using Poco::ThreadPool;
using Poco::Event;
using Poco::Buffer;
using Poco::StreamCopier;
using Poco::FileInputStream;
using Poco::TemporaryFile;
using Poco::Process;
using Poco::ProcessHandle;
using Poco::Pipe;
using Poco::PipeInputStream;
using Poco::StringTokenizer;

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
