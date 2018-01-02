//
// Created by Luca Marturana on 14/08/15.
//

#include <iostream>
#include <string>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <functional>
#include <unordered_map>
#include <sstream>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <strings.h>
#include <arpa/inet.h>
#include <string.h>
#define HELPER_32
#include "tcp_client_server.h"
#include <sys/quota.h>
#include <poll.h>
#include <signal.h>
#include <cassert>

using namespace std;

void proc_mgmt(const vector<string>& args)
{
	auto filename = args.at(0).c_str();
	static const char DATA[] = "josephine";
	unlink(filename);

	FILE* f = fopen(filename, "w+");
	fwrite(DATA, sizeof(DATA) - 1, 1, f);
	fclose(f);

	unlink(filename);
}

void mmap_test(const vector<string>& args)
{
	int errno2;
	void *p;
	munmap((void*) 0x50, 300);
	p = mmap(0, 0, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_DENYWRITE, -1, 0);
	errno2 = errno;
	p = mmap(NULL, 1003520, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	munmap(p, 1003520);
	cout << errno2 << " " << p << endl;
}

bool str_to_bool(const string& s)
{
	if(s == "true")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void pread_pwrite(const vector<string>& args)
{
	char buf[32];
	const auto FILENAME = "test_pread_pwrite";
	int fd = creat(FILENAME, S_IRWXU);
	if(fd < 0)
	{
		cerr << "ERROR" << endl;
		return;
	}

	auto ret = write(fd, "ficafica", sizeof("ficafica") - 1);
	assert(ret > 0);
	
	ret = pwrite(fd, "cazo", sizeof("cazo") - 1, 4);
	assert(ret > 0);

	ssize_t bytes_sent = pwrite64(fd, "cazo", sizeof("cazo") - 1, 987654321);
	//
	// On NFS, pwrite64 succeeds, so the test must evaluate the return
	// code in the proper way
	//
	bool pwrite64_succeeded = bytes_sent > 0;

	cout << (pwrite64_succeeded? 1 : 0) << endl;
	
	pread64(fd, buf, 32, 987654321);
	close(fd);

	int fd1 = open(FILENAME, O_RDONLY);
	if(fd1 < 0)
	{
		cerr << "ERROR" << endl;
		return;
	}

	pread(fd1, buf, 4, 4);

	close(fd1);

	unlink(FILENAME);
}

void preadv_pwritev(const vector<string>& args)
{
	const auto FILENAME = "test_preadv_pwritev";
	int wv_count;
	char msg1[10] = "aaaaa";
	char msg2[10] = "bbbbb";
	char msg3[10] = "ccccc";
	struct iovec wv[3];
	int rres;
	auto fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);
	
	write(fd, "123456789012345678901234567890", sizeof("ficafica") - 1);

	wv[0].iov_base = msg1;
	wv[1].iov_base = msg2;
	wv[2].iov_base = msg3;
	wv[0].iov_len  = strlen(msg1);
	wv[1].iov_len  = strlen(msg2);
	wv[2].iov_len  = strlen(msg3);
	wv_count = 3;

	auto bytes_sent = pwritev64(fd, wv, wv_count, 987654321);
	//
	// On NFS, pwritev64 succeeds, so the test must evaluate the return
	// code in the proper way
	//
	bool pwritev64_succeeded = bytes_sent > 0;
	
	cout << (pwritev64_succeeded? 1 : 0) << endl;

	bytes_sent = pwritev(fd, wv, wv_count, 10);

	cout << (bytes_sent > 0 ? 1 : 0) << endl;

	close(fd);

	auto fd1 = open(FILENAME, O_CREAT | O_RDONLY, S_IRWXU);

	wv[0].iov_len  = sizeof(msg1);
	wv[1].iov_len  = sizeof(msg2);
	wv[2].iov_len  = sizeof(msg3);

	rres = preadv64(fd1, wv, wv_count, 987654321);

	rres = preadv(fd1, wv, wv_count, 10);
	if(rres <= 0)
	{
		cerr << "ERROR" << endl;
	}

	close(fd1);

	unlink(FILENAME);
	cout << flush;
}

void quotactl_ko(const vector<string>& args)
{
	quotactl(QCMD(Q_QUOTAON, USRQUOTA), "/dev/xxx", 2, (caddr_t)"/quota.user"); // 2 => QFMT_VFS_V0
	quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
}

void quotactl_ok(const vector<string>& args)
{
	struct dqblk mydqblk;
	struct dqinfo mydqinfo;
	quotactl(QCMD(Q_QUOTAON, USRQUOTA), "/dev/loop0", 2, (caddr_t)"/tmp/testquotamnt/aquota.user"); // 2 => QFMT_VFS_V0
	quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqblk); // 0 => root user
	fwrite(&mydqblk.dqb_bhardlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_bsoftlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_curspace, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_ihardlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_isoftlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_btime, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_itime, 1, sizeof(uint64_t), stdout);
	quotactl(QCMD(Q_GETINFO, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqinfo);
	fwrite(&mydqinfo.dqi_bgrace, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqinfo.dqi_igrace, 1, sizeof(uint64_t), stdout);
	quotactl(QCMD(Q_QUOTAOFF, USRQUOTA), "/dev/loop0", 0, NULL);
}

void ppoll_timeout(const vector<string>& args)
{
	int my_pipe[2];
	auto ret = pipe(my_pipe);
	if(ret != 0)
	{
		return;
	}

	struct pollfd ufds[2];
	ufds[0].fd = my_pipe[0];
	ufds[0].events = POLLIN;
	ufds[1].fd = my_pipe[1];
	ufds[1].events = POLLOUT;

	struct timespec timeout;
	timeout.tv_sec = 0;
	timeout.tv_nsec = 1000000;

	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGCHLD);
	ppoll(ufds, 2, &timeout, &sigs);
}

const unordered_map<string, function<void(const vector<string>&)>> func_map = {
			{ "proc_mgmt", proc_mgmt},
			{ "mmap_test", mmap_test},
			{ "tcp_client", [](const vector<string>& args)
			{
				auto iot = static_cast<iotype>(stoi(args.at(1)));
				tcp_client client(
					inet_addr(args.at(0).c_str()),
					iot,
					str_to_bool(args.at(2)),
					stoi(args.at(3)),
					str_to_bool(args.at(4)));
				client.run();
			}},
			{ "tcp_server", [](const vector<string>& args) {
				auto iot = static_cast<iotype>(stoi(args.at(0)));

				tcp_server server(iot,
					str_to_bool(args.at(1)),
					str_to_bool(args.at(2)),
					str_to_bool(args.at(3)),
					stoi(args.at(4)),
					str_to_bool(args.at(5)));
				server.run();
			}},
			{ "pread_pwrite", pread_pwrite},
			{ "preadv_pwritev", preadv_pwritev},
			{ "quotactl_ko", quotactl_ko},
			{ "quotactl_ok", quotactl_ok},
			{ "ppoll_timeout", ppoll_timeout}
	};

// Helper to test ia32 emulation on 64bit
int main(int argc, char** argv)
{
	cout << "STARTED" << endl;
	char s[32];
	(void)read(0, s, sizeof s);
	if(argc > 1)
	{
		vector<string> args;
		for(int j = 1; j < argc; ++j)
		{
			args.emplace_back(argv[j]);
		}
		auto cmd = args.front();
		args.erase(args.begin());
		func_map.at(cmd)(args);
	}
	return 0;
}
