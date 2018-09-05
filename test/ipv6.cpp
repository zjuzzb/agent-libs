#include <functional>
#include <memory>

#include <gtest.h>

#include <sinsp.h>

using namespace std;

typedef function<bool (string &output)> validate_func_t;

class ipv6_filtercheck_test : public testing::Test
{
protected:
	virtual void SetUp()
	{
	}

	virtual void TearDown()
	{
	}

	void read_file(const char *filename, const char *extra_filter, std::function<void(sinsp_evt *)> evtcb, bool generate_ip_net_filters=true)
	{
		m_inspector = make_shared<sinsp>();
		m_formatter_cache = make_shared<sinsp_evt_formatter_cache>(m_inspector.get());
		m_inspector->set_hostname_and_port_resolution_mode(true);
		m_inspector->open(filename);
		m_socket_connected = false;
		m_check_local_remote = false;
		m_check_is_server = false;

		if(generate_ip_net_filters)
		{
			gen_ip_net_filters();
		}

		string filter = "evt.type in (socket, connect, recvfrom, sendto, close, accept, connect, bind, read, write, poll) and evt.dir=< and fd.type!=file and fd.type!=unix and fd.type!=file and fd.type!=pipe";
		if(extra_filter)
		{
			filter += " and ";
			filter += extra_filter;
		}

		m_inspector->set_filter(filter.c_str());

		while(1)
		{
			int32_t res;
			sinsp_evt* evt;

			res = m_inspector->next(&evt);

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
				break;
			}

			evtcb(evt);
		}

		m_inspector->close();
	}

	void check_ipv6_filterchecks(sinsp_evt *evt)
	{
		string full_output;
		string full = "*%evt.num %evt.outputtime %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info";
		m_formatter_cache->tostring(evt, full, &full_output);

		verify_filtercheck(evt, "*%fd.type", "ipv6", full_output);
		verify_filtercheck(evt, "*%fd.typechar", "6", full_output);
		verify_filtercheck(evt, "*%fd.sockfamily", "ip", full_output);

		if(m_socket_connected)
		{
			verify_filtercheck(evt, "*%fd.name", m_conn_name.c_str(), full_output);

			verify_filtercheck(evt, "*%fd.cip", m_client_ip, full_output);
			verify_filtercheck(evt, "*%fd.sip", m_server_ip, full_output);

			verify_filtercheck(evt, "*%fd.cport", m_client_port, full_output);
			verify_filtercheck(evt, "*%fd.sport", m_server_port, full_output);

			ASSERT_TRUE(m_ip_client_filter->run(evt)) << "fd.ip=" << m_client_ip << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_ip_server_filter->run(evt)) << "fd.ip=" << m_server_ip << " did not match event. Full event output: " << full_output;

			ASSERT_TRUE(m_net_client_filter->run(evt)) << "fd.net=" << m_client_net << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_net_server_filter->run(evt)) << "fd.net=" << m_server_net << " did not match event. Full event output: " << full_output;

			ASSERT_TRUE(m_cnet_filter->run(evt)) << "fd.cnet=" << m_client_net << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_snet_filter->run(evt)) << "fd.snet=" << m_server_net << " did not match event. Full event output: " << full_output;

			verify_filtercheck(evt, "*%fd.cproto", m_client_proto, full_output);
			verify_filtercheck(evt, "*%fd.sproto", m_server_proto, full_output);

			verify_filtercheck(evt, "*%fd.l4proto", m_l4proto, full_output);

			if(m_check_is_server)
			{
				verify_filtercheck(evt, "*%fd.is_server", m_is_server, full_output);
			}
		}

		if(m_check_local_remote)
		{
			verify_filtercheck(evt, "*%fd.lip", m_client_ip, full_output);
			verify_filtercheck(evt, "*%fd.rip", m_server_ip, full_output);

			verify_filtercheck(evt, "*%fd.lport", m_client_port, full_output);
			verify_filtercheck(evt, "*%fd.rport", m_server_port, full_output);

			ASSERT_TRUE(m_lnet_filter->run(evt)) << "fd.lnet=" << m_client_net << " did not match event. Full event output: " << full_output;
			ASSERT_TRUE(m_rnet_filter->run(evt)) << "fd.rnet=" << m_server_net << " did not match event. Full event output: " << full_output;

			verify_filtercheck(evt, "*%fd.lproto", m_client_proto, full_output);
			verify_filtercheck(evt, "*%fd.rproto", m_server_proto, full_output);
		}
	}

	void verify_filtercheck(sinsp_evt *evt, const char *format, string expected, string full_output)
	{
		verify_filtercheck(evt, format, expected.c_str(), full_output);
	}

	void verify_filtercheck(sinsp_evt *evt, const char *cformat, const char *expected, string full_output)
	{
		string output;
		string format = cformat;

		m_formatter_cache->tostring(evt, format, &output);

		ASSERT_STREQ(expected, output.c_str()) << " Result of format " << cformat << " did not match expected. Full event output: " << full_output;
	}

	void gen_ip_net_filters()
	{
		sinsp_filter_compiler ip_client(m_inspector.get(), "fd.ip=" + m_client_ip);
		m_ip_client_filter.reset(ip_client.compile());

		sinsp_filter_compiler ip_server(m_inspector.get(), "fd.ip=" + m_server_ip);
		m_ip_server_filter.reset(ip_server.compile());

		sinsp_filter_compiler net_client(m_inspector.get(), "fd.net=" + m_client_net);
		m_net_client_filter.reset(net_client.compile());

		sinsp_filter_compiler net_server(m_inspector.get(), "fd.net=" + m_server_net);
		m_net_server_filter.reset(net_server.compile());

		sinsp_filter_compiler cnet(m_inspector.get(), "fd.cnet=" + m_client_net);
		m_cnet_filter.reset(cnet.compile());

		sinsp_filter_compiler snet(m_inspector.get(), "fd.snet=" + m_server_net);
		m_snet_filter.reset(snet.compile());

		sinsp_filter_compiler lnet(m_inspector.get(), "fd.lnet=" + m_client_net);
		m_lnet_filter.reset(lnet.compile());

		sinsp_filter_compiler rnet(m_inspector.get(), "fd.rnet=" + m_server_net);
		m_rnet_filter.reset(rnet.compile());
	}

	shared_ptr<sinsp> m_inspector;
	shared_ptr<sinsp_evt_formatter_cache> m_formatter_cache;

	string m_client_ip;
	string m_server_ip;
	string m_client_port;
	string m_server_port;
	string m_client_net;
	string m_server_net;
	string m_client_proto;
	string m_server_proto;
	string m_conn_name;
	string m_l4proto;
	string m_is_server;

	shared_ptr<sinsp_filter> m_ip_client_filter;
	shared_ptr<sinsp_filter> m_ip_server_filter;
	shared_ptr<sinsp_filter> m_net_client_filter;
	shared_ptr<sinsp_filter> m_net_server_filter;
	shared_ptr<sinsp_filter> m_cnet_filter;
	shared_ptr<sinsp_filter> m_snet_filter;
	shared_ptr<sinsp_filter> m_lnet_filter;
	shared_ptr<sinsp_filter> m_rnet_filter;
	bool m_socket_connected;
	bool m_check_local_remote;
	bool m_check_is_server;
};

TEST_F(ipv6_filtercheck_test, curl_google_dnsreq)
{
	m_client_ip = "2600:1f18:262c:6542:9aa6:df7a:9a47:d29e";
	m_server_ip = "2001:4860:4860::8888";
	m_client_port = "40251";
	m_server_port = "53";
	m_client_net = "2600:1f18:262c:6542::";
	m_server_net = "2001:4860:4860::";
	m_client_proto = "40251";
	m_server_proto = "domain";
	m_conn_name = "2600:1f18:262c:6542:9aa6:df7a:9a47:d29e:40251->2001:4860:4860::8888:domain";
	m_l4proto = "udp";
	m_is_server = "false";

	read_file("./resources/ipv6_traces/curl_google.scap", "thread.tid=17498", [this](sinsp_evt *evt) {
		string evname = string(evt->get_name());

		// Once we see a connect or bind, we can assume the
		// socket is connected and it's possible to get
		// client/server and local/remote information.
		if(evname == "connect" ||
		   evname == "bind")
		{
			m_socket_connected = true;
			m_check_local_remote = true;
			m_check_is_server = true;
		}

		check_ipv6_filterchecks(evt);
	});
}

TEST_F(ipv6_filtercheck_test, curl_google_www)
{
	m_client_ip = "2600:1f18:262c:6542:9aa6:df7a:9a47:d29e";
	m_server_ip = "2607:f8b0:4004:802::2004";
	m_client_port = "37140";
	m_server_port = "80";
	m_client_net = "2600:1f18:262c:6542::";
	m_server_net = "2607:f8b0:4004:802::";
	m_client_proto = "37140";
	m_server_proto = "http";
	m_conn_name = "2600:1f18:262c:6542:9aa6:df7a:9a47:d29e:37140->2607:f8b0:4004:802::2004:http";
	m_l4proto = "tcp";
	m_is_server = "false";

	read_file("./resources/ipv6_traces/curl_google.scap", "thread.tid=17497", [this](sinsp_evt *evt) {
		string evname = string(evt->get_name());

		// Once we see a connect or bind, we can assume the
		// socket is connected and it's possible to get
		// client/server and local/remote information.
		if(evname == "connect" ||
		   evname == "bind")
		{
			m_socket_connected = true;
			m_check_local_remote = true;
			m_check_is_server = true;
		}

		check_ipv6_filterchecks(evt);
	});
}

TEST_F(ipv6_filtercheck_test, single_ipv6_conn_client)
{
	m_client_ip = "2001:db8::4";
	m_server_ip = "2001:db8::3";
	m_client_port = "54405";
	m_server_port = "1234";
	m_client_net = "2001:db8::";
	m_server_net = "2001:db8::";
	m_client_proto = "54405";
	m_server_proto = "1234";
	m_conn_name = "2001:db8::4:54405->2001:db8::3:1234";
	m_l4proto = "tcp";
	m_is_server = "false";

	read_file("./resources/ipv6_traces/single_ipv6_conn.scap", "proc.pid=25888", [this](sinsp_evt *evt) {
		string evname = string(evt->get_name());

		// Once we see a connect, we can assume the
		// socket is connected and it's possible to get
		// client/server information. However, we can *not*
		// get local/remote information as this connection was
		// done between two ips on the same local interface.
		if(evname == "connect")
		{
			m_socket_connected = true;
		}

		check_ipv6_filterchecks(evt);
	});
}

TEST_F(ipv6_filtercheck_test, single_ipv6_conn_server)
{
	m_client_ip = "2001:db8::4";
	m_server_ip = "2001:db8::3";
	m_client_port = "54405";
	m_server_port = "1234";
	m_client_net = "2001:db8::";
	m_server_net = "2001:db8::";
	m_client_proto = "54405";
	m_server_proto = "1234";
	m_conn_name = "2001:db8::4:54405->2001:db8::3:1234";
	m_l4proto = "tcp";
	m_is_server = "server";

	read_file("./resources/ipv6_traces/single_ipv6_conn.scap", "proc.pid=25886", [this](sinsp_evt *evt) {
		string evname = string(evt->get_name());

		// Once we see a connect, we can assume the
		// socket is connected and it's possible to get
		// client/server information. However, we can *not*
		// get local/remote information as this connection was
		// done between two ips on the same local interface.
		if(evname == "connect")
		{
			m_socket_connected = true;
		}

		check_ipv6_filterchecks(evt);
	});
}


TEST_F(ipv6_filtercheck_test, test_ipv6_client)
{
	// test_ipv6_client.cpp does the following:
	//  1. sendto() on an unconnected socket to ::1
	//  2. connect to ::1, port 2345
	//  3. send() on the connected socket (to ::1)
	//  4. connect to google dns server, port 53
	//  5. send() on the connected socket (to google dns server)
	//  6. sendto() back to ::1, port 2345

	// The test verifies that the addresses/ports on the socket
	// change properly for the connects/sendtos.

	enum state_t  {sendto_unconnected, send_connected, send_reconnected, sendto_reconnected, done};

	state_t state = sendto_unconnected;

	read_file("./resources/ipv6_traces/test_ipv6_client.scap", "proc.name=test_ipv6_clien", [&](sinsp_evt *evt) {
		string evname = string(evt->get_name());

		string full_output;
		string full = "*%evt.num %evt.outputtime %evt.cpu %proc.name (%thread.tid) %evt.dir %evt.type %evt.info";
		m_formatter_cache->tostring(evt, full, &full_output);

		if(evname == "send" ||
		   evname == "sendto")
		{
			switch(state)
			{
			case sendto_unconnected:
				verify_filtercheck(evt, "*%fd.name", "::1:0->::1:2345", full_output);
				state = send_connected;
				break;
			case send_connected:
				verify_filtercheck(evt, "*%fd.name", "::1:38255->::1:2345", full_output);
				state = send_reconnected;
				break;
			case send_reconnected:
				verify_filtercheck(evt, "*%fd.name", "::1:38255->2001:4860:4860::8888:domain", full_output);
				state = sendto_reconnected;
				break;
			case sendto_reconnected:
				verify_filtercheck(evt, "*%fd.name", "::1:38255->::1:2345", full_output);
				state = done;
				break;
			case done:
				break;
			}
		}
	}, false);

	ASSERT_TRUE(state == done);
}
