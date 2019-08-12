#include <iostream>
#include <sinsp.h>
#include <sinsp_int.h>
#include <filterchecks.h>
#include "utils.h"
#include "draios.pb.h"
#include "analyzer_int.h"
#include "analyzer.h"
#include <baseliner.h>

#undef AVOID_FDS_FROM_THREAD_TABLE

extern sinsp_evttables g_infotables;
extern sinsp_filter_check_list g_filterlist;

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// /proc parser thread
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
void proc_parser(proc_parser_state* state)
{
	sinsp* inspector_ori = state->m_bl->get_inspector();

	//
	// Create and open the secondary inspector used for /proc parsing
	//
	state->m_inspector = new sinsp();
	state->m_inspector->set_hostname_and_port_resolution_mode(false);

	g_logger.format(sinsp_logger::SEV_INFO,
		"baseliner /proc scanner thread started");

	try
	{
		if(inspector_ori->is_live())
		{
			state->m_inspector->open();
		}
		else
		{
			state->m_inspector->open(inspector_ori->get_input_filename());
		}
	}
	catch(...)
	{
		g_logger.format(sinsp_logger::SEV_ERROR,
			"baseliner proc parser failure: can't open inspector %s",
			state->m_inspector->getlasterr().c_str());
		return;
	}

	//
	// This signals to the baseliner that our inspector can be merged
	//
	state->m_done = true;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Baseliner
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
sinsp_baseliner::sinsp_baseliner():
	m_inspector(nullptr),
	m_ifaddr_list(nullptr),
	m_progtable(),
	m_container_table(),
#ifdef ASYNC_PROC_PARSING
	m_procparser_thread(nullptr),
	m_procparser_state(nullptr),
#endif
	m_nofd_fs_extractors(),
	m_do_baseline_calculation(false)
{ }

void sinsp_baseliner::init(sinsp* inspector)
{
#ifdef ASYNC_PROC_PARSING
	m_procparser_thread = NULL;
#endif
	m_inspector = inspector;
	m_inspector->m_container_manager.subscribe_on_new_container([this](const sinsp_container_info &container_info, sinsp_threadinfo *tinfo) {
		on_new_container(container_info, tinfo);
	});
	m_ifaddr_list = m_inspector->get_ifaddr_list();
	load_tables(0);

	std::shared_ptr<sinsp_filter_check> arg1, arg2, absp, absdst;
	arg1.reset(g_filterlist.new_filter_check_from_fldname("evt.arg[1]", m_inspector, true));
	arg1->parse_field_name("evt.arg[1]", true, false);
	arg2.reset(g_filterlist.new_filter_check_from_fldname("evt.arg[2]", m_inspector, true));
	arg2->parse_field_name("evt.arg[2]", true, false);
	absp.reset(g_filterlist.new_filter_check_from_fldname("evt.abspath", m_inspector, false));
	absp->parse_field_name("evt.abspath", true, false);
	absdst.reset(g_filterlist.new_filter_check_from_fldname("evt.abspath.dst", m_inspector, false));
	absdst->parse_field_name("evt.abspath.dst", true, false);

	m_nofd_fs_extractors.emplace(PPME_SYSCALL_MKDIR_2_X, arg1);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_RMDIR_2_X, arg1);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_UNLINK_2_X, arg1);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_RENAME_X, arg1);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_MKDIRAT_X, absp);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_UNLINKAT_2_X, absp);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_RENAMEAT_X, absp);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_RENAME_X, arg2);
	m_nofd_fs_extractors.emplace(PPME_SYSCALL_RENAMEAT_X, absdst);

	m_do_baseline_calculation = false;
}

sinsp_baseliner::~sinsp_baseliner()
{
	clear_tables();

#ifdef ASYNC_PROC_PARSING
	if(m_procparser_thread != NULL)
	{
		if(m_procparser_thread->joinable())
		{
			m_procparser_thread->join();
		}
		delete m_procparser_thread;
		delete m_procparser_state;
	}
#endif
}

void sinsp_baseliner::load_tables(uint64_t time)
{
	init_containers();

#ifdef ASYNC_PROC_PARSING
	init_programs(m_inspector, time, true);

	if(m_procparser_thread != NULL)
	{
		//
		// Note: if we get there, the m_done flag of the thread state is guaranteed
		//       to be set to true, so we are sure that the join returns immediately.
		//       we still call it because otherwise, based on specification of C++11
		//       threads, the delete will crash.
		//
		if(m_procparser_thread->joinable())
		{
			m_procparser_thread->join();
		}

		delete m_procparser_thread;
		delete m_procparser_state;
	}

	m_procparser_state = new proc_parser_state(this, time);
	m_procparser_thread = new std::thread(proc_parser, m_procparser_state);
#else
	init_programs(m_inspector, time, false);
#endif
}

void sinsp_baseliner::clear_tables()
{
	//
	// Free all of the allocated entries in the prog table, which is a table of pointers
	//
	for(auto it : m_progtable)
	{
		delete it.second;
	}

	//
	// Clear the tables
	//
	m_progtable.clear();
	m_container_table.clear();
}

void sinsp_baseliner::init_programs(sinsp* inspector, uint64_t time, bool skip_fds)
{
	//
	// Go through the thread list and identify the main threads
	//
	inspector->m_thread_manager->m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
		tinfo.m_blprogram = NULL;

#ifdef AVOID_FDS_FROM_THREAD_TABLE
		//
		// If this is not the beginning of the capture, we just go through every FD
		// and we reset its baseline flag
		//
		if(time != 0)
		{
			sinsp_fdtable* fdt = tinfo.get_fd_table();

			if(fdt != NULL)
			{
				for(auto itf : fdt->m_table)
				{
					sinsp_fdinfo_t* fdinfo = &itf.second;
					fdinfo->reset_inpipeline();
				}
			}

			skip_fds = true;
		}
#endif
		//
		// Add main threads and their FDs to the program table.
		//
		if(tinfo.is_main_thread())
		{
			blprogram* np;

			auto it = m_progtable.find(tinfo.m_program_hash_falco);
			if(it == m_progtable.end())
			{
				if(m_progtable.size() >= BL_MAX_PROG_TABLE_SIZE)
				{
					// break out of threadtable loop
					return false;
				}

				np = new blprogram();

				np->m_dirs.m_regular_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;
				np->m_dirs.m_startup_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;

				m_progtable[tinfo.m_program_hash_falco] = np;
			}
			else
			{
				np = it->second;
			}

			//
			// Copy the basic thread info
			//
			np->m_comm = tinfo.m_comm;
			np->m_exe = tinfo.m_exe;
			if(tinfo.m_comm == "java")
			{
				np->m_pids.push_back(tinfo.m_pid);
			}
			//np->m_args = tinfo.m_args;
			//np->m_env = tinfo.m_env;
			np->m_container_id = tinfo.m_container_id;
			np->m_user_id = tinfo.m_uid;
			np->m_comm = tinfo.m_comm;

			//
			// Calculate the delta from program creation.
			// Note: we don't search for the main process thread because this loop already makes
			//       sure to go through main threads only.
			//
			uint64_t cdelta = 0;

			if(time != 0)
			{
				uint64_t clone_ts = (tinfo.m_clone_ts != 0)? tinfo.m_clone_ts : inspector->m_firstevent_ts;
				cdelta = time - clone_ts;
			}

			if(skip_fds)
			{
				// next loop
				return true;
			}

			//
			// Process the FD table
			//
			sinsp_fdtable* fdt = tinfo.get_fd_table();

			if(fdt != NULL)
			{
				for(auto itf : fdt->m_table)
				{
					sinsp_fdinfo_t* fdinfo = &itf.second;

					switch(fdinfo->m_type)
					{
					case SCAP_FD_FILE:
					case SCAP_FD_FILE_V2:
					{
						//
						// Add the entry to the file table
						//
						file_category category = blfiletable::flags2filecategory(UNCATEGORIZED, fdinfo->m_openflags);
						np->m_files.add(fdinfo->m_name, category, cdelta);

						//
						// Add the entry to the directory tables
						//
						std::string sdir = blfiletable::file_to_dir(fdinfo->m_name);
						np->m_dirs.add(sdir, category, cdelta);

						break;
					}
					case SCAP_FD_DIRECTORY:
					{
						//
						// Add the entry to the directory tables
						//
						std::string sdir = fdinfo->m_name + '/';
						file_category category = blfiletable::flags2filecategory(UNCATEGORIZED, fdinfo->m_openflags);
						np->m_dirs.add(sdir, category, cdelta);

						break;
					}
					case SCAP_FD_IPV4_SOCK:
						{
							ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;

							if(fdinfo->is_role_server())
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np->m_server_ports.add_l_tcp(tuple.m_fields.m_dport, cdelta);
									np->m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip, cdelta);
									np->m_c_subnet_endpoints.add_c_tcp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip), cdelta);
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np->m_server_ports.add_l_udp(tuple.m_fields.m_dport, cdelta);
									np->m_ip_endpoints.add_udp(tuple.m_fields.m_sip, cdelta);
									np->m_c_subnet_endpoints.add_udp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip), cdelta);
								}
							}
							else
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np->m_server_ports.add_r_tcp(tuple.m_fields.m_dport, cdelta);
									np->m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip, cdelta);
									np->m_c_subnet_endpoints.add_s_tcp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip), cdelta);
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np->m_server_ports.add_r_udp(tuple.m_fields.m_dport, cdelta);
									np->m_ip_endpoints.add_udp(tuple.m_fields.m_dip, cdelta);
									np->m_c_subnet_endpoints.add_udp(
										bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip), cdelta);
								}
							}
						}
						break;
					case SCAP_FD_IPV4_SERVSOCK:
					{
						if(fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto == SCAP_L4_TCP)
						{
							np->m_bound_ports.add_l_tcp(fdinfo->m_sockinfo.m_ipv4serverinfo.m_port, cdelta);
						}
						if(fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto == SCAP_L4_UDP)
						{
							np->m_bound_ports.add_l_udp(fdinfo->m_sockinfo.m_ipv4serverinfo.m_port, cdelta);
						}
						break;
					}
					case SCAP_FD_IPV6_SERVSOCK:
						if(fdinfo->m_sockinfo.m_ipv6serverinfo.m_l4proto == SCAP_L4_TCP)
						{
							np->m_bound_ports.add_l_tcp(fdinfo->m_sockinfo.m_ipv6serverinfo.m_port, cdelta);
						}
						if(fdinfo->m_sockinfo.m_ipv6serverinfo.m_l4proto == SCAP_L4_UDP)
						{
							np->m_bound_ports.add_l_udp(fdinfo->m_sockinfo.m_ipv6serverinfo.m_port, cdelta);
						}
						break;
					case SCAP_FD_IPV6_SOCK:
						{
							ipv6tuple tuple = fdinfo->m_sockinfo.m_ipv6info;

							if(fdinfo->is_role_server())
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np->m_server_ports.add_l_tcp(tuple.m_fields.m_dport, cdelta);
									// TODO: add support for ipv6 addresses
									// np->m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip, cdelta);
									// np->m_c_subnet_endpoints.add_c_tcp(
										// bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip), cdelta);
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np->m_server_ports.add_l_udp(tuple.m_fields.m_dport, cdelta);
									// TODO: add support for ipv6 addresses
									// np->m_ip_endpoints.add_udp(tuple.m_fields.m_sip, cdelta);
									// np->m_c_subnet_endpoints.add_udp(
										// bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip), cdelta);
								}
							}
							else
							{
								if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
								{
									np->m_server_ports.add_r_tcp(tuple.m_fields.m_dport, cdelta);
									// TODO: add support for ipv6 addresses
									// np->m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip, cdelta);
									// np->m_c_subnet_endpoints.add_s_tcp(
										// bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip), cdelta);
								}
								else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
								{
									np->m_server_ports.add_r_udp(tuple.m_fields.m_dport, cdelta);
									// TODO: add support for ipv6 addresses
									// np->m_ip_endpoints.add_udp(tuple.m_fields.m_dip, cdelta);
									// np->m_c_subnet_endpoints.add_udp(
										// bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip), cdelta);
								}
							}
						}
						break;
					default:
						break;
					}
				}
			}
		}
		// next loop
		return true;
	});

	//
	// In this second pass, we go over the thread table and add all of the main processes
	// to their prarents' executed program list
	//
	// XXX: is this just tinfo.traverse_parent_state() in disguise?
	// XXX: O(n^2), worst case
	inspector->m_thread_manager->m_threadtable.loop([&] (sinsp_threadinfo& tinfo) {
		if(tinfo.is_main_thread())
		{
			auto ptinfo = tinfo.get_parent_thread();
			if(ptinfo == NULL)
			{
				return false;
			}

			auto itp = m_progtable.find(ptinfo->m_program_hash_falco);

			if(itp != m_progtable.end())
			{
				uint64_t cdelta = 0;
				uint64_t clone_ts;

				if(time != 0)
				{
					clone_ts = (tinfo.m_clone_ts != 0)? tinfo.m_clone_ts : inspector->m_firstevent_ts;
					cdelta = time - clone_ts;
				}

				itp->second->m_executed_programs.add(tinfo.m_comm, cdelta);
			}
		}
		return true;
	});

}

void sinsp_baseliner::init_containers()
{
	auto containers = m_inspector->m_container_manager.get_containers();

	for(auto& it : *containers)
	{
		m_container_table[it.first] = blcontainer(it.second.m_name,
			it.second.m_image, it.second.m_imageid);
	}
}

void sinsp_baseliner::register_callbacks(sinsp_fd_listener* listener)
{
	//
	// Initialize the FD listener
	//
	m_inspector->m_parser->m_fd_listener = listener;
}

void sinsp_baseliner::serialize_json(std::string filename)
{
	Json::Value root;
	Json::Value econt;
	Json::Value table(Json::arrayValue);
	Json::Value ctable;

	std::ofstream ofs(filename, std::ofstream::out);
	if(!ofs.is_open())
	{
		throw(sinsp_exception("can't open file " + filename + " for writing"));
	}

	for(auto& it : m_progtable)
	{
		Json::Value eprog;

		eprog["comm"] = it.second->m_comm;
		eprog["exe"] = it.second->m_exe;
		eprog["user_id"] = it.second->m_user_id;

		if(!it.second->m_container_id.empty())
		{
			eprog["container_id"] = it.second->m_container_id;
		}

/*
		// Args
		if(it.second.m_args.size() != 0)
		{
			Json::Value echild;

			for(auto it1 : it.second.m_args)
			{
				echild.append(it1);
			}

			eprog["args"] = echild;
		}

		// Env
		if(it.second.m_env.size() != 0)
		{
			Json::Value echild;

			for(auto it1 : it.second.m_env)
			{
				echild.append(it1);
			}

			eprog["env"] = echild;
		}
*/
		// Files
		Json::Value efiles;
		it.second->m_files.serialize_json(efiles);
		if(!efiles.empty())
		{
			eprog["files"] = efiles;
		}

		// Dirs
		Json::Value edirs;
		it.second->m_dirs.serialize_json(edirs);
		if(!edirs.empty())
		{
			eprog["dirs"] = edirs;
		}

		// Executed Programs
		Json::Value eeprogs;
		it.second->m_executed_programs.serialize_json(eeprogs);
		if(!eeprogs.empty())
		{
			eprog["executed_programs"] = eeprogs;
		}

		// Server ports
		Json::Value eserver_ports;
		it.second->m_server_ports.serialize_json(eserver_ports);
		if(!eserver_ports.empty())
		{
			eprog["server_ports"] = eserver_ports;
		}

		// bound ports
		Json::Value ebound_ports;
		it.second->m_bound_ports.serialize_json(ebound_ports);
		if(!ebound_ports.empty())
		{
			eprog["bound_ports"] = ebound_ports;
		}

		// IP endpoints
		Json::Value eip_endpoints;
		it.second->m_ip_endpoints.serialize_json(eip_endpoints);
		if(!eip_endpoints.empty())
		{
			eprog["ip_endpoints"] = eip_endpoints;
		}

		// IP c subnets
		Json::Value ec_subnet_endpoints;
		it.second->m_c_subnet_endpoints.serialize_json(ec_subnet_endpoints);
		if(!ec_subnet_endpoints.empty())
		{
			eprog["c_subnet_endpoints"] = ec_subnet_endpoints;
		}

		// syscalls
		Json::Value eesyscalls;
		it.second->m_syscalls.serialize_json(eesyscalls);
		if(!eesyscalls.empty())
		{
			eprog["syscalls"] = eesyscalls;
		}

		table.append(eprog);
	}

	root["progs"] = table;

	for(auto& it : m_container_table)
	{
		Json::Value cinfo;
		cinfo["name"] = it.second.m_name;
		cinfo["image_name"] = it.second.m_image_name;
		cinfo["image_id"] = it.second.m_image_id;

		ctable[it.first] = cinfo;
	}

	root["containers"] = ctable;

	ofs << root << std::endl;
}

void sinsp_baseliner::serialize_protobuf(draiosproto::falco_baseline* pbentry)
{
	//
	// Serialize the programs
	//
	for(auto& it : m_progtable)
	{
		draiosproto::falco_prog* prog = pbentry->add_progs();

		prog->set_comm(it.second->m_comm);
		prog->set_exe(it.second->m_exe);

		//
		// For java processes, we patch the comm and exe with the name coming from
		// the JMX information for the first process associated with this program
		//
		if(it.second->m_comm == "java")
		{
			ASSERT(it.second->m_pids.size() != 0);

			if(it.second->m_pids.size() != 0)
			{
				std::string jname;

				if(m_inspector->m_analyzer->find_java_process_name(
							it.second->m_pids[0], jname))
				{
					prog->set_comm(jname);
				}
			}
		}
		prog->set_user_id(it.second->m_user_id);
		if(!it.second->m_container_id.empty())
		{
			prog->set_container_id(it.second->m_container_id);
		}

		// Files
		if(it.second->m_files.has_data())
		{
			draiosproto::falco_category* cfiles = prog->add_cats();
			cfiles->set_name("files");
			it.second->m_files.serialize_protobuf(cfiles);
		}

		// Dirs
		if(it.second->m_dirs.has_data())
		{
			draiosproto::falco_category* cdirs = prog->add_cats();
			cdirs->set_name("dirs");
			it.second->m_dirs.serialize_protobuf(cdirs);
		}

		// Executed Programs
		if(it.second->m_executed_programs.has_data())
		{
			draiosproto::falco_category* cexecuted_programs = prog->add_cats();
			cexecuted_programs->set_name("executed_programs");
			it.second->m_executed_programs.serialize_protobuf(cexecuted_programs);
		}

		// Server ports
		if(it.second->m_server_ports.has_data())
		{
			draiosproto::falco_category* cserver_ports = prog->add_cats();
			cserver_ports->set_name("server_ports");
			it.second->m_server_ports.serialize_protobuf(cserver_ports);
		}

		// bound ports
		if(it.second->m_bound_ports.has_data())
		{
			draiosproto::falco_category* cbound_ports = prog->add_cats();
			cbound_ports->set_name("bound_ports");
			it.second->m_bound_ports.serialize_protobuf(cbound_ports);
		}

		// IP endpoints
		if(it.second->m_ip_endpoints.has_data())
		{
			draiosproto::falco_category* cip_endpoints = prog->add_cats();
			cip_endpoints->set_name("ip_endpoints");
			it.second->m_ip_endpoints.serialize_protobuf(cip_endpoints);
		}

		// IP c subnets
		if(it.second->m_c_subnet_endpoints.has_data())
		{
			draiosproto::falco_category* cc_subnet_endpoints = prog->add_cats();
			cc_subnet_endpoints->set_name("c_subnet_endpoints");
			it.second->m_c_subnet_endpoints.serialize_protobuf(cc_subnet_endpoints);
		}

		// syscalls
		if(it.second->m_syscalls.has_data())
		{
			draiosproto::falco_category* csyscalls = prog->add_cats();
			csyscalls->set_name("syscalls");
			it.second->m_syscalls.serialize_protobuf(csyscalls);
		}
	}

	//
	// Serialize the containers
	//
	for (auto& it : m_container_table)
	{
		draiosproto::falco_container* cont = pbentry->add_containers();

		cont->set_id(it.first);
		cont->set_name(it.second.m_name);

		if (it.second.m_image_name != "")
		{
			cont->set_image_name(it.second.m_image_name);
		}

		if (it.second.m_image_id != "")
		{
			cont->set_image_id(it.second.m_image_id);
		}
	}
}

#ifdef ASYNC_PROC_PARSING
void sinsp_baseliner::merge_proc_data()
{
	//
	// If this is a file, we get here at the end of the capture.
	// We join the /proc scanner thread to make sure it's done
	//
	if(!m_inspector->is_live())
	{
		if(m_procparser_thread->joinable())
		{
			m_procparser_thread->join();
		}
	}

	//
	// If m_procparser_state->m_inspector is not NULL, it means that
	// the data hasn't been flushed yet
	//
	if(m_procparser_state->m_inspector != NULL)
	{
		g_logger.format(sinsp_logger::SEV_INFO,
			"merging baseliner /proc data during interval switch");

		//
		// If the /proc thread is still scanning, we have a problem
		//
		if(!m_procparser_state->m_done)
		{
			g_logger.format(sinsp_logger::SEV_ERROR,
				"baseliner proc parser thread not done after a full interval. Skipping baseline emission.");
			return;
		}

		//
		// Merge the data extracted by the /proc scanner
		//
		init_programs(m_procparser_state->m_inspector,
			m_procparser_state->m_time, false);

		//
		// Destroy the second inspector that was used to scan proc/
		//
		delete m_procparser_state->m_inspector;
		m_procparser_state->m_inspector = NULL;
	}
}
#endif

void sinsp_baseliner::emit_as_protobuf(uint64_t time, draiosproto::falco_baseline* pbentry)
{
#ifdef ASYNC_PROC_PARSING
	merge_proc_data();
#endif
	g_logger.format(sinsp_logger::SEV_INFO, "emitting falco baseline %" PRIu64, time);

	serialize_protobuf(pbentry);

	if(m_inspector->is_live())
	{
		clear_tables();
		load_tables(time);
	}
}

inline blprogram* sinsp_baseliner::get_program(sinsp_threadinfo* tinfo)
{
	blprogram* pinfo;

	if(tinfo == NULL)
	{
		return NULL;
	}
	else if(tinfo->m_blprogram != NULL)
	{
		pinfo = tinfo->m_blprogram;
	}
	else
	{
		//
		// Find the program entry
		//
		auto it = m_progtable.find(tinfo->m_program_hash_falco);

		if(it == m_progtable.end())
		{
			return NULL;
		}

		pinfo = it->second;
		tinfo->m_blprogram = pinfo;
	}

	return pinfo;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Table update methods
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
void sinsp_baseliner::on_file_open(sinsp_evt *evt, std::string& name, uint32_t openflags)
{
	// We do baseline calculatation only if the agent's resource usage is low
	if(!m_do_baseline_calculation)
	{
		return;
	}

	sinsp_threadinfo* tinfo = evt->get_thread_info();
	sinsp_evt_param *parinfo;
	file_category cat = file_category::NONE;
	int64_t fd;

	//
	// Check the return value. We only care about successful opened files
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;
	if(fd < 0)
	{
		cat = file_category::FAILED_OPS;
	}

	blprogram* pinfo = get_program(tinfo);
	if(pinfo == NULL)
	{
		return;
	}

	sinsp_threadinfo* mt = tinfo->get_main_thread();
	uint64_t clone_ts;

	if(mt != NULL)
	{
		clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
	}
	else
	{
		clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
	}

	//
	// Compute the right file category
	//
	cat = blfiletable::flags2filecategory(cat, openflags);

	//
	// Add the entry to the file table
	//
	pinfo->m_files.add(name, cat, evt->get_ts() - clone_ts);

	//
	// Add the entry to the directory tables
	//
	std::string sdir = blfiletable::file_to_dir(name);
	pinfo->m_dirs.add(sdir, cat, evt->get_ts() - clone_ts);
}

void sinsp_baseliner::on_new_proc(sinsp_evt *evt, sinsp_threadinfo* tinfo)
{
	// We do baseline calculatation only if the agent's resource usage is low
	if(!m_do_baseline_calculation)
	{
		return;
	}

	ASSERT(tinfo != NULL);

	//
	// Note: the hash is exe+container
	//
	size_t phash = tinfo->m_program_hash_falco;

	//
	// Find the program entry
	//
	auto it = m_progtable.find(phash);
	if(it == m_progtable.end())
	{
		if(m_progtable.size() >= BL_MAX_PROG_TABLE_SIZE)
		{
			return;
		}

		blprogram* np = new blprogram();
		tinfo->m_blprogram = np;

		np->m_comm = tinfo->m_comm;
		np->m_exe = tinfo->m_exe;
		np->m_container_id = tinfo->m_container_id;
		np->m_user_id = tinfo->m_uid;
		np->m_dirs.m_regular_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;
		np->m_dirs.m_startup_table.m_max_table_size = BL_MAX_DIRS_TABLE_SIZE;

		m_progtable[phash] = np;

		sinsp_threadinfo* ptinfo = m_inspector->get_thread(tinfo->m_ptid);

		if(ptinfo != NULL)
		{
			auto itp = m_progtable.find(ptinfo->m_program_hash_falco);

			if(itp != m_progtable.end())
			{
				sinsp_threadinfo* mt = tinfo->get_main_thread();
				uint64_t clone_ts;

				if(mt != NULL)
				{
					clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
				}
				else
				{
					clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
				}

				itp->second->m_executed_programs.add(tinfo->m_comm,
					evt->get_ts() - clone_ts);
			}
		}
	}
	else
	{
		blprogram* pinfo = it->second;
		tinfo->m_blprogram = pinfo;

		if(tinfo->m_comm == "java" && tinfo->is_main_thread())
		{
			pinfo->m_pids.push_back(tinfo->m_pid);
		}

		//ASSERT(pinfo.m_comm == tinfo->m_comm);
		ASSERT(pinfo->m_exe == tinfo->m_exe);
		//ASSERT(pinfo.m_args == tinfo->m_args);
		//ASSERT(pinfo.m_parent_comm == tinfo->m_parent_comm);
		ASSERT(pinfo->m_container_id == tinfo->m_container_id);
		//ASSERT(pinfo.m_user_id == tinfo->m_uid);
	}
}

void sinsp_baseliner::on_connect(sinsp_evt *evt)
{
	// We do baseline calculatation only if the agent's resource usage is low
	if(!m_do_baseline_calculation)
	{
		return;
	}

	//
	// Note: the presence of fdinfo is assured in sinsp_parser::parse_connect_exit, so
	//       we don't need to check it
	//
	sinsp_fdinfo_t* fdinfo = evt->get_fd_info();
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	//
	// Find the program entry
	//
	blprogram* pinfo = get_program(tinfo);
	if(pinfo == NULL)
	{
		return;
	}

	sinsp_threadinfo* mt = tinfo->get_main_thread();
	uint64_t clone_ts;

	if(mt != NULL)
	{
		clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
	}
	else
	{
		clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
	}

	uint64_t cdelta = evt->get_ts() - clone_ts;

	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;

		if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
		{
			pinfo->m_server_ports.add_r_tcp(tuple.m_fields.m_dport,
				cdelta);
			pinfo->m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip,
				cdelta);
			pinfo->m_c_subnet_endpoints.add_s_tcp(
				bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip),
				cdelta);
		}
		else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
		{
			pinfo->m_server_ports.add_r_udp(tuple.m_fields.m_dport,
				cdelta);
			pinfo->m_ip_endpoints.add_udp(tuple.m_fields.m_dip,
				cdelta);
			pinfo->m_c_subnet_endpoints.add_udp(
				bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip),
				cdelta);
		}
	}
	else if(fdinfo->m_type == SCAP_FD_IPV6_SOCK)
	{
		ipv6tuple tuple = fdinfo->m_sockinfo.m_ipv6info;

		if(tuple.m_fields.m_l4proto == SCAP_L4_TCP)
		{
			pinfo->m_server_ports.add_r_tcp(tuple.m_fields.m_dport,
				cdelta);
			// TODO: add ipv6 support
			// pinfo->m_ip_endpoints.add_s_tcp(tuple.m_fields.m_dip,
				// cdelta);
			// pinfo->m_c_subnet_endpoints.add_s_tcp(
				// bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip),
				// cdelta);
		}
		else if(tuple.m_fields.m_l4proto == SCAP_L4_UDP)
		{
			pinfo->m_server_ports.add_r_udp(tuple.m_fields.m_dport,
				cdelta);
			// TODO: add ipv6 support
			// pinfo->m_ip_endpoints.add_udp(tuple.m_fields.m_dip,
				// cdelta);
			// pinfo->m_c_subnet_endpoints.add_udp(
				// bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_dip),
				// cdelta);
		}
	}
}

void sinsp_baseliner::on_accept(sinsp_evt *evt, sinsp_fdinfo_t* fdinfo)
{
	// We do baseline calculatation only if the agent's resource usage is low
	if(!m_do_baseline_calculation)
	{
		return;
	}

	sinsp_threadinfo* tinfo = evt->get_thread_info();

	//
	// Find the program entry
	//
	blprogram* pinfo = get_program(tinfo);
	if(pinfo == NULL)
	{
		return;
	}

	sinsp_threadinfo* mt = tinfo->get_main_thread();
	uint64_t clone_ts;

	if(mt != NULL)
	{
		clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
	}
	else
	{
		clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
	}

	uint64_t cdelta = evt->get_ts() - clone_ts;

	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		ipv4tuple tuple = fdinfo->m_sockinfo.m_ipv4info;
		pinfo->m_server_ports.add_l_tcp(tuple.m_fields.m_dport,
			cdelta);
		pinfo->m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip,
			cdelta);
		pinfo->m_c_subnet_endpoints.add_c_tcp(
			bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip),
			cdelta);
	}
	else if(fdinfo->m_type == SCAP_FD_IPV6_SOCK)
	{
		ipv6tuple tuple = fdinfo->m_sockinfo.m_ipv6info;
		pinfo->m_server_ports.add_l_tcp(tuple.m_fields.m_dport,
			cdelta);
		// TODO: add ipv6 support
		// pinfo->m_ip_endpoints.add_c_tcp(tuple.m_fields.m_sip,
			// cdelta);
		// pinfo->m_c_subnet_endpoints.add_c_tcp(
			// bl_ip_endpoint_table::c_subnet(tuple.m_fields.m_sip),
			// cdelta);
	}
}

void sinsp_baseliner::on_bind(sinsp_evt *evt)
{
	// We do baseline calculatation only if the agent's resource usage is low
	if(!m_do_baseline_calculation)
	{
		return;
	}

	//
	// Note: the presence of fdinfo is assured in sinsp_parser::parse_connect_exit, so
	//       we don't need to check it
	//
	sinsp_fdinfo_t* fdinfo = evt->get_fd_info();

	sinsp_threadinfo* tinfo = evt->get_thread_info();

	//
	// Find the program entry
	//
	blprogram* pinfo = get_program(tinfo);
	if(pinfo == NULL)
	{
		return;
	}

	sinsp_threadinfo* mt = tinfo->get_main_thread();
	uint64_t clone_ts;

	if(mt != NULL)
	{
		clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
	}
	else
	{
		clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
	}

	ipv4serverinfo tuple = fdinfo->m_sockinfo.m_ipv4serverinfo;
	ipv6serverinfo tuplev6 = fdinfo->m_sockinfo.m_ipv6serverinfo;
	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK &&
			tuple.m_l4proto == SCAP_L4_TCP)
	{
		pinfo->m_bound_ports.add_l_tcp(tuple.m_port,
					       evt->get_ts() - clone_ts);
	}
	else if(fdinfo->m_type == SCAP_FD_IPV6_SOCK &&
			tuplev6.m_l4proto == SCAP_L4_TCP)
	{
		pinfo->m_bound_ports.add_l_tcp(tuple.m_port,
					       evt->get_ts() - clone_ts);
	}
}

void sinsp_baseliner::on_new_container(const sinsp_container_info& container_info, sinsp_threadinfo *tinfo)
{
	m_container_table[container_info.m_id] = blcontainer(container_info.m_name,
		container_info.m_image,
		container_info.m_imageid);
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Single event processing methods
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
void sinsp_baseliner::add_fd_from_io_evt(sinsp_evt *evt, enum ppm_event_category category)
{
	sinsp_fdinfo_t* fdinfo = evt->m_fdinfo;
	if(fdinfo == NULL)
	{
		return;
	}

	scap_fd_type fd_type = fdinfo->m_type;

	switch(fd_type)
	{
	case SCAP_FD_FILE_V2:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
		if(category == EC_IO_READ)
		{
			if(!evt->m_fdinfo->is_inpipeline_r())
			{
				on_file_open(evt, fdinfo->m_name, PPM_O_RDONLY);
				evt->m_fdinfo->set_inpipeline_r();
			}
		}
		else if(category == EC_IO_WRITE)
		{
			if(!evt->m_fdinfo->is_inpipeline_rw())
			{
				on_file_open(evt, fdinfo->m_name, PPM_O_RDWR);
				evt->m_fdinfo->set_inpipeline_rw();
			}
		}
		else if(category == EC_IO_OTHER)
		{
			if(!evt->m_fdinfo->is_inpipeline_other())
			{
				on_file_open(evt, fdinfo->m_name, 0);
				evt->m_fdinfo->set_inpipeline_other();
			}
		}
		else
		{
			ASSERT(false);
		}

		break;
	case SCAP_FD_IPV4_SOCK:
	case SCAP_FD_IPV6_SOCK:
	case SCAP_FD_IPV4_SERVSOCK:
	case SCAP_FD_IPV6_SERVSOCK:
		if(!evt->m_fdinfo->is_inpipeline_r())
		{
			if(fdinfo->is_role_server())
			{
				on_accept(evt, fdinfo);
			}
			else
			{
				on_connect(evt);
			}

			evt->m_fdinfo->set_inpipeline_r();
		}

		break;
	default:
		break;
	}
}

sinsp* sinsp_baseliner::get_inspector()
{
	return m_inspector;
}

void sinsp_baseliner::set_baseline_calculation_enabled(const bool enabled)
{
	m_do_baseline_calculation = enabled;
}

bool sinsp_baseliner::is_baseline_calculation_enabled() const
{
	return m_do_baseline_calculation;
}

inline void sinsp_baseliner::extract_from_event(sinsp_evt *evt)
{
	file_category cat = file_category::NONE;
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	uint16_t etype = evt->get_type();

	if(m_nofd_fs_extractors.find(etype) == m_nofd_fs_extractors.end())
	{
		return;
	}

	//
	// Check the return value. We only care about successful operations
	//
	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t rv = *(int64_t *)parinfo->m_val;
	if(rv != 0)
	{
		cat = file_category::FAILED_OPS;
	}

	blprogram* pinfo = get_program(tinfo);
	if(pinfo == NULL)
	{
		return;
	}

	sinsp_threadinfo* mt = tinfo->get_main_thread();
	uint64_t clone_ts;

	if(mt != NULL)
	{
		clone_ts = (mt->m_clone_ts != 0)? mt->m_clone_ts : m_inspector->m_firstevent_ts;
	}
	else
	{
		clone_ts = (tinfo->m_clone_ts != 0)? tinfo->m_clone_ts : m_inspector->m_firstevent_ts;
	}
	uint64_t time_from_clone = evt->get_ts() - clone_ts;

	// these operations are always rw
	cat = static_cast<file_category>(cat | file_category::READ_WRITE);

	bool dir_unlink = false;
	if(etype == PPME_SYSCALL_UNLINKAT_2_X)
	{
		parinfo = evt->get_param(3);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t flags = *(uint32_t *)parinfo->m_val;
		dir_unlink = flags & PPM_AT_REMOVEDIR;
	}

	auto range = m_nofd_fs_extractors.equal_range(evt->get_type());

	for(auto it = range.first; it != range.second; ++it)
	{
		uint8_t *val;
		uint32_t len;

		val = it->second->extract(evt, &len);
		std::string name((const char *)val);

		//
		// Add the parent directory to the directory table
		//
		std::string sdir = blfiletable::file_to_dir(name);
		pinfo->m_dirs.add(sdir, cat, time_from_clone);

		if((etype != PPME_SYSCALL_UNLINK_2_X && etype != PPME_SYSCALL_UNLINKAT_2_X) ||
		   (etype == PPME_SYSCALL_UNLINKAT_2_X && dir_unlink))
		{
			//
			// Add the directory to the directory table
			//
			pinfo->m_dirs.add(name, cat, time_from_clone);
		}

		if((etype == PPME_SYSCALL_UNLINK_2_X || (etype == PPME_SYSCALL_UNLINKAT_2_X && !dir_unlink)) ||
		   (etype == PPME_SYSCALL_RENAME_X || etype == PPME_SYSCALL_RENAMEAT_X))
		{
			//
			// unlink/unlinkat of a file or
			// we don't know if name is a file or a directory
			// so add it to the file table
			//
			pinfo->m_files.add(name, cat, time_from_clone);
		}
	}
}

void sinsp_baseliner::process_event(sinsp_evt *evt)
{
	// We do baseline calculatation only if the agent's resource usage is low
	if(!m_do_baseline_calculation)
	{
		return;
	}

	extract_from_event(evt);

	uint16_t etype = evt->m_pevt->type;
	if(!PPME_IS_ENTER(etype))
	{
		return;
	}

	//
	// Skip some unnecessary events
	//
	enum ppm_event_flags flags = g_infotables.m_event_info[etype].flags;

	if(etype == PPME_SCHEDSWITCH_6_E || (flags & (EF_SKIPPARSERESET | EF_UNUSED)))
	{
		return;
	}

#ifdef ASYNC_PROC_PARSING
	//
	// Check if it's time to merge the data from the /proc scanner thread
	//
	if(m_procparser_state->m_inspector != NULL && m_procparser_state->m_done)
	{
		g_logger.format(sinsp_logger::SEV_INFO,
			"merging baseliner /proc data during syscall parsing");

		//
		// Merge the data extracted by the /proc scanner
		//
		init_programs(m_procparser_state->m_inspector,
			m_procparser_state->m_time, false);

		//
		// Destroy the second inspector that was used to scan proc/
		//
		delete m_procparser_state->m_inspector;
		m_procparser_state->m_inspector = NULL;
	}
#endif

	//
	// Find the thread info
	//
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(tinfo == NULL)
	{
		return;
	}

#ifdef AVOID_FDS_FROM_THREAD_TABLE
	enum ppm_event_category category = g_infotables.m_event_info[etype].category;
	if(category & EC_IO_BASE)
	{
		add_fd_from_io_evt(evt, category);
	}
#endif

	blprogram* pinfo = get_program(tinfo);

	if(pinfo == NULL)
	{
		return;
	}

	//
	// Extract the ID, which depends on the type event: for generic
	// events we need to go find the system call ID.
	//
	uint32_t evid;

	if(etype == PPME_GENERIC_E || etype == PPME_GENERIC_X)
	{
		sinsp_evt_param *parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		uint16_t val = *(uint16_t *)parinfo->m_val;

		evid = val << 16;
	}
	else
	{
		evid = evt->get_type();
	}

	// Note that every syscall is included in the baseline
	// fingerprint. Within the agent, many syscalls are removed
	// from consideration when actually enforcing the baseline.
	pinfo->m_syscalls.add(evid, 0);
}
