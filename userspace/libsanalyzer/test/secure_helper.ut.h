#pragma once

void add_connections_helper(uint64_t ts,
                            int n_client,
                            int n_server,
                            bool local = false,
                            bool interactive = false,
                            bool cmdline = false,
                            int cmdline_len = 0,
                            bool client_and_server = false);
