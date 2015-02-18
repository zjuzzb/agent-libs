#pragma once

#include "main.h"

class pipe_manager;
void run_sdjagent(shared_ptr<pipe_manager>);
void run_monitor(const string& pidfile, shared_ptr<pipe_manager>);
