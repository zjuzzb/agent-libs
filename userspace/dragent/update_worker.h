#pragma once

#include "main.h"
#include "configuration.h"

class update_worker : public Runnable
{
public:
	update_worker(dragent_configuration* configuration);

	void run();

private:
	void update_debian();
	void update_rhel();
	void launch(const string& command, const vector<string> args);
	
	dragent_configuration* m_configuration;
};
