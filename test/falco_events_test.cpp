#include <set>
#include <string>

#include <gtest.h>

#include <sinsp.h>
#include <analyzer.h>

using namespace std;

class falco_events_test : public testing::Test
{
protected:
	static void log_cb(std::string &&str, uint32_t sev)
	{
		m_event_counts[sev] = m_event_counts[sev] + 1;
	}

	virtual void SetUp()
	{
		m_inspector = new sinsp();
		m_analyzer = new sinsp_analyzer(m_inspector);
		m_inspector->m_analyzer = m_analyzer;

		//
		// Reset counts. This is necessary as m_event_counts is static.
		//
		for (uint32_t i = sinsp_logger::SEV_EVT_MIN; i <= sinsp_logger::SEV_EVT_MAX; i++)
		{
			m_event_counts[i] = 0;
		}

		g_logger.remove_callback_log();
		g_logger.add_callback_log(log_cb);

		m_enable_falco = true;
	}

	virtual void TearDown()
	{
		m_inspector->close();
		delete m_inspector;
		delete m_analyzer;
	}

	void load(std::string &scap_file)
	{
		if(m_enable_falco)
		{
			double sampling_multiplier = 0;
			m_analyzer->enable_falco("./resources/falco/falco_rules.yaml",
						 "./resources/falco/user_falco_rules.yaml",
						 m_disabled_patterns,
						 sampling_multiplier);
		}
		m_inspector->open(scap_file);
	}

	void run_inspector()
	{
		int32_t res;
		sinsp_evt* ev;

		while(1)
		{
			res = m_inspector->next(&ev);

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
				//
				// Event read error.
				// Notify the chisels that we're exiting, and then die with an error.
				//
				cerr << "res = " << res << endl;
				throw sinsp_exception(m_inspector->getlasterr().c_str());
			}

			if(!m_inspector->is_debug_enabled() &&
			   ev->get_category() & EC_INTERNAL)
			{
				continue;
			}
		}
	}

	sinsp *m_inspector;
	sinsp_analyzer *m_analyzer;
	set<string> m_disabled_patterns;
	bool m_enable_falco;
	static map<uint32_t,int32_t> m_event_counts;
};

map<uint32_t,int32_t> falco_events_test::m_event_counts;

TEST_F(falco_events_test, match_system_rules)
{
	string scap_file = "./resources/falco/match-system-rules.scap";
	load(scap_file);

	run_inspector();

	ASSERT_GT(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}

TEST_F(falco_events_test, system_rules_disabled)
{
	m_disabled_patterns.insert("write_binary_dir");
	string scap_file = "./resources/falco/match-system-rules.scap";
	load(scap_file);

	run_inspector();

	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}

TEST_F(falco_events_test, system_rules_disabled_re)
{
	m_disabled_patterns.insert(".*binary.*");
	string scap_file = "./resources/falco/match-system-rules.scap";
	load(scap_file);

	run_inspector();

	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}

TEST_F(falco_events_test, match_user_rules)
{
	string scap_file = "./resources/falco/match-user-rules.scap";
	load(scap_file);

	run_inspector();

	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_GT(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}

TEST_F(falco_events_test, user_rules_disabled)
{
	m_disabled_patterns.insert("write_etc");
	string scap_file = "./resources/falco/match-user-rules.scap";
	load(scap_file);

	run_inspector();

	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}

TEST_F(falco_events_test, user_rules_disabled_re)
{
	m_disabled_patterns.insert(".*etc");
	string scap_file = "./resources/falco/match-user-rules.scap";
	load(scap_file);

	run_inspector();

	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}

TEST_F(falco_events_test, match_nothing)
{
	string scap_file = "./resources/falco/match-nothing.scap";
	load(scap_file);

	run_inspector();

	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}

TEST_F(falco_events_test, engine_disabled)
{
	m_enable_falco = false;
	string scap_file = "./resources/falco/match-system-rules.scap";
	load(scap_file);

	run_inspector();

	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_WARNING], 0);
	ASSERT_EQ(m_event_counts[sinsp_logger::SEV_EVT_ERROR], 0);
}
