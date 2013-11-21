#include "sinsp.h"
#include "sinsp_int.h"
#include "filter.h"
#include "filterchecks.h"
#include "eventformatter.h"


///////////////////////////////////////////////////////////////////////////////
// rawstring_check implementation
///////////////////////////////////////////////////////////////////////////////
#ifdef HAS_FILTERING
sinsp_evt_formatter::sinsp_evt_formatter(const string& fmt)
{
	set_format(fmt);
}

void sinsp_evt_formatter::set_format(const string& fmt)
{
	uint32_t j;
	uint32_t last_nontoken_str_start = 0;
	const char* cfmt = fmt.c_str();

	m_tokens.clear();

	for(j = 0; j < fmt.length(); j++)
	{
		if(cfmt[j] == '%')
		{
			if(last_nontoken_str_start != j)
			{
				m_tokens.push_back(new rawstring_check(fmt.substr(last_nontoken_str_start, j - last_nontoken_str_start)));
			}

			sinsp_filter_check* chk = sinsp_filter_check::new_filter_check_from_name(string(cfmt + j + 1));
			if(chk == NULL)
			{
				throw sinsp_exception("invalid formatting token " + string(cfmt + j + 1));
			}

			j += chk->parse_field_name(cfmt + j + 1);
			ASSERT(j <= fmt.length());

			m_tokens.push_back(chk);

			last_nontoken_str_start = j + 1;
		}
	}
}

void sinsp_evt_formatter::tostring(sinsp_evt* evt, OUT string* res)
{
	vector<sinsp_filter_check*>::iterator it;
	res->clear();

	for(it = m_tokens.begin(); it != m_tokens.end(); ++it)
	{
		(*res) += (*it)->tostring(evt);
	}
}

#else  // HAS_FILTERING

sinsp_evt_formatter::sinsp_evt_formatter(const string& fmt)
{
}

void sinsp_evt_formatter::set_format(const string& fmt)
{
	throw sinsp_exception("sinsp_evt_formatter unvavailable because it was not compiled in the library");
}

void sinsp_evt_formatter::tostring(sinsp_evt* evt, OUT string* res)
{
	throw sinsp_exception("sinsp_evt_formatter unvavailable because it was not compiled in the library");
}
#endif // HAS_FILTERING
