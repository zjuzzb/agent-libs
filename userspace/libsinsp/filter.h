#pragma once

#ifdef HAS_FILTERING

bool flt_compare(ppm_cmp_operator op, ppm_param_type type, void* operand1, void* operand2);
char* flt_to_string(uint8_t* rawval, event_field_info* finfo);

enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

class operand_info
{
public:
	uint32_t m_id;
	ppm_param_type m_type;
	string m_name;
	string m_description;
};

class filter_check_info
{
public:
	string m_name;
	uint32_t m_nfiedls;
	const event_field_info* m_fields;
};

///////////////////////////////////////////////////////////////////////////////
// The filter check interface
// NOTE: in order to add a new type of filter check, you need to add a class for
//       it and then add it to new_filter_check_from_name.
///////////////////////////////////////////////////////////////////////////////
class sinsp_filter_check
{
public:
	sinsp_filter_check();
	
	virtual ~sinsp_filter_check()
	{
	}

	//
	// Used by the engine to allocate new filter checks
	//
	static sinsp_filter_check* new_filter_check_from_name(string name);

	//
	// Get the list of fields that this check exports
	//
	virtual filter_check_info* get_filelds()
	{
		return NULL;
	}

	//
	// Parse the name of the field.
	// Returns the lenght of the parsed field if successful, an exception in 
	// case of error.
	//
	virtual int32_t parse_field_name(const char* str) = 0;
	
	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field lenght because the filtering engine can calculate it.
	//
	virtual void parse_filter_value(const char* str) = 0;

	//
	// Return the info about the field that this instance contains 
	//
	virtual const event_field_info* get_field_info() = 0;

	//
	// Extract the field from the event
	//
	virtual uint8_t* extract(sinsp_evt *evt) = 0;

	//
	// Compare the field with the constant value obtained from parse_filter_value()
	//
	virtual bool compare(sinsp_evt *evt) = 0;

	void set_inspector(sinsp* inspector);

	//
	// Extract the value from the event and convert it into a string
	//
	char* tostring(sinsp_evt* evt);

	sinsp* m_inspector;
	boolop m_boolop;
	ppm_cmp_operator m_cmpop;

protected:
	char* rawval_to_string(uint8_t* rawval, const event_field_info* finfo);

	char m_getpropertystr_storage[1024];
	const event_field_info* m_field;
};

///////////////////////////////////////////////////////////////////////////////
// Filter expression class
// A filter expression contains multiple filters connected by boolean expressions,
// e.g. "check or check", "check and check and check", "not check"
///////////////////////////////////////////////////////////////////////////////
class sinsp_filter_expression : public sinsp_filter_check
{
public:
	sinsp_filter_expression();
	~sinsp_filter_expression();
	void add_check(sinsp_filter_check* chk);
	// does nothing for sinsp_filter_expression
	void parse(string expr);
	bool compare(sinsp_evt *evt);

	//
	// The following methods are part of the filter check interface but are irrelevant
	// for this class, because they are used only for the leaves of the filtering tree.
	//
	int32_t parse_field_name(const char* str)
	{
		ASSERT(false);
		return 0;
	}

	void parse_filter_value(const char* str)
	{
		ASSERT(false);
	}

	const event_field_info* get_field_info()
	{
		ASSERT(false);
		return NULL;
	}

	uint8_t* extract(sinsp_evt *evt)
	{
		ASSERT(false);
		return NULL;
	}

	sinsp_filter_expression* m_parent;
	vector<sinsp_filter_check*> m_checks;
};

///////////////////////////////////////////////////////////////////////////////
// The filter class
// This is the main class that compiles and runs filters
///////////////////////////////////////////////////////////////////////////////
class sinsp_filter
{
public:
	sinsp_filter(string fltstr, sinsp* inspector);
	bool run(sinsp_evt *evt);

private:
	enum state
	{
		ST_EXPRESSION_DONE,
		ST_NEED_EXPRESSION,
	};

	static bool isblank(char c);
	bool is_special_char(char c);
	char next();
	bool compare_no_consume(string str);

	string next_operand();
	ppm_cmp_operator next_comparison_operator();
	void parse_check(sinsp_filter_expression* parent_expr, boolop op);
	void push_expression(boolop op);
	void pop_expression();
	void parse(string fltstr);

	sinsp* m_inspector;

	string m_fltstr;
	int32_t m_scanpos;
	int32_t m_scansize;
	state m_state;
	sinsp_filter_expression* m_curexpr;
	boolop m_last_boolop;
	int32_t m_nest_level;

	sinsp_filter_expression m_filter;

	friend class sinsp_evt_formatter;
};

#endif // HAS_FILTERING
