#pragma once

#ifdef HAS_FILTERING
enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

///////////////////////////////////////////////////////////////////////////////
// Filter check classes
///////////////////////////////////////////////////////////////////////////////

//
// The filter check interface
// NOTE: in order to add a new type of filter check, you need to add a class for
//       it and then add it to sinsp_filter::parse_check.
//
class sinsp_filter_check
{
public:
	sinsp_filter_check();
	virtual ~sinsp_filter_check()
	{
	}

	virtual void parse_operand1(string val)
	{
		return;
	}
	virtual void parse_operand2(string val)
	{
		return;
	}
	virtual bool run(sinsp_evt *evt) = 0;

	bool compare(ppm_cmp_operator op, ppm_param_type type, void* operand1, void* operand2);

	boolop m_boolop;
	ppm_cmp_operator m_cmpop;
};

//
// comm check
//
class sinsp_filter_check_comm : public sinsp_filter_check
{
public:
	void parse_operand2(string val);
	bool run(sinsp_evt *evt);
	static bool recognize_operand(string operand);

	string m_comm;
};

//
// numeric tid check
//
class sinsp_filter_check_tid : public sinsp_filter_check
{
public:
	void parse_operand2(string val);
	bool run(sinsp_evt *evt);
	static bool recognize_operand(string operand);

	int64_t m_tid;
};

//
// fd name check
//
class sinsp_filter_check_fdname : public sinsp_filter_check
{
public:
	void parse_operand2(string val);
	bool run(sinsp_evt *evt);
	static bool recognize_operand(string operand);

	string m_fdname;
};

//
// numeric fd check
//
class sinsp_filter_check_fd : public sinsp_filter_check
{
public:
	void parse_operand2(string val);
	bool run(sinsp_evt *evt);
	static bool recognize_operand(string operand);

	int64_t m_fd;
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
	bool run(sinsp_evt *evt);

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
	sinsp_filter(string fltstr);
	bool run(sinsp_evt *evt);

private:
	enum state
	{
		ST_EXPRESSION_DONE,
		ST_NEED_EXPRESSION,
	};

	bool isblank(char c);
	bool is_special_char(char c);
	char next();
	bool compare_no_consume(string str);

	string next_operand();
	ppm_cmp_operator next_comparison_operator();
	void parse_check(sinsp_filter_expression* parent_expr, boolop op);
	void push_expression(boolop op);
	void pop_expression();
	void parse(string fltstr);

	string m_fltstr;
	int32_t m_scanpos;
	int32_t m_scansize;
	state m_state;
	sinsp_filter_expression* m_curexpr;
	boolop m_last_boolop;
	int32_t m_nest_level;

	sinsp_filter_expression m_filter;
};

#endif // HAS_FILTERING
