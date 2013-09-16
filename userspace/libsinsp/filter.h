#pragma once

enum boolop
{
	BO_NONE = 0,
	BO_NOT = 1,
	BO_OR = 2,
	BO_AND = 4,
	BO_ORNOT = 3,
	BO_ANDNOT = 5,
};

enum cmpop
{
	CO_NONE = 0,
	CO_EQ = 1,
	CO_NE = 2,
	CO_LT = 3,
	CO_LE = 4,
	CO_GT = 5,
	CO_GE = 6,
	CO_CONTAINS = 7,
};

//
// The filter check interface
//
class sinsp_filter_check
{
public:
	sinsp_filter_check();
	virtual void parse_operand1(string val)
	{
		return;
	}
	virtual void parse_operand2(string val)
	{
		return;
	}
	virtual bool run(sinsp_evt *evt) = 0;

	boolop m_boolop;
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
// tid check
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
// A filter expression, e.g. "check or check", "check and check and check", "not check"
//
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

//
// The filter class
//
class sinsp_filter
{
public:
	sinsp_filter(string fltstr);
	bool run(sinsp_evt *evt);

private:
	enum state
	{
		ST_READY_FOR_EXPRESSION,
		ST_INBRACKETS,
		ST_PARSING_CHECK,
		ST_PARSING_EXPRESSION,
	};

	bool isblank(char c);
	bool is_special_char(char c);
	char next();
	bool compare_no_consume(string str);

	string next_operand();
	cmpop next_comparison_operator();
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

	sinsp_filter_expression m_filter;
};