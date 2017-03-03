package com.sysdigcloud.sdjagent;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import static java.lang.System.out;


public class Tracer
{
    public Tracer() throws IOException
    {
	this.nullFile = new PrintWriter(new FileOutputStream(NULL_FILE_PATH), true);
    }

    
    public void run(String id, String tag, List<NameValue> args, FunctionObject functionObj, Object... functionArgs) throws Exception
    {
	try
	{
	    checkIdFormat(id);
	    emit(id, tag, args, functionObj, functionArgs);
	}
	catch (Exception exc)
	{
	    throw new Exception("Application reported an exception. Error message: " + exc.toString());
	}
    }


    private void emit(String id, String tag, List<NameValue> args, FunctionObject functionObj, Object... functionArgs) throws Exception
    {
	StringBuilder entryTrace = new StringBuilder();
	entryTrace.append(ENTRY_EVENT_SYMBOL).append(FIELD_SEPARATOR).append(id).append(FIELD_SEPARATOR).append(tag).append(FIELD_SEPARATOR).append(formatArguments(args));
	this.nullFile.println(entryTrace);
	functionObj.call(functionArgs);
	StringBuilder exitTrace = new StringBuilder();
	exitTrace.append(EXIT_EVENT_SYMBOL).append(FIELD_SEPARATOR).append(id).append(FIELD_SEPARATOR).append(tag).append(FIELD_SEPARATOR).append(formatArguments(args));
	this.nullFile.println(exitTrace);
    }

    private void checkIdFormat(String id) throws IdFormatException
    {
	if (id.compareTo(THREAD_ID) == 0 || id.compareTo(PROCESS_ID) == 0 || id.compareTo(PARENT_PID) == 0)
	    return;
	
	try
	{
	    Long.parseLong(id);
	    return;
	}
	catch (NumberFormatException exc)
	{
	    throw new IdFormatException("Invalid ID format.");
	}
    }

    private String formatArguments(List<NameValue> args)
    {
	StringBuilder argsStr = new StringBuilder();
	for (NameValue elem : args)
	    argsStr.append(elem.toString() + ARGS_SEPARATOR);
	int argsStrLen = argsStr.length();
	argsStr.setCharAt(argsStrLen - 1, FIELD_SEPARATOR);
	return argsStr.toString();
    }
    
    private static final String NULL_FILE_PATH = "/dev/null";

    private static final Character ENTRY_EVENT_SYMBOL = '>';

    private static final Character EXIT_EVENT_SYMBOL = '<';

    private static final Character FIELD_SEPARATOR = ':';
    
    private static final Character ARGS_SEPARATOR = ',';

    private static final String THREAD_ID = "t";

    private static final String PROCESS_ID = "p";

    private static final String PARENT_PID = "pp";
    
    private static PrintWriter nullFile;
    
    public static void main(String args[]) 
    {
	try
	{
	    Tracer trc = new Tracer();

	    {
		List<NameValue> argList1 = Arrays.asList(new NameValue("hello", "world"), new NameValue("yabadaba", "doo"));
		trc.run("t", "mytag", argList1,
		    new FunctionObject()
		    {
			@Override
			public void call(Object... args)
			{
			    out.println("objs0=" + args[0]);
			}
		    },
		    "hello");

	    List<NameValue> argList2 = Arrays.asList(new NameValue("zdravo", "svete"), new NameValue("opa", "bato"), new NameValue("jabadaba", "du"));
	    trc.run("p", "yourtag", argList2,
		new FunctionObject()
		{
		    @Override
		    public void call(Object... args) throws InterruptedException
		    {
			out.println("Sleeping for " + (Integer)args[0] + " seconds.");
			Thread.sleep((Integer)(args[0]) * 1000);
		    }
		},
		10);
	    }
	}
	catch (Exception exc)
	{
	    out.println("Application reported an exception: " + exc);
	}	
    }
}


class NameValue
{
    public NameValue(String name, String value)
    {
	this.name = name;
	this.value = value;
    }

    public int hashCode()
    {
	int nameHash = (this.name != null ? this.name.hashCode() : 0);
	int valueHash = (this.value != null ? this.value.hashCode() : 0);
	return (nameHash + valueHash) * valueHash + nameHash;
    }

    public boolean equals(Object other)
    {
	if (other instanceof NameValue)
	{
	    NameValue otherObj = (NameValue)other;
	    return ((this.name == otherObj.name || (this.name != null && otherObj.name != null && this.name.equals(otherObj.name))) &&
		(this.value == otherObj.value || (this.value != null && otherObj.value != null && this.value.equals(otherObj.value))));
        }
	return false;
    }

    public String toString()
    {
	return this.name + "=" + this.value;
    }

    public String name;

    public String value;
}



@FunctionalInterface
interface FunctionObject
{
    void call(Object... args) throws Exception;
}



class IdFormatException extends Exception
{
    public IdFormatException()
    {
	super();
    }

    public IdFormatException(String message)
    {
	super(message);
    }

    public IdFormatException(Throwable cause)
    {
	super(cause);
    }
}
