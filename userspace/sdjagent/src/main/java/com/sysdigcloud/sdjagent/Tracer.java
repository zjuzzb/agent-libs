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

    public void run(String id, String tag, List<NameValue> args, FunctionObject function, Object... functionArgs) throws Exception
    {
	try
	{
	    checkIdFormat(id);
	    emit(id, tag, args, function, functionArgs);
	}
	catch (Exception exc)
	{
	    throw new Exception("Application reported an exception. Error message: " + exc.toString());
	}
    }

    

    private void emit(String id, String tag, List<NameValue> args, FunctionObject function, Object... functionArgs) throws Exception
    {
	String entryTrace = ENTRY_EVENT_SYMBOL + FIELD_SEPARATOR + id + FIELD_SEPARATOR + tag + FIELD_SEPARATOR + formatArguments(args);
	this.nullFile.println(entryTrace);
	function.call(functionArgs);
	String exitTrace = EXIT_EVENT_SYMBOL + FIELD_SEPARATOR + id + FIELD_SEPARATOR + tag + FIELD_SEPARATOR + formatArguments(args);
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
	return args.stream().map(NameValue::toString).collect(Collectors.joining(this.ARGS_SEPARATOR)) + this.FIELD_SEPARATOR;
    }
    
    private static final String NULL_FILE_PATH = "/dev/null";

    private static final String ENTRY_EVENT_SYMBOL = ">";

    private static final String EXIT_EVENT_SYMBOL = "<";

    private static final String FIELD_SEPARATOR = ":";
    
    private static final String ARGS_SEPARATOR = ",";

    private static final String THREAD_ID = "t";

    private static final String PROCESS_ID = "p";

    private static final String PARENT_PID = "pp";
    
    private PrintWriter nullFile;
    
    public static void main(String args[]) 
    {
	try
	{
	    Tracer trc = new Tracer();

	    List<NameValue> argList1 = Arrays.asList(new NameValue("hello", "world"), new NameValue("yabadaba", "doo"));
	    trc.run("t", "mytag", argList1,
	        (Object... objs) ->
		{
		    out.println("objs0=" + objs[0]);
		},
		"hello");
	    
	    List<NameValue> argList2 = Arrays.asList(new NameValue("zdravo", "svete"), new NameValue("opa", "bato"), new NameValue("jabadaba", "du"));
	    trc.run("p", "yourtag", argList2,
	        (Object... objs) ->
		{
		    out.println("Sleeping for " + (int)objs[0] + " seconds.");
		    Thread.sleep((int)(objs[0]) * 1000);
		},
		10);
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
