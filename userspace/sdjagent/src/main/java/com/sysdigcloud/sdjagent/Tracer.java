package com.sysdigcloud.sdjagent;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.stream.Collectors;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import static java.lang.System.out;
import static java.lang.System.err;


/**
Simple library for emitting sysdig tracers.

@author Tomislav Karastojkovic <tomislav@sysdig.com>
**/
public class Tracer
{
    /**
    Sets tracer parameters.

    @param id   ID of a tracer.
    @param tag  Tag of a tracer.
    @param args Arguments of a tracer.
    **/
    public Tracer(String id, String tag, ArrayList<NameValue> args)
    {
	this.id = new String(id);
	this.tag = new StringBuilder(tag);
	if (!checkIdFormat())
	{
	    err.println("Invalid id format, setting to process id.");
	    this.id = "p";
	}
	this.args = new ArrayList(args);
	this.tracer = null;
    }

    
    /**
    Copy constructor.

    @param other Tracer to be copied.
    **/
    public Tracer(Tracer other)
    {
	this.id = new String(other.id);
	this.tag = new StringBuilder(other.tag);
	this.args = new ArrayList(other.args);
	this.tracer = other.tracer;
	this.functionObj = other.functionObj;
    }

    
    /**
    Sets a function to be traced.

    @param functionObj Function to be traced.
    **/
    public void span(FunctionObject functionObj)
    {
	this.functionObj = functionObj;
    }


    /**
    Sets a function to be traced and a tracer to be nested.

    @param tracer      Tracer to be nested.
    @param functionObj Function to be traced.
    **/
    public void span(Tracer tracer, FunctionObject functionObj)
    {
	this.tracer = new Tracer(tracer);
	this.functionObj = functionObj;
    }


    /**
    Starts tracing of a previously set function. 
    **/
    public void run()
    {
	try
	{
	    enter();
	    if (this.tracer != null)
	    {
		this.tracer.tag.insert(0, TAG_SEPARATOR).insert(0, this.tag);
		this.tracer.run();
		this.functionObj.call();
	    }
	    else
	    {
		this.functionObj.call();
	    }
	    exit();
	}
	catch (Exception exc)
	{
	    err.println("Running tracing caused an exception: " + exc);
	}
    }

    
    /**
    Emits an entry tracer.
    **/
    public void enter()
    {
	try
	{
	    StringBuilder entryTrace = new StringBuilder();
	    entryTrace.append(ENTRY_EVENT_SYMBOL).append(FIELD_SEPARATOR).append(this.id).append(FIELD_SEPARATOR).append(this.tag).
		append(FIELD_SEPARATOR).append(formatArguments());
	    this.nullFile.println(entryTrace);
	}
	catch (Exception exc)
	{
	    err.println("Emitting entry event caused an exception: " + exc);
	}
    }

    
    /**
    Emits an exit tracer.
    **/
    public void exit()
    {
	try
	{
	    StringBuilder exitTrace = new StringBuilder();
	    exitTrace.append(EXIT_EVENT_SYMBOL).append(FIELD_SEPARATOR).append(this.id).append(FIELD_SEPARATOR).append(this.tag).append(FIELD_SEPARATOR).
		append(formatArguments());
	    this.nullFile.println(exitTrace);
	}
	catch (Exception exc)
	{
	    err.println("Emitting entry event caused an exception: " + exc);
	}
    }


    /**
    Verifies if trace id is in the valid format.

    @return True if format is valid, false if not.
    **/
    private boolean checkIdFormat()
    {
	if (this.id.compareTo(THREAD_ID) == 0 || this.id.compareTo(PROCESS_ID) == 0 || this.id.compareTo(PARENT_PID) == 0)
	    return true;
	
	try
	{
	    Long.parseLong(this.id);
	    return true;
	}
	catch (NumberFormatException exc)
	{
	}
	
	return false;
    }

    
    /**
    Formats arguments in Sysdig format.

    @return String representation of arguments.
    **/
    private String formatArguments()
    {
	StringBuilder argsStr = new StringBuilder();
	for (NameValue elem : this.args)
	    argsStr.append(elem.toString() + ARGS_SEPARATOR);
	int argsStrLen = argsStr.length();
	argsStr.setCharAt(argsStrLen - 1, FIELD_SEPARATOR);
	return argsStr.toString();
    }

    
    /**
    Null device used by Sysdig for tracing.
    **/
    private static final String NULL_FILE_PATH = "/dev/null";

    
    /**
    Entry event symbol for the direction field.
    **/
    private static final Character ENTRY_EVENT_SYMBOL = '>';

    
    /**
    Exit event symbol for the direction field.
    **/
    private static final Character EXIT_EVENT_SYMBOL = '<';

    
    /**
    Separator of tracer fields.
    **/
    private static final Character FIELD_SEPARATOR = ':';

    
    /**
    Separator of tracer tags.
    **/
    private static final Character TAG_SEPARATOR = '.';

    
    /**
    Separator of tracer arguments.
    **/
    private static final Character ARGS_SEPARATOR = ',';

    
    /**
    Tracer id symbol when thread id used.
    **/
    private static final String THREAD_ID = "t";

    
    /**
    Tracer id symbol when process id used.
    **/
    private static final String PROCESS_ID = "p";

    
    /**
    Tracer id symbol when parent process id used.
    **/
    private static final String PARENT_PID = "pp";


    static
    {
	try
	{
	    nullFile = new PrintWriter(new FileOutputStream(NULL_FILE_PATH), true);
	}
	catch (IOException exc)
	{
	}
    }

    
    /**
    Null file used by Sysdig for tracing.
    **/
    private static PrintWriter nullFile;

    
    /**
    Tracer id.
    **/
    private String id;

    
    /**
    Tracer tag.
    **/
    private StringBuilder tag;

    
    /**
    Tracer arguments.
    **/
    ArrayList<NameValue> args;

    
    /**
    Function object to be traced.
    **/
    FunctionObject functionObj;

    
    /**
    Tracer to be nested as child tracer.
    **/
    Tracer tracer;

    
    /**
    Test method of the class.
    **/
    public static void main(String args[]) throws IOException
    {	
	{
            // running tracers
	    
	    ArrayList<NameValue> argList1 = new ArrayList<NameValue>(Arrays.asList(new NameValue("hello", "world"), new NameValue("yabadaba", "doo")));
	    Tracer trc1 = new Tracer("t", "mytag", argList1);
	    trc1.span(new FunctionObject("hello")
		{
		    @Override
		    public void call()
		    {
			out.println("args[0]=" + (String)(this.args[0]));
		    }
		});

	    
	    trc1.run();

	    
	    ArrayList<NameValue> argList2 = new ArrayList<NameValue>(Arrays.asList(new NameValue("zdravo", "svete"), new NameValue("opa", "bato"),
	        new NameValue("jabadaba", "du")));
	    Tracer trc2 = new Tracer("p", "yourtag", argList2);
	    trc2.span(new FunctionObject(10)
		{
		    @Override
		    public void call()
		    {
			try
			{
			    out.println("Sleeping for " + (Integer)args[0] + " seconds.");
			    Thread.sleep((Integer)(args[0]) * 1000);
			}
			catch (InterruptedException exc)
			{
			    out.println("Function call caused an exception: " + exc);
			}
		    }
		});
	    trc2.run();  
	}
	

	{
	    // runnning nested tracers
	    
	    try
	    {

		
		ArrayList<NameValue> argList1 = new ArrayList<NameValue>(Arrays.asList(new NameValue("hello", "world"), new NameValue("yabadaba", "doo")));
		Tracer trc1 = new Tracer("t", "parenttag", argList1);
		ArrayList<NameValue> argList2 = new ArrayList<NameValue>(Arrays.asList(new NameValue("zdravo", "svete"), new NameValue("opa", "bato"),
		    new NameValue("jabadaba", "du")));
		Tracer trc2 = new Tracer("p", "childtag", argList2);
		ArrayList<NameValue> argList3 = new ArrayList<NameValue>(Arrays.asList(new NameValue("salut", "le monde")));
		Tracer trc3 = new Tracer("pp", "grandchildtag", argList3);

		trc3.span(new FunctionObject("zdravo", "svete")
		    {
			@Override
			public void call()
			{
			    out.println("args[0]=" + (String)this.args[0] + ", args[1]=" + (String)this.args[1]);
			}
		    });
		
		trc2.span(trc3, new FunctionObject(10)
		    {
			@Override
			public void call()
			{
			    try
			    {
				out.println("Sleeping for " + (Integer)args[0] + " seconds.");
				Thread.sleep((Integer)(args[0]) * 1000);
			    }
			    catch (InterruptedException exc)
			    {
				out.println("Function call caused an exception: " + exc);
			    }
			}
		    });

		trc1.span(trc2, new FunctionObject("hello")
		{
		    @Override
		    public void call()
		    {
			out.println("args[0]=" + (String)(this.args[0]));
		    }
		});
		trc1.run();
	    }
	    catch (Exception exc)
	    {
		out.println("Application reported an exception. Error message: " + exc.toString());
	    }	     
	}
    }
}


/**
Tracer arguments name/value implementation.
**/
class NameValue
{
    /**
    Sets name and value components of an object.

    @param name  Name part of the pair.
    @param value Value part of the pair.
    **/
    public NameValue(String name, String value)
    {
	this.name = name;
	this.value = value;
    }

    
    /**
    Calculates hash code of an object.

    @return Hash code of an object.
    **/
    public int hashCode()
    {
	int nameHash = (this.name != null ? this.name.hashCode() : 0);
	int valueHash = (this.value != null ? this.value.hashCode() : 0);
	return (nameHash + valueHash) * valueHash + nameHash;
    }

    
    /**
    Comparator of two instances of the class.

    @param other Object to compare against.
    @return      True if equal, false if not.
    **/
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

    
    /**
    String representation as required by Sysdig.

    @return String representation of an object.
    **/
    public String toString()
    {
	return this.name + "=" + this.value;
    }

    
    /**
    Stores name of the pair.
    **/
    public String name;

    
    /**
    Stores value of the pair.
    **/
    public String value;
}


/**
Functional interface to be used for defining functions to be traced.
**/
abstract class FunctionObject
{
    /**
    Copy constructor.

    @param other Function to be copied together with its arguments.
    **/
    public FunctionObject(FunctionObject other)
    {
	this(other.args);
    }

    /**
    Constructor using function arguments.

    @param args Function arguments to be used when the function object is called.
    **/
    public FunctionObject(Object... args)
    {
	this.args = new Object[args.length];
	System.arraycopy(args, 0, this.args, 0, args.length);
    }
    
    /**
    Function to be implemented and traced, can use arguments set by the constructor.
    **/
    public abstract void call();

    /**
    Function arguments to be used when called.
    **/
    public Object[] args;
}
