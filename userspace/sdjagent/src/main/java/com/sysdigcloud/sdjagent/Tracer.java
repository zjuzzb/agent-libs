package com.sysdigcloud.sdjagent;

import java.util.Arrays;
import java.util.ArrayList;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.io.IOException;
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
    Null or empty tag will be replaced by default one.

    @param tag Tag of a tracer.
    **/
    public Tracer(String tag)
    {
	if (tag == null || tag.isEmpty())
	{
	    err.println("Empty tag not allowed, setting it to default.");
	    this.tag = new String("default");
	}
	else
	    this.tag = new String(tag);
    }


    /**
    Spans a child tag.
    Null or empty tag will be replaced by default one.

    @param tag Tag of a child.
    @return    Child tracer.
    **/
    public Tracer span(String tag)
    {
	if (tag == null || tag.isEmpty())
	{
	    err.println("Empty tag not allowed, setting it to default.");
	    return new Tracer(this.tag + TAG_SEPARATOR + "default");
	}
	
	String childTag = this.tag + TAG_SEPARATOR + tag;
	return new Tracer(childTag);
    }

    
    /**
    Emits an entry tracer.

    @param args Tracer arguments.
    **/
    public void enter(ArrayList<NameValue> args)
    {
	try
	{
	    StringBuilder entryTrace = new StringBuilder();
	    entryTrace.append(ENTRY_EVENT_SYMBOL).append(FIELD_SEPARATOR).append(THREAD_ID).append(FIELD_SEPARATOR).append(this.tag).
		append(FIELD_SEPARATOR).append(formatArguments(args));
	    this.nullFile.println(entryTrace);
	}
	catch (Exception exc)
	{
	    err.println("Emitting entry event caused an exception: " + exc);
	}
    }

    
    /**
    Emits an exit tracer.

    @param args Tracer arguments.
    **/
    public void exit(ArrayList<NameValue> args)
    {
	try
	{
	    StringBuilder exitTrace = new StringBuilder();
	    exitTrace.append(EXIT_EVENT_SYMBOL).append(FIELD_SEPARATOR).append(THREAD_ID).append(FIELD_SEPARATOR).append(this.tag).append(FIELD_SEPARATOR).
		append(formatArguments(args));
	    this.nullFile.println(exitTrace);
	}
	catch (Exception exc)
	{
	    err.println("Emitting entry event caused an exception: " + exc);
	}
    }

    
    /**
    Formats arguments in sysdig format.
    Empty argument list is allowed.

    @param args Arguments to format.
    @return     String representation of arguments.
    **/
    private String formatArguments(ArrayList<NameValue> args)
    {
	if (args == null || args.isEmpty())
	    return new String(Character.toString(FIELD_SEPARATOR));
	
	StringBuilder argsStr = new StringBuilder();
	for (NameValue elem : args)
	    argsStr.append(elem.toString() + ARGS_SEPARATOR);
	int argsStrLen = argsStr.length();
	argsStr.setCharAt(argsStrLen - 1, FIELD_SEPARATOR);
	return argsStr.toString();
    }

    
    /**
    Null device used by sysdig for tracing.
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
    Null file used by sysdig for tracing.
    **/
    private static PrintWriter nullFile;

    
    /**
    Tracer id.
    **/
    private String id;

    
    /**
    Tracer tag.
    **/
    private String tag;
   
    
    /**
    Test method of the class.
    **/
    public static void main(String args[]) throws IOException
    {
	{
	    Tracer t1 = new Tracer("mytag");
	    t1.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("hello", "world"), new NameValue("zdravo", "svete"))));
	    out.println("Hello, World!");
	    t1.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("status", "successful"))));

	    Tracer t2 = new Tracer("yourtag");
	    t2.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("yabadaba", "doo"))));
	    out.println("Flintstones!");
	    t2.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("result", "-1"), new NameValue("status", "error"))));
	}
	{
	    Tracer parent = new Tracer("parenttag");
	    parent.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("hello", "world"), new NameValue("zdravo", "svete"))));
	    out.println("Hello, World!");
	    
	    Tracer child1 = parent.span("child1tag");
	    child1.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("yabadaba", "doo"))));
	    out.println("Flintstones!");
	    child1.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("result", "-1"), new NameValue("status", "error"))));

	    Tracer child2 = parent.span("child2tag");
	    child2.enter(null);
	    out.println("Go go go!");

	    Tracer grandChild = child2.span("grandchildtag");
	    grandChild.enter(new ArrayList<NameValue>(Arrays.asList(new NameValue("lol", "rofl"))));
	    out.println("wtf!");
	    grandChild.exit(new ArrayList<NameValue>());
	    
	    child2.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("wow", "yeah"))));
	    parent.exit(new ArrayList<NameValue>(Arrays.asList(new NameValue("status", "successful"))));
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
