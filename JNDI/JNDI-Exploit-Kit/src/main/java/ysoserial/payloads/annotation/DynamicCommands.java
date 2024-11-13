package ysoserial.payloads.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedElement;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface DynamicCommands {
    String NONE = "";
    String EXEC_GLOBAL = "exec_global";
    String EXEC_WIN = "exec_win";
    String EXEC_UNIX = "exec_unix";
    String JAVA_REVERSE_SHELL = "java_reverse_shell";
    String SLEEP = "sleep";
    String DNS = "dns";

    String[] value() default {};

    public static class Utils {
        public static String[] getDynamicCommands(AnnotatedElement annotated) {
            DynamicCommands dinamicCommands = annotated.getAnnotation(DynamicCommands.class);
            if (dinamicCommands != null && dinamicCommands.value() != null) {
                return dinamicCommands.value();
            } else {
                return new String[0];
            }
        }
    }
}