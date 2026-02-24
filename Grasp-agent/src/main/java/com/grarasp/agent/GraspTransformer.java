package com.grarasp.agent;

import com.grarasp.core.config.RaspConfig;
import com.grarasp.core.plugin.IPlugin;
import com.grarasp.core.util.ClassPoolManager;
import com.grarasp.core.util.ErrorReporter;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtConstructor;

import java.io.ByteArrayInputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

public class GraspTransformer implements ClassFileTransformer {

    private final Map<String, IPlugin> pluginMap = new HashMap<>();

    public GraspTransformer() {
        ServiceLoader<IPlugin> plugins = ServiceLoader.load(IPlugin.class);
        for (IPlugin plugin : plugins) {
            for (String targetClass : plugin.getTargetClassNames()) {
                pluginMap.put(targetClass, plugin);
            }
        }
    }

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) throws IllegalClassFormatException {

        if (className == null) return null;
        String dotClassName = className.replace('/', '.');

        // [核心 Hook] 防御所有类加载 (内存马注入)
        if ("java.lang.ClassLoader".equals(dotClassName)) {
            return hookClassLoader(loader, classfileBuffer);
        }

        // [核心 Hook] ProcessBuilder 命令执行
        if ("java.lang.ProcessBuilder".equals(dotClassName)) {
            return hookProcessBuilder(loader, classfileBuffer);
        }

        // [核心 Hook] Runtime.exec 命令执行
        if ("java.lang.Runtime".equals(dotClassName)) {
            return hookRuntime(loader, classfileBuffer);
        }

        // [核心 Hook] JNDI 注入防护
        if ("javax.naming.InitialContext".equals(dotClassName)) {
            return hookInitialContext(loader, classfileBuffer);
        }

        // [核心 Hook] ScriptEngine 脚本执行
        if ("javax.script.AbstractScriptEngine".equals(dotClassName)) {
            return hookScriptEngine(loader, classfileBuffer);
        }

        // 插件分发
        IPlugin plugin = pluginMap.get(dotClassName);
        if (plugin != null) {
            try {
                return plugin.transform(loader, dotClassName, classfileBuffer);
            } catch (Exception e) {
                ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                    "Plugin transform failed for " + dotClassName, e);
            }
        }
        return null;
    }

    private byte[] hookClassLoader(ClassLoader loader, byte[] classfileBuffer) {
        try {
            // Note: ClassLoader is loaded by Bootstrap, loader parameter is usually null
            ClassPool cp = ClassPoolManager.getClassPool(null);
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

            // Hook 核心方法: protected final Class defineClass(String name, byte[] b, int off, int len)
            // 这是所有自定义 ClassLoader (包括 JSP 的 ClassDefiner) 最终必须调用的入口
            CtClass[] params = new CtClass[]{
                    cp.get("java.lang.String"),
                    cp.get("byte[]"),
                    CtClass.intType,
                    CtClass.intType
            };

            CtMethod m = cc.getDeclaredMethod("defineClass", params);

            // 插入检测逻辑: 将字节码 ($2) 传给 Spy
            // 使用 ISO-8859-1 解码的逻辑已在 Core 中实现，这里只负责透传
            String code = "{" +
                    "   StackTraceElement[] stack = java.lang.Thread.currentThread().getStackTrace();" +
                    "   com.grarasp.spy.Spy.check(\"class_define\", $1, \"defineClass\", new Object[]{stack, $2});" +
                    "}";

            m.insertBefore(code);

            byte[] byteCode = cc.toBytecode();
            cc.detach();
            System.out.println("[GraRasp] ✅ Hooked java.lang.ClassLoader successfully!");
            return byteCode;
        } catch (Exception e) {
            // 某些 JVM 实现可能不允许修改核心类，或者 javassist 找不到类
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Failed to hook ClassLoader", e);
        }
        return null;
    }

    private byte[] hookProcessBuilder(ClassLoader loader, byte[] classfileBuffer) {
        try {
            ClassPool cp = ClassPoolManager.getClassPool(loader);
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));
            CtMethod m = cc.getDeclaredMethod("start");
            // 传递命令列表和调用栈
            String code = "{" +
                "   StackTraceElement[] stack = Thread.currentThread().getStackTrace();" +
                "   com.grarasp.spy.Spy.check(\"rce_processbuilder\", \"java.lang.ProcessBuilder\", \"start\", new Object[]{this.command(), stack});" +
                "}";
            m.insertBefore(code);
            byte[] byteCode = cc.toBytecode();
            cc.detach();
            System.out.println("[GraRasp] ✅ Hooked java.lang.ProcessBuilder successfully!");
            return byteCode;
        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Failed to hook ProcessBuilder", e);
        }
        return null;
    }

    private byte[] hookRuntime(ClassLoader loader, byte[] classfileBuffer) {
        try {
            ClassPool cp = ClassPoolManager.getClassPool(null);
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

            // Hook 所有 exec 方法重载
            for (CtMethod m : cc.getDeclaredMethods("exec")) {
                String code = "{" +
                    "   StackTraceElement[] stack = Thread.currentThread().getStackTrace();" +
                    "   com.grarasp.spy.Spy.check(\"rce_runtime\", \"java.lang.Runtime\", \"exec\", new Object[]{$1, stack});" +
                    "}";
                m.insertBefore(code);
            }

            byte[] byteCode = cc.toBytecode();
            cc.detach();
            System.out.println("[GraRasp] ✅ Hooked java.lang.Runtime.exec() successfully!");
            return byteCode;
        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Failed to hook Runtime", e);
        }
        return null;
    }

    private byte[] hookInitialContext(ClassLoader loader, byte[] classfileBuffer) {
        try {
            ClassPool cp = ClassPoolManager.getClassPool(loader);
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

            // Hook lookup 方法
            for (CtMethod m : cc.getDeclaredMethods("lookup")) {
                String code = "{" +
                    "   StackTraceElement[] stack = Thread.currentThread().getStackTrace();" +
                    "   com.grarasp.spy.Spy.check(\"jndi_lookup\", \"javax.naming.InitialContext\", \"lookup\", new Object[]{$1, stack});" +
                    "}";
                m.insertBefore(code);
            }

            byte[] byteCode = cc.toBytecode();
            cc.detach();
            System.out.println("[GraRasp] ✅ Hooked javax.naming.InitialContext.lookup() successfully!");
            return byteCode;
        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Failed to hook InitialContext", e);
        }
        return null;
    }

    private byte[] hookScriptEngine(ClassLoader loader, byte[] classfileBuffer) {
        try {
            ClassPool cp = ClassPoolManager.getClassPool(loader);
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

            // Hook eval 方法
            for (CtMethod m : cc.getDeclaredMethods("eval")) {
                String code = "{" +
                    "   StackTraceElement[] stack = Thread.currentThread().getStackTrace();" +
                    "   com.grarasp.spy.Spy.check(\"script_eval\", \"javax.script.ScriptEngine\", \"eval\", new Object[]{$1, stack});" +
                    "}";
                m.insertBefore(code);
            }

            byte[] byteCode = cc.toBytecode();
            cc.detach();
            System.out.println("[GraRasp] ✅ Hooked javax.script.ScriptEngine.eval() successfully!");
            return byteCode;
        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Failed to hook ScriptEngine", e);
        }
        return null;
    }
}