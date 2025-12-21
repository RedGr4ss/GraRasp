package com.grarasp.agent;

import com.grarasp.core.plugin.IPlugin;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.LoaderClassPath;

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

        System.out.println("[GraRasp] Loading plugins via SPI...");
        for (IPlugin plugin : plugins) {
            for (String targetClass : plugin.getTargetClassNames()) {
                System.out.println("[GraRasp] >>> Registering Plugin: " + plugin.getClass().getSimpleName() + " -> " + targetClass);
                pluginMap.put(targetClass, plugin);
            }
        }
        System.out.println("[GraRasp] Plugins loaded. Total hook targets: " + pluginMap.size());
    }

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) throws IllegalClassFormatException {

        if (className == null) return null;
        String dotClassName = className.replace('/', '.');

        // [新增策略] Hook java.lang.ClassLoader (防御所有类型的类加载)
        if ("java.lang.ClassLoader".equals(dotClassName)) {
            return hookClassLoader(loader, classfileBuffer);
        }

        // 1. ProcessBuilder RCE (内置保留)
        if ("java.lang.ProcessBuilder".equals(dotClassName)) {
            return hookProcessBuilder(loader, classfileBuffer);
        }

        // 2. 插件分发
        IPlugin plugin = pluginMap.get(dotClassName);
        if (plugin != null) {
            try {
                return plugin.transform(loader, dotClassName, classfileBuffer);
            } catch (Exception e) {
                System.err.println("[GraRasp] Plugin transform failed: " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * Hook java.lang.ClassLoader.defineClass
     */
    private byte[] hookClassLoader(ClassLoader loader, byte[] classfileBuffer) {
        try {
            ClassPool cp = ClassPool.getDefault();
            // ClassLoader 是核心类，通常由 Bootstrap 加载，不需要 appendLoaderClassPath
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

            // defineClass 有多个重载，我们 Hook 核心的 protected final Class defineClass(String name, byte[] b, int off, int len)
            CtMethod m = cc.getDeclaredMethod("defineClass", new CtClass[]{
                    cp.get("java.lang.String"),
                    cp.get("byte[]"),
                    CtClass.intType,
                    CtClass.intType
            });

            // 插入检测逻辑：将当前线程栈和类字节码传给 Core 分析
            // $1 是 name, $2 是 byte[] b
            String code = "{" +
                    "   StackTraceElement[] stack = java.lang.Thread.currentThread().getStackTrace();" +
                    "   com.grarasp.spy.Spy.check(\"class_define\", $1, \"defineClass\", new Object[]{stack, $2});" +
                    "}";
            m.insertBefore(code);

            byte[] byteCode = cc.toBytecode();
            cc.detach();
            System.out.println("[GraRasp] Hook java.lang.ClassLoader success!");
            return byteCode;
        } catch (Exception e) {
            // defineClass 可能在某些 JVM 实现中是 native 的或者无法修改，这里仅做尝试
            // System.err.println("[GraRasp] Hook ClassLoader failed: " + e.getMessage());
        }
        return null;
    }

    private byte[] hookProcessBuilder(ClassLoader loader, byte[] classfileBuffer) {
        try {
            ClassPool cp = ClassPool.getDefault();
            if (loader != null) cp.appendClassPath(new LoaderClassPath(loader));
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));
            CtMethod m = cc.getDeclaredMethod("start");
            m.insertBefore("{ com.grarasp.spy.Spy.check(\"rce\", \"java.lang.ProcessBuilder\", \"start\", $args); }");
            byte[] byteCode = cc.toBytecode();
            cc.detach();
            return byteCode;
        } catch (Exception e) { e.printStackTrace(); }
        return null;
    }
}