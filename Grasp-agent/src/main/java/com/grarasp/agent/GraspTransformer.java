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
        // ... (保持原有的插件加载逻辑) ...
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

        // ... (ProcessBuilder Hook) ...
        if ("java.lang.ProcessBuilder".equals(dotClassName)) {
            return hookProcessBuilder(loader, classfileBuffer);
        }

        // 插件分发
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

    private byte[] hookClassLoader(ClassLoader loader, byte[] classfileBuffer) {
        try {
            // 注意: ClassLoader 是由 Bootstrap 加载的，loader 参数通常为 null
            ClassPool cp = ClassPool.getDefault();
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
            System.err.println("[GraRasp] ❌ Failed to hook ClassLoader: " + e.getMessage());
            // e.printStackTrace(); // 调试时可打开
        }
        return null;
    }

    // ... hookProcessBuilder 保持不变 ...
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
        } catch (Exception e) { }
        return null;
    }
}