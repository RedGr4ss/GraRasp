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
            // [升级逻辑] 遍历插件定义的所有目标类
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

        // 1. ProcessBuilder RCE (内置保留)
        if ("java.lang.ProcessBuilder".equals(dotClassName)) {
            return hookProcessBuilder(loader, classfileBuffer);
        }

        // 2. 插件分发
        IPlugin plugin = pluginMap.get(dotClassName);
        if (plugin != null) {
            try {
                // 注意：我们传入了 className，方便插件内部判断当前处理的是哪个类
                return plugin.transform(loader, dotClassName, classfileBuffer);
            } catch (Exception e) {
                System.err.println("[GraRasp] Plugin transform failed: " + e.getMessage());
            }
        }
        return null;
    }

    // ... hookProcessBuilder 方法保持不变 ...
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