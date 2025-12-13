package com.grarasp.plugin.tomcat;

import com.grarasp.core.plugin.IPlugin;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.LoaderClassPath;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

public class TomcatPlugin implements IPlugin {

    private static final String TARGET_CONTEXT = "org.apache.catalina.core.StandardContext";
    private static final String TARGET_PIPELINE = "org.apache.catalina.core.StandardPipeline";
    // [新增] WebSocket 容器类
    private static final String TARGET_WEBSOCKET = "org.apache.tomcat.websocket.server.WsServerContainer";

    @Override
    public Collection<String> getTargetClassNames() {
        return Arrays.asList(TARGET_CONTEXT, TARGET_PIPELINE, TARGET_WEBSOCKET);
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, byte[] classfileBuffer) throws Exception {
        // System.out.println("[TomcatPlugin] Processing: " + className); // 调试时可开启

        ClassPool cp = ClassPool.getDefault();
        if (loader != null) cp.appendClassPath(new LoaderClassPath(loader));
        CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

        if (TARGET_CONTEXT.equals(className)) {
            hookStandardContext(cc);
        } else if (TARGET_PIPELINE.equals(className)) {
            hookStandardPipeline(cc);
        } else if (TARGET_WEBSOCKET.equals(className)) {
            // [新增] 处理 WebSocket
            hookWsServerContainer(cc);
        }

        byte[] byteCode = cc.toBytecode();
        cc.detach();
        return byteCode;
    }

    private void hookStandardContext(CtClass cc) {
        try {
            cc.getDeclaredMethod("addFilterDef").insertBefore("{ com.grarasp.spy.Spy.check(\"memshell_filter\", \"StandardContext\", \"addFilterDef\", new Object[]{$0, $1}); }");
            cc.getDeclaredMethod("addChild").insertBefore("{ com.grarasp.spy.Spy.check(\"memshell_servlet\", \"StandardContext\", \"addChild\", new Object[]{$0, $1}); }");
            cc.getDeclaredMethod("addApplicationEventListener").insertBefore("{ com.grarasp.spy.Spy.check(\"memshell_listener\", \"StandardContext\", \"addApplicationEventListener\", new Object[]{$0, $1}); }");
        } catch (Exception e) {}
    }

    private void hookStandardPipeline(CtClass cc) {
        try {
            cc.getDeclaredMethod("addValve").insertBefore("{ com.grarasp.spy.Spy.check(\"memshell_valve\", \"StandardPipeline\", \"addValve\", new Object[]{$0, $1}); }");
        } catch (Exception e) {}
    }

    // [新增] Hook WebSocket 注册
    private void hookWsServerContainer(CtClass cc) {
        try {
            // public void addEndpoint(ServerEndpointConfig sec)
            CtMethod m = cc.getDeclaredMethod("addEndpoint", new CtClass[]{cp.get("javax.websocket.server.ServerEndpointConfig")});
            m.insertBefore("{ com.grarasp.spy.Spy.check(\"memshell_websocket\", \"WsServerContainer\", \"addEndpoint\", new Object[]{$0, $1}); }");
            System.out.println("[TomcatPlugin] Hook WsServerContainer.addEndpoint success!");
        } catch (Exception e) {
            System.err.println("[TomcatPlugin] Hook WebSocket failed: " + e.getMessage());
        }
    }

    // 辅助获取 ClassPool (如果之前定义在外面，这里不需要重复)
    private ClassPool cp = ClassPool.getDefault();
}