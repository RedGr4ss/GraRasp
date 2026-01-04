package com.grarasp.plugin.tomcat;

import com.grarasp.core.plugin.IPlugin;
import javassist.*;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

public class TomcatPlugin implements IPlugin {

    private static final String TARGET_CONTEXT = "org.apache.catalina.core.StandardContext";
    private static final String TARGET_PIPELINE = "org.apache.catalina.core.StandardPipeline";
    private static final String TARGET_WEBSOCKET = "org.apache.tomcat.websocket.server.WsServerContainer";
    private static final String TARGET_FILTER_CONFIG = "org.apache.catalina.core.ApplicationFilterConfig";
    private static final String TARGET_WRAPPER = "org.apache.catalina.core.StandardWrapper";

    @Override
    public Collection<String> getTargetClassNames() {
        return Arrays.asList(
                TARGET_CONTEXT, TARGET_PIPELINE, TARGET_WEBSOCKET,
                TARGET_FILTER_CONFIG, TARGET_WRAPPER
        );
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, byte[] classfileBuffer) throws Exception {
        ClassPool cp = ClassPool.getDefault();
        if (loader != null) cp.appendClassPath(new LoaderClassPath(loader));
        CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

        if (TARGET_CONTEXT.equals(className)) {
            hookStandardContext(cc);
            // [核心] Hook 启动流程，主动注册 Context
            hookContextStart(cc);
        } else if (TARGET_PIPELINE.equals(className)) {
            hookStandardPipeline(cc);
        } else if (TARGET_WEBSOCKET.equals(className)) {
            hookWsServerContainer(cc, cp);
        }
        else if (TARGET_FILTER_CONFIG.equals(className)) {
            hookConstructor(cc, "config_create", "ApplicationFilterConfig");
        } else if (TARGET_WRAPPER.equals(className)) {
            hookConstructor(cc, "wrapper_create", "StandardWrapper");
        }

        byte[] byteCode = cc.toBytecode();
        cc.detach();
        return byteCode;
    }

    /**
     * [新增] Hook StandardContext.startInternal
     * 作用：当 Context 启动时，主动将其注册到 GraspCore
     */
    private void hookContextStart(CtClass cc) {
        try {
            CtMethod m = cc.getDeclaredMethod("startInternal");
            // 调用 Spy 发送事件，携带当前 Context 对象 ($0)
            m.insertAfter("{ com.grarasp.spy.Spy.check(\"context_start\", \"StandardContext\", \"startInternal\", new Object[]{$0}); }");
            System.out.println("[TomcatPlugin] Hook startInternal success!");
        } catch (Exception e) {
            System.err.println("[TomcatPlugin] Hook startInternal failed: " + e.getMessage());
        }
    }

    private void hookStandardContext(CtClass cc) {
        try {
            insertSpy(cc, "addFilterDef", "memshell_filter", "StandardContext");
            insertSpy(cc, "addChild", "memshell_servlet", "StandardContext");
            insertSpy(cc, "addApplicationEventListener", "memshell_listener", "StandardContext");
        } catch (Exception e) {}
    }

    private void hookStandardPipeline(CtClass cc) {
        try {
            insertSpy(cc, "addValve", "memshell_valve", "StandardPipeline");
        } catch (Exception e) {}
    }

    private void hookWsServerContainer(CtClass cc, ClassPool cp) {
        try {
            CtClass paramClass = null;
            String endpointConfigClass = "javax.websocket.server.ServerEndpointConfig";
            try {
                paramClass = cp.get(endpointConfigClass);
            } catch (NotFoundException e) {
                try {
                    endpointConfigClass = "jakarta.websocket.server.ServerEndpointConfig";
                    paramClass = cp.get(endpointConfigClass);
                } catch (NotFoundException ex) {
                    return; // 依赖缺失，跳过
                }
            }
            CtMethod m = cc.getDeclaredMethod("addEndpoint", new CtClass[]{paramClass});
            m.insertBefore("{ com.grarasp.spy.Spy.check(\"memshell_websocket\", \"WsServerContainer\", \"addEndpoint\", new Object[]{$0, $1}); }");
            System.out.println("[TomcatPlugin] Hook WsServerContainer success!");
        } catch (Exception e) {
            System.err.println("[TomcatPlugin] Hook WebSocket failed: " + e.getMessage());
        }
    }

    private void hookConstructor(CtClass cc, String checkType, String targetName) {
        try {
            CtConstructor[] constructors = cc.getConstructors();
            for (CtConstructor c : constructors) {
                c.insertBefore("{ com.grarasp.spy.Spy.check(\"" + checkType + "\", \"" + targetName + "\", \"<init>\", $args); }");
            }
            System.out.println("[TomcatPlugin] Hook Constructor success: " + targetName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void insertSpy(CtClass cc, String methodName, String checkType, String targetName) {
        try {
            CtMethod m = cc.getDeclaredMethod(methodName);
            m.insertBefore("{ com.grarasp.spy.Spy.check(\"" + checkType + "\", \"" + targetName + "\", \"" + methodName + "\", new Object[]{$0, $1}); }");
        } catch (Exception e) {}
    }
}