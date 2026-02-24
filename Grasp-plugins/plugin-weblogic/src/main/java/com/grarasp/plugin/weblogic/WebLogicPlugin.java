package com.grarasp.plugin.weblogic;

import com.grarasp.core.plugin.IPlugin;
import com.grarasp.core.util.ClassPoolManager;
import com.grarasp.core.util.ErrorReporter;
import javassist.*;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

public class WebLogicPlugin implements IPlugin {

    // WebLogic 的核心上下文类
    private static final String TARGET_CONTEXT = "weblogic.servlet.internal.WebAppServletContext";

    // 另一种可能的入口 (针对旧版本或特定 Servlet 实现)
    private static final String TARGET_SERVLET_STUB = "weblogic.servlet.internal.ServletStubImpl";

    @Override
    public Collection<String> getTargetClassNames() {
        return Arrays.asList(TARGET_CONTEXT, TARGET_SERVLET_STUB);
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, byte[] classfileBuffer) throws Exception {
        ClassPool cp = ClassPoolManager.getClassPool(loader);
        CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

        if (TARGET_CONTEXT.equals(className)) {
            // 1. Hook 内存马注入 (Filter)
            hookMethod(cc, "registerFilter", "memshell_filter", "WebAppServletContext");

            // 2. Hook 内存马注入 (Servlet)
            hookMethod(cc, "registerServlet", "memshell_servlet", "WebAppServletContext");

            // 3. Hook Context 启动 (用于巡检注册)
            hookContextStart(cc);
        }

        byte[] byteCode = cc.toBytecode();
        cc.detach();
        return byteCode;
    }

    /**
     * 通用 Hook 方法
     */
    private void hookMethod(CtClass cc, String methodName, String checkType, String targetName) {
        try {
            CtMethod[] methods = cc.getDeclaredMethods(methodName);
            for (CtMethod m : methods) {
                // $0 是当前对象 (this), $args 是参数
                m.insertBefore("{ com.grarasp.spy.Spy.check(\"" + checkType + "\", \"" + targetName + "\", \"" + methodName + "\", new Object[]{$0}); }");
            }
            System.out.println("[WebLogicPlugin] Hook " + methodName + " success!");
        } catch (NotFoundException e) {
            // Method may not exist (version differences), ignore
        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Failed to hook " + methodName + " in " + targetName, e);
        }
    }

    /**
     * 捕获 WebLogic Context 启动，注册到 Core 以便巡检
     */
    private void hookContextStart(CtClass cc) {
        try {
            CtMethod m = cc.getDeclaredMethod("start");
            m.insertAfter("{ com.grarasp.spy.Spy.check(\"context_start\", \"WebAppServletContext\", \"start\", new Object[]{$0}); }");
            System.out.println("[WebLogicPlugin] Hook start (Context Registration) success!");
        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Hook start failed in WebAppServletContext", e);
        }
    }
}