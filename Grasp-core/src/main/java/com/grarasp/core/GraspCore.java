package com.grarasp.core;

import com.grarasp.spy.Spy;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * [生产环境版] 核心检测逻辑 - 终极修正版 (v1.0.2)
 * 修复：字节码编码问题、关键字匹配格式问题、List/Array 混合清除
 */
public class GraspCore implements Spy.SpyHandler {

    private static final boolean BLOCK_MODE = true;

    // 主动维护的活跃 Context 集合
    private static final Set<Object> activeContexts = new CopyOnWriteArraySet<>();

    // 白名单组件
    private static final Set<String> COMPONENT_WHITELIST = new HashSet<>(Arrays.asList(
            "Tomcat WebSocket (JSR356) Filter",
            "ServletRequest Context Filter",
            "WsFilter",
            "org.apache.catalina.valves.ErrorReportValve",
            "org.apache.catalina.valves.AccessLogValve",
            "org.apache.catalina.core.StandardContextValve",
            "org.apache.catalina.authenticator.NonLoginAuthenticator",
            "org.apache.catalina.authenticator.BasicAuthenticator",
            "org.apache.catalina.authenticator.SSLAuthenticator",
            "org.apache.catalina.core.StandardContext$ContextFilterMaps",
            "org.apache.catalina.core.StandardWrapper",
            "org.springframework.web.context.ContextLoaderListener",
            "org.springframework.web.util.IntrospectorCleanupListener"
    ));

    public static void init() {
        Spy.spyHandler = new GraspCore();
        System.out.println("[GraRasp] Core initialized. Protection Online.");

        // 启动后台巡检线程 (30秒一次)
        Thread scanner = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(30000);
                    scanMemoryShells();
                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    System.err.println("[GraRasp Scanner] Main Loop Error: " + e.getMessage());
                }
            }
        }, "GraRasp-Scanner");
        scanner.setDaemon(true);
        scanner.start();
        System.out.println("[GraRasp] Memory Shell Scanner started (Auto-Removal Enabled).");
    }

    public static void registerContext(Object context) {
        if (context != null) {
            activeContexts.add(context);
        }
    }

    @Override
    public void handleCheck(String type, String className, String method, Object[] params) {
        if (type == null) return;

        try {
            if ("context_start".equals(type)) {
                if (params != null && params.length > 0) registerContext(params[0]);
                return;
            }

            if (type.startsWith("memshell")) {
                checkMemoryShellState(type, params);
            } else if ("class_define".equals(type)) {
                checkClassDefine(params);
            } else if ("config_create".equals(type) || "wrapper_create".equals(type)) {
                checkRuntimeCreation(type, params);
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            // 忽略业务异常
        }
    }

    /**
     * [策略一] 检测类加载 - 终极增强版 (覆盖各类反序列化)
     */
    private void checkClassDefine(Object[] params) {
        if (params == null || params.length < 2) return;
        StackTraceElement[] stack = (StackTraceElement[]) params[0];
        byte[] bytecode = (byte[]) params[1];

        String classContent = new String(bytecode, StandardCharsets.ISO_8859_1);

        // --- 1. 深度来源分析 (扩充反序列化指纹) ---
        boolean isSuspiciousSource = false;
        for (StackTraceElement element : stack) {
            String cls = element.getClassName();

            // [新增] 覆盖主流反序列化/表达式注入框架
            if (
                // 1. 原生反序列化 & JSP
                    cls.contains("org.apache.jasper") ||
                            cls.contains("java.io.ObjectInputStream") ||
                            cls.contains("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl") ||

                            // 2. JSON/XML 反序列化 (Fastjson, Jackson, XStream)
                            cls.contains("com.alibaba.fastjson") ||
                            cls.contains("com.fasterxml.jackson") ||
                            cls.contains("com.thoughtworks.xstream") ||

                            // 3. YAML 反序列化 (SnakeYAML)
                            cls.contains("org.yaml.snakeyaml") ||

                            // 4. 表达式注入 (OGNL, SpEL, MVEL) - Struts2, Spring RCE 常见入口
                            cls.contains("ognl.Ognl") ||
                            cls.contains("org.springframework.expression.spel") ||
                            cls.contains("org.mvel2") ||

                            // 5. 常见 Webshell 管理工具特征 (冰蝎/哥斯拉/Behinder 部分 Payload 会用到这些类)
                            cls.contains("net.rebeyond.behinder") ||
                            cls.contains("com.metasploit")
            ) {
                isSuspiciousSource = true;
                break;
            }
        }

        // --- 2. [基础] 接口特征匹配 (WebShell) ---
        boolean isWebComponent = containsKeyword(classContent, "javax.servlet.Filter", "javax/servlet/Filter") ||
                containsKeyword(classContent, "javax.servlet.Servlet", "javax/servlet/Servlet") ||
                containsKeyword(classContent, "ServletRequestListener", "ServletRequestListener") ||
                containsKeyword(classContent, "org.apache.catalina.Valve", "org/apache/catalina/Valve");

        if (isWebComponent && isSuspiciousSource) {
            alertAndBlock("Suspicious WebComponent from Untrusted Source", "WebShell Bytecode");
        }

        // --- 3. [进阶] 注入器行为检测 (Zero-Trust) ---
        boolean hasHackerTools = containsKeyword(classContent, "sun.misc.Unsafe", "sun/misc/Unsafe") ||
                classContent.contains("setAccessible") ||
                classContent.contains("java/lang/reflect/Field");

        boolean targetsTomcat = containsKeyword(classContent, "org.apache.catalina", "org/apache/catalina") ||
                containsKeyword(classContent, "StandardContext", "StandardContext") ||
                containsKeyword(classContent, "ApplicationContext", "ApplicationContext");

        // 规则A (增强版): 只要是 可疑来源 (JSP/Fastjson/Jackson/...) 触发的 Unsafe -> 杀
        // 这能防住那些没有直接引用 Tomcat 类，但试图做内存操作的通用型恶意载荷
        if (isSuspiciousSource && hasHackerTools) {
            alertAndBlock("Suspicious Unsafe/Reflection from Untrusted Source", "Memory Shell Injector");
        }

        // 规则B: 任意来源 + Unsafe + Tomcat -> 杀 (兜底策略，防漏报)
        if (hasHackerTools && targetsTomcat) {
            boolean isWhitelisted = classContent.contains("org/springframework") ||
                    classContent.contains("org/apache/tomcat") ||
                    classContent.contains("org/apache/catalina") ||
                    classContent.contains("org/apache/coyote") ||
                    classContent.contains("org/apache/dubbo"); // 补充常见框架

            if (!isWhitelisted) {
                alertAndBlock("Malicious Injector Detected (Unsafe + Tomcat)", "Memory Shell Injector");
            }
        }
    }
    // 辅助方法：多关键字匹配
    private boolean containsKeyword(String content, String... keywords) {
        for (String k : keywords) {
            if (content.contains(k)) return true;
        }
        return false;
    }

    /**
     * [策略二] 检测运行时对象创建
     */
    private void checkRuntimeCreation(String type, Object[] params) {
        if (params.length > 0 && params[0] != null) {
            Object context = params[0];
            if (context.getClass().getName().endsWith("StandardContext")) {
                String state = getMethodValue(context, "getState");
                if ("STARTED".equalsIgnoreCase(state)) {
                    alertAndBlock("Runtime creation of " + type + " in STARTED state", "Reflective Registration");
                }
            }
        }
    }

    private void checkMemoryShellState(String type, Object[] params) {
        if (params.length < 2) return;
        Object target = params[0];
        if (type.contains("websocket")) {
            target = extractStandardContextFromWs(target);
        }
        if (target != null) {
            String state = getMethodValue(target, "getState");
            if ("STARTED".equalsIgnoreCase(state)) {
                alertAndBlock("Runtime API call: " + type, "Standard API Abuse");
            }
        }
    }

    /**
     * [策略三] 后台巡检逻辑
     */
    private static void scanMemoryShells() {
        if (activeContexts.isEmpty()) return;

        for (Object ctx : activeContexts) {
            try {
                scanFilters(ctx);
                scanListeners(ctx); // 支持数组清除
                scanValves(ctx);
            } catch (Exception e) {
                System.err.println("[GraRasp Scanner] Scan Context Failed: " + e.getMessage());
            }
        }
    }

    private static void scanFilters(Object ctx) {
        try {
            Object filterMaps = getFieldValue(ctx, "filterMaps");
            if (filterMaps != null && filterMaps.getClass().getName().endsWith("ContextFilterMaps")) {
                filterMaps = getFieldValue(filterMaps, "array");
            }
            if (filterMaps != null && filterMaps.getClass().isArray()) {
                int len = Array.getLength(filterMaps);
                for (int i = 0; i < len; i++) {
                    Object map = Array.get(filterMaps, i);
                    if (map == null) continue;
                    String filterName = (String) getMethodValue(map, "getFilterName");
                    if (filterName != null && !COMPONENT_WHITELIST.contains(filterName)) {
                        Object filterDef = findFilterDef(ctx, filterName);
                        if (filterDef != null) {
                            String filterClass = (String) getMethodValue(filterDef, "getFilterClass");
                            checkSuspiciousClass("Filter", filterName, filterClass);
                        }
                    }
                }
            }
        } catch (Exception e) {}
    }

    // --- 扫描 Listeners (支持数组覆盖移除) ---
    private static void scanListeners(Object ctx) {
        try {
            Object listenersObj = getMethodValueObj(ctx, "getApplicationEventListeners");
            if (listenersObj == null) {
                listenersObj = getFieldValue(ctx, "applicationEventListenersList");
            }
            if (listenersObj == null) return;

            List<Object> safeListeners = new ArrayList<>();
            boolean foundMalicious = false;

            if (listenersObj instanceof Object[]) {
                for (Object obj : (Object[]) listenersObj) {
                    if (checkListenerObject(obj)) foundMalicious = true;
                    else safeListeners.add(obj);
                }
            } else if (listenersObj instanceof Collection) {
                for (Object obj : (Collection<?>) listenersObj) {
                    if (checkListenerObject(obj)) foundMalicious = true;
                    else safeListeners.add(obj);
                }
            }

            if (foundMalicious) {
                Object[] newListenersArray = safeListeners.toArray();
                Method setMethod = ctx.getClass().getMethod("setApplicationEventListeners", Object[].class);
                setMethod.setAccessible(true);
                setMethod.invoke(ctx, new Object[]{newListenersArray});
                System.err.println("[GraRasp Scanner] 🛡️ KILL: Malicious Listeners removed! Context reloaded.");
            }

        } catch (Exception e) {
            // System.err.println("[GraRasp Scanner] Scan Listeners Error: " + e.getMessage());
        }
    }

    private static boolean checkListenerObject(Object listener) {
        if (listener == null) return false;
        String className = listener.getClass().getName();

        if (className.startsWith("org.apache.catalina") ||
                className.startsWith("org.springframework") ||
                className.startsWith("com.grarasp")) {
            if (isSuspiciousClassLoader(listener.getClass())) {
                System.err.println("[GraRasp Scanner] 🚨 Found Memory Listener (Spoofed Package): " + className);
                return true;
            }
            return false;
        }

        System.err.println("[GraRasp Scanner] 🚨 Found Memory Listener: " + className);
        return true;
    }

    private static void scanValves(Object ctx) {
        try {
            Object pipeline = getMethodValueObj(ctx, "getPipeline");
            if (pipeline != null) {
                Object valves = getMethodValueObj(pipeline, "getValves");
                if (valves != null && valves.getClass().isArray()) {
                    int len = Array.getLength(valves);
                    for (int i = 0; i < len; i++) {
                        Object valve = Array.get(valves, i);
                        if (valve == null) continue;
                        String className = valve.getClass().getName();

                        boolean isSafe = COMPONENT_WHITELIST.contains(className) ||
                                className.startsWith("org.apache.catalina.valves") ||
                                className.startsWith("org.apache.catalina.core") ||
                                className.startsWith("org.apache.catalina.authenticator");

                        if (!isSafe) {
                            if (isSuspiciousClassLoader(valve.getClass()) || className.contains("Proxy") || className.contains("$$")) {
                                System.err.println("[GraRasp Scanner] 🚨 Found Memory Valve: " + className);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {}
    }

    private static void checkSuspiciousClass(String type, String name, String className) {
        if (className != null && (className.contains("$$") || className.contains("Proxy") || className.contains("Malicious") || className.contains("shell"))) {
            System.err.println("[GraRasp Scanner] 🚨 Found Memory " + type + ": " + name + " (" + className + ")");
        }
    }

    private static boolean isSuspiciousClassLoader(Class<?> clazz) {
        ClassLoader cl = clazz.getClassLoader();
        if (cl == null) return false;
        String clName = cl.getClass().getName();
        if (clName.contains("ParallelWebappClassLoader") || clName.contains("AppClassLoader")) {
            return false;
        }
        return true;
    }

    private void alertAndBlock(String msg, String type) {
        System.err.println("========================================");
        System.err.println("[GraRasp Security Alert] 🚨 " + msg);
        System.err.println("Type:    " + type);
        System.err.println("Action:  Blocked");
        System.err.println("========================================");
        if (BLOCK_MODE) {
            throw new SecurityException("GraRasp Blocked: " + msg);
        }
    }

    private static String getMethodValue(Object target, String methodName) {
        try {
            Method m = target.getClass().getMethod(methodName);
            m.setAccessible(true);
            return String.valueOf(m.invoke(target));
        } catch (Exception e) { return "UNKNOWN"; }
    }

    private static Object getMethodValueObj(Object target, String methodName) {
        try {
            Method m = target.getClass().getMethod(methodName);
            m.setAccessible(true);
            return m.invoke(target);
        } catch (Exception e) { return null; }
    }

    private static Object getFieldValue(Object target, String fieldName) {
        if (target == null) return null;
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Field f = clazz.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            } catch (Exception e) { return null; }
        }
        return null;
    }

    private static Object findFilterDef(Object ctx, String filterName) {
        try {
            Map filterDefs = (Map) getFieldValue(ctx, "filterDefs");
            if (filterDefs != null) return filterDefs.get(filterName);
        } catch (Exception e) {}
        return null;
    }

    private Object extractStandardContextFromWs(Object wsContainer) {
        try {
            Object facade = getFieldValue(wsContainer, "servletContext");
            if (facade == null) return null;
            Object appContext = getFieldValue(facade, "context");
            if (appContext == null) return null;
            return getFieldValue(appContext, "context");
        } catch (Exception e) { return null; }
    }
}