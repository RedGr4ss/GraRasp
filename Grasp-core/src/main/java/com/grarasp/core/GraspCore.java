package com.grarasp.core;

import com.grarasp.spy.Spy;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/**
 * [生产环境版] 核心检测逻辑
 * 包含：显式API检测、类加载检测、运行时对象创建检测、后台内存扫描 (Filter/Listener/Valve)
 */
public class GraspCore implements Spy.SpyHandler {

    private static final boolean BLOCK_MODE = true;

    // 白名单 Filter/Valve/Listener (仅作示例，生产环境需根据业务调整)
    private static final Set<String> COMPONENT_WHITELIST = new HashSet<>(Arrays.asList(
            "Tomcat WebSocket (JSR356) Filter",
            "ServletRequest Context Filter",
            "WsFilter",
            "org.apache.catalina.valves.ErrorReportValve",
            "org.apache.catalina.valves.AccessLogValve",
            "org.apache.catalina.core.StandardContext$ContextFilterMaps", // 内部类
            "org.apache.catalina.core.StandardWrapper",
            "org.springframework.web.context.ContextLoaderListener"
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
                    e.printStackTrace();
                }
            }
        }, "GraRasp-Scanner");
        scanner.setDaemon(true);
        scanner.start();
        System.out.println("[GraRasp] Memory Shell Scanner started (Filter/Listener/Valve).");
    }

    @Override
    public void handleCheck(String type, String className, String method, Object[] params) {
        if (type == null) return;

        try {
            if (type.startsWith("memshell")) {
                checkMemoryShellState(type, params);
            } else if ("class_define".equals(type)) {
                checkClassDefine(params);
            } else if ("config_create".equals(type) || "wrapper_create".equals(type)) {
                checkRuntimeCreation(type, params);
            } else if ("rce".equals(type)) {
                // checkRce(params);
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            // 忽略业务异常
        }
    }

    /**
     * [策略一] 检测类加载
     * 针对 MemshellParty 生成的各类内存马进行特征识别
     */
    private void checkClassDefine(Object[] params) {
        if (params == null || params.length < 2) return;
        StackTraceElement[] stack = (StackTraceElement[]) params[0];
        byte[] bytecode = (byte[]) params[1];

        boolean isJsp = false;
        boolean isDeserialization = false;

        for (StackTraceElement element : stack) {
            String cls = element.getClassName();
            String mtd = element.getMethodName();

            if (cls.contains("org.apache.jasper.servlet.JspServlet")) {
                isJsp = true;
            }
            if ("readObject".equals(mtd) && "java.io.ObjectInputStream".equals(cls)) {
                isDeserialization = true;
            }
            if ("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl".equals(cls)) {
                isDeserialization = true;
            }
        }

        // 字节码特征匹配：增加 Listener 和 Valve 的接口特征
        String classContent = new String(bytecode);
        boolean isWebComponent = classContent.contains("javax/servlet/Filter") ||
                classContent.contains("javax/servlet/Servlet") ||
                classContent.contains("jakarta/servlet/Filter") ||
                // MemshellParty 常用接口
                classContent.contains("javax/servlet/ServletRequestListener") ||
                classContent.contains("jakarta/servlet/ServletRequestListener") ||
                classContent.contains("org/apache/catalina/Valve");

        if (isWebComponent) {
            if (isJsp) {
                alertAndBlock("Suspicious JSP defining WebComponent", "JSP DefineClass");
            }
            if (isDeserialization) {
                alertAndBlock("Deserialization loading WebComponent", "Deserialization RCE");
            }
        }
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
     * [策略三] 后台巡检逻辑 (全覆盖升级版)
     */
    private static void scanMemoryShells() {
        Set<Object> contexts = findAllStandardContexts();

        for (Object ctx : contexts) {
            try {
                // 1. 扫描 Filters
                scanFilters(ctx);

                // 2. 扫描 Listeners (新增)
                scanListeners(ctx);

                // 3. 扫描 Valves (新增)
                scanValves(ctx);

            } catch (Exception e) {
                // e.printStackTrace();
            }
        }
    }

    // --- 扫描 Filter ---
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

    // --- [新增] 扫描 Listeners ---
    // 针对 MemshellParty Listener 内存马
    private static void scanListeners(Object ctx) {
        try {
            // 获取 applicationEventListenersList (这是一个 List<Object>)
            Object listenersList = getMethodValueObj(ctx, "getApplicationEventListeners");
            if (listenersList == null) {
                // 如果通过 getter 拿不到，尝试反射字段 (Tomcat 不同版本字段名可能不同)
                listenersList = getFieldValue(ctx, "applicationEventListenersList");
            }

            if (listenersList instanceof Object[]) {
                // 某些版本可能是数组
                for (Object listener : (Object[]) listenersList) {
                    checkListenerObject(listener);
                }
            } else if (listenersList instanceof Iterable) {
                // 常见情况是 ArrayList
                for (Object listener : (Iterable<?>) listenersList) {
                    checkListenerObject(listener);
                }
            }
        } catch (Exception e) {}
    }

    private static void checkListenerObject(Object listener) {
        if (listener == null) return;
        String className = listener.getClass().getName();

        // 白名单检查
        if (className.startsWith("org.apache.catalina") ||
                className.startsWith("org.springframework")) { // ⚠️注意: MemshellParty 可能会伪造包名
            // 进阶检查: 检查类加载器
            if (isSuspiciousClassLoader(listener.getClass())) {
                System.err.println("[GraRasp Scanner] 🚨 Found Memory Listener (Spoofed Package): " + className);
                // 这里可以执行移除逻辑: List.remove(listener)
            }
            return;
        }

        checkSuspiciousClass("Listener", "Unknown", className);
    }

    // --- [新增] 扫描 Valves ---
    // 针对 ProxyValve
    private static void scanValves(Object ctx) {
        try {
            // 获取 Pipeline
            Object pipeline = getMethodValueObj(ctx, "getPipeline");
            if (pipeline != null) {
                // 获取 Valves 数组
                Object valves = getMethodValueObj(pipeline, "getValves");
                if (valves != null && valves.getClass().isArray()) {
                    int len = Array.getLength(valves);
                    for (int i = 0; i < len; i++) {
                        Object valve = Array.get(valves, i);
                        if (valve == null) continue;

                        String className = valve.getClass().getName();
                        if (!COMPONENT_WHITELIST.contains(className) && !className.startsWith("org.apache.catalina.valves")) {
                            // 同样检查类加载器
                            if (isSuspiciousClassLoader(valve.getClass()) || className.contains("Proxy") || className.contains("$$")) {
                                System.err.println("[GraRasp Scanner] 🚨 Found Memory Valve: " + className);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {}
    }

    // --- 通用检测逻辑 ---

    private static void checkSuspiciousClass(String type, String name, String className) {
        if (className != null && (className.contains("$$") || className.contains("Proxy") || className.contains("Malicious") || className.contains("shell"))) {
            System.err.println("[GraRasp Scanner] 🚨 Found Memory " + type + ": " + name + " (" + className + ")");
        }
    }

    // 核心判断：类加载器是否可疑
    // 内存马通常由自定义的 ClassLoader 加载，或者通过 defineClass 临时加载（ClassLoader 为 null 或 匿名）
    private static boolean isSuspiciousClassLoader(Class<?> clazz) {
        ClassLoader cl = clazz.getClassLoader();
        if (cl == null) return false; // Bootstrap ClassLoader (JDK核心类) 通常安全

        String clName = cl.getClass().getName();
        // 正常的业务类应该由 ParallelWebappClassLoader 加载
        if (clName.contains("ParallelWebappClassLoader") || clName.contains("AppClassLoader")) {
            return false;
        }

        // 如果是 URLClassLoader (且不是 Tomcat 的)，或者完全匿名的 ClassLoader，则非常可疑
        // MemshellParty 有时会用 TransletClassLoader 或 自定义 Loader
        return true;
    }

    // ----------------- 辅助方法 -----------------

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
        } catch (Exception e) {
            return "UNKNOWN";
        }
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

    private static Set<Object> findAllStandardContexts() {
        Set<Object> contexts = new HashSet<>();
        try {
            Thread[] threads = new Thread[Thread.activeCount() + 100];
            int count = Thread.enumerate(threads);
            for (int i = 0; i < count; i++) {
                Thread t = threads[i];
                if (t == null) continue;
                ClassLoader cl = t.getContextClassLoader();
                if (cl != null && cl.getClass().getName().contains("WebappClassLoader")) {
                    Object resources = getMethodValueObj(cl, "getResources");
                    if (resources != null) {
                        Object context = getMethodValueObj(resources, "getContext");
                        if (context != null && context.getClass().getName().endsWith("StandardContext")) {
                            contexts.add(context);
                        }
                    }
                }
            }
        } catch (Throwable e) {}
        return contexts;
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