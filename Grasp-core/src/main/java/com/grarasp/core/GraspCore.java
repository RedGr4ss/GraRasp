package com.grarasp.core;

import com.grarasp.core.config.RaspConfig;
import com.grarasp.core.detector.CommandDetector;
import com.grarasp.core.detector.JndiDetector;
import com.grarasp.core.detector.SpelDetector;
import com.grarasp.core.util.ErrorReporter;
import com.grarasp.core.util.ReflectionCache;
import com.grarasp.spy.Spy;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * [生产环境版] 核心检测逻辑 - v1.5.0
 * 新增特性：
 * 1. 配置外部化支持
 * 2. SpEL 增强检测（Unicode/空格绕过）
 * 3. Runtime.exec / JNDI / ScriptEngine Hook
 * 4. 命令执行检测器
 * 5. 增强巡检：风险评分、自动清除、WebLogic 全组件扫描
 * 6. 增量扫描优化
 */
public class GraspCore implements Spy.SpyHandler {

    private static volatile Thread scannerThread;
    private static final AtomicBoolean running = new AtomicBoolean(false);

    // 主动维护的活跃 Context 集合
    private static final Set<Object> activeContexts = new CopyOnWriteArraySet<>();

    // 已扫描组件缓存（增量扫描优化）
    private static final Map<String, Long> scannedComponents = new ConcurrentHashMap<>();

    // 检测到的可疑组件
    private static final Map<String, SuspiciousComponent> suspiciousComponents = new ConcurrentHashMap<>();

    // 扫描统计
    private static final AtomicLong scanCount = new AtomicLong(0);
    private static final AtomicLong detectionCount = new AtomicLong(0);
    private static final AtomicLong cleanCount = new AtomicLong(0);

    // 风险评分阈值
    private static final int RISK_THRESHOLD_WARN = 30;
    private static final int RISK_THRESHOLD_BLOCK = 60;
    private static final int RISK_THRESHOLD_CLEAN = 80;

    public static void init() {
        // 加载配置
        RaspConfig config = RaspConfig.getInstance();

        Spy.spyHandler = new GraspCore();
        System.out.println("[GraRasp] Core initialized v1.5.0. Protection Online.");
        System.out.println("[GraRasp] Block mode: " + config.isBlockMode());

        // 启动后台巡检线程
        if (config.isScanEnabled()) {
            running.set(true);
            scannerThread = new Thread(() -> {
                int interval = config.getScanInterval();
                while (running.get()) {
                    try {
                        Thread.sleep(interval);
                        if (running.get()) {
                            scanMemoryShells();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    } catch (Exception e) {
                        ErrorReporter.reportError(ErrorReporter.ErrorType.SCANNER,
                            "Scanner main loop error", e);
                    }
                }
            }, "GraRasp-Scanner");
            scannerThread.setDaemon(true);
            scannerThread.start();
            System.out.println("[GraRasp] Enhanced Memory Shell Scanner started (interval: " + config.getScanInterval() + "ms)");
        } else {
            System.out.println("[GraRasp] Memory Shell Scanner disabled by config");
        }

        // 注册关闭钩子
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            shutdown();
        }, "GraRasp-Shutdown"));
    }

    /**
     * 优雅关闭扫描器
     */
    public static void shutdown() {
        System.out.println("[GraRasp] Shutting down scanner...");
        running.set(false);
        if (scannerThread != null) {
            scannerThread.interrupt();
            try {
                scannerThread.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        ReflectionCache.clearAll();
        System.out.println("[GraRasp] Shutdown complete. Stats: scans=" + scanCount.get() +
            ", detections=" + detectionCount.get() + ", cleaned=" + cleanCount.get());
    }

    /**
     * 获取扫描统计信息
     */
    public static Map<String, Long> getStats() {
        Map<String, Long> stats = new HashMap<>();
        stats.put("scanCount", scanCount.get());
        stats.put("detectionCount", detectionCount.get());
        stats.put("cleanCount", cleanCount.get());
        stats.put("activeContexts", (long) activeContexts.size());
        stats.put("suspiciousComponents", (long) suspiciousComponents.size());
        return stats;
    }

    /**
     * 获取可疑组件列表
     */
    public static Map<String, SuspiciousComponent> getSuspiciousComponents() {
        return Collections.unmodifiableMap(suspiciousComponents);
    }

    public static void registerContext(Object context) {
        if (context != null) {
            activeContexts.add(context);
        }
    }

    @Override
    public void handleCheck(String type, String className, String method, Object[] params) {
        if (type == null) return;

        RaspConfig config = RaspConfig.getInstance();

        try {
            // 1. Context 注册事件
            if ("context_start".equals(type)) {
                if (params != null && params.length > 0) registerContext(params[0]);
                return;
            }

            // 2. Spring SpEL 注入检测（增强版）
            if ("rce_spel".equals(type)) {
                checkSpEL(params);
                return;
            }

            // 3. Runtime.exec 命令执行检测
            if ("rce_runtime".equals(type)) {
                checkRuntimeExec(params);
                return;
            }

            // 4. ProcessBuilder 命令执行检测
            if ("rce_processbuilder".equals(type)) {
                checkProcessBuilder(params);
                return;
            }

            // 5. JNDI 注入检测
            if ("jndi_lookup".equals(type)) {
                checkJndiLookup(params);
                return;
            }

            // 6. ScriptEngine 脚本执行检测
            if ("script_eval".equals(type)) {
                checkScriptEval(params);
                return;
            }

            // 7. 内存马与类加载检测
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
            ErrorReporter.reportError(ErrorReporter.ErrorType.DETECTION,
                "Detection check failed for type: " + type, e);
        }
    }

    // --- SpEL 检测逻辑（增强版）---
    private void checkSpEL(Object[] params) {
        if (params == null || params.length < 1 || params[0] == null) return;
        String expression = (String) params[0];

        // 使用增强版 SpEL 检测器
        String result = SpelDetector.detect(expression);
        if (result != null) {
            alertAndBlock("SpEL Injection: " + result, "SpEL Injection RCE");
        }
    }

    // --- Runtime.exec 检测逻辑 ---
    private void checkRuntimeExec(Object[] params) {
        if (params == null || params.length < 1) return;

        Object command = params[0];
        StackTraceElement[] stack = params.length > 1 ? (StackTraceElement[]) params[1] : null;

        // 检测命令内容
        String result = CommandDetector.detect(command);
        if (result != null) {
            alertAndBlock("Runtime.exec: " + result, "Command Execution");
        }

        // 检测可疑调用来源
        if (stack != null && CommandDetector.isSuspiciousSource(stack)) {
            alertAndBlock("Runtime.exec from suspicious source", "Command Execution from Untrusted Source");
        }
    }

    // --- ProcessBuilder 检测逻辑 ---
    private void checkProcessBuilder(Object[] params) {
        if (params == null || params.length < 1) return;

        Object command = params[0];
        StackTraceElement[] stack = params.length > 1 ? (StackTraceElement[]) params[1] : null;

        // 检测命令内容
        String result = CommandDetector.detect(command);
        if (result != null) {
            alertAndBlock("ProcessBuilder: " + result, "Command Execution");
        }

        // 检测可疑调用来源
        if (stack != null && CommandDetector.isSuspiciousSource(stack)) {
            alertAndBlock("ProcessBuilder from suspicious source", "Command Execution from Untrusted Source");
        }
    }

    // --- JNDI 注入检测逻辑 ---
    private void checkJndiLookup(Object[] params) {
        if (params == null || params.length < 1) return;

        String name = params[0] != null ? params[0].toString() : null;
        StackTraceElement[] stack = params.length > 1 ? (StackTraceElement[]) params[1] : null;

        // 检测 JNDI 名称
        String result = JndiDetector.detect(name);
        if (result != null) {
            alertAndBlock("JNDI Lookup: " + result, "JNDI Injection");
        }

        // 检测可疑调用来源
        if (stack != null && JndiDetector.isSuspiciousSource(stack)) {
            // 对于可疑来源，即使是看起来正常的 JNDI 名称也要警告
            if (name != null && (name.contains("://") || name.contains("${"))) {
                alertAndBlock("JNDI Lookup from suspicious source: " + name, "JNDI Injection from Untrusted Source");
            }
        }
    }

    // --- ScriptEngine 检测逻辑 ---
    private void checkScriptEval(Object[] params) {
        if (params == null || params.length < 1) return;

        Object script = params[0];
        StackTraceElement[] stack = params.length > 1 ? (StackTraceElement[]) params[1] : null;

        String scriptStr = script != null ? script.toString() : "";

        // 检测危险脚本内容
        if (scriptStr.contains("Runtime") ||
            scriptStr.contains("ProcessBuilder") ||
            scriptStr.contains("exec(") ||
            scriptStr.contains("java.lang.") ||
            scriptStr.contains("getClass()")) {
            alertAndBlock("Dangerous script execution: " + truncate(scriptStr, 100), "Script Injection");
        }

        // 检测可疑调用来源
        if (stack != null && CommandDetector.isSuspiciousSource(stack)) {
            alertAndBlock("ScriptEngine.eval from suspicious source", "Script Execution from Untrusted Source");
        }
    }

    private String truncate(String str, int maxLen) {
        if (str == null) return null;
        if (str.length() <= maxLen) return str;
        return str.substring(0, maxLen) + "...";
    }

    // --- 类加载检测逻辑 (含 WebLogic T3 反序列化防御) ---
    private void checkClassDefine(Object[] params) {
        if (params == null || params.length < 2) return;

        RaspConfig config = RaspConfig.getInstance();
        if (!config.isClassLoaderHookEnabled()) return;

        StackTraceElement[] stack = (StackTraceElement[]) params[0];
        byte[] bytecode = (byte[]) params[1];

        String classContent = new String(bytecode, StandardCharsets.ISO_8859_1);

        // 1. 深度来源分析
        boolean isSuspiciousSource = false;
        for (StackTraceElement element : stack) {
            String cls = element.getClassName();
            if (
                    cls.contains("org.apache.jasper") ||
                            cls.contains("java.io.ObjectInputStream") ||
                            cls.contains("weblogic.rjvm") ||
                            cls.contains("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl") ||
                            cls.contains("com.alibaba.fastjson") ||
                            cls.contains("com.fasterxml.jackson") ||
                            cls.contains("ognl.Ognl") ||
                            cls.contains("org.springframework.expression.spel") ||
                            cls.contains("net.rebeyond.behinder") ||
                            cls.contains("com.metasploit")
            ) {
                isSuspiciousSource = true;
                break;
            }
        }

        // 2. 注入器行为检测
        boolean hasHackerTools = containsKeyword(classContent, "sun.misc.Unsafe", "sun/misc/Unsafe") ||
                classContent.contains("setAccessible");

        boolean targetsMiddleware = containsKeyword(classContent, "org.apache.catalina", "org/apache/catalina", "StandardContext") ||
                containsKeyword(classContent, "weblogic.servlet", "WebAppServletContext");

        // 规则A: 可疑来源 + Unsafe -> 拦截
        if (isSuspiciousSource && hasHackerTools) {
            alertAndBlock("Suspicious Unsafe/Reflection from Untrusted Source", "Memory Shell Injector");
        }

        // 规则B: 任意来源 + Unsafe + 中间件核心类 -> 拦截
        if (hasHackerTools && targetsMiddleware) {
            if (!config.isClassWhitelisted(classContent)) {
                alertAndBlock("Malicious Injector Detected (Unsafe + Middleware)", "Memory Shell Injector");
            }
        }
    }

    private boolean containsKeyword(String content, String... keywords) {
        for (String k : keywords) {
            if (content.contains(k)) return true;
        }
        return false;
    }

    // --- 运行时创建检测 ---
    private void checkRuntimeCreation(String type, Object[] params) {
        // 简单针对 Tomcat，WebLogic 此处略过，主要靠 checkMemoryShellState
        if (params.length > 0 && params[0] != null) {
            Object context = params[0];
            if (context.getClass().getName().endsWith("StandardContext")) {
                String state = ReflectionCache.invokeMethodAsString(context, "getState");
                if ("STARTED".equalsIgnoreCase(state)) {
                    alertAndBlock("Runtime creation of " + type + " in STARTED state", "Reflective Registration");
                }
            }
        }
    }

    private void checkMemoryShellState(String type, Object[] params) {
        if (params.length < 1) return;
        Object target = params[0];
        String targetClassName = target.getClass().getName();

        // WebSocket 内存马检测 (WsServerContainer.addEndpoint)
        if (type.equals("memshell_websocket") || targetClassName.contains("WsServerContainer")) {
            // WebSocket Endpoint 运行时注入，直接拦截
            // 正常的 WebSocket Endpoint 应该在应用启动时通过注解或 web.xml 注册
            // 运行时通过 JSP/反序列化等方式注入的都是恶意的
            StackTraceElement[] stack = params.length > 2 ? (StackTraceElement[]) params[2] : null;
            String endpointPath = extractWebSocketPath(params.length > 1 ? params[1] : null);
            String endpointClassName = extractWebSocketClassName(params.length > 1 ? params[1] : null);
            if (!shouldBlockWebSocketRegistration(endpointPath, endpointClassName, stack)) {
                if (stack != null && !isExpectedWebSocketStartupSource(stack)) {
                    System.out.println("[GraRasp] WARN WebSocket registration allowed: path=" + endpointPath +
                        ", class=" + endpointClassName);
                }
                return;
            }
            String endpointInfo = "";
            if (params.length > 1 && params[1] != null) {
                // 获取 Endpoint 路径
                Object endpointConfig = params[1];
                String path = ReflectionCache.invokeMethodAsString(endpointConfig, "getPath");
                String endpointClass = ReflectionCache.invokeMethodAsString(endpointConfig, "getEndpointClass");
                endpointInfo = " path=" + path + ", class=" + endpointClass;
            }
            alertAndBlock("WebSocket MemShell Injection Detected!" + endpointInfo, "WebSocket MemShell");
            return;
        }

        // Tomcat 判断
        if (targetClassName.contains("StandardContext")) {
            String state = ReflectionCache.invokeMethodAsString(target, "getState");
            if ("STARTED".equalsIgnoreCase(state)) {
                alertAndBlock("Runtime API call: " + type, "Standard API Abuse");
            }
        }
        // WebLogic 判断
        else if (targetClassName.contains("WebAppServletContext")) {
            // WebLogic Context 也有 started 状态，通常可以通过 isActive() 或类似方法判断
            // 这里简单假设只要 Hook 到了就是运行时注入 (因为 WebLogic 部署时通常不走这个 Hook 点)
            String name = (String) ReflectionCache.invokeMethod(target, "getLogContext"); // 辅助获取 Context 名
            // 对于 WebLogic，更严谨的是检查 Server 状态，这里作为演示直接拦截
            alertAndBlock("Runtime API call (WebLogic): " + type, "WebLogic API Abuse");
        }
    }

    // ==================== 增强巡检逻辑 ====================

    static boolean shouldBlockWebSocketRegistration(String path, String endpointClass, StackTraceElement[] stack) {
        RaspConfig config = RaspConfig.getInstance();
        if (isWhitelistedWebSocket(path, endpointClass, config.getComponentWhitelist())) {
            return false;
        }

        boolean suspiciousSource = isSuspiciousWebSocketSource(stack);
        boolean startupSource = isExpectedWebSocketStartupSource(stack);
        int riskScore = calculateWebSocketRisk(path, endpointClass);

        if (suspiciousSource) {
            return true;
        }

        if (startupSource) {
            return riskScore >= RISK_THRESHOLD_CLEAN;
        }

        return riskScore >= RISK_THRESHOLD_WARN;
    }

    static boolean isExpectedWebSocketStartupSource(StackTraceElement[] stack) {
        if (stack == null) return false;

        for (StackTraceElement element : stack) {
            String cls = element.getClassName();
            String method = element.getMethodName();
            if ("org.apache.tomcat.websocket.server.WsSci".equals(cls) && "onStartup".equals(method)) {
                return true;
            }
            if (cls.contains("SpringServletContainerInitializer") ||
                cls.contains("ServletContextInitializerBeans") ||
                cls.contains("TomcatStarter")) {
                return true;
            }
        }
        return false;
    }

    static boolean isSuspiciousWebSocketSource(StackTraceElement[] stack) {
        if (stack == null) return false;

        if (CommandDetector.isSuspiciousSource(stack) || JndiDetector.isSuspiciousSource(stack)) {
            return true;
        }

        for (StackTraceElement element : stack) {
            String cls = element.getClassName().toLowerCase(Locale.ROOT);
            if (cls.contains("org.apache.jasper") ||
                cls.contains("org.apache.jsp") ||
                cls.contains("objectinputstream") ||
                cls.contains("behinder") ||
                cls.contains("godzilla") ||
                cls.contains("metasploit") ||
                cls.contains("antsword") ||
                cls.contains("memoryshell")) {
                return true;
            }
        }
        return false;
    }

    static int calculateWebSocketRisk(String path, String endpointClass) {
        int riskScore = 0;
        String normalizedPath = path == null ? "" : path.toLowerCase(Locale.ROOT);
        String normalizedClassName = normalizeComponentClassName(endpointClass);
        String normalizedClass = normalizedClassName.toLowerCase(Locale.ROOT);

        if (normalizedPath.contains("shell") || normalizedPath.contains("cmd") ||
            normalizedPath.contains("inject") || normalizedPath.contains("mem")) {
            riskScore += 30;
        }

        if (normalizedClass.contains("shell") || normalizedClass.contains("memshell") ||
            normalizedClass.contains("godzilla") || normalizedClass.contains("behinder") ||
            normalizedClass.contains("inject") || normalizedClass.contains("payload")) {
            riskScore += 50;
        }

        if (normalizedClassName.contains("$$") || normalizedClassName.contains("$Lambda")) {
            riskScore += 20;
        }

        if (normalizedClassName.matches(".*\\$\\d+$")) {
            riskScore += 10;
        }

        if (normalizedClassName.isEmpty()) {
            riskScore += 5;
        } else if (!normalizedClassName.contains(".")) {
            riskScore += 5;
        }

        return Math.min(riskScore, 100);
    }

    private static boolean isWhitelistedWebSocket(String path, String endpointClass, Set<String> whitelist) {
        String normalizedClassName = normalizeComponentClassName(endpointClass);
        return whitelist.contains(path) || whitelist.contains(endpointClass) ||
            (!normalizedClassName.isEmpty() && whitelist.contains(normalizedClassName));
    }

    static String normalizeComponentClassName(String className) {
        if (className == null) {
            return "";
        }
        String normalized = className.trim().replaceFirst("^class\\s+", "");
        if (normalized.isEmpty() || "unknown".equalsIgnoreCase(normalized) || "null".equalsIgnoreCase(normalized)) {
            return "";
        }
        return normalized;
    }

    private static String extractWebSocketPath(Object endpointConfig) {
        if (endpointConfig == null) return "unknown";
        String path = ReflectionCache.invokeMethodAsString(endpointConfig, "getPath");
        return path == null ? "unknown" : path;
    }

    private static String extractWebSocketClassName(Object endpointConfig) {
        if (endpointConfig == null) return "unknown";
        Object endpointClass = ReflectionCache.invokeMethod(endpointConfig, "getEndpointClass");
        if (endpointClass instanceof Class) {
            return ((Class<?>) endpointClass).getName();
        }
        if (endpointClass != null) {
            String normalized = normalizeComponentClassName(endpointClass.toString());
            return normalized.isEmpty() ? "unknown" : normalized;
        }
        return "unknown";
    }

    private static void scanMemoryShells() {
        if (activeContexts.isEmpty()) return;

        scanCount.incrementAndGet();
        RaspConfig config = RaspConfig.getInstance();
        Set<String> whitelist = config.getComponentWhitelist();

        for (Object ctx : activeContexts) {
            try {
                String ctxType = ctx.getClass().getName();

                // Tomcat 扫描
                if (ctxType.contains("StandardContext")) {
                    scanTomcatFilters(ctx, whitelist);
                    scanTomcatListeners(ctx, whitelist);
                    scanTomcatValves(ctx, whitelist);
                    scanTomcatServlets(ctx, whitelist);
                    scanTomcatWebSockets(ctx, whitelist);
                }
                // WebLogic 扫描
                else if (ctxType.contains("WebAppServletContext")) {
                    scanWebLogicFilters(ctx, whitelist);
                    scanWebLogicListeners(ctx, whitelist);
                    scanWebLogicServlets(ctx, whitelist);
                }
            } catch (Exception e) {
                // 忽略单个 Context 扫描错误
            }
        }

        // 处理检测结果
        processDetections(config);
    }

    // ==================== Tomcat 扫描 ====================

    private static void scanTomcatFilters(Object ctx, Set<String> whitelist) {
        try {
            Object filterMaps = ReflectionCache.getFieldValue(ctx, "filterMaps");
            if (filterMaps != null && filterMaps.getClass().getName().endsWith("ContextFilterMaps")) {
                filterMaps = ReflectionCache.getFieldValue(filterMaps, "array");
            }
            if (filterMaps != null && filterMaps.getClass().isArray()) {
                int len = Array.getLength(filterMaps);
                for (int i = 0; i < len; i++) {
                    Object map = Array.get(filterMaps, i);
                    if (map == null) continue;
                    String filterName = ReflectionCache.invokeMethodAsString(map, "getFilterName");
                    if (filterName == null || whitelist.contains(filterName)) continue;

                    Object filterDef = findFilterDef(ctx, filterName);
                    if (filterDef != null) {
                        String filterClass = ReflectionCache.invokeMethodAsString(filterDef, "getFilterClass");
                        Object filterInstance = ReflectionCache.invokeMethod(filterDef, "getFilter");
                        analyzeComponent("Filter", filterName, filterClass, filterInstance, ctx);
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    private static void scanTomcatListeners(Object ctx, Set<String> whitelist) {
        try {
            Object[] listeners = (Object[]) ReflectionCache.getFieldValue(ctx, "applicationEventListenersList");
            if (listeners == null) {
                Object listObj = ReflectionCache.getFieldValue(ctx, "applicationEventListenersObjects");
                if (listObj instanceof Object[]) {
                    listeners = (Object[]) listObj;
                }
            }

            if (listeners != null) {
                for (Object listener : listeners) {
                    if (listener == null) continue;
                    String listenerClass = listener.getClass().getName();
                    if (!whitelist.contains(listenerClass)) {
                        analyzeComponent("Listener", listenerClass, listenerClass, listener, ctx);
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    private static void scanTomcatValves(Object ctx, Set<String> whitelist) {
        try {
            Object pipeline = ReflectionCache.invokeMethod(ctx, "getPipeline");
            if (pipeline == null) return;

            Object valve = ReflectionCache.invokeMethod(pipeline, "getFirst");
            Set<String> seen = new HashSet<>();

            while (valve != null) {
                String valveClass = valve.getClass().getName();
                if (seen.contains(valveClass)) break;
                seen.add(valveClass);

                if (!whitelist.contains(valveClass)) {
                    analyzeComponent("Valve", valveClass, valveClass, valve, ctx);
                }
                valve = ReflectionCache.invokeMethod(valve, "getNext");
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    private static void scanTomcatServlets(Object ctx, Set<String> whitelist) {
        try {
            Object[] children = (Object[]) ReflectionCache.invokeMethod(ctx, "findChildren");
            if (children == null) return;

            for (Object wrapper : children) {
                if (wrapper == null) continue;
                String servletName = ReflectionCache.invokeMethodAsString(wrapper, "getName");
                String servletClass = ReflectionCache.invokeMethodAsString(wrapper, "getServletClass");

                if (servletName != null && !whitelist.contains(servletName) &&
                    servletClass != null && !whitelist.contains(servletClass)) {
                    Object servlet = ReflectionCache.invokeMethod(wrapper, "getServlet");
                    analyzeComponent("Servlet", servletName, servletClass, servlet, ctx);
                }
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    /**
     * 扫描 Tomcat WebSocket Endpoints
     */
    private static void scanTomcatWebSockets(Object ctx, Set<String> whitelist) {
        try {
            // 获取 ServletContext
            Object servletContext = ReflectionCache.invokeMethod(ctx, "getServletContext");
            if (servletContext == null) return;

            // 获取 WsServerContainer
            Object wsContainer = ReflectionCache.invokeMethod(servletContext, "getAttribute",
                new Class[]{String.class}, new Object[]{"javax.websocket.server.ServerContainer"});
            if (wsContainer == null) return;

            // 获取已注册的 Endpoints
            // WsServerContainer 内部维护了 configExactMatchMap 和 configTemplateMatchMap
            Map<?, ?> exactMatch = (Map<?, ?>) ReflectionCache.getFieldValue(wsContainer, "configExactMatchMap");
            Map<?, ?> templateMatch = (Map<?, ?>) ReflectionCache.getFieldValue(wsContainer, "configTemplateMatchMap");

            // 扫描精确匹配的 Endpoints
            if (exactMatch != null) {
                for (Map.Entry<?, ?> entry : exactMatch.entrySet()) {
                    String path = entry.getKey() != null ? entry.getKey().toString() : "unknown";
                    Object endpointConfig = entry.getValue();
                    if (endpointConfig != null) {
                        analyzeWebSocketEndpoint(path, endpointConfig, wsContainer, whitelist);
                    }
                }
            }

            // 扫描模板匹配的 Endpoints
            if (templateMatch != null) {
                for (Map.Entry<?, ?> entry : templateMatch.entrySet()) {
                    Object uriTemplate = entry.getKey();
                    String path = uriTemplate != null ? ReflectionCache.invokeMethodAsString(uriTemplate, "getPath") : "unknown";
                    Object endpointConfig = entry.getValue();
                    if (endpointConfig != null) {
                        analyzeWebSocketEndpoint(path, endpointConfig, wsContainer, whitelist);
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    /**
     * 分析 WebSocket Endpoint
     */
    private static void analyzeWebSocketEndpoint(String path, Object endpointConfig, Object wsContainer, Set<String> whitelist) {
        try {
            // 获取 Endpoint 类
            String className = extractWebSocketClassName(endpointConfig);

            // 跳过白名单
            if (isWhitelistedWebSocket(path, className, whitelist)) {
                return;
            }

            // 分析可疑特征
            int riskScore = calculateWebSocketRisk(path, className);

            // 匿名类或 Lambda

            // 无包名

            // 可疑路径

            // 可疑类名

            if (riskScore >= RISK_THRESHOLD_WARN) {
                SuspiciousComponent comp = new SuspiciousComponent("WebSocket", path, className, endpointConfig, wsContainer, riskScore);
                String key = "WebSocket:" + path + ":" + className;
                suspiciousComponents.put(key, comp);
                detectionCount.incrementAndGet();

                System.err.println("[GraRasp] Suspicious WebSocket Endpoint: path=" + path +
                    ", class=" + className + ", risk=" + riskScore);
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    // ==================== WebLogic 扫描 ====================

    private static void scanWebLogicFilters(Object ctx, Set<String> whitelist) {
        try {
            Object filterManager = ReflectionCache.invokeMethod(ctx, "getFilterManager");
            if (filterManager == null) return;

            Map<?, ?> filters = (Map<?, ?>) ReflectionCache.getFieldValue(filterManager, "filters");
            if (filters == null) {
                filters = (Map<?, ?>) ReflectionCache.getFieldValue(filterManager, "filterDefs");
            }

            if (filters != null) {
                for (Object filterDef : filters.values()) {
                    String filterClass = ReflectionCache.invokeMethodAsString(filterDef, "getFilterClassName");
                    String filterName = ReflectionCache.invokeMethodAsString(filterDef, "getFilterName");

                    if (filterName != null && !whitelist.contains(filterName)) {
                        Object filterInstance = ReflectionCache.invokeMethod(filterDef, "getFilter");
                        analyzeComponent("WebLogic-Filter", filterName, filterClass, filterInstance, ctx);
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    private static void scanWebLogicListeners(Object ctx, Set<String> whitelist) {
        try {
            // 尝试获取 EventListeners
            Object eventsManager = ReflectionCache.invokeMethod(ctx, "getEventsManager");
            if (eventsManager != null) {
                Object[] listeners = (Object[]) ReflectionCache.getFieldValue(eventsManager, "listeners");
                if (listeners == null) {
                    Object listenerList = ReflectionCache.getFieldValue(eventsManager, "eventListeners");
                    if (listenerList instanceof List) {
                        listeners = ((List<?>) listenerList).toArray();
                    }
                }

                if (listeners != null) {
                    for (Object listener : listeners) {
                        if (listener == null) continue;
                        String listenerClass = listener.getClass().getName();
                        if (!whitelist.contains(listenerClass)) {
                            analyzeComponent("WebLogic-Listener", listenerClass, listenerClass, listener, ctx);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    private static void scanWebLogicServlets(Object ctx, Set<String> whitelist) {
        try {
            Object servletMapping = ReflectionCache.getFieldValue(ctx, "servletMapping");
            if (servletMapping == null) {
                servletMapping = ReflectionCache.invokeMethod(ctx, "getServletMapping");
            }

            if (servletMapping instanceof Map) {
                Map<?, ?> mappings = (Map<?, ?>) servletMapping;
                for (Object entry : mappings.entrySet()) {
                    if (entry instanceof Map.Entry) {
                        Map.Entry<?, ?> e = (Map.Entry<?, ?>) entry;
                        Object stub = e.getValue();
                        if (stub != null) {
                            String servletClass = ReflectionCache.invokeMethodAsString(stub, "getServletClassName");
                            String servletName = ReflectionCache.invokeMethodAsString(stub, "getServletName");

                            if (servletName != null && !whitelist.contains(servletName) &&
                                servletClass != null && !whitelist.contains(servletClass)) {
                                Object servlet = ReflectionCache.invokeMethod(stub, "getServlet");
                                analyzeComponent("WebLogic-Servlet", servletName, servletClass, servlet, ctx);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
    }

    // ==================== 风险分析与检测 ====================

    /**
     * 分析组件，计算风险评分
     */
    private static void analyzeComponent(String type, String name, String className, Object instance, Object ctx) {
        String key = type + ":" + name + ":" + className;

        // 增量扫描：跳过最近扫描过的组件
        Long lastScan = scannedComponents.get(key);
        long now = System.currentTimeMillis();
        if (lastScan != null && (now - lastScan) < 60000) {
            return; // 1分钟内扫描过，跳过
        }
        scannedComponents.put(key, now);

        // 计算风险评分
        int riskScore = calculateRiskScore(type, name, className, instance);

        if (riskScore >= RISK_THRESHOLD_WARN) {
            SuspiciousComponent comp = new SuspiciousComponent(type, name, className, instance, ctx, riskScore);
            suspiciousComponents.put(key, comp);
            detectionCount.incrementAndGet();
        }
    }

    /**
     * 计算风险评分（0-100）
     */
    static int calculateRiskScore(String type, String name, String className, Object instance) {
        int score = 0;
        String normalizedClassName = normalizeComponentClassName(className);

        // 1. 类名特征检测 (+10-50)
        if (!normalizedClassName.isEmpty()) {
            String lower = normalizedClassName.toLowerCase(Locale.ROOT);

            // 动态代理类
            if (normalizedClassName.contains("$$") || normalizedClassName.contains("$Proxy")) {
                score += 20;
            }
            // CGLIB 代理
            if (lower.contains("cglib") || lower.contains("enhancer")) {
                score += 15;
            }
            // 明显恶意标识
            if (lower.contains("shell") || lower.contains("malicious") ||
                lower.contains("exploit") || lower.contains("payload") ||
                lower.contains("hack") || lower.contains("evil")) {
                score += 40;
            }
            // 已知攻击工具
            if (lower.contains("behinder") || lower.contains("godzilla") ||
                lower.contains("memshell") || lower.contains("inject") ||
                lower.contains("antsword") || lower.contains("cknife")) {
                score += 50;
            }
            // 匿名类
            if (normalizedClassName.matches(".*\\$\\d+$")) {
                score += 10;
            }
            // 无包名类
            if (!normalizedClassName.contains(".")) {
                score += 5;
            }
            // Base64 编码类名
            if (normalizedClassName.matches(".*[A-Za-z0-9+/]{20,}.*")) {
                score += 15;
            }
        }

        // 2. 类加载器检测 (+10-30)
        if (instance != null) {
            try {
                ClassLoader cl = instance.getClass().getClassLoader();
                if (cl != null) {
                    String clName = cl.getClass().getName();
                    // 非标准类加载器
                    if (!clName.startsWith("sun.") && !clName.startsWith("java.") &&
                        !clName.startsWith("jdk.") && !clName.startsWith("org.apache.") &&
                        !clName.startsWith("weblogic.") && !clName.startsWith("org.springframework.")) {
                        score += 15;
                    }
                    // TransletClassLoader (TemplatesImpl 攻击)
                    if (clName.contains("TransletClassLoader")) {
                        score += 30;
                    }
                    // 自定义 URLClassLoader
                    if (clName.contains("URLClassLoader") && !clName.startsWith("java.")) {
                        score += 20;
                    }
                }
            } catch (Exception e) {
                // 忽略
            }
        }

        // 3. 字节码/反射特征检测 (+5-30)
        if (instance != null) {
            score += analyzeInstanceFeatures(instance);
        }

        return Math.min(score, 100);
    }

    /**
     * 分析实例特征
     */
    private static int analyzeInstanceFeatures(Object instance) {
        int score = 0;
        try {
            Class<?> clazz = instance.getClass();

            // 检查方法
            Method[] methods = clazz.getDeclaredMethods();
            for (Method m : methods) {
                String methodName = m.getName().toLowerCase();
                // 命令执行相关
                if (methodName.contains("exec") || methodName.contains("cmd") ||
                    methodName.contains("shell") || methodName.contains("command")) {
                    score += 10;
                }
                // 反射相关
                if (methodName.contains("invoke") || methodName.contains("reflect") ||
                    methodName.contains("loadclass")) {
                    score += 5;
                }
                // 加解密相关
                if (methodName.contains("encrypt") || methodName.contains("decrypt") ||
                    methodName.contains("encode") || methodName.contains("decode")) {
                    score += 5;
                }
            }

            // 检查字段
            Field[] fields = clazz.getDeclaredFields();
            for (Field f : fields) {
                String fieldType = f.getType().getName();
                // Runtime/ProcessBuilder 字段
                if (fieldType.contains("Runtime") || fieldType.contains("ProcessBuilder")) {
                    score += 20;
                }
                // 加密相关
                if (fieldType.contains("Cipher") || fieldType.contains("SecretKey")) {
                    score += 10;
                }
                // 网络相关
                if (fieldType.contains("Socket") || fieldType.contains("URLConnection")) {
                    score += 10;
                }
            }

            // 检查 ProtectionDomain
            ProtectionDomain pd = clazz.getProtectionDomain();
            if (pd != null && pd.getCodeSource() == null) {
                score += 15; // 无代码来源，可能是动态生成
            }

            // 检查父类
            Class<?> superClass = clazz.getSuperclass();
            if (superClass != null) {
                String superName = superClass.getName();
                if (superName.contains("ClassLoader")) {
                    score += 20;
                }
                if (superName.contains("AbstractTranslet")) {
                    score += 40;
                }
            }

        } catch (Exception e) {
            // 忽略
        }
        return score;
    }

    /**
     * 处理检测结果
     */
    private static void processDetections(RaspConfig config) {
        for (Map.Entry<String, SuspiciousComponent> entry : suspiciousComponents.entrySet()) {
            SuspiciousComponent comp = entry.getValue();

            if (comp.isProcessed()) continue;

            // 根据风险等级处理
            if (comp.getRiskScore() >= RISK_THRESHOLD_CLEAN && config.isBlockMode()) {
                // 高风险：尝试清除
                boolean cleaned = tryCleanComponent(comp);
                if (cleaned) {
                    cleanCount.incrementAndGet();
                    System.err.println("[GraRasp] CLEANED " + comp.getType() + ": " + comp.getName() +
                        " (class=" + comp.getClassName() + ", risk=" + comp.getRiskScore() + ")");
                    sendAlert(comp, "CLEANED");
                } else {
                    alertComponent(comp, "HIGH RISK - Clean Failed");
                }
            } else if (comp.getRiskScore() >= RISK_THRESHOLD_BLOCK) {
                // 中高风险：告警
                alertComponent(comp, "MEDIUM-HIGH RISK");
            } else {
                // 低风险：仅记录
                System.out.println("[GraRasp] WARN " + comp.getType() + ": " + comp.getName() +
                    " (risk=" + comp.getRiskScore() + ")");
            }

            comp.setProcessed(true);
        }
    }

    // ==================== 自动清除逻辑 ====================

    /**
     * 尝试清除可疑组件
     */
    private static boolean tryCleanComponent(SuspiciousComponent comp) {
        try {
            Object ctx = comp.getContext();
            String type = comp.getType();
            String name = comp.getName();

            if (type.contains("Filter")) {
                return cleanFilter(ctx, name);
            } else if (type.contains("Listener")) {
                return cleanListener(ctx, comp.getInstance());
            } else if (type.contains("Valve")) {
                return cleanValve(ctx, comp.getInstance());
            } else if (type.contains("Servlet")) {
                return cleanServlet(ctx, name);
            }
        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.SCANNER,
                "Failed to clean component: " + comp.getName(), e);
        }
        return false;
    }

    private static boolean cleanFilter(Object ctx, String filterName) {
        try {
            String ctxClass = ctx.getClass().getName();

            // Tomcat 清除
            if (ctxClass.contains("StandardContext")) {
                // 获取 FilterDef
                Object filterDef = findFilterDef(ctx, filterName);
                if (filterDef == null) return false;

                // 移除 FilterMap
                Object filterMaps = ReflectionCache.getFieldValue(ctx, "filterMaps");
                if (filterMaps != null && filterMaps.getClass().getName().endsWith("ContextFilterMaps")) {
                    filterMaps = ReflectionCache.getFieldValue(filterMaps, "array");
                }
                if (filterMaps != null && filterMaps.getClass().isArray()) {
                    // 找到并移除对应的 FilterMap
                    Method removeFilterMap = ctx.getClass().getMethod("removeFilterMap",
                        Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap"));
                    int len = Array.getLength(filterMaps);
                    for (int i = 0; i < len; i++) {
                        Object map = Array.get(filterMaps, i);
                        if (map != null) {
                            String fn = ReflectionCache.invokeMethodAsString(map, "getFilterName");
                            if (filterName.equals(fn)) {
                                removeFilterMap.invoke(ctx, map);
                                break;
                            }
                        }
                    }
                }

                // 移除 FilterDef
                Method removeFilterDef = ctx.getClass().getMethod("removeFilterDef",
                    Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef"));
                removeFilterDef.invoke(ctx, filterDef);
                return true;
            }
        } catch (Exception e) {
            // 忽略
        }
        return false;
    }

    private static boolean cleanListener(Object ctx, Object listener) {
        try {
            if (ctx.getClass().getName().contains("StandardContext")) {
                Method removeListener = ctx.getClass().getMethod("removeApplicationEventListener", Object.class);
                removeListener.invoke(ctx, listener);
                return true;
            }
        } catch (Exception e) {
            // 忽略
        }
        return false;
    }

    private static boolean cleanValve(Object ctx, Object valve) {
        try {
            if (ctx.getClass().getName().contains("StandardContext")) {
                Object pipeline = ReflectionCache.invokeMethod(ctx, "getPipeline");
                if (pipeline != null) {
                    Method removeValve = pipeline.getClass().getMethod("removeValve",
                        Class.forName("org.apache.catalina.Valve"));
                    removeValve.invoke(pipeline, valve);
                    return true;
                }
            }
        } catch (Exception e) {
            // 忽略
        }
        return false;
    }

    private static boolean cleanServlet(Object ctx, String servletName) {
        try {
            if (ctx.getClass().getName().contains("StandardContext")) {
                Object[] children = (Object[]) ReflectionCache.invokeMethod(ctx, "findChildren");
                if (children != null) {
                    Method removeChild = ctx.getClass().getMethod("removeChild",
                        Class.forName("org.apache.catalina.Container"));
                    for (Object child : children) {
                        String name = ReflectionCache.invokeMethodAsString(child, "getName");
                        if (servletName.equals(name)) {
                            removeChild.invoke(ctx, child);
                            return true;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // 忽略
        }
        return false;
    }

    // ==================== 告警逻辑 ====================

    private static void alertComponent(SuspiciousComponent comp, String level) {
        System.err.println("========================================");
        System.err.println("[GraRasp] " + level + " Memory Shell Detected!");
        System.err.println("Type:      " + comp.getType());
        System.err.println("Name:      " + comp.getName());
        System.err.println("Class:     " + comp.getClassName());
        System.err.println("Risk:      " + comp.getRiskScore() + "/100");
        System.err.println("========================================");

        sendAlert(comp, level);
    }

    private static void sendAlert(SuspiciousComponent comp, String level) {
        RaspConfig config = RaspConfig.getInstance();
        String webhook = config.getAlertWebhook();
        if (webhook != null && !webhook.isEmpty()) {
            new Thread(() -> {
                try {
                    java.net.URL url = new java.net.URL(webhook);
                    java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setDoOutput(true);
                    conn.setConnectTimeout(3000);
                    conn.setReadTimeout(3000);

                    String json = String.format(
                        "{\"level\":\"%s\",\"type\":\"%s\",\"name\":\"%s\",\"class\":\"%s\",\"risk\":%d,\"timestamp\":%d}",
                        level, comp.getType(), comp.getName(), comp.getClassName(),
                        comp.getRiskScore(), System.currentTimeMillis()
                    );

                    try (java.io.OutputStream os = conn.getOutputStream()) {
                        os.write(json.getBytes(StandardCharsets.UTF_8));
                    }
                    conn.getResponseCode();
                    conn.disconnect();
                } catch (Exception e) {
                    // 忽略
                }
            }, "GraRasp-Alert").start();
        }
    }

    // ==================== 辅助方法 ====================

    private void alertAndBlock(String msg, String type) {
        RaspConfig config = RaspConfig.getInstance();

        System.err.println("========================================");
        System.err.println("[GraRasp Security Alert] 🚨 " + msg);
        System.err.println("Type:    " + type);
        System.err.println("Action:  " + (config.isBlockMode() ? "Blocked" : "Monitor Only"));
        System.err.println("========================================");

        // 发送 Webhook 告警
        String webhook = config.getAlertWebhook();
        if (webhook != null && !webhook.isEmpty()) {
            sendWebhookAlert(webhook, msg, type);
        }

        if (config.isBlockMode()) {
            throw new SecurityException("GraRasp Blocked: " + msg);
        }
    }

    private void sendWebhookAlert(String webhook, String msg, String type) {
        // 异步发送，避免阻塞
        new Thread(() -> {
            try {
                java.net.URL url = new java.net.URL(webhook);
                java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);

                String json = String.format(
                    "{\"alert\":\"%s\",\"type\":\"%s\",\"timestamp\":%d}",
                    escapeJson(msg), escapeJson(type), System.currentTimeMillis()
                );

                try (java.io.OutputStream os = conn.getOutputStream()) {
                    os.write(json.getBytes(StandardCharsets.UTF_8));
                }

                conn.getResponseCode(); // 触发请求
                conn.disconnect();
            } catch (Exception e) {
                // 忽略 webhook 发送失败
            }
        }, "GraRasp-Webhook").start();
    }

    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r");
    }

    private static Object findFilterDef(Object ctx, String filterName) {
        try {
            Map<?, ?> filterDefs = (Map<?, ?>) ReflectionCache.getFieldValue(ctx, "filterDefs");
            if (filterDefs != null) return filterDefs.get(filterName);
        } catch (Exception e) {}
        return null;
    }

    // ==================== 可疑组件数据类 ====================

    /**
     * 可疑组件信息
     */
    public static class SuspiciousComponent {
        private final String type;
        private final String name;
        private final String className;
        private final Object instance;
        private final Object context;
        private final int riskScore;
        private final long detectTime;
        private volatile boolean processed;

        public SuspiciousComponent(String type, String name, String className,
                                   Object instance, Object context, int riskScore) {
            this.type = type;
            this.name = name;
            this.className = className;
            this.instance = instance;
            this.context = context;
            this.riskScore = riskScore;
            this.detectTime = System.currentTimeMillis();
            this.processed = false;
        }

        public String getType() { return type; }
        public String getName() { return name; }
        public String getClassName() { return className; }
        public Object getInstance() { return instance; }
        public Object getContext() { return context; }
        public int getRiskScore() { return riskScore; }
        public long getDetectTime() { return detectTime; }
        public boolean isProcessed() { return processed; }
        public void setProcessed(boolean processed) { this.processed = processed; }

        @Override
        public String toString() {
            return String.format("SuspiciousComponent{type='%s', name='%s', class='%s', risk=%d}",
                type, name, className, riskScore);
        }
    }
}
