package com.grarasp.core.config;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RASP 配置管理器
 * 支持从 YAML 文件加载配置，提供默认值
 */
public class RaspConfig {

    private static volatile RaspConfig INSTANCE;
    private static final String CONFIG_FILE = "grarasp.yml";

    // 扫描配置
    private boolean scanEnabled = true;
    private int scanInterval = 30000;

    // 阻断模式
    private boolean blockMode = true;

    // 检测规则开关
    private boolean spelDetectionEnabled = true;
    private boolean classLoaderHookEnabled = true;
    private boolean runtimeExecHookEnabled = true;
    private boolean jndiHookEnabled = true;

    // 白名单
    private Set<String> componentWhitelist = new HashSet<>();
    private Set<String> classWhitelist = new HashSet<>();

    // SpEL 危险关键字
    private Set<String> spelDangerousClasses = new HashSet<>();
    private Set<String> spelDangerousMethods = new HashSet<>();

    // 日志配置
    private String logLevel = "INFO";
    private String logFile = null;

    // 告警配置
    private String alertWebhook = null;

    private RaspConfig() {
        initDefaults();
    }

    public static RaspConfig getInstance() {
        if (INSTANCE == null) {
            synchronized (RaspConfig.class) {
                if (INSTANCE == null) {
                    INSTANCE = new RaspConfig();
                    INSTANCE.loadConfig();
                }
            }
        }
        return INSTANCE;
    }

    /**
     * 重新加载配置（支持热更新）
     */
    public static void reload() {
        synchronized (RaspConfig.class) {
            INSTANCE = new RaspConfig();
            INSTANCE.loadConfig();
        }
    }

    private void initDefaults() {
        // 默认组件白名单
        componentWhitelist.addAll(Arrays.asList(
            // Tomcat
            "Tomcat WebSocket (JSR356) Filter",
            "ServletRequest Context Filter",
            "WsFilter",
            "org.apache.catalina.valves.ErrorReportValve",
            "org.apache.catalina.valves.AccessLogValve",
            "org.apache.catalina.core.StandardContextValve",
            "org.apache.catalina.authenticator.NonLoginAuthenticator",
            "org.apache.catalina.authenticator.BasicAuthenticator",
            "org.apache.catalina.core.StandardContext$ContextFilterMaps",
            // Spring
            "org.springframework.web.context.ContextLoaderListener",
            "org.springframework.web.util.IntrospectorCleanupListener",
            "characterEncodingFilter",
            "hiddenHttpMethodFilter",
            "httpPutFormContentFilter",
            "requestContextFilter",
            "org.springframework.web.filter.CharacterEncodingFilter",
            "org.springframework.web.filter.HiddenHttpMethodFilter",
            "org.springframework.web.filter.FormContentFilter",
            "org.springframework.web.filter.RequestContextFilter",
            // WebLogic
            "JspServlet",
            "FileServlet",
            "weblogic.servlet.internal.ServletStubImpl"
        ));

        // 默认类白名单
        classWhitelist.addAll(Arrays.asList(
            "org.springframework",
            "org.apache.tomcat",
            "org.apache.catalina",
            "weblogic.",
            "com.oracle."
        ));

        // SpEL 危险类
        spelDangerousClasses.addAll(Arrays.asList(
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "java.lang.ProcessImpl",
            "java.lang.UNIXProcess",
            "javax.script.ScriptEngineManager",
            "javax.script.ScriptEngine",
            "java.lang.ClassLoader",
            "java.lang.Class",
            "java.lang.reflect.Method",
            "java.lang.reflect.Constructor",
            "java.lang.reflect.Field",
            "java.io.File",
            "java.io.FileInputStream",
            "java.io.FileOutputStream",
            "java.io.FileWriter",
            "java.io.FileReader",
            "java.net.URL",
            "java.net.URLClassLoader",
            "javax.naming.InitialContext",
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "sun.misc.Unsafe",
            "jdk.internal.misc.Unsafe"
        ));

        // SpEL 危险方法
        spelDangerousMethods.addAll(Arrays.asList(
            "exec",
            "getRuntime",
            "loadClass",
            "forName",
            "newInstance",
            "getMethod",
            "invoke",
            "getDeclaredMethod",
            "getDeclaredField",
            "setAccessible",
            "defineClass",
            "lookup",
            "eval",
            "getEngineByName",
            "getEngineByExtension"
        ));
    }

    private void loadConfig() {
        // 1. 尝试从系统属性获取配置文件路径
        String configPath = System.getProperty("grarasp.config");

        // 2. 尝试从环境变量获取
        if (configPath == null) {
            configPath = System.getenv("GRARASP_CONFIG");
        }

        // 3. 尝试从当前目录加载
        File configFile = null;
        if (configPath != null) {
            configFile = new File(configPath);
        } else {
            // 尝试多个位置
            String[] paths = {
                CONFIG_FILE,
                "conf/" + CONFIG_FILE,
                "config/" + CONFIG_FILE,
                System.getProperty("user.home") + "/.grarasp/" + CONFIG_FILE
            };
            for (String path : paths) {
                File f = new File(path);
                if (f.exists() && f.isFile()) {
                    configFile = f;
                    break;
                }
            }
        }

        if (configFile != null && configFile.exists()) {
            try {
                parseYaml(configFile);
                System.out.println("[GraRasp] Config loaded from: " + configFile.getAbsolutePath());
            } catch (Exception e) {
                System.err.println("[GraRasp] Failed to load config: " + e.getMessage());
            }
        } else {
            System.out.println("[GraRasp] Using default configuration");
        }
    }

    /**
     * 简易 YAML 解析器（不依赖第三方库）
     */
    private void parseYaml(File file) throws IOException {
        Map<String, Object> config = new LinkedHashMap<>();
        List<String> currentPath = new ArrayList<>();
        int[] indentStack = new int[20];
        int stackDepth = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // 跳过空行和注释
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }

                // 计算缩进
                int indent = 0;
                for (char c : line.toCharArray()) {
                    if (c == ' ') indent++;
                    else break;
                }

                // 调整路径深度
                while (stackDepth > 0 && indent <= indentStack[stackDepth - 1]) {
                    currentPath.remove(currentPath.size() - 1);
                    stackDepth--;
                }

                // 解析键值对
                if (trimmed.contains(":")) {
                    int colonIndex = trimmed.indexOf(':');
                    String key = trimmed.substring(0, colonIndex).trim();
                    String value = trimmed.substring(colonIndex + 1).trim();

                    if (value.isEmpty()) {
                        // 嵌套对象
                        currentPath.add(key);
                        indentStack[stackDepth++] = indent;
                    } else {
                        // 简单值
                        String fullKey = String.join(".", currentPath) + (currentPath.isEmpty() ? "" : ".") + key;
                        config.put(fullKey, parseValue(value));
                    }
                } else if (trimmed.startsWith("- ")) {
                    // 数组元素
                    String value = trimmed.substring(2).trim();
                    String fullKey = String.join(".", currentPath);
                    @SuppressWarnings("unchecked")
                    List<String> list = (List<String>) config.computeIfAbsent(fullKey, k -> new ArrayList<String>());
                    list.add(value);
                }
            }
        }

        // 应用配置
        applyConfig(config);
    }

    private Object parseValue(String value) {
        // 去除引号
        if ((value.startsWith("\"") && value.endsWith("\"")) ||
            (value.startsWith("'") && value.endsWith("'"))) {
            return value.substring(1, value.length() - 1);
        }
        // 布尔值
        if ("true".equalsIgnoreCase(value)) return true;
        if ("false".equalsIgnoreCase(value)) return false;
        // 数字
        try {
            if (value.contains(".")) {
                return Double.parseDouble(value);
            }
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return value;
        }
    }

    @SuppressWarnings("unchecked")
    private void applyConfig(Map<String, Object> config) {
        // 扫描配置
        if (config.containsKey("scan.enabled")) {
            scanEnabled = (Boolean) config.get("scan.enabled");
        }
        if (config.containsKey("scan.interval")) {
            scanInterval = ((Number) config.get("scan.interval")).intValue();
        }

        // 阻断模式
        if (config.containsKey("block_mode")) {
            blockMode = (Boolean) config.get("block_mode");
        }

        // 检测规则
        if (config.containsKey("rules.spel")) {
            spelDetectionEnabled = (Boolean) config.get("rules.spel");
        }
        if (config.containsKey("rules.classloader")) {
            classLoaderHookEnabled = (Boolean) config.get("rules.classloader");
        }
        if (config.containsKey("rules.runtime_exec")) {
            runtimeExecHookEnabled = (Boolean) config.get("rules.runtime_exec");
        }
        if (config.containsKey("rules.jndi")) {
            jndiHookEnabled = (Boolean) config.get("rules.jndi");
        }

        // 白名单
        if (config.containsKey("whitelist.components")) {
            componentWhitelist.addAll((List<String>) config.get("whitelist.components"));
        }
        if (config.containsKey("whitelist.classes")) {
            classWhitelist.addAll((List<String>) config.get("whitelist.classes"));
        }

        // SpEL 危险类/方法
        if (config.containsKey("spel.dangerous_classes")) {
            spelDangerousClasses.addAll((List<String>) config.get("spel.dangerous_classes"));
        }
        if (config.containsKey("spel.dangerous_methods")) {
            spelDangerousMethods.addAll((List<String>) config.get("spel.dangerous_methods"));
        }

        // 日志配置
        if (config.containsKey("log.level")) {
            logLevel = (String) config.get("log.level");
        }
        if (config.containsKey("log.file")) {
            logFile = (String) config.get("log.file");
        }

        // 告警配置
        if (config.containsKey("alert.webhook")) {
            alertWebhook = (String) config.get("alert.webhook");
        }
    }

    // Getters
    public boolean isScanEnabled() { return scanEnabled; }
    public int getScanInterval() { return scanInterval; }
    public boolean isBlockMode() { return blockMode; }
    public boolean isSpelDetectionEnabled() { return spelDetectionEnabled; }
    public boolean isClassLoaderHookEnabled() { return classLoaderHookEnabled; }
    public boolean isRuntimeExecHookEnabled() { return runtimeExecHookEnabled; }
    public boolean isJndiHookEnabled() { return jndiHookEnabled; }
    public Set<String> getComponentWhitelist() { return componentWhitelist; }
    public Set<String> getClassWhitelist() { return classWhitelist; }
    public Set<String> getSpelDangerousClasses() { return spelDangerousClasses; }
    public Set<String> getSpelDangerousMethods() { return spelDangerousMethods; }
    public String getLogLevel() { return logLevel; }
    public String getLogFile() { return logFile; }
    public String getAlertWebhook() { return alertWebhook; }

    /**
     * 检查类名是否在白名单中
     */
    public boolean isClassWhitelisted(String className) {
        if (className == null) return false;
        for (String prefix : classWhitelist) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
