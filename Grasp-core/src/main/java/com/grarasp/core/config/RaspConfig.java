package com.grarasp.core.config;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RASP configuration manager.
 * Uses a lightweight YAML-like parser to avoid introducing runtime dependencies.
 */
public class RaspConfig {

    private static volatile RaspConfig INSTANCE;
    private static final String CONFIG_FILE = "grarasp.yml";

    private boolean scanEnabled = true;
    private int scanInterval = 30000;

    private boolean blockMode = true;

    private boolean spelDetectionEnabled = true;
    private boolean classLoaderHookEnabled = true;
    private boolean runtimeExecHookEnabled = true;
    private boolean jndiHookEnabled = true;

    private Set<String> componentWhitelist = new HashSet<>();
    private Set<String> classWhitelist = new HashSet<>();

    private Set<String> spelDangerousClasses = new HashSet<>();
    private Set<String> spelDangerousMethods = new HashSet<>();

    private String logLevel = "INFO";
    private String logFile = null;

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

    public static void reload() {
        synchronized (RaspConfig.class) {
            INSTANCE = new RaspConfig();
            INSTANCE.loadConfig();
        }
    }

    private void initDefaults() {
        componentWhitelist.addAll(Arrays.asList(
            "Tomcat WebSocket (JSR356) Filter",
            "ServletRequest Context Filter",
            "WsFilter",
            "org.apache.catalina.valves.ErrorReportValve",
            "org.apache.catalina.valves.AccessLogValve",
            "org.apache.catalina.core.StandardContextValve",
            "org.apache.catalina.authenticator.NonLoginAuthenticator",
            "org.apache.catalina.authenticator.BasicAuthenticator",
            "org.apache.catalina.core.StandardContext$ContextFilterMaps",
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
            "JspServlet",
            "FileServlet",
            "weblogic.servlet.internal.ServletStubImpl"
        ));

        classWhitelist.addAll(Arrays.asList(
            "org.springframework",
            "org.apache.tomcat",
            "org.apache.catalina",
            "weblogic.",
            "com.oracle."
        ));

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
        String configPath = System.getProperty("grarasp.config");
        if (configPath == null) {
            configPath = System.getenv("GRARASP_CONFIG");
        }

        File configFile = null;
        if (configPath != null) {
            configFile = new File(configPath);
        } else {
            String[] paths = {
                CONFIG_FILE,
                "conf/" + CONFIG_FILE,
                "config/" + CONFIG_FILE,
                System.getProperty("user.home") + "/.grarasp/" + CONFIG_FILE
            };
            for (String path : paths) {
                File file = new File(path);
                if (file.exists() && file.isFile()) {
                    configFile = file;
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

    private void parseYaml(File file) throws IOException {
        Map<String, Object> config = new LinkedHashMap<>();
        List<String> currentPath = new ArrayList<>();
        Deque<Integer> indentStack = new ArrayDeque<>();

        try (BufferedReader reader = new BufferedReader(
            new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }

                int indent = 0;
                for (char c : line.toCharArray()) {
                    if (c == ' ') {
                        indent++;
                    } else {
                        break;
                    }
                }

                while (!indentStack.isEmpty() && indent <= indentStack.peek()) {
                    currentPath.remove(currentPath.size() - 1);
                    indentStack.pop();
                }

                if (trimmed.startsWith("- ")) {
                    String fullKey = String.join(".", currentPath);
                    List<String> list = getOrCreateList(config, fullKey);
                    list.add(trimmed.substring(2).trim());
                    continue;
                }

                int colonIndex = trimmed.indexOf(':');
                if (colonIndex < 0) {
                    continue;
                }

                String key = trimmed.substring(0, colonIndex).trim();
                String value = trimmed.substring(colonIndex + 1).trim();
                if (value.isEmpty()) {
                    currentPath.add(key);
                    indentStack.push(indent);
                } else {
                    String fullKey = String.join(".", currentPath);
                    if (!fullKey.isEmpty()) {
                        fullKey += ".";
                    }
                    config.put(fullKey + key, parseValue(value));
                }
            }
        }

        applyConfig(config);
    }

    private List<String> getOrCreateList(Map<String, Object> config, String key) {
        Object existing = config.get(key);
        if (existing instanceof List) {
            @SuppressWarnings("unchecked")
            List<String> list = (List<String>) existing;
            return list;
        }
        List<String> list = new ArrayList<>();
        config.put(key, list);
        return list;
    }

    private Object parseValue(String value) {
        if ((value.startsWith("\"") && value.endsWith("\"")) ||
            (value.startsWith("'") && value.endsWith("'"))) {
            return value.substring(1, value.length() - 1);
        }
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        try {
            if (value.contains(".")) {
                return Double.parseDouble(value);
            }
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return value;
        }
    }

    private void applyConfig(Map<String, Object> config) {
        scanEnabled = getBoolean(config, "scan.enabled", scanEnabled);
        scanInterval = Math.max(1000, getInt(config, "scan.interval", scanInterval));

        blockMode = getBoolean(config, "block_mode", blockMode);

        spelDetectionEnabled = getBoolean(config, "rules.spel", spelDetectionEnabled);
        classLoaderHookEnabled = getBoolean(config, "rules.classloader", classLoaderHookEnabled);
        runtimeExecHookEnabled = getBoolean(config, "rules.runtime_exec", runtimeExecHookEnabled);
        jndiHookEnabled = getBoolean(config, "rules.jndi", jndiHookEnabled);

        componentWhitelist.addAll(getStringList(config, "whitelist.components"));
        classWhitelist.addAll(getStringList(config, "whitelist.classes"));

        spelDangerousClasses.addAll(getStringList(config, "spel.dangerous_classes"));
        spelDangerousMethods.addAll(getStringList(config, "spel.dangerous_methods"));

        logLevel = getString(config, "log.level", logLevel);
        logFile = getString(config, "log.file", logFile);
        alertWebhook = getString(config, "alert.webhook", alertWebhook);
    }

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

    public boolean isClassWhitelisted(String className) {
        if (className == null) return false;
        for (String prefix : classWhitelist) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private boolean getBoolean(Map<String, Object> config, String key, boolean defaultValue) {
        Object value = config.get(key);
        if (value == null) return defaultValue;
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof String) {
            return Boolean.parseBoolean((String) value);
        }
        System.err.println("[GraRasp] Invalid boolean config for " + key + ": " + value);
        return defaultValue;
    }

    private int getInt(Map<String, Object> config, String key, int defaultValue) {
        Object value = config.get(key);
        if (value == null) return defaultValue;
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                // fall through
            }
        }
        System.err.println("[GraRasp] Invalid integer config for " + key + ": " + value);
        return defaultValue;
    }

    private String getString(Map<String, Object> config, String key, String defaultValue) {
        Object value = config.get(key);
        return value == null ? defaultValue : String.valueOf(value);
    }

    private List<String> getStringList(Map<String, Object> config, String key) {
        Object value = config.get(key);
        if (value == null) {
            return Collections.emptyList();
        }
        if (value instanceof List) {
            List<?> raw = (List<?>) value;
            List<String> result = new ArrayList<>(raw.size());
            for (Object item : raw) {
                result.add(String.valueOf(item));
            }
            return result;
        }
        System.err.println("[GraRasp] Invalid list config for " + key + ": " + value);
        return Collections.emptyList();
    }
}
