package com.grarasp.core.detector;

import com.grarasp.core.config.RaspConfig;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * JNDI 注入检测器
 * 检测 JNDI lookup 中的恶意协议和地址
 */
public class JndiDetector {

    // 危险协议
    private static final Set<String> DANGEROUS_PROTOCOLS = new HashSet<>(Arrays.asList(
        "ldap://",
        "ldaps://",
        "rmi://",
        "dns://",
        "iiop://",
        "corba://",
        "nds://",
        "nis://"
    ));

    // 本地安全协议（白名单）
    private static final Set<String> SAFE_PROTOCOLS = new HashSet<>(Arrays.asList(
        "java:",
        "jndi:",
        "jdbc:"
    ));

    // IP 地址模式
    private static final Pattern IP_PATTERN = Pattern.compile(
        "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
    );

    // 内网 IP 段
    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile(
        "(^127\\.)|(^10\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^192\\.168\\.)"
    );

    // 可疑域名模式（常见 DNSLog 平台）
    private static final Set<String> DNSLOG_DOMAINS = new HashSet<>(Arrays.asList(
        "dnslog.cn",
        "ceye.io",
        "burpcollaborator.net",
        "oastify.com",
        "interact.sh",
        "requestbin.net",
        "pipedream.net",
        "webhook.site",
        "ngrok.io",
        "localtunnel.me"
    ));

    /**
     * 检测 JNDI lookup 名称是否危险
     * @param name JNDI 名称
     * @return 检测结果，null 表示安全，否则返回威胁描述
     */
    public static String detect(String name) {
        if (name == null || name.isEmpty()) {
            return null;
        }

        RaspConfig config = RaspConfig.getInstance();
        if (!config.isJndiHookEnabled()) {
            return null;
        }

        String lowerName = name.toLowerCase();

        // 1. 检查是否是安全协议
        for (String safe : SAFE_PROTOCOLS) {
            if (lowerName.startsWith(safe)) {
                return null; // 安全
            }
        }

        // 2. 检测危险协议
        for (String dangerous : DANGEROUS_PROTOCOLS) {
            if (lowerName.startsWith(dangerous)) {
                return detectDangerousLookup(name, dangerous);
            }
        }

        // 3. 检测变形绕过
        String bypassResult = checkBypassTechniques(name);
        if (bypassResult != null) {
            return bypassResult;
        }

        return null;
    }

    /**
     * 检测危险的 JNDI lookup
     */
    private static String detectDangerousLookup(String name, String protocol) {
        // 提取主机部分
        String hostPart = name.substring(protocol.length());
        int slashIndex = hostPart.indexOf('/');
        if (slashIndex > 0) {
            hostPart = hostPart.substring(0, slashIndex);
        }
        int colonIndex = hostPart.indexOf(':');
        if (colonIndex > 0) {
            hostPart = hostPart.substring(0, colonIndex);
        }

        // 检测外部 IP
        if (IP_PATTERN.matcher(hostPart).matches()) {
            if (!INTERNAL_IP_PATTERN.matcher(hostPart).find()) {
                return "JNDI injection to external IP: " + name;
            }
            // 即使是内网 IP，LDAP/RMI 也很可疑
            if (protocol.startsWith("ldap") || protocol.startsWith("rmi")) {
                return "JNDI injection to internal IP (suspicious): " + name;
            }
        }

        // 检测 DNSLog 域名
        for (String dnslog : DNSLOG_DOMAINS) {
            if (hostPart.endsWith(dnslog)) {
                return "JNDI injection to DNSLog platform: " + name;
            }
        }

        // 检测 localhost 变体
        if (hostPart.equals("localhost") || hostPart.equals("127.0.0.1") || hostPart.equals("0.0.0.0")) {
            // 本地 LDAP/RMI 也可能是攻击（本地起恶意服务）
            if (protocol.startsWith("ldap") || protocol.startsWith("rmi")) {
                return "JNDI injection to localhost (suspicious): " + name;
            }
        }

        // 默认：任何外部 LDAP/RMI 都是危险的
        if (protocol.startsWith("ldap") || protocol.startsWith("rmi")) {
            return "JNDI injection detected [" + protocol + "]: " + name;
        }

        return null;
    }

    /**
     * 检测绕过技术
     */
    private static String checkBypassTechniques(String name) {
        String lower = name.toLowerCase();

        // 1. URL 编码绕过
        if (name.contains("%")) {
            String decoded = urlDecode(name);
            if (!decoded.equals(name)) {
                String result = detect(decoded);
                if (result != null) {
                    return "URL encoded bypass: " + result;
                }
            }
        }

        // 2. Unicode 绕过
        if (name.contains("\\u")) {
            String decoded = unicodeDecode(name);
            if (!decoded.equals(name)) {
                String result = detect(decoded);
                if (result != null) {
                    return "Unicode bypass: " + result;
                }
            }
        }

        // 3. 大小写混淆
        // ldAp:// LDAP:// 等
        for (String protocol : DANGEROUS_PROTOCOLS) {
            String protocolName = protocol.substring(0, protocol.indexOf(':'));
            if (lower.startsWith(protocolName + ":")) {
                return "Case-insensitive protocol bypass: " + name;
            }
        }

        // 4. 空格/特殊字符绕过
        String trimmed = name.replaceAll("\\s", "");
        if (!trimmed.equals(name)) {
            String result = detect(trimmed);
            if (result != null) {
                return "Whitespace bypass: " + result;
            }
        }

        // 5. ${} 表达式绕过 (Log4j style)
        if (name.contains("${") && name.contains("}")) {
            return "Expression injection in JNDI name: " + name;
        }

        return null;
    }

    /**
     * URL 解码
     */
    private static String urlDecode(String input) {
        try {
            return java.net.URLDecoder.decode(input, "UTF-8");
        } catch (Exception e) {
            return input;
        }
    }

    /**
     * Unicode 解码
     */
    private static String unicodeDecode(String input) {
        if (input == null || !input.contains("\\u")) {
            return input;
        }

        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < input.length()) {
            if (i + 5 < input.length() && input.charAt(i) == '\\' && input.charAt(i + 1) == 'u') {
                try {
                    int code = Integer.parseInt(input.substring(i + 2, i + 6), 16);
                    sb.append((char) code);
                    i += 6;
                    continue;
                } catch (NumberFormatException e) {
                    // 不是有效的 Unicode 转义
                }
            }
            sb.append(input.charAt(i));
            i++;
        }
        return sb.toString();
    }

    /**
     * 检测调用栈是否来自可疑来源
     */
    public static boolean isSuspiciousSource(StackTraceElement[] stack) {
        if (stack == null) return false;

        for (StackTraceElement element : stack) {
            String cls = element.getClassName();
            // 来自反序列化
            if (cls.contains("ObjectInputStream") ||
                cls.contains("readObject")) {
                return true;
            }
            // 来自 Log4j
            if (cls.contains("log4j") ||
                cls.contains("logging")) {
                return true;
            }
            // 来自表达式引擎
            if (cls.contains("ognl") ||
                cls.contains("spel") ||
                cls.contains("mvel") ||
                cls.contains("jexl")) {
                return true;
            }
            // 来自 Fastjson/Jackson
            if (cls.contains("fastjson") ||
                cls.contains("jackson") ||
                cls.contains("gson")) {
                return true;
            }
        }
        return false;
    }
}
