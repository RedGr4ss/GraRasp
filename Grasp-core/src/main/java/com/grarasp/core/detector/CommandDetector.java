package com.grarasp.core.detector;

import com.grarasp.core.config.RaspConfig;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 命令执行检测器
 * 检测 Runtime.exec、ProcessBuilder、ScriptEngine 等命令执行
 */
public class CommandDetector {

    // 危险命令关键字
    private static final Set<String> DANGEROUS_COMMANDS = new HashSet<>(Arrays.asList(
        // Linux/Unix
        "bash", "sh", "zsh", "ksh", "csh",
        "wget", "curl", "nc", "netcat", "ncat",
        "python", "python3", "perl", "ruby", "php",
        "chmod", "chown", "rm", "mkfifo",
        "base64", "xxd", "od",
        "/bin/", "/usr/bin/", "/tmp/",
        // Windows
        "cmd", "cmd.exe", "powershell", "powershell.exe",
        "certutil", "bitsadmin", "mshta", "regsvr32",
        "wscript", "cscript",
        // 通用危险
        "whoami", "id", "uname",
        "cat /etc/passwd", "type c:\\",
        "net user", "net localgroup",
        // 反弹 shell
        "/dev/tcp/", "mkfifo", "telnet"
    ));

    // 反弹 shell 模式
    private static final Pattern REVERSE_SHELL_PATTERN = Pattern.compile(
        "(bash\\s+-i|/dev/tcp/|nc\\s+-e|ncat\\s+-e|" +
        "python\\s+-c.*socket|perl\\s+-e.*socket|" +
        "php\\s+-r.*fsockopen|ruby\\s+-rsocket|" +
        "\\|\\s*sh|\\|\\s*bash)",
        Pattern.CASE_INSENSITIVE
    );

    // Base64 编码命令模式
    private static final Pattern BASE64_PATTERN = Pattern.compile(
        "(echo\\s+[A-Za-z0-9+/=]{20,}\\s*\\|\\s*base64\\s+-d|" +
        "base64\\s+-d\\s*<<<|" +
        "\\$\\(echo\\s+[A-Za-z0-9+/=]+\\s*\\|\\s*base64\\s+-d\\))",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * 检测命令是否危险
     * @param command 命令字符串或命令数组
     * @return 检测结果，null 表示安全，否则返回威胁描述
     */
    public static String detect(Object command) {
        if (command == null) {
            return null;
        }

        RaspConfig config = RaspConfig.getInstance();
        if (!config.isRuntimeExecHookEnabled()) {
            return null;
        }

        String cmdStr;
        if (command instanceof String[]) {
            cmdStr = String.join(" ", (String[]) command);
        } else if (command instanceof String) {
            cmdStr = (String) command;
        } else {
            cmdStr = command.toString();
        }

        // 1. 检测反弹 shell
        if (REVERSE_SHELL_PATTERN.matcher(cmdStr).find()) {
            return "Reverse shell detected: " + truncate(cmdStr, 100);
        }

        // 2. 检测 Base64 编码命令
        if (BASE64_PATTERN.matcher(cmdStr).find()) {
            return "Base64 encoded command detected: " + truncate(cmdStr, 100);
        }

        // 3. 检测危险命令关键字
        String lowerCmd = cmdStr.toLowerCase();
        for (String dangerous : DANGEROUS_COMMANDS) {
            if (lowerCmd.contains(dangerous.toLowerCase())) {
                // 进一步分析是否真的危险
                if (isReallyDangerous(cmdStr, dangerous)) {
                    return "Dangerous command detected [" + dangerous + "]: " + truncate(cmdStr, 100);
                }
            }
        }

        // 4. 检测命令注入特征
        String injectionResult = checkCommandInjection(cmdStr);
        if (injectionResult != null) {
            return injectionResult;
        }

        return null;
    }

    /**
     * 检测命令注入特征
     */
    private static String checkCommandInjection(String cmd) {
        // 命令分隔符
        if (cmd.contains(";") || cmd.contains("&&") || cmd.contains("||")) {
            // 检查是否有多个命令
            String[] parts = cmd.split("[;&|]+");
            if (parts.length > 1) {
                for (String part : parts) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty() && containsDangerousCommand(trimmed)) {
                        return "Command injection detected: " + truncate(cmd, 100);
                    }
                }
            }
        }

        // 命令替换
        if (cmd.contains("$(") || cmd.contains("`")) {
            return "Command substitution detected: " + truncate(cmd, 100);
        }

        // 管道到 shell
        if (cmd.matches(".*\\|\\s*(sh|bash|zsh|ksh).*")) {
            return "Pipe to shell detected: " + truncate(cmd, 100);
        }

        return null;
    }

    /**
     * 进一步判断是否真的危险
     */
    private static boolean isReallyDangerous(String cmd, String keyword) {
        // 某些关键字需要上下文判断
        String lower = cmd.toLowerCase();

        // wget/curl 下载到可执行位置
        if (keyword.equals("wget") || keyword.equals("curl")) {
            return lower.contains("-o") || lower.contains(">") ||
                   lower.contains("/tmp/") || lower.contains("/var/tmp/") ||
                   lower.contains("| sh") || lower.contains("| bash");
        }

        // chmod 修改权限
        if (keyword.equals("chmod")) {
            return lower.contains("+x") || lower.contains("777") || lower.contains("755");
        }

        // 其他关键字直接认为危险
        return true;
    }

    private static boolean containsDangerousCommand(String cmd) {
        String lower = cmd.toLowerCase();
        for (String dangerous : DANGEROUS_COMMANDS) {
            if (lower.contains(dangerous.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private static String truncate(String str, int maxLen) {
        if (str == null) return null;
        if (str.length() <= maxLen) return str;
        return str.substring(0, maxLen) + "...";
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
            // 来自表达式引擎
            if (cls.contains("ognl") ||
                cls.contains("spel") ||
                cls.contains("mvel") ||
                cls.contains("jexl") ||
                cls.contains("freemarker") ||
                cls.contains("velocity")) {
                return true;
            }
            // 来自脚本引擎
            if (cls.contains("javax.script") ||
                cls.contains("ScriptEngine") ||
                cls.contains("Nashorn") ||
                cls.contains("rhino")) {
                return true;
            }
            // 来自已知攻击工具
            if (cls.contains("behinder") ||
                cls.contains("godzilla") ||
                cls.contains("metasploit") ||
                cls.contains("cobalt")) {
                return true;
            }
        }
        return false;
    }
}
