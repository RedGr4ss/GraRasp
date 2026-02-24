package com.grarasp.core.detector;

import com.grarasp.core.config.RaspConfig;

import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SpEL 表达式安全检测器
 * 增强版：支持 Unicode 解码、空格规范化、多种绕过检测
 */
public class SpelDetector {

    // Unicode 转义模式: \\uXXXX
    private static final Pattern UNICODE_PATTERN = Pattern.compile("\\\\u([0-9a-fA-F]{4})");

    // 八进制转义模式: \\XXX
    private static final Pattern OCTAL_PATTERN = Pattern.compile("\\\\([0-7]{1,3})");

    // T() 类型表达式模式
    private static final Pattern TYPE_PATTERN = Pattern.compile(
        "T\\s*\\(\\s*([\\w.$]+)\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    // new 实例化模式
    private static final Pattern NEW_PATTERN = Pattern.compile(
        "new\\s+([\\w.$]+)\\s*\\(",
        Pattern.CASE_INSENSITIVE
    );

    // 方法调用模式
    private static final Pattern METHOD_PATTERN = Pattern.compile(
        "\\.\\s*([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\("
    );

    // 反射调用模式
    private static final Pattern REFLECTION_PATTERN = Pattern.compile(
        "(getClass|forName|getMethod|getDeclaredMethod|invoke|newInstance|getConstructor)\\s*\\("
    );

    // 字符串拼接绕过检测
    private static final Pattern CONCAT_PATTERN = Pattern.compile(
        "(['\"]\\s*\\+\\s*['\"])|(\\.concat\\s*\\()"
    );

    /**
     * 检测 SpEL 表达式是否包含恶意内容
     * @return 检测结果，null 表示安全，否则返回威胁描述
     */
    public static String detect(String expression) {
        if (expression == null || expression.isEmpty()) {
            return null;
        }

        RaspConfig config = RaspConfig.getInstance();
        if (!config.isSpelDetectionEnabled()) {
            return null;
        }

        // 1. 预处理：解码和规范化
        String normalized = normalize(expression);

        // 2. 检测 T() 类型表达式中的危险类
        String typeResult = checkTypeExpression(normalized, config.getSpelDangerousClasses());
        if (typeResult != null) {
            return typeResult;
        }

        // 3. 检测 new 实例化危险类
        String newResult = checkNewExpression(normalized, config.getSpelDangerousClasses());
        if (newResult != null) {
            return newResult;
        }

        // 4. 检测危险方法调用
        String methodResult = checkDangerousMethods(normalized, config.getSpelDangerousMethods());
        if (methodResult != null) {
            return methodResult;
        }

        // 5. 检测反射调用链
        String reflectionResult = checkReflectionChain(normalized);
        if (reflectionResult != null) {
            return reflectionResult;
        }

        // 6. 检测字符串拼接绕过
        if (hasStringConcatBypass(normalized)) {
            // 对拼接后的字符串再次检测
            String concatenated = simulateConcat(normalized);
            if (concatenated != null) {
                String concatResult = detect(concatenated);
                if (concatResult != null) {
                    return "String concatenation bypass detected: " + concatResult;
                }
            }
        }

        return null;
    }

    /**
     * 规范化表达式：解码 Unicode、去除多余空格
     */
    public static String normalize(String expression) {
        if (expression == null) return null;

        String result = expression;

        // 1. 解码 Unicode 转义
        result = decodeUnicode(result);

        // 2. 解码八进制转义
        result = decodeOctal(result);

        // 3. 解码 HTML 实体
        result = decodeHtmlEntities(result);

        // 4. 规范化空格（保留单个空格）
        result = result.replaceAll("\\s+", " ");

        // 5. 去除注释
        result = removeComments(result);

        return result;
    }

    /**
     * 解码 Unicode 转义序列
     */
    private static String decodeUnicode(String input) {
        if (input == null || !input.contains("\\u")) {
            return input;
        }

        StringBuffer sb = new StringBuffer();
        Matcher matcher = UNICODE_PATTERN.matcher(input);
        while (matcher.find()) {
            int codePoint = Integer.parseInt(matcher.group(1), 16);
            matcher.appendReplacement(sb, String.valueOf((char) codePoint));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * 解码八进制转义序列
     */
    private static String decodeOctal(String input) {
        if (input == null || !input.contains("\\")) {
            return input;
        }

        StringBuffer sb = new StringBuffer();
        Matcher matcher = OCTAL_PATTERN.matcher(input);
        while (matcher.find()) {
            int codePoint = Integer.parseInt(matcher.group(1), 8);
            matcher.appendReplacement(sb, String.valueOf((char) codePoint));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * 解码 HTML 实体
     */
    private static String decodeHtmlEntities(String input) {
        if (input == null) return null;

        return input
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&apos;", "'");
    }

    /**
     * 去除注释
     */
    private static String removeComments(String input) {
        if (input == null) return null;

        // 去除单行注释
        input = input.replaceAll("//.*", "");
        // 去除多行注释
        input = input.replaceAll("/\\*.*?\\*/", "");

        return input;
    }

    /**
     * 检测 T() 类型表达式
     */
    private static String checkTypeExpression(String expression, Set<String> dangerousClasses) {
        Matcher matcher = TYPE_PATTERN.matcher(expression);
        while (matcher.find()) {
            String className = matcher.group(1);
            // 规范化类名（去除空格）
            className = className.replaceAll("\\s", "");

            for (String dangerous : dangerousClasses) {
                if (className.equalsIgnoreCase(dangerous) ||
                    className.endsWith("." + dangerous) ||
                    dangerous.endsWith("." + className)) {
                    return "Dangerous class in T() expression: " + className;
                }
            }
        }
        return null;
    }

    /**
     * 检测 new 实例化表达式
     */
    private static String checkNewExpression(String expression, Set<String> dangerousClasses) {
        Matcher matcher = NEW_PATTERN.matcher(expression);
        while (matcher.find()) {
            String className = matcher.group(1);
            className = className.replaceAll("\\s", "");

            for (String dangerous : dangerousClasses) {
                if (className.equalsIgnoreCase(dangerous) ||
                    className.endsWith("." + dangerous) ||
                    dangerous.endsWith("." + className)) {
                    return "Dangerous class instantiation: new " + className;
                }
            }
        }
        return null;
    }

    /**
     * 检测危险方法调用
     */
    private static String checkDangerousMethods(String expression, Set<String> dangerousMethods) {
        Matcher matcher = METHOD_PATTERN.matcher(expression);
        while (matcher.find()) {
            String methodName = matcher.group(1);
            if (dangerousMethods.contains(methodName)) {
                return "Dangerous method call: " + methodName + "()";
            }
        }
        return null;
    }

    /**
     * 检测反射调用链
     */
    private static String checkReflectionChain(String expression) {
        Matcher matcher = REFLECTION_PATTERN.matcher(expression);
        int reflectionCount = 0;
        StringBuilder methods = new StringBuilder();

        while (matcher.find()) {
            reflectionCount++;
            if (methods.length() > 0) methods.append(" -> ");
            methods.append(matcher.group(1));
        }

        // 检测到反射链（2个以上反射方法调用）
        if (reflectionCount >= 2) {
            return "Reflection chain detected: " + methods;
        }

        // 单个反射调用也需要警告
        if (reflectionCount == 1 && expression.contains("invoke")) {
            return "Reflection invoke detected: " + methods;
        }

        return null;
    }

    /**
     * 检测字符串拼接绕过
     */
    private static boolean hasStringConcatBypass(String expression) {
        return CONCAT_PATTERN.matcher(expression).find();
    }

    /**
     * 模拟字符串拼接（简单实现）
     */
    private static String simulateConcat(String expression) {
        // 简单的字符串拼接模拟
        // 例如: 'java.lang.' + 'Runtime' -> 'java.lang.Runtime'
        try {
            // 移除拼接操作符，合并字符串
            String result = expression
                .replaceAll("['\"]\\s*\\+\\s*['\"]", "")
                .replaceAll("\\.concat\\s*\\(['\"]([^'\"]*)['\"]\\)", "$1");
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 快速检测（用于高性能场景）
     * 只做基本的关键字匹配，不做完整解析
     */
    public static boolean quickCheck(String expression) {
        if (expression == null || expression.isEmpty()) {
            return false;
        }

        String lower = expression.toLowerCase();

        // 快速关键字检测
        return lower.contains("runtime") ||
               lower.contains("processbuilder") ||
               lower.contains("exec") ||
               lower.contains("getruntime") ||
               lower.contains("scriptengine") ||
               lower.contains("classloader") ||
               lower.contains("forname") ||
               lower.contains("getmethod") ||
               lower.contains("invoke") ||
               lower.contains("unsafe") ||
               lower.contains("initialcontext") ||
               lower.contains("lookup");
    }
}
