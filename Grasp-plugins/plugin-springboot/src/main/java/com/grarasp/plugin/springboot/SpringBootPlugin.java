package com.grarasp.plugin.springboot;

import com.grarasp.core.plugin.IPlugin;
import com.grarasp.core.util.ClassPoolManager;
import com.grarasp.core.util.ErrorReporter;
import javassist.*;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

public class SpringBootPlugin implements IPlugin {

    // 目标：Spring SpEL 表达式解析器
    private static final String TARGET_SPEL_PARSER = "org.springframework.expression.spel.standard.SpelExpressionParser";

    @Override
    public Collection<String> getTargetClassNames() {
        return Arrays.asList(TARGET_SPEL_PARSER);
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, byte[] classfileBuffer) throws Exception {
        if (!TARGET_SPEL_PARSER.equals(className)) {
            return null;
        }

        try {
            ClassPool cp = ClassPoolManager.getClassPool(loader);
            CtClass cc = cp.makeClass(new ByteArrayInputStream(classfileBuffer));

            // Hook doParseExpression(String expressionString, ParserContext context)
            // 这是解析表达式的入口，$1 是 expressionString
            CtMethod m = cc.getDeclaredMethod("doParseExpression");

            // 插入 Spy.check 调用，类型为 "rce_spel"
            m.insertBefore("{ com.grarasp.spy.Spy.check(\"rce_spel\", \"SpelExpressionParser\", \"doParseExpression\", new Object[]{$1}); }");

            System.out.println("[SpringBootPlugin] ✅ Hooked SpelExpressionParser success!");

            byte[] byteCode = cc.toBytecode();
            cc.detach();
            return byteCode;

        } catch (Exception e) {
            ErrorReporter.reportError(ErrorReporter.ErrorType.PLUGIN_TRANSFORM,
                "Hook SpelExpressionParser failed", e);
        }
        return null;
    }
}