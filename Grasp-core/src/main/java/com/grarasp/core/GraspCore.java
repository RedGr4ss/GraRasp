package com.grarasp.core;

import com.grarasp.spy.Spy;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * [生产环境版] 核心逻辑实现类
 * 移除了调试日志，保留了核心的阻断能力
 */
public class GraspCore implements Spy.SpyHandler {

    // [配置] 是否开启阻断模式
    private static final boolean BLOCK_MODE = true;

    public static void init() {
        Spy.spyHandler = new GraspCore();
        System.out.println("[GraRasp] Core initialized. Protection Online.");
    }

    @Override
    public void handleCheck(String type, String className, String method, Object[] params) {
        // 1. 内存马检测
        if (type != null && type.startsWith("memshell")) {
            checkMemoryShell(type, params);
        }

        // 2. RCE 检测 (如果保留了相关插件)
        if ("rce".equals(type)) {
            // checkRCE(params);
        }
    }

    /**
     * 核心检测逻辑：运行时状态检查
     */
    private void checkMemoryShell(String type, Object[] params) {
        if (params == null || params.length < 2) return;

        Object targetObject = params[0];
        Object component = params[1];

        try {
            String state = "UNKNOWN";
            Object realContext = targetObject;

            // 特殊处理 WebSocket：需要从 WsServerContainer 中提取 StandardContext
            if (type.contains("websocket")) {
                realContext = extractStandardContextFromWs(targetObject);
            }

            // 获取生命周期状态
            if (realContext != null) {
                try {
                    Method getStateMethod = realContext.getClass().getMethod("getState");
                    getStateMethod.setAccessible(true);
                    state = String.valueOf(getStateMethod.invoke(realContext));
                } catch (NoSuchMethodException e) {
                    // 忽略没有 getState 方法的对象
                }
            }

            // [核心判断] 如果是 STARTED 状态下的注册行为 -> 阻断
            if ("STARTED".equalsIgnoreCase(state)) {

                // 1. 打印红色的安全告警日志 (这是运维需要看到的)
                System.err.println("========================================");
                System.err.println("[GraRasp Security Alert] 🚨 Memory Shell Detected!");
                System.err.println("Type:    " + type);
                System.err.println("Context: " + (realContext != null ? realContext.getClass().getName() : "null"));
                System.err.println("State:   " + state + " (Suspicious: Runtime Modification)");
                System.err.println("Payload: " + (component != null ? component.getClass().getName() : "null"));
                System.err.println("========================================");

                // 2. 抛出异常阻断
                if (BLOCK_MODE) {
                    throw new SecurityException("GraRasp Blocked: Runtime " + type + " registration is not allowed in STARTED state!");
                }
            }

        } catch (Exception e) {
            // 如果是我们抛出的 SecurityException，必须向上抛出以实现阻断
            if (e instanceof SecurityException) {
                throw (SecurityException) e;
            }
            // 其他异常（如反射失败）通常选择静默处理，避免影响业务稳定性
        }
    }

    /**
     * 从 WsServerContainer 中提取 StandardContext
     * 路径: WsServerContainer.servletContext -> ApplicationContextFacade.context -> ApplicationContext.context -> StandardContext
     */
    private Object extractStandardContextFromWs(Object wsContainer) {
        try {
            Object facade = getFieldValue(wsContainer, "servletContext");
            if (facade == null) return null;

            Object appContext = getFieldValue(facade, "context");
            if (appContext == null) return null;

            return getFieldValue(appContext, "context");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 工具方法：递归反射获取字段值
     */
    private Object getFieldValue(Object target, String fieldName) {
        if (target == null) return null;
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(target);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }
}