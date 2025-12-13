package com.grarasp.spy;

/**
 * Spy 类是 RASP 注入到目标业务代码中的"探针"。
 * 业务代码（如 Tomcat）通过这个类调用 Core 的检测逻辑。
 */
public class Spy {

    // 这是一个钩子接口，将来具体的检测逻辑会注入到这里
    public static volatile SpyHandler spyHandler;

    /**
     * 业务代码被插桩后，会调用这个方法
     * @param type hook 类型 (例如 "file", "rce")
     * @param className 类名
     * @param method 方法名
     * @param params 方法参数
     */
    public static void check(String type, String className, String method, Object[] params) {
        if (spyHandler != null) {
            spyHandler.handleCheck(type, className, method, params);
        } else {
            // 如果核心还没加载，什么都不做，直接放行
        }
    }

    // 定义一个简单的接口，让 Core 去实现
    public interface SpyHandler {
        void handleCheck(String type, String className, String method, Object[] params);
    }
}