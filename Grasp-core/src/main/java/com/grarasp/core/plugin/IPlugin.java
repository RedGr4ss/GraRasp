package com.grarasp.core.plugin;

import java.util.Collection;

public interface IPlugin {

    /**
     * [升级] 现在支持返回多个目标类名
     * @return 目标类名集合
     */
    Collection<String> getTargetClassNames();

    /**
     * 转换逻辑
     */
    byte[] transform(ClassLoader loader, String className, byte[] classfileBuffer) throws Exception;
}