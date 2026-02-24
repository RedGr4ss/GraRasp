package com.grarasp.core.util;

import javassist.ClassPool;
import javassist.LoaderClassPath;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared ClassPool manager to prevent memory leaks
 * Reuses ClassPool instances per ClassLoader and provides proper cleanup
 */
public class ClassPoolManager {

    private static final Map<ClassLoader, ClassPool> poolCache = new ConcurrentHashMap<>();
    private static final ClassPool defaultPool = ClassPool.getDefault();

    /**
     * Get or create a ClassPool for the given ClassLoader
     * @param loader the ClassLoader (null for bootstrap)
     * @return a managed ClassPool instance
     */
    public static ClassPool getClassPool(ClassLoader loader) {
        if (loader == null) {
            return defaultPool;
        }

        return poolCache.computeIfAbsent(loader, cl -> {
            ClassPool pool = new ClassPool(defaultPool);
            pool.appendClassPath(new LoaderClassPath(cl));
            return pool;
        });
    }

    /**
     * Clean up ClassPool for a specific ClassLoader
     * Call this when a ClassLoader is being unloaded
     */
    public static void removeClassPool(ClassLoader loader) {
        if (loader != null) {
            ClassPool pool = poolCache.remove(loader);
            if (pool != null) {
                pool.clearImportedPackages();
            }
        }
    }

    /**
     * Clear all cached ClassPools (for testing or shutdown)
     */
    public static void clearAll() {
        for (ClassPool pool : poolCache.values()) {
            pool.clearImportedPackages();
        }
        poolCache.clear();
    }
}
