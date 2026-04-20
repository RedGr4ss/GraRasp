package com.grarasp.core.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Caches reflection lookups to improve performance
 * Reduces overhead from repeated Method/Field lookups and setAccessible calls
 */
public class ReflectionCache {

    private static final Map<String, Method> methodCache = new ConcurrentHashMap<>();
    private static final Map<String, Field> fieldCache = new ConcurrentHashMap<>();

    /**
     * Get or cache a method
     * @return Method object or null if not found
     */
    public static Method getMethod(Object target, String methodName, Class<?>... paramTypes) {
        if (target == null) return null;

        String key = buildMethodKey(target.getClass(), methodName, paramTypes);
        return methodCache.computeIfAbsent(key, k -> {
            try {
                Method m = target.getClass().getMethod(methodName, paramTypes);
                m.setAccessible(true);
                return m;
            } catch (Exception e) {
                return null;
            }
        });
    }

    /**
     * Get or cache a field (searches superclasses)
     * @return Field object or null if not found
     */
    public static Field getField(Object target, String fieldName) {
        if (target == null) return null;

        String key = target.getClass().getName() + "." + fieldName;
        return fieldCache.computeIfAbsent(key, k -> {
            Class<?> clazz = target.getClass();
            while (clazz != null) {
                try {
                    Field f = clazz.getDeclaredField(fieldName);
                    f.setAccessible(true);
                    return f;
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            return null;
        });
    }

    /**
     * Invoke a cached method and return String value
     */
    public static String invokeMethodAsString(Object target, String methodName) {
        try {
            Method m = getMethod(target, methodName);
            if (m != null) {
                return String.valueOf(m.invoke(target));
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Invoke a cached method and return Object value
     */
    public static Object invokeMethod(Object target, String methodName) {
        try {
            Method m = getMethod(target, methodName);
            if (m != null) {
                return m.invoke(target);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Invoke a method with parameters and return Object value
     */
    public static Object invokeMethod(Object target, String methodName, Class<?>[] paramTypes, Object[] args) {
        try {
            Method m = getMethod(target, methodName, paramTypes);
            if (m != null) {
                return m.invoke(target, args);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Get field value using cached Field
     */
    public static Object getFieldValue(Object target, String fieldName) {
        try {
            Field f = getField(target, fieldName);
            if (f != null) {
                return f.get(target);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Clear all caches (for testing or when ClassLoaders are unloaded)
     */
    public static void clearAll() {
        methodCache.clear();
        fieldCache.clear();
    }

    private static String buildMethodKey(Class<?> targetClass, String methodName, Class<?>... paramTypes) {
        StringBuilder key = new StringBuilder(targetClass.getName())
            .append('#')
            .append(methodName)
            .append('(');

        if (paramTypes != null && paramTypes.length > 0) {
            key.append(Arrays.toString(paramTypes));
        }

        return key.append(')').toString();
    }
}
