package com.grarasp.core.util;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

public class ReflectionCacheTest {

    @After
    public void tearDown() {
        ReflectionCache.clearAll();
    }

    @Test
    public void cachesOverloadedMethodsIndependently() {
        OverloadedTarget target = new OverloadedTarget();

        Object noArgResult = ReflectionCache.invokeMethod(target, "value");
        Object argResult = ReflectionCache.invokeMethod(
            target, "value", new Class<?>[]{String.class}, new Object[]{"codex"});

        Assert.assertEquals("no-arg", noArgResult);
        Assert.assertEquals("arg:codex", argResult);
    }

    public static class OverloadedTarget {
        public String value() {
            return "no-arg";
        }

        public String value(String input) {
            return "arg:" + input;
        }
    }
}
