package com.grarasp.core.config;

import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

public class RaspConfigTest {

    @Test
    public void parsesUtf8AndNestedLists() throws Exception {
        File tempFile = File.createTempFile("grarasp-config", ".yml");
        tempFile.deleteOnExit();

        String yaml =
            "block_mode: false\n" +
            "scan:\n" +
            "  interval: 500\n" +
            "whitelist:\n" +
            "  components:\n" +
            "    - 自定义过滤器\n" +
            "rules:\n" +
            "  runtime_exec: false\n";

        try (FileOutputStream output = new FileOutputStream(tempFile)) {
            output.write(yaml.getBytes(StandardCharsets.UTF_8));
        }

        RaspConfig config = newConfigInstance();
        Method parseYaml = RaspConfig.class.getDeclaredMethod("parseYaml", File.class);
        parseYaml.setAccessible(true);
        parseYaml.invoke(config, tempFile);

        Assert.assertFalse(config.isBlockMode());
        Assert.assertEquals(1000, config.getScanInterval());
        Assert.assertFalse(config.isRuntimeExecHookEnabled());
        Assert.assertTrue(config.getComponentWhitelist().contains("自定义过滤器"));
    }

    private RaspConfig newConfigInstance() throws Exception {
        Constructor<RaspConfig> constructor = RaspConfig.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        return constructor.newInstance();
    }
}
