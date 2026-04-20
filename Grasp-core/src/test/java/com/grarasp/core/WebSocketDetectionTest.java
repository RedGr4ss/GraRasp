package com.grarasp.core;

import org.junit.Assert;
import org.junit.Test;

public class WebSocketDetectionTest {

    @Test
    public void allowsExpectedStartupRegistration() {
        StackTraceElement[] stack = new StackTraceElement[]{
            new StackTraceElement("org.apache.tomcat.websocket.server.WsSci", "onStartup", "WsSci.java", 112)
        };

        Assert.assertFalse(
            GraspCore.shouldBlockWebSocketRegistration(
                "/websocket/drawboard",
                "websocket.drawboard.DrawboardEndpoint",
                stack
            )
        );
    }

    @Test
    public void blocksSuspiciousEndpointEvenDuringStartup() {
        StackTraceElement[] stack = new StackTraceElement[]{
            new StackTraceElement("org.apache.tomcat.websocket.server.WsSci", "onStartup", "WsSci.java", 112)
        };

        Assert.assertTrue(
            GraspCore.shouldBlockWebSocketRegistration(
                "/shell/ws",
                "com.evil.memshell.GodzillaEndpoint",
                stack
            )
        );
    }

    @Test
    public void blocksNonStartupRegistrationWithRiskySource() {
        StackTraceElement[] stack = new StackTraceElement[]{
            new StackTraceElement("org.apache.jsp.test_jsp", "_jspService", "test.jsp", 12)
        };

        Assert.assertTrue(
            GraspCore.shouldBlockWebSocketRegistration(
                "/chat",
                "com.demo.ChatEndpoint",
                stack
            )
        );
    }
}
