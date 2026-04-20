package com.grarasp.core;

import org.junit.Assert;
import org.junit.Test;

public class RiskScoreTuningTest {

    @Test
    public void weakNamingSignalsAloneStayBelowWarnThreshold() {
        Assert.assertTrue(
            GraspCore.calculateRiskScore("Servlet", "RequestHeaderExample", "RequestHeaderExample", null) < 30
        );
    }

    @Test
    public void obviousMaliciousClassNamesStillReachWarnThreshold() {
        Assert.assertTrue(
            GraspCore.calculateRiskScore("Servlet", "evilServlet", "com.evil.memshell.GodzillaServlet", null) >= 30
        );
    }
}
