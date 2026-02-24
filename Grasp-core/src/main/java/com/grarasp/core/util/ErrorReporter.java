package com.grarasp.core.util;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Centralized error reporting and metrics collection
 */
public class ErrorReporter {

    private static final AtomicLong totalErrors = new AtomicLong(0);
    private static final AtomicLong pluginErrors = new AtomicLong(0);
    private static final AtomicLong scanErrors = new AtomicLong(0);
    private static final AtomicLong detectionErrors = new AtomicLong(0);

    public enum ErrorType {
        PLUGIN_TRANSFORM,
        SCANNER,
        DETECTION,
        REFLECTION,
        GENERAL
    }

    /**
     * Report an error with context
     */
    public static void reportError(ErrorType type, String context, Throwable error) {
        totalErrors.incrementAndGet();

        switch (type) {
            case PLUGIN_TRANSFORM:
                pluginErrors.incrementAndGet();
                System.err.println("[GraRasp Error] Plugin Transform Failed: " + context);
                break;
            case SCANNER:
                scanErrors.incrementAndGet();
                System.err.println("[GraRasp Error] Scanner Failed: " + context);
                break;
            case DETECTION:
                detectionErrors.incrementAndGet();
                System.err.println("[GraRasp Error] Detection Failed: " + context);
                break;
            case REFLECTION:
                System.err.println("[GraRasp Error] Reflection Failed: " + context);
                break;
            case GENERAL:
                System.err.println("[GraRasp Error] " + context);
                break;
        }

        if (error != null) {
            System.err.println("  Cause: " + error.getClass().getName() + ": " + error.getMessage());
            // Uncomment for debugging:
            // error.printStackTrace();
        }
    }

    /**
     * Report an error without exception
     */
    public static void reportError(ErrorType type, String context) {
        reportError(type, context, null);
    }

    /**
     * Get error statistics
     */
    public static String getStatistics() {
        return String.format(
            "[GraRasp Stats] Total Errors: %d (Plugin: %d, Scanner: %d, Detection: %d)",
            totalErrors.get(), pluginErrors.get(), scanErrors.get(), detectionErrors.get()
        );
    }

    /**
     * Reset all counters (for testing)
     */
    public static void reset() {
        totalErrors.set(0);
        pluginErrors.set(0);
        scanErrors.set(0);
        detectionErrors.set(0);
    }

    /**
     * Get total error count
     */
    public static long getTotalErrors() {
        return totalErrors.get();
    }
}
