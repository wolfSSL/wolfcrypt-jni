/* WolfCryptDebug.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jce;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.*;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.function.Supplier;

class WolfCryptDebug {

    private static final Logger jceLogger =
        Logger.getLogger("com.wolfssl.provider.jce");

    public static boolean DEBUG = checkProperty();

    /** Error level debug message */
    public static final String ERROR = "ERROR";

    /** Info level debug message */
    public static final String INFO = "INFO";

    /** Time formatter for log messages */
    private static final DateTimeFormatter TimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withZone(ZoneId.systemDefault());

    static {
        configureLoggers();
    }

    /**
     * Custom handler that flushes after each log record
     */
    private static class FlushingStreamHandler extends StreamHandler {
        public FlushingStreamHandler() {
            super(System.err, new WolfCryptFormatter());
        }

        @Override
        public synchronized void publish(LogRecord record) {
            super.publish(record);
            flush();
        }
    }

    /**
     * Configure loggers based on system properties
     */
    private static void configureLoggers() {
        /* Remove any existing handlers */
        for (Handler handler : jceLogger.getHandlers()) {
            jceLogger.removeHandler(handler);
        }

        /* Only configure handlers if debug is enabled */
        if (DEBUG) {
            /* Create custom handler that flushes after each log record */
            FlushingStreamHandler handler = new FlushingStreamHandler();
            handler.setFormatter(new WolfCryptFormatter());
            jceLogger.addHandler(handler);
        }

        /* Set log levels based on debug properties */
        jceLogger.setLevel(DEBUG ? Level.ALL : Level.OFF);

        /* Disable parent handlers to prevent double logging */
        jceLogger.setUseParentHandlers(false);
    }

    /**
     * Custom formatter for log records
     */
    private static class WolfCryptFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {
            if (record == null) {
                return "null record\n";
            }

            String sourceClass = record.getSourceClassName();
            if (sourceClass == null) {
                sourceClass = "";
            } else {
                /* Extract simple class name (after last dot) */
                int lastDot = sourceClass.lastIndexOf('.');
                if (lastDot != -1) {
                    sourceClass = sourceClass.substring(lastDot + 1);
                }
            }

            Level level = record.getLevel();
            String levelStr = level != null ? level.getName() : "UNKNOWN";

            long threadId = record.getThreadID();
            String message = record.getMessage();
            if (message == null) {
                message = "";
            }

            return String.format("%s [%s %s: TID %d: %s] %s\n",
                    TimeFormatter.format(
                        Instant.ofEpochMilli(record.getMillis())),
                    "wolfJCE",
                    levelStr,
                    threadId,
                    sourceClass,
                    message);
        }
    }

    private static boolean checkProperty() {

        String enabled = System.getProperty("wolfjce.debug");

        if ((enabled != null) && (enabled.equalsIgnoreCase("true"))) {
            return true;
        }

        return false;
    }

    /**
     * Refresh debug enabled/disabled flags based on current
     * System properties.
     */
    public static synchronized void refreshDebugFlags() {
        boolean oldDebug = DEBUG;

        DEBUG = checkProperty();

        /* Only reconfigure if debug state has changed */
        if (oldDebug != DEBUG) {
            configureLoggers();
        }
    }

    /**
     * Print out debug message if debugging is enabled.
     *
     * @param <T> class type of cl
     * @param cl class being called from to get debug info
     * @param tag level of debug message, ie WolfCryptDebug.INFO
     * @param messageSupplier supplier of message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, String tag,
        Supplier<String> messageSupplier) {

        log(cl, "wolfJCE", tag, 0, messageSupplier);
    }

    /**
     * Print out debug message if debugging is enabled.
     *
     * @param <T> class type of cl
     * @param cl class being called from to get debug info
     * @param component component name, ie "wolfJCE"
     * @param tag level of debug message, ie WolfCryptDebug.INFO
     * @param nativePtr native pointer
     * @param messageSupplier supplier of message to be printed out
     */
    public static synchronized <T> void log(Class<T> cl, String component,
        String tag, long nativePtr, Supplier<String> messageSupplier) {

        if (!DEBUG) {
            return;
        }

        Level level = tag.equals(ERROR) ? Level.SEVERE : Level.INFO;

        String className = cl.getSimpleName();
        if (nativePtr != 0) {
            className = className + ": " + nativePtr;
        }

        LogRecord record = new LogRecord(level, messageSupplier.get());
        record.setSourceClassName(cl.getName());
        jceLogger.log(record);
    }
}
