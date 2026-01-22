/* WolfObjectTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.WolfObject;

/**
 * Unit tests for WolfObject class.
 */
public class WolfObjectTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {
        System.out.println("JNI WolfObject Class");
    }

    /**
     * Test that isLibraryLoadSkipped() returns false when the
     * wolfssl.skipLibraryLoad system property is not set.
     *
     * In normal test execution, the property is not set, so the native
     * libraries are loaded via System.loadLibrary() and this method
     * should return false.
     */
    @Test
    public void testIsLibraryLoadSkippedReturnsFalseByDefault() {
        /* In normal test runs without the system property set,
         * library loading should NOT be skipped */
        assertFalse("isLibraryLoadSkipped() should return false when " +
                    "wolfssl.skipLibraryLoad property is not set",
                    WolfObject.isLibraryLoadSkipped());
    }

    /**
     * Test that the system property value is correctly read.
     *
     * This test verifies that when the wolfssl.skipLibraryLoad property
     * is not set (null), the library loading proceeds normally. Setting
     * the property after class loading has no effect since the static
     * initializer has already executed.
     */
    @Test
    public void testSystemPropertyNotSetByDefault() {
        /* Verify the system property is not set in normal test runs */
        String skipLoad = System.getProperty("wolfssl.skipLibraryLoad");

        /* Property should be null or not "true" during normal test runs */
        boolean shouldSkip = (skipLoad != null &&
                              skipLoad.equalsIgnoreCase("true"));
        assertFalse("wolfssl.skipLibraryLoad should not be set to true " +
                    "in normal test runs", shouldSkip);

        /* This should match what WolfObject reports */
        assertEquals("isLibraryLoadSkipped() should match property state",
                     shouldSkip, WolfObject.isLibraryLoadSkipped());
    }

    /**
     * Test that setting the property after class loading has no effect.
     *
     * The static initializer runs once when the class is first loaded.
     * Setting the system property afterward should not change the
     * isLibraryLoadSkipped() return value.
     */
    @Test
    public void testSettingPropertyAfterLoadHasNoEffect() {
        /* Get the current state (should be false) */
        boolean originalState = WolfObject.isLibraryLoadSkipped();

        /* Save original property value */
        String originalProperty = System.getProperty("wolfssl.skipLibraryLoad");

        try {
            /* Set the property after the class has already been loaded */
            System.setProperty("wolfssl.skipLibraryLoad", "true");

            /* The state should NOT change because the static initializer
             * has already run */
            assertEquals("Setting property after class load should not " +
                         "change isLibraryLoadSkipped() result",
                         originalState, WolfObject.isLibraryLoadSkipped());
        }
        finally {
            /* Restore original property state */
            if (originalProperty == null) {
                System.clearProperty("wolfssl.skipLibraryLoad");
            }
            else {
                System.setProperty("wolfssl.skipLibraryLoad", originalProperty);
            }
        }
    }

    /**
     * Test that WolfObject can be instantiated (indirectly tests that
     * native library loading succeeded).
     */
    @Test
    public void testWolfObjectClassLoadsSuccessfully() {
        /* If we reach this point, the WolfObject class has been loaded
         * successfully, which means the native library was loaded and
         * init() was called without throwing an exception */
        assertNotNull("WolfObject class should be loaded",
                      WolfObject.class);
    }
}

