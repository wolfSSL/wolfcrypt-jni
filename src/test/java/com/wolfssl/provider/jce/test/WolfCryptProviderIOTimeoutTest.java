/* WolfCryptProviderIOTimeoutTest.java
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;

import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.security.Security;
import java.security.Provider;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXRevocationChecker;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptPKIXRevocationChecker;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Tests for wolfjce.ioTimeout system property handling in
 * WolfCryptPKIXRevocationChecker.
 *
 * The wolfjce.ioTimeout property is read during
 * WolfCryptPKIXRevocationChecker.init(), which is called
 * at validation time. This allows the property to be set
 * or changed after provider registration.
 *
 * These tests verify that init() correctly reads and
 * applies valid property values, and throws
 * CertPathValidatorException for invalid values.
 */
public class WolfCryptProviderIOTimeoutTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testSetup() {
        System.out.println(
            "JCE WolfCryptPKIXRevocationChecker IO Timeout");

        Security.insertProviderAt(
            new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);
    }

    /**
     * Clean up wolfjce.ioTimeout system property after each
     * test to avoid affecting other tests.
     */
    @After
    public void clearProperty() {
        System.clearProperty("wolfjce.ioTimeout");
    }

    /**
     * Helper to create a new revocation checker and call
     * init(). Uses SOFT_FAIL so init() does not throw if
     * OCSP is not compiled in.
     */
    private WolfCryptPKIXRevocationChecker initChecker()
        throws Exception {

        WolfCryptPKIXRevocationChecker checker =
            new WolfCryptPKIXRevocationChecker();
        checker.setOptions(java.util.EnumSet.of(
            PKIXRevocationChecker.Option.SOFT_FAIL));
        checker.init(false);
        return checker;
    }

    /* -------------------------------------------------------- */
    /* Valid value tests - init() should succeed                 */
    /* -------------------------------------------------------- */

    @Test
    public void testCheckerValidIOTimeout() throws Exception {
        if (!WolfCrypt.IoTimeoutEnabled()) {
            return;
        }
        /* Set valid timeout, init should not throw */
        System.setProperty("wolfjce.ioTimeout", "5");
        WolfCryptPKIXRevocationChecker checker = initChecker();
        assertNotNull("Checker should not be null", checker);
    }

    @Test
    public void testCheckerIOTimeoutZero() throws Exception {
        if (!WolfCrypt.IoTimeoutEnabled()) {
            return;
        }
        /* Zero disables timeout, should succeed */
        System.setProperty("wolfjce.ioTimeout", "0");
        WolfCryptPKIXRevocationChecker checker = initChecker();
        assertNotNull("Checker should not be null", checker);
    }

    @Test
    public void testCheckerIOTimeoutMax() throws Exception {
        if (!WolfCrypt.IoTimeoutEnabled()) {
            return;
        }
        /* Max valid value (3600 seconds = 1 hour) */
        System.setProperty("wolfjce.ioTimeout", "3600");
        WolfCryptPKIXRevocationChecker checker = initChecker();
        assertNotNull("Checker should not be null", checker);
    }

    @Test
    public void testCheckerNoIOTimeoutProperty()
        throws Exception {

        /* No property set, init should work normally */
        System.clearProperty("wolfjce.ioTimeout");
        WolfCryptPKIXRevocationChecker checker = initChecker();
        assertNotNull("Checker should not be null", checker);
    }

    @Test
    public void testCheckerEmptyIOTimeoutProperty()
        throws Exception {

        /* Empty string should be ignored, same as not set */
        System.setProperty("wolfjce.ioTimeout", "");
        WolfCryptPKIXRevocationChecker checker = initChecker();
        assertNotNull("Checker should not be null", checker);
    }

    @Test
    public void testCheckerIOTimeoutSetAfterConstruction()
        throws Exception {

        if (!WolfCrypt.IoTimeoutEnabled()) {
            return;
        }

        /* Verify property is read at init() time, not at
         * construction time. Create checker first, then set
         * property, then call init(). */
        WolfCryptPKIXRevocationChecker checker =
            new WolfCryptPKIXRevocationChecker();
        checker.setOptions(java.util.EnumSet.of(
            PKIXRevocationChecker.Option.SOFT_FAIL));

        /* Set property after checker construction */
        System.setProperty("wolfjce.ioTimeout", "10");

        /* init() should pick up the property */
        checker.init(false);
        assertNotNull("Checker should not be null", checker);
    }

    @Test
    public void testCheckerIOTimeoutChangeBetweenInits()
        throws Exception {

        if (!WolfCrypt.IoTimeoutEnabled()) {
            return;
        }

        /* Verify property change is picked up on
         * subsequent init() calls */
        WolfCryptPKIXRevocationChecker checker =
            new WolfCryptPKIXRevocationChecker();
        checker.setOptions(java.util.EnumSet.of(
            PKIXRevocationChecker.Option.SOFT_FAIL));

        /* First init with 5 second timeout */
        System.setProperty("wolfjce.ioTimeout", "5");
        checker.init(false);

        /* Change to 30 seconds and re-init */
        System.setProperty("wolfjce.ioTimeout", "30");
        checker.init(false);

        assertNotNull("Checker should not be null", checker);
    }

    /* -------------------------------------------------------- */
    /* Invalid value tests - init() should throw                */
    /* CertPathValidatorException                               */
    /* -------------------------------------------------------- */

    @Test(expected = CertPathValidatorException.class)
    public void testCheckerInvalidIOTimeoutNonNumeric()
        throws Exception {

        /* Non-numeric value should fail init() */
        System.setProperty("wolfjce.ioTimeout", "abc");
        initChecker();
    }

    @Test(expected = CertPathValidatorException.class)
    public void testCheckerInvalidIOTimeoutFloat()
        throws Exception {

        /* Float value should fail init() */
        System.setProperty("wolfjce.ioTimeout", "5.5");
        initChecker();
    }

    @Test(expected = CertPathValidatorException.class)
    public void testCheckerNegativeIOTimeout()
        throws Exception {

        /* Negative value should fail init() */
        System.setProperty("wolfjce.ioTimeout", "-1");
        initChecker();
    }

    @Test(expected = CertPathValidatorException.class)
    public void testCheckerIOTimeoutExceedsMax()
        throws Exception {

        /* Value exceeding max (3600) should fail init() */
        System.setProperty("wolfjce.ioTimeout", "3601");
        initChecker();
    }

    @Test(expected = CertPathValidatorException.class)
    public void testCheckerIOTimeoutOverflowValue()
        throws Exception {

        /* Overflow integer value should fail init() */
        System.setProperty("wolfjce.ioTimeout",
            "99999999999999");
        initChecker();
    }
}
