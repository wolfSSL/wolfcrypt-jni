/* FilteredProviderNegativeTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

package com.wolfssl.security.providers.test;

import static org.junit.Assert.*;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import com.wolfssl.security.providers.FilteredSun;
import com.wolfssl.security.providers.FilteredSunEC;
import com.wolfssl.security.providers.FilteredSunRsaSign;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Negative test for the filtered Sun security providers.
 *
 * The filtered providers register only a small allow-list of non-crypto
 * services. Requesting a blocked crypto algorithm directly from one of the
 * filtered providers (two-arg getInstance with the provider name) must fail
 * with NoSuchAlgorithmException, because that algorithm is not registered with
 * that specific provider.
 *
 * Blocked crypto service TYPES:
 *     Cipher, Signature, MessageDigest, Mac, KeyPairGenerator,
 *     KeyGenerator, SecureRandom, KeyAgreement
 *
 * Requires Java 9+ (see FilteredProviderSmokeTest for required JVM flags).
 */
public class FilteredProviderNegativeTest {

    /** Security property controlling filtered provider registration names. */
    private static final String NAME_PROP = "wolfssl.filtered.useOriginalNames";

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkJavaVersionAndInstall() {
        Assume.assumeTrue(
            "FilteredSun* providers require Java 9 or greater",
            javaMajorVersion() >= 9);

        System.out.println("FilteredSun* provider negative test");

        /* Pin the name override property to "false" while constructing and
         * registering the providers, so registration names stay FilteredSun*
         * even if the test JVM's java.security sets
         * wolfssl.filtered.useOriginalNames=true (e.g. on a hardened image).
         * Restore the prior value afterward. */
        String prev = Security.getProperty(NAME_PROP);
        Security.setProperty(NAME_PROP, "false");
        try {
            Security.addProvider(new FilteredSun());
            Security.addProvider(new FilteredSunEC());
            Security.addProvider(new FilteredSunRsaSign());
        } finally {
            Security.setProperty(NAME_PROP, (prev != null) ? prev : "false");
        }
    }

    private static int javaMajorVersion() {
        String v = System.getProperty("java.specification.version");
        if (v == null) {
            return 0;
        }
        if (v.startsWith("1.")) {
            v = v.substring(2);
        }
        int dot = v.indexOf('.');
        if (dot >= 0) {
            v = v.substring(0, dot);
        }
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    @FunctionalInterface
    private interface ThrowingCall {
        void run() throws Exception;
    }

    /**
     * Run the supplied getInstance() call and assert it throws
     * NoSuchAlgorithmException.
     */
    private void assertThrowsNsa(String msg, ThrowingCall call)
        throws NoSuchProviderException {
        try {
            call.run();
            fail(msg + " (expected NoSuchAlgorithmException, none thrown)");
        } catch (NoSuchAlgorithmException expected) {
            /* expected: algorithm not registered with this provider */
        } catch (NoSuchProviderException e) {
            throw e;
        } catch (Exception e) {
            fail(msg + " (expected NoSuchAlgorithmException, got "
                + e.getClass().getName() + ": " + e.getMessage() + ")");
        }
    }

    /**
     * Attempt to get a representative algorithm of each blocked TYPE from
     * the named provider and assert NoSuchAlgorithmException is thrown.
     */
    private void assertBlocked(String providerName)
        throws NoSuchProviderException {

        assertThrowsNsa("Cipher AES not blocked from " + providerName,
            () -> javax.crypto.Cipher.getInstance("AES", providerName));
        assertThrowsNsa("Signature SHA256withRSA not blocked from "
                + providerName,
            () -> java.security.Signature.getInstance(
                "SHA256withRSA", providerName));
        assertThrowsNsa("MessageDigest SHA-256 not blocked from "
                + providerName,
            () -> java.security.MessageDigest.getInstance(
                "SHA-256", providerName));
        assertThrowsNsa("Mac HmacSHA256 not blocked from " + providerName,
            () -> javax.crypto.Mac.getInstance("HmacSHA256", providerName));
        assertThrowsNsa("KeyPairGenerator RSA not blocked from "
                + providerName,
            () -> java.security.KeyPairGenerator.getInstance(
                "RSA", providerName));
        assertThrowsNsa("KeyGenerator AES not blocked from " + providerName,
            () -> javax.crypto.KeyGenerator.getInstance("AES", providerName));
        assertThrowsNsa("SecureRandom SHA1PRNG not blocked from "
                + providerName,
            () -> java.security.SecureRandom.getInstance(
                "SHA1PRNG", providerName));
        assertThrowsNsa("KeyAgreement ECDH not blocked from " + providerName,
            () -> javax.crypto.KeyAgreement.getInstance(
                "ECDH", providerName));
    }

    @Test
    public void testFilteredSunBlocksCryptoTypes()
        throws NoSuchProviderException {
        assertBlocked("FilteredSun");
    }

    @Test
    public void testFilteredSunEcBlocksCryptoTypes()
        throws NoSuchProviderException {
        assertBlocked("FilteredSunEC");
    }

    @Test
    public void testFilteredSunRsaSignBlocksCryptoTypes()
        throws NoSuchProviderException {
        assertBlocked("FilteredSunRsaSign");
    }
}

