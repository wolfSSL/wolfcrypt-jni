/* PwdbasedTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Pwdbased;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * Tests for the Pwdbased PBKDF2 and PKCS12 PBKDF JNI wrappers.
 */
public class PwdbasedTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testSetup() {
        System.out.println("JNI Pwdbased Class");
    }

    /* Password with distinctive pattern, used to detect modification */
    private static byte[] makePassword() {
        byte[] pass = new byte[32];
        for (int i = 0; i < pass.length; i++) {
            pass[i] = (byte)(0x41 + ((i * 7) % 26));
        }
        return pass;
    }

    /**
     * PBKDF2-HMAC-SHA256 known answer test from RFC 7914 Section 11.
     */
    @Test
    public void testPbkdf2KnownAnswer() {

        Assume.assumeTrue("PBKDF2 not compiled in native wolfSSL",
            FeatureDetect.Pbkdf2Enabled());
        /* RFC 7914 vector uses a 6 byte key and 4 byte salt, below the FIPS
         * HMAC key and salt minimums, skip this known answer test in FIPS */
        Assume.assumeTrue("RFC 7914 KAT inputs below FIPS minimums",
            !Fips.enabled);

        byte[] pass = "passwd".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] expected = Util.h2b(
            "55AC046E56E3089FEC1691C22544B605" +
            "F94185216DDE0465E68B9D57C20DACBC" +
            "49CA9CCCF179B645991664B39D77EF31" +
            "7C71B845B1E30BD509112041D3A19783");

        byte[] key = Pwdbased.PBKDF2(pass, salt, 1, 64,
            WolfCrypt.WC_HASH_TYPE_SHA256);

        assertArrayEquals(expected, key);
    }

    /**
     * PBKDF2 must not modify the caller's password array, and repeated
     * calls with the same password must derive the same key.
     */
    @Test
    public void testPbkdf2DoesNotModifyPassword() {

        Assume.assumeTrue("PBKDF2 not compiled in native wolfSSL",
            FeatureDetect.Pbkdf2Enabled());

        byte[] pass = makePassword();
        byte[] passCopy = pass.clone();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};

        byte[] key1 = Pwdbased.PBKDF2(pass, salt, 1000, 32,
            WolfCrypt.WC_HASH_TYPE_SHA256);
        assertArrayEquals("PBKDF2 modified caller password array",
            passCopy, pass);

        byte[] key2 = Pwdbased.PBKDF2(pass, salt, 1000, 32,
            WolfCrypt.WC_HASH_TYPE_SHA256);
        assertArrayEquals("repeated PBKDF2 derived different key",
            key1, key2);
    }

    /**
     * PKCS12 PBKDF must not modify the caller's password array.
     */
    @Test
    public void testPkcs12PbkdfDoesNotModifyPassword() {

        byte[] pass = makePassword();
        byte[] passCopy = pass.clone();
        byte[] salt = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] key = null;

        try {
            key = Pwdbased.PKCS12_PBKDF(pass, salt, 100, 24,
                WolfCrypt.WC_HASH_TYPE_SHA256, 1);
        } catch (WolfCryptException e) {
            Assume.assumeTrue("PKCS12 PBKDF not compiled in native wolfSSL",
                e.getError() != WolfCryptError.NOT_COMPILED_IN);
            throw e;
        }

        assertNotNull(key);
        assertArrayEquals("PKCS12_PBKDF modified caller password array",
            passCopy, pass);
    }
}
