/* AsnTest.java
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335,
 * USA
 */

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.BeforeClass;

import com.wolfssl.wolfcrypt.Asn;

/**
 * Unit tests for Asn class, particularly dynamic OID retrieval
 */
public class AsnTest {

    @BeforeClass
    public static void checkAvailability() {
        try {
            /* Force initialization of Asn class static variables */
            int md5 = Asn.MD5h;
        } catch (UnsatisfiedLinkError ule) {
            /* wolfCrypt JNI library not found, skip tests */
            System.out.println("wolfCrypt JNI library not found, " +
                               "skipping tests");
            org.junit.Assume.assumeTrue(false);
        }
    }

    @Test
    public void testDynamicOIDRetrieval() {

        /* Test that all OID constants are initialized to non-zero values.
         * The new dynamic system should return proper hash-based OID values
         * from native wolfSSL, not the old hard-coded values. */

        assertNotEquals("MD5h should not be zero", 0, Asn.MD5h);
        assertNotEquals("SHAh should not be zero", 0, Asn.SHAh);
        assertNotEquals("SHA224h should not be zero", 0, Asn.SHA224h);
        assertNotEquals("SHA256h should not be zero", 0, Asn.SHA256h);
        assertNotEquals("SHA384h should not be zero", 0, Asn.SHA384h);
        assertNotEquals("SHA512h should not be zero", 0, Asn.SHA512h);
        assertNotEquals("SHA3_224h should not be zero", 0, Asn.SHA3_224h);
        assertNotEquals("SHA3_256h should not be zero", 0, Asn.SHA3_256h);
        assertNotEquals("SHA3_384h should not be zero", 0, Asn.SHA3_384h);
        assertNotEquals("SHA3_512h should not be zero", 0, Asn.SHA3_512h);
    }

    @Test
    public void testOIDEncodingWithNewValues() {

        /* Test that the new OID values produce valid DER encodings.
         * Valid encodings should have length > 40 and proper structure. */

        byte[] digest = new byte[32];
        byte[] encoded = new byte[512];

        /* Test SHA-256 encoding */
        long encodedLength = Asn.encodeSignature(encoded, digest,
                                                 digest.length, Asn.SHA256h);
        assertTrue("SHA-256 encoding should be successful", encodedLength > 40);
        assertTrue("SHA-256 encoding should be reasonable length",
                   encodedLength < 100);

        /* Check basic DER structure */
        assertEquals("First byte should be SEQUENCE tag", 0x30,
                     encoded[0] & 0xFF);
        assertTrue("SEQUENCE length should be reasonable",
                   (encoded[1] & 0xFF) > 30);
        assertEquals("Algorithm ID should be SEQUENCE", 0x30,
                     encoded[2] & 0xFF);

        /* Test SHA-1 encoding */
        encodedLength = Asn.encodeSignature(encoded, digest, digest.length,
                                            Asn.SHAh);
        assertTrue("SHA-1 encoding should be successful", encodedLength > 40);
        assertTrue("SHA-1 encoding should be reasonable length",
                   encodedLength < 100);

        /* Test MD5 encoding */
        encodedLength = Asn.encodeSignature(encoded, digest, digest.length,
                                            Asn.MD5h);
        assertTrue("MD5 encoding should be successful", encodedLength > 40);
        assertTrue("MD5 encoding should be reasonable length",
                   encodedLength < 100);
    }

    @Test
    public void testOIDUniqueness() {

        /* Test that all OID values are unique.
         * Each algorithm should have a distinct OID value. */

        int[] oids = {
            Asn.MD5h, Asn.SHAh, Asn.SHA224h, Asn.SHA256h, Asn.SHA384h,
            Asn.SHA512h, Asn.SHA3_224h, Asn.SHA3_256h, Asn.SHA3_384h,
            Asn.SHA3_512h
        };

        /* Check that all values are unique */
        for (int i = 0; i < oids.length; i++) {
            for (int j = i + 1; j < oids.length; j++) {
                assertNotEquals("OID values should be unique", oids[i],
                                oids[j]);
            }
        }
    }
}
