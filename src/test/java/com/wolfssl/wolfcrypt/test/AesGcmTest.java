/* AesGcmTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Random;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.AesGcm;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class AesGcmTest {

    /*
     * This is Test Case 16 from the document Galois/
     * Counter Mode of Operation (GCM) by McGrew and
     * Viega.
     */
    byte[] p = new byte[] {
        (byte)0xd9, (byte)0x31, (byte)0x32, (byte)0x25,
        (byte)0xf8, (byte)0x84, (byte)0x06, (byte)0xe5,
        (byte)0xa5, (byte)0x59, (byte)0x09, (byte)0xc5,
        (byte)0xaf, (byte)0xf5, (byte)0x26, (byte)0x9a,
        (byte)0x86, (byte)0xa7, (byte)0xa9, (byte)0x53,
        (byte)0x15, (byte)0x34, (byte)0xf7, (byte)0xda,
        (byte)0x2e, (byte)0x4c, (byte)0x30, (byte)0x3d,
        (byte)0x8a, (byte)0x31, (byte)0x8a, (byte)0x72,
        (byte)0x1c, (byte)0x3c, (byte)0x0c, (byte)0x95,
        (byte)0x95, (byte)0x68, (byte)0x09, (byte)0x53,
        (byte)0x2f, (byte)0xcf, (byte)0x0e, (byte)0x24,
        (byte)0x49, (byte)0xa6, (byte)0xb5, (byte)0x25,
        (byte)0xb1, (byte)0x6a, (byte)0xed, (byte)0xf5,
        (byte)0xaa, (byte)0x0d, (byte)0xe6, (byte)0x57,
        (byte)0xba, (byte)0x63, (byte)0x7b, (byte)0x39
    };

    byte[] a = new byte[] {
        (byte)0xfe, (byte)0xed, (byte)0xfa, (byte)0xce,
        (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef,
        (byte)0xfe, (byte)0xed, (byte)0xfa, (byte)0xce,
        (byte)0xde, (byte)0xad, (byte)0xbe, (byte)0xef,
        (byte)0xab, (byte)0xad, (byte)0xda, (byte)0xd2
    };

    /* AES-256 test vectors */
    byte[] k1 = new byte[] {
        (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
        (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c,
        (byte)0x6d, (byte)0x6a, (byte)0x8f, (byte)0x94,
        (byte)0x67, (byte)0x30, (byte)0x83, (byte)0x08,
        (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
        (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c,
        (byte)0x6d, (byte)0x6a, (byte)0x8f, (byte)0x94,
        (byte)0x67, (byte)0x30, (byte)0x83, (byte)0x08
    };
    byte[] iv1 = new byte[] {
        (byte)0xca, (byte)0xfe, (byte)0xba, (byte)0xbe,
        (byte)0xfa, (byte)0xce, (byte)0xdb, (byte)0xad,
        (byte)0xde, (byte)0xca, (byte)0xf8, (byte)0x88
    };

    byte[] c1 = new byte[] {
        (byte)0x52, (byte)0x2d, (byte)0xc1, (byte)0xf0,
        (byte)0x99, (byte)0x56, (byte)0x7d, (byte)0x07,
        (byte)0xf4, (byte)0x7f, (byte)0x37, (byte)0xa3,
        (byte)0x2a, (byte)0x84, (byte)0x42, (byte)0x7d,
        (byte)0x64, (byte)0x3a, (byte)0x8c, (byte)0xdc,
        (byte)0xbf, (byte)0xe5, (byte)0xc0, (byte)0xc9,
        (byte)0x75, (byte)0x98, (byte)0xa2, (byte)0xbd,
        (byte)0x25, (byte)0x55, (byte)0xd1, (byte)0xaa,
        (byte)0x8c, (byte)0xb0, (byte)0x8e, (byte)0x48,
        (byte)0x59, (byte)0x0d, (byte)0xbb, (byte)0x3d,
        (byte)0xa7, (byte)0xb0, (byte)0x8b, (byte)0x10,
        (byte)0x56, (byte)0x82, (byte)0x88, (byte)0x38,
        (byte)0xc5, (byte)0xf6, (byte)0x1e, (byte)0x63,
        (byte)0x93, (byte)0xba, (byte)0x7a, (byte)0x0a,
        (byte)0xbc, (byte)0xc9, (byte)0xf6, (byte)0x62
    };

    byte[] t1 = new byte[] {
        (byte)0x76, (byte)0xfc, (byte)0x6e, (byte)0xce,
        (byte)0x0f, (byte)0x4e, (byte)0x17, (byte)0x68,
        (byte)0xcd, (byte)0xdf, (byte)0x88, (byte)0x53,
        (byte)0xbb, (byte)0x2d, (byte)0x55, (byte)0x1b
    };

    /* AES-192 test vectors */

    /* FIPS, QAT and PIC32MZ HW Crypto only support 12-byte IV */
    /* Test Case 12, uses same plaintext and AAD data. */
    byte[] k2 = new byte[] {
        (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
        (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c,
        (byte)0x6d, (byte)0x6a, (byte)0x8f, (byte)0x94,
        (byte)0x67, (byte)0x30, (byte)0x83, (byte)0x08,
        (byte)0xfe, (byte)0xff, (byte)0xe9, (byte)0x92,
        (byte)0x86, (byte)0x65, (byte)0x73, (byte)0x1c
    };

    byte[] iv2 = new byte[] {
        (byte)0x93, (byte)0x13, (byte)0x22, (byte)0x5d,
        (byte)0xf8, (byte)0x84, (byte)0x06, (byte)0xe5,
        (byte)0x55, (byte)0x90, (byte)0x9c, (byte)0x5a,
        (byte)0xff, (byte)0x52, (byte)0x69, (byte)0xaa,
        (byte)0x6a, (byte)0x7a, (byte)0x95, (byte)0x38,
        (byte)0x53, (byte)0x4f, (byte)0x7d, (byte)0xa1,
        (byte)0xe4, (byte)0xc3, (byte)0x03, (byte)0xd2,
        (byte)0xa3, (byte)0x18, (byte)0xa7, (byte)0x28,
        (byte)0xc3, (byte)0xc0, (byte)0xc9, (byte)0x51,
        (byte)0x56, (byte)0x80, (byte)0x95, (byte)0x39,
        (byte)0xfc, (byte)0xf0, (byte)0xe2, (byte)0x42,
        (byte)0x9a, (byte)0x6b, (byte)0x52, (byte)0x54,
        (byte)0x16, (byte)0xae, (byte)0xdb, (byte)0xf5,
        (byte)0xa0, (byte)0xde, (byte)0x6a, (byte)0x57,
        (byte)0xa6, (byte)0x37, (byte)0xb3, (byte)0x9b
    };

    byte[] c2 = new byte[] {
        (byte)0xd2, (byte)0x7e, (byte)0x88, (byte)0x68,
        (byte)0x1c, (byte)0xe3, (byte)0x24, (byte)0x3c,
        (byte)0x48, (byte)0x30, (byte)0x16, (byte)0x5a,
        (byte)0x8f, (byte)0xdc, (byte)0xf9, (byte)0xff,
        (byte)0x1d, (byte)0xe9, (byte)0xa1, (byte)0xd8,
        (byte)0xe6, (byte)0xb4, (byte)0x47, (byte)0xef,
        (byte)0x6e, (byte)0xf7, (byte)0xb7, (byte)0x98,
        (byte)0x28, (byte)0x66, (byte)0x6e, (byte)0x45,
        (byte)0x81, (byte)0xe7, (byte)0x90, (byte)0x12,
        (byte)0xaf, (byte)0x34, (byte)0xdd, (byte)0xd9,
        (byte)0xe2, (byte)0xf0, (byte)0x37, (byte)0x58,
        (byte)0x9b, (byte)0x29, (byte)0x2d, (byte)0xb3,
        (byte)0xe6, (byte)0x7c, (byte)0x03, (byte)0x67,
        (byte)0x45, (byte)0xfa, (byte)0x22, (byte)0xe7,
        (byte)0xe9, (byte)0xb7, (byte)0x37, (byte)0x3b
    };

    byte[] t2 = new byte[] {
        (byte)0xdc, (byte)0xf5, (byte)0x66, (byte)0xff,
        (byte)0x29, (byte)0x1c, (byte)0x25, (byte)0xbb,
        (byte)0xb8, (byte)0x56, (byte)0x8f, (byte)0xc3,
        (byte)0xd3, (byte)0x76, (byte)0xa6, (byte)0xd9
    };

    /* AES-128 test vectors */
    /* The following is an interesting test case from the example
     * FIPS test vectors for AES-GCM. IVlen = 1 byte */
    byte[] p3 = new byte[] {
        (byte)0x57, (byte)0xce, (byte)0x45, (byte)0x1f,
        (byte)0xa5, (byte)0xe2, (byte)0x35, (byte)0xa5,
        (byte)0x8e, (byte)0x1a, (byte)0xa2, (byte)0x3b,
        (byte)0x77, (byte)0xcb, (byte)0xaf, (byte)0xe2
    };

    byte[] k3 = new byte[] {
        (byte)0xbb, (byte)0x01, (byte)0xd7, (byte)0x03,
        (byte)0x81, (byte)0x1c, (byte)0x10, (byte)0x1a,
        (byte)0x35, (byte)0xe0, (byte)0xff, (byte)0xd2,
        (byte)0x91, (byte)0xba, (byte)0xf2, (byte)0x4b
    };

    byte[] iv3 = new byte[] {
        (byte)0xca
    };

    byte[] c3 = new byte[] {
        (byte)0x6b, (byte)0x5f, (byte)0xb3, (byte)0x9d,
        (byte)0xc1, (byte)0xc5, (byte)0x7a, (byte)0x4f,
        (byte)0xf3, (byte)0x51, (byte)0x4d, (byte)0xc2,
        (byte)0xd5, (byte)0xf0, (byte)0xd0, (byte)0x07
    };

    byte[] a3 = new byte[] {
        (byte)0x40, (byte)0xfc, (byte)0xdc, (byte)0xd7,
        (byte)0x4a, (byte)0xd7, (byte)0x8b, (byte)0xf1,
        (byte)0x3e, (byte)0x7c, (byte)0x60, (byte)0x55,
        (byte)0x50, (byte)0x51, (byte)0xdd, (byte)0x54
    };

    byte[] t3 = new byte[] {
        (byte)0x06, (byte)0x90, (byte)0xed, (byte)0x01,
        (byte)0x34, (byte)0xdd, (byte)0xc6, (byte)0x95,
        (byte)0x31, (byte)0x2e, (byte)0x2a, (byte)0xf9,
        (byte)0x57, (byte)0x7a, (byte)0x1e, (byte)0xa6
    };

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    /**
     * Make sure AesGcm class is available and not compiled out in native lib
     */
    @BeforeClass
    public static void checkAvailability() {
        try {
            new AesGcm();
            System.out.println("JNI AesGcm Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("AES-GCM test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    /**
     * AesGcm() constructor should not initialize internal NativeStruct object
     */
    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesGcm().getNativeStruct());
    }

    @Test
    public void deprecatedConstructorThrows() {
        try {
            new AesGcm(new byte[] {0x0});
            fail("Failed to throw expected exception");
        } catch (WolfCryptException e) {
            /* expected */
        }
    }

    /**
     * Basic argument checks on AesGcm.setKey()
     */
    @Test
    public void testSetKey() throws WolfCryptException {

        AesGcm aes = null;

        /* Setting null key in constructor should fail */
        try {
            aes = new AesGcm();
            aes.setKey(null);
            fail("AesGcm.setKey(null) should throw exception");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test setting key after object creation */

        /* 128-bit key */
        if (FeatureDetect.Aes128Enabled()) {
            aes = new AesGcm();
            aes.setKey(k3);
            aes.releaseNativeStruct();
        }

        /* 192-bit key */
        if (FeatureDetect.Aes192Enabled()) {
            aes = new AesGcm();
            aes.setKey(k2);
            aes.releaseNativeStruct();
        }

        /* 256-bit key */
        if (FeatureDetect.Aes256Enabled()) {
            aes = new AesGcm();
            aes.setKey(k1);
            aes.releaseNativeStruct();
        }
    }

    @Test
    public void testAesGcm128() throws WolfCryptException {

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t3.length];

        /* skip test if AES-128 is not compiled in native library */
        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        /* encrypt before key setup should throw exception */
        try {
            enc.encrypt(null, null, null, null);
            fail("encrypt() before setKey() should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* decrypt before key setup should throw exception */
        try {
            dec.decrypt(null, null, null, null);
            fail("decrypt() before setKey() should throw exception");
        } catch (IllegalStateException e) {
            /* expected */
        }

        enc.setKey(k3);
        dec.setKey(k3);

        /* success case */
        cipher = enc.encrypt(p3, iv3, tag, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag);

        plain = dec.decrypt(cipher, iv3, tag, a3);
        assertArrayEquals(p3, plain);

        /* encrypt with null input should pass */
        try {
            enc.encrypt(null, iv3, tag, a3);
        } catch (WolfCryptException e) {
            fail("encrypt() with null input should pass");
        }

        /* bad encrypt arguments: null iv */
        try {
            enc.encrypt(p3, null, tag, a3);
            fail("encrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad encrypt arguments: null tag */
        try {
            enc.encrypt(p3, iv3, null, a3);
            fail("encrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* decrypt with null input but valid tag and AAD should pass */
        try {
            enc.decrypt(null, iv3, tag, a3);
        } catch (WolfCryptException e) {
            fail("decrypt() with null input should pass");
        }

        /* bad decrypt arguments: null iv */
        try {
            enc.decrypt(cipher, null, tag, a3);
            fail("decrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad decrypt arguments: null tag */
        try {
            enc.decrypt(cipher, iv3, null, a3);
            fail("decrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* release native structs */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testAesGcm192() throws WolfCryptException {

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t2.length];

        /* skip test if AES-192 is not compiled in native library, or if
         * using wolfCrypt FIPS since it only supports 12-byte IVs */
        if (!FeatureDetect.Aes192Enabled() || Fips.enabled) {
            return;
        }

        enc.setKey(k2);
        dec.setKey(k2);

        /* success case */
        cipher = enc.encrypt(p, iv2, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c2, cipher);
        assertArrayEquals(t2, tag);

        plain = dec.decrypt(cipher, iv2, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* encrypt with null input should pass */
        try {
            enc.encrypt(null, iv2, tag, a);
        } catch (WolfCryptException e) {
            fail("encrypt() with null input should pass");
        }

        /* bad encrypt arguments: null iv */
        try {
            enc.encrypt(p, null, tag, a);
            fail("encrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad encrypt arguments: null tag */
        try {
            enc.encrypt(p, iv2, null, a);
            fail("encrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* decrypt with null input but valid tag and AAD should pass */
        try {
            enc.decrypt(null, iv2, tag, a);
        } catch (WolfCryptException e) {
            fail("decrypt() with null input should pass");
        }

        /* bad decrypt arguments: null iv */
        try {
            enc.decrypt(cipher, null, tag, a);
            fail("decrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad decrypt arguments: null tag */
        try {
            enc.decrypt(cipher, iv2, null, a);
            fail("decrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* release native structs */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testAesGcm256() throws WolfCryptException {

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t1.length];

        /* skip test if AES-192 is not compiled in native library, or if
         * using wolfCrypt FIPS since it only supports 12-byte IVs */
        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        enc.setKey(k1);
        dec.setKey(k1);

        /* success case */
        cipher = enc.encrypt(p, iv1, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c1, cipher);
        assertArrayEquals(t1, tag);

        plain = dec.decrypt(cipher, iv1, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* encrypt with null input should pass */
        try {
            enc.encrypt(null, iv1, tag, a);
        } catch (WolfCryptException e) {
            fail("encrypt() with null input should pass");
        }

        /* bad encrypt arguments: null iv */
        try {
            enc.encrypt(p, null, tag, a);
            fail("encrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad encrypt arguments: null tag */
        try {
            enc.encrypt(p, iv1, null, a);
            fail("encrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* decrypt with null input but valid tag and AAD should pass */
        try {
            enc.decrypt(null, iv1, tag, a);
        } catch (WolfCryptException e) {
            fail("decrypt() with null input should pass");
        }

        /* bad decrypt arguments: null iv */
        try {
            enc.decrypt(cipher, null, tag, a);
            fail("decrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad decrypt arguments: null tag */
        try {
            enc.decrypt(cipher, iv1, null, a);
            fail("decrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* release native structs */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReleaseAndReinitObjectAes128() throws WolfCryptException {

        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t3.length];

        /* skip test if AES-128 is not compiled in native library */
        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();

        enc.setKey(k3);
        dec.setKey(k3);

        cipher = enc.encrypt(p3, iv3, tag, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag);

        plain = dec.decrypt(cipher, iv3, tag, a3);
        assertArrayEquals(p3, plain);

        /* free objects */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();

        /* try to re-init and re-use them */
        enc = new AesGcm();
        dec = new AesGcm();

        enc.setKey(k3);
        dec.setKey(k3);

        cipher = enc.encrypt(p3, iv3, tag, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag);

        plain = dec.decrypt(cipher, iv3, tag, a3);
        assertArrayEquals(p3, plain);

        /* free again */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReleaseAndReinitObjectAes192() throws WolfCryptException {

        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t2.length];

        /* skip test if AES-192 is not compiled in native library, or if
         * using wolfCrypt FIPS since it only supports 12-byte IVs */
        if (!FeatureDetect.Aes192Enabled() || Fips.enabled) {
            return;
        }

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();

        enc.setKey(k2);
        dec.setKey(k2);

        cipher = enc.encrypt(p, iv2, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c2, cipher);
        assertArrayEquals(t2, tag);

        plain = dec.decrypt(cipher, iv2, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* free objects */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();

        /* try to re-init and re-use them */
        enc = new AesGcm();
        dec = new AesGcm();

        enc.setKey(k2);
        dec.setKey(k2);

        cipher = enc.encrypt(p, iv2, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c2, cipher);
        assertArrayEquals(t2, tag);

        plain = dec.decrypt(cipher, iv2, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* free again */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReleaseAndReinitObjectAes256() throws WolfCryptException {

        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t1.length];

        /* skip test if AES-256 is not compiled in native library */
        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();

        enc.setKey(k1);
        dec.setKey(k1);

        cipher = enc.encrypt(p, iv1, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c1, cipher);
        assertArrayEquals(t1, tag);

        plain = dec.decrypt(cipher, iv1, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* free objects */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();

        /* try to re-init and re-use them */
        enc = new AesGcm();
        dec = new AesGcm();

        enc.setKey(k1);
        dec.setKey(k1);

        cipher = enc.encrypt(p, iv1, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c1, cipher);
        assertArrayEquals(t1, tag);

        plain = dec.decrypt(cipher, iv1, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* free again */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReuseObjectAes128() throws WolfCryptException {

        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t3.length];

        /* skip test if AES-128 is not compiled in native library */
        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();

        enc.setKey(k3);
        dec.setKey(k3);

        cipher = enc.encrypt(p3, iv3, tag, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag);

        plain = dec.decrypt(cipher, iv3, tag, a3);
        assertArrayEquals(p3, plain);

        /* now, try to reuse existing enc/dec objects */
        cipher = enc.encrypt(p3, iv3, tag, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag);

        plain = dec.decrypt(cipher, iv3, tag, a3);
        assertArrayEquals(p3, plain);

        /* free native structs */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReuseObjectAes192() throws WolfCryptException {

        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t2.length];

        /* skip test if AES-192 is not compiled in native library, or if
         * using wolfCrypt FIPS since it only supports 12-byte IVs */
        if (!FeatureDetect.Aes192Enabled() || Fips.enabled) {
            return;
        }

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();

        enc.setKey(k2);
        dec.setKey(k2);

        cipher = enc.encrypt(p, iv2, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c2, cipher);
        assertArrayEquals(t2, tag);

        plain = dec.decrypt(cipher, iv2, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* now, try to reuse existing enc/dec objects */
        cipher = enc.encrypt(p, iv2, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c2, cipher);
        assertArrayEquals(t2, tag);

        plain = dec.decrypt(cipher, iv2, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* free native structs */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReuseObjectAes256() throws WolfCryptException {

        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t1.length];

        /* skip test if AES-256 is not compiled in native library */
        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        AesGcm enc = new AesGcm();
        AesGcm dec = new AesGcm();

        enc.setKey(k1);
        dec.setKey(k1);

        cipher = enc.encrypt(p, iv1, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c1, cipher);
        assertArrayEquals(t1, tag);

        plain = dec.decrypt(cipher, iv1, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* now, try to reuse existing enc/dec objects */
        cipher = enc.encrypt(p, iv1, tag, a);
        assertNotNull(cipher);
        assertArrayEquals(c1, cipher);
        assertArrayEquals(t1, tag);

        plain = dec.decrypt(cipher, iv1, tag, a);
        assertNotNull(plain);
        assertArrayEquals(p, plain);

        /* free native structs */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testThreadedAes128() throws InterruptedException {

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
        final byte[] rand2kBuf = new byte[2048];

        /* skip test if AES-128 is not compiled in native library */
        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand2kBuf);

        /* encrypt / decrypt input data, make sure decrypted matches original */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    AesGcm enc = new AesGcm();
                    AesGcm dec = new AesGcm();
                    byte[] cipher = new byte[2048];
                    byte[] plain = new byte[2048];
                    byte[] tag = new byte[t3.length];

                    try {
                        enc.setKey(k3);
                        dec.setKey(k3);

                        cipher = enc.encrypt(rand2kBuf, iv3, tag, null);
                        plain = dec.decrypt(cipher, iv3, tag, null);

                        /* make sure decrypted is same as input */
                        if (Arrays.equals(rand2kBuf, plain)) {
                            results.add(0);
                        }
                        else {
                            /* not equal, error case */
                            results.add(1);
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(1);

                    } finally {
                        enc.releaseNativeStruct();
                        dec.releaseNativeStruct();
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in AES-GMC-128 thread test");
            }
        }
    }

    @Test
    public void testThreadedAes192() throws InterruptedException {

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
        final byte[] rand2kBuf = new byte[2048];

        /* skip test if AES-192 is not compiled in native library, or if
         * using wolfCrypt FIPS since it only supports 12-byte IVs */
        if (!FeatureDetect.Aes192Enabled() || Fips.enabled) {
            return;
        }

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand2kBuf);

        /* encrypt / decrypt input data, make sure decrypted matches original */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    AesGcm enc = new AesGcm();
                    AesGcm dec = new AesGcm();
                    byte[] cipher = new byte[2048];
                    byte[] plain = new byte[2048];
                    byte[] tag = new byte[t2.length];

                    try {
                        enc.setKey(k2);
                        dec.setKey(k2);

                        cipher = enc.encrypt(rand2kBuf, iv2, tag, null);
                        plain = dec.decrypt(cipher, iv2, tag, null);

                        /* make sure decrypted is same as input */
                        if (Arrays.equals(rand2kBuf, plain)) {
                            results.add(0);
                        }
                        else {
                            /* not equal, error case */
                            results.add(1);
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(1);

                    } finally {
                        enc.releaseNativeStruct();
                        dec.releaseNativeStruct();
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in AES-GCM-192 thread test");
            }
        }
    }

    @Test
    public void testThreadedAes256() throws InterruptedException {

        int numThreads = 20;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
        final byte[] rand2kBuf = new byte[2048];

        /* skip test if AES-256 is not compiled in native library */
        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand2kBuf);

        /* encrypt / decrypt input data, make sure decrypted matches original */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    AesGcm enc = new AesGcm();
                    AesGcm dec = new AesGcm();
                    byte[] cipher = new byte[2048];
                    byte[] plain = new byte[2048];
                    byte[] tag = new byte[t1.length];

                    try {
                        enc.setKey(k1);
                        dec.setKey(k1);

                        cipher = enc.encrypt(rand2kBuf, iv1, tag, null);
                        plain = dec.decrypt(cipher, iv1, tag, null);

                        /* make sure decrypted is same as input */
                        if (Arrays.equals(rand2kBuf, plain)) {
                            results.add(0);
                        }
                        else {
                            /* not equal, error case */
                            results.add(1);
                        }

                    } catch (Exception e) {
                        e.printStackTrace();
                        results.add(1);

                    } finally {
                        enc.releaseNativeStruct();
                        dec.releaseNativeStruct();
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in AES-GCM-256 thread test");
            }
        }
    }

    /**
     * Test AES-GCM with null plaintext using test vectors from
     * OpenJDK TestKATForGCM.java that have null plaintext input.
     * This tests scenarios where users may only provide AAD to
     * generate an authentication tag.
     */
    @Test
    public void testAesGcmWithNullPlaintext() throws WolfCryptException {

        /*
         * Test vector 1 from OpenJDK: AES-128, 96-bit IV,
         * no plaintext, no AAD, 128-bit tag
         */
        byte[] key1 = new byte[] {
            (byte)0x11, (byte)0x75, (byte)0x4c, (byte)0xd7,
            (byte)0x2a, (byte)0xec, (byte)0x30, (byte)0x9b,
            (byte)0xf5, (byte)0x2f, (byte)0x76, (byte)0x87,
            (byte)0x21, (byte)0x2e, (byte)0x89, (byte)0x57
        };
        byte[] iv1 = new byte[] {
            (byte)0x3c, (byte)0x81, (byte)0x9d, (byte)0x9a,
            (byte)0x9b, (byte)0xed, (byte)0x08, (byte)0x76,
            (byte)0x15, (byte)0x03, (byte)0x0b, (byte)0x65
        };
        byte[] expectedTag1 = new byte[] {
            (byte)0x25, (byte)0x03, (byte)0x27, (byte)0xc6,
            (byte)0x74, (byte)0xaa, (byte)0xf4, (byte)0x77,
            (byte)0xae, (byte)0xf2, (byte)0x67, (byte)0x57,
            (byte)0x48, (byte)0xcf, (byte)0x69, (byte)0x71
        };

        /*
         * Test vector 6 from OpenJDK: AES-128, 96-bit IV,
         * no plaintext, 16-byte AAD, 128-bit tag
         */
        byte[] key2 = new byte[] {
            (byte)0x77, (byte)0xbe, (byte)0x63, (byte)0x70,
            (byte)0x89, (byte)0x71, (byte)0xc4, (byte)0xe2,
            (byte)0x40, (byte)0xd1, (byte)0xcb, (byte)0x79,
            (byte)0xe8, (byte)0xd7, (byte)0x7f, (byte)0xeb
        };
        byte[] iv2 = new byte[] {
            (byte)0xe0, (byte)0xe0, (byte)0x0f, (byte)0x19,
            (byte)0xfe, (byte)0xd7, (byte)0xba, (byte)0x01,
            (byte)0x36, (byte)0xa7, (byte)0x97, (byte)0xf3
        };
        byte[] aad2 = new byte[] {
            (byte)0x7a, (byte)0x43, (byte)0xec, (byte)0x1d,
            (byte)0x9c, (byte)0x0a, (byte)0x5a, (byte)0x78,
            (byte)0xa0, (byte)0xb1, (byte)0x65, (byte)0x33,
            (byte)0xa6, (byte)0x21, (byte)0x3c, (byte)0xab
        };
        byte[] expectedTag2 = new byte[] {
            (byte)0x20, (byte)0x9f, (byte)0xcc, (byte)0x8d,
            (byte)0x36, (byte)0x75, (byte)0xed, (byte)0x93,
            (byte)0x8e, (byte)0x9c, (byte)0x71, (byte)0x66,
            (byte)0x70, (byte)0x9d, (byte)0xd9, (byte)0x46
        };

        /* skip test if AES-128 is not compiled in native library */
        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        /* Test case 1: null plaintext, no AAD */
        AesGcm enc = new AesGcm();
        enc.setKey(key1);
        byte[] tag = new byte[expectedTag1.length];
        byte[] ciphertext = enc.encrypt(null, iv1, tag, null);

        /* Should return null/empty ciphertext since input was null */
        assertTrue("Ciphertext should be null or empty when input is null",
            ciphertext == null || ciphertext.length == 0);

        /* Tag should match expected value */
        assertArrayEquals("Tag should match expected value for null " +
            "plaintext, no AAD", expectedTag1, tag);
        enc.releaseNativeStruct();

        /* Test case 2: null plaintext, with AAD */
        enc = new AesGcm();
        enc.setKey(key2);
        tag = new byte[expectedTag2.length];
        ciphertext = enc.encrypt(null, iv2, tag, aad2);

        /* Should return null/empty ciphertext since input was null */
        assertTrue("Ciphertext should be null or empty when input is null",
            ciphertext == null || ciphertext.length == 0);

        /* Tag should match expected value */
        assertArrayEquals("Tag should match expected value for null " +
            "plaintext with AAD", expectedTag2, tag);

        /* Test decryption with null ciphertext */
        AesGcm dec = new AesGcm();
        dec.setKey(key2);
        byte[] plaintext = dec.decrypt(null, iv2, tag, aad2);

        /* Should return null/empty plaintext since ciphertext was null */
        assertTrue("Plaintext should be null or empty when ciphertext " +
            "is null", plaintext == null || plaintext.length == 0);

        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }
}

