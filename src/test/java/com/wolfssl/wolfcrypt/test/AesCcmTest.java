/* AesCcmTest.java
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
import org.junit.runners.model.Statement;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.AesCcm;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class AesCcmTest {

    /* AES-128 test vectors */
    byte[] k3 = new byte[] {
        (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
        (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
        (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
        (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf
    };
    byte[] iv3 = new byte[] {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03,
        (byte)0x02, (byte)0x01, (byte)0x00, (byte)0xa0,
        (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4, (byte)0xa5
    };
    byte[] p3 = new byte[] {
        (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
        (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
        (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
        (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
        (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
        (byte)0x1c, (byte)0x1d, (byte)0x1e
    };
    byte[] a3 = new byte[] {
        (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
        (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07
    };
    byte[] c3 = new byte[] {
        (byte)0x58, (byte)0x8c, (byte)0x97, (byte)0x9a,
        (byte)0x61, (byte)0xc6, (byte)0x63, (byte)0xd2,
        (byte)0xf0, (byte)0x66, (byte)0xd0, (byte)0xc2,
        (byte)0xc0, (byte)0xf9, (byte)0x89, (byte)0x80,
        (byte)0x6d, (byte)0x5f, (byte)0x6b, (byte)0x61,
        (byte)0xda, (byte)0xc3, (byte)0x84
    };
    byte[] t3 = new byte[] {
        (byte)0x17, (byte)0xe8, (byte)0xd1, (byte)0x2c,
        (byte)0xfd, (byte)0xf9, (byte)0x26, (byte)0xe0
    };

    /* AES-192 test vectors - using longer plaintext */
    byte[] k2 = new byte[] {
        (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
        (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
        (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
        (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf,
        (byte)0xd0, (byte)0xd1, (byte)0xd2, (byte)0xd3,
        (byte)0xd4, (byte)0xd5, (byte)0xd6, (byte)0xd7
    };
    byte[] iv2 = new byte[] {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x04,
        (byte)0x03, (byte)0x02, (byte)0x01, (byte)0xa0,
        (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4, (byte)0xa5
    };
    byte[] p2 = new byte[] {
        (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
        (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
        (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
        (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
        (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
        (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
        (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23
    };
    byte[] a2 = new byte[] {
        (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
        (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
        (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b
    };

    /* AES-256 test vectors - using even longer plaintext */
    byte[] k1 = new byte[] {
        (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
        (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
        (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
        (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf,
        (byte)0xd0, (byte)0xd1, (byte)0xd2, (byte)0xd3,
        (byte)0xd4, (byte)0xd5, (byte)0xd6, (byte)0xd7,
        (byte)0xd8, (byte)0xd9, (byte)0xda, (byte)0xdb,
        (byte)0xdc, (byte)0xdd, (byte)0xde, (byte)0xdf
    };
    byte[] iv1 = new byte[] {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x05,
        (byte)0x04, (byte)0x03, (byte)0x02, (byte)0xa0,
        (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4, (byte)0xa5
    };
    byte[] p1 = new byte[] {
        (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
        (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
        (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
        (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
        (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
        (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
        (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
        (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
        (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b,
        (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f
    };
    byte[] a1 = new byte[] {
        (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
        (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
        (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
        (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
    };

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Rule to check if AES-CCM is available, skips tests if not.
     * AesCcm() constructor does not allocate native memory, so no need
     * to release if it throws. */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule aesCcmAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base,
                               Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    try {
                        new AesCcm();
                    } catch (WolfCryptException e) {
                        Assume.assumeTrue("AES-CCM not compiled in: " +
                            e.getError(), false);
                    }
                    base.evaluate();
                }
            };
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        System.out.println("JNI AesCcm Class");
    }

    /*
     * AesCcm() constructor should not initialize internal NativeStruct object
     */
    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesCcm().getNativeStruct());
    }

    /*
     * Basic argument checks on AesCcm.setKey()
     */
    @Test
    public void testSetKey() throws WolfCryptException {

        AesCcm aes = null;

        /* Setting null key should fail */
        try {
            aes = new AesCcm();
            aes.setKey(null);
            fail("AesCcm.setKey(null) should throw exception");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test setting key after object creation */

        /* 128-bit key */
        if (FeatureDetect.Aes128Enabled()) {
            aes = new AesCcm();
            aes.setKey(k3);
            aes.releaseNativeStruct();
        }

        /* 192-bit key */
        if (FeatureDetect.Aes192Enabled()) {
            aes = new AesCcm();
            aes.setKey(k2);
            aes.releaseNativeStruct();
        }

        /* 256-bit key */
        if (FeatureDetect.Aes256Enabled()) {
            aes = new AesCcm();
            aes.setKey(k1);
            aes.releaseNativeStruct();
        }
    }

    @Test
    public void testAesCcm128() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        AesCcm dec = new AesCcm();
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

        /* success case: null input with aad. FIPSv2 incorrectly returned
         * BAD_FUNC_ARG when in buffer was null. Skip this test for v2 */
        if (Fips.fipsVersion != 2) {
            try {
                enc.encrypt(null, iv3, tag, a3);
            } catch (WolfCryptException e) {
                fail("encrypt() with null input should pass");
            }
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

        /* success case: null input with aad. FIPSv2 incorrectly returned
         * BAD_FUNC_ARG when in buffer was null. Skip this test for v2 */
        if (Fips.fipsVersion != 2) {
            try {
                enc.decrypt(null, iv3, tag, a3);
            } catch (WolfCryptException e) {
                fail("decrypt() with null input should pass");
            }
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
    public void testAesCcm192() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        AesCcm dec = new AesCcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[8];

        /* skip test if AES-192 is not compiled in native library */
        if (!FeatureDetect.Aes192Enabled()) {
            return;
        }

        enc.setKey(k2);
        dec.setKey(k2);

        /* success case */
        cipher = enc.encrypt(p2, iv2, tag, a2);
        assertNotNull(cipher);
        assertEquals(p2.length, cipher.length);

        plain = dec.decrypt(cipher, iv2, tag, a2);
        assertNotNull(plain);
        assertArrayEquals(p2, plain);

        /* success case: null input with aad. FIPSv2 incorrectly returned
         * BAD_FUNC_ARG when in buffer was null. Skip this test for v2 */
        if (Fips.fipsVersion != 2) {
            try {
                enc.encrypt(null, iv2, tag, a2);
            } catch (WolfCryptException e) {
                fail("encrypt() with null input should pass");
            }
        }

        /* bad encrypt arguments: null iv */
        try {
            enc.encrypt(p2, null, tag, a2);
            fail("encrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad encrypt arguments: null tag */
        try {
            enc.encrypt(p2, iv2, null, a2);
            fail("encrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* success case: null input with aad. FIPSv2 incorrectly returned
         * BAD_FUNC_ARG when in buffer was null. Skip this test for v2 */
        if (Fips.fipsVersion != 2) {
            try {
                enc.decrypt(null, iv2, tag, a2);
            } catch (WolfCryptException e) {
                fail("decrypt() with null input should pass");
            }
        }

        /* bad decrypt arguments: null iv */
        try {
            enc.decrypt(cipher, null, tag, a2);
            fail("decrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad decrypt arguments: null tag */
        try {
            enc.decrypt(cipher, iv2, null, a2);
            fail("decrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* release native structs */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testAesCcm256() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        AesCcm dec = new AesCcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[8];

        /* skip test if AES-256 is not compiled in native library */
        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        enc.setKey(k1);
        dec.setKey(k1);

        /* success case */
        cipher = enc.encrypt(p1, iv1, tag, a1);
        assertNotNull(cipher);
        assertEquals(p1.length, cipher.length);

        plain = dec.decrypt(cipher, iv1, tag, a1);
        assertNotNull(plain);
        assertArrayEquals(p1, plain);

        /* success case: null input with aad. FIPSv2 incorrectly returned
         * BAD_FUNC_ARG when in buffer was null. Skip this test for v2 */
        if (Fips.fipsVersion != 2) {
            try {
                enc.encrypt(null, iv1, tag, a1);
            } catch (WolfCryptException e) {
                fail("encrypt() with null input should pass");
            }
        }

        /* bad encrypt arguments: null iv */
        try {
            enc.encrypt(p1, null, tag, a1);
            fail("encrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad encrypt arguments: null tag */
        try {
            enc.encrypt(p1, iv1, null, a1);
            fail("encrypt() with null auth tag should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* success case: null input with aad. FIPSv2 incorrectly returned
         * BAD_FUNC_ARG when in buffer was null. Skip this test for v2 */
        if (Fips.fipsVersion != 2) {
            try {
                enc.decrypt(null, iv1, tag, a1);
            } catch (WolfCryptException e) {
                fail("decrypt() with null input should pass");
            }
        }

        /* bad decrypt arguments: null iv */
        try {
            enc.decrypt(cipher, null, tag, a1);
            fail("decrypt() with null IV should fail");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* bad decrypt arguments: null tag */
        try {
            enc.decrypt(cipher, iv1, null, a1);
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

        AesCcm enc = new AesCcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t3.length];

        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        enc.setKey(k3);
        cipher = enc.encrypt(p3, iv3, tag, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag);

        /* release native struct */
        enc.releaseNativeStruct();

        /* test that object state is back to uninitialized */
        try {
            enc.encrypt(p3, iv3, tag, a3);
            fail("Should throw IllegalStateException after release");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            enc.setKey(k3);
            fail("Should throw IllegalStateException after release");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testReleaseAndReinitObjectAes192() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[8];

        if (!FeatureDetect.Aes192Enabled()) {
            return;
        }

        enc.setKey(k2);
        cipher = enc.encrypt(p2, iv2, tag, a2);
        assertNotNull(cipher);
        assertEquals(p2.length, cipher.length);

        /* release native struct */
        enc.releaseNativeStruct();

        /* test that object state is back to uninitialized */
        try {
            enc.encrypt(p2, iv2, tag, a2);
            fail("Should throw IllegalStateException after release");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            enc.setKey(k2);
            fail("Should throw IllegalStateException after release");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testReleaseAndReinitObjectAes256() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[8];

        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        enc.setKey(k1);
        cipher = enc.encrypt(p1, iv1, tag, a1);
        assertNotNull(cipher);
        assertEquals(p1.length, cipher.length);

        /* release native struct */
        enc.releaseNativeStruct();

        /* test that object state is back to uninitialized */
        try {
            enc.encrypt(p1, iv1, tag, a1);
            fail("Should throw IllegalStateException after release");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            enc.setKey(k1);
            fail("Should throw IllegalStateException after release");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testReuseObjectAes128() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        AesCcm dec = new AesCcm();
        byte[] cipher = null;
        byte[] plain = null;
        byte[] tag = new byte[t3.length];
        byte[] tag2 = new byte[t3.length];

        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        enc.setKey(k3);
        dec.setKey(k3);

        /* encrypt once */
        cipher = enc.encrypt(p3, iv3, tag, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag);

        /* decrypt once */
        plain = dec.decrypt(cipher, iv3, tag, a3);
        assertArrayEquals(p3, plain);

        /* try to use same objects again */
        cipher = enc.encrypt(p3, iv3, tag2, a3);
        assertArrayEquals(c3, cipher);
        assertArrayEquals(t3, tag2);

        plain = dec.decrypt(cipher, iv3, tag2, a3);
        assertArrayEquals(p3, plain);

        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReuseObjectAes192() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        AesCcm dec = new AesCcm();
        byte[] cipher = null;
        byte[] cipher2 = null;
        byte[] plain = null;
        byte[] plain2 = null;
        byte[] tag = new byte[8];
        byte[] tag2 = new byte[8];

        if (!FeatureDetect.Aes192Enabled()) {
            return;
        }

        enc.setKey(k2);
        dec.setKey(k2);

        /* encrypt once */
        cipher = enc.encrypt(p2, iv2, tag, a2);
        assertNotNull(cipher);
        assertEquals(p2.length, cipher.length);

        /* decrypt once */
        plain = dec.decrypt(cipher, iv2, tag, a2);
        assertNotNull(plain);
        assertArrayEquals(p2, plain);

        /* try to use same objects again */
        cipher2 = enc.encrypt(p2, iv2, tag2, a2);
        assertNotNull(cipher2);
        assertEquals(p2.length, cipher2.length);
        assertArrayEquals(cipher, cipher2);
        assertArrayEquals(tag, tag2);

        plain2 = dec.decrypt(cipher2, iv2, tag2, a2);
        assertNotNull(plain2);
        assertArrayEquals(p2, plain2);

        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testReuseObjectAes256() throws WolfCryptException {

        AesCcm enc = new AesCcm();
        AesCcm dec = new AesCcm();
        byte[] cipher = null;
        byte[] cipher2 = null;
        byte[] plain = null;
        byte[] plain2 = null;
        byte[] tag = new byte[8];
        byte[] tag2 = new byte[8];

        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        enc.setKey(k1);
        dec.setKey(k1);

        /* encrypt once */
        cipher = enc.encrypt(p1, iv1, tag, a1);
        assertNotNull(cipher);
        assertEquals(p1.length, cipher.length);

        /* decrypt once */
        plain = dec.decrypt(cipher, iv1, tag, a1);
        assertNotNull(plain);
        assertArrayEquals(p1, plain);

        /* try to use same objects again */
        cipher2 = enc.encrypt(p1, iv1, tag2, a1);
        assertNotNull(cipher2);
        assertEquals(p1.length, cipher2.length);
        assertArrayEquals(cipher, cipher2);
        assertArrayEquals(tag, tag2);

        plain2 = dec.decrypt(cipher2, iv1, tag2, a1);
        assertNotNull(plain2);
        assertArrayEquals(p1, plain2);

        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testThreadedAes128() throws InterruptedException {

        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Exception> exceptions =
            new LinkedBlockingQueue<Exception>();

        if (!FeatureDetect.Aes128Enabled()) {
            return;
        }

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        AesCcm enc = new AesCcm();
                        AesCcm dec = new AesCcm();
                        byte[] cipher = null;
                        byte[] plain = null;
                        byte[] tag = new byte[t3.length];

                        enc.setKey(k3);
                        dec.setKey(k3);

                        cipher = enc.encrypt(p3, iv3, tag, a3);
                        if (!Arrays.equals(c3, cipher)) {
                            throw new Exception(
                                "Threading error in AES-CCM-128 thread test");
                        }

                        plain = dec.decrypt(cipher, iv3, tag, a3);
                        if (!Arrays.equals(p3, plain)) {
                            throw new Exception(
                                "Threading error in AES-CCM-128 thread test");
                        }

                        enc.releaseNativeStruct();
                        dec.releaseNativeStruct();

                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        service.shutdown();

        if (exceptions.size() > 0) {
            Iterator<Exception> iter = exceptions.iterator();
            while (iter.hasNext()) {
                Exception e = iter.next();
                e.printStackTrace();
            }
            fail("Threading error in AES-CCM-128 thread test");
        }
    }

    @Test
    public void testThreadedAes192() throws InterruptedException {

        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Exception> exceptions =
            new LinkedBlockingQueue<Exception>();

        if (!FeatureDetect.Aes192Enabled()) {
            return;
        }

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        AesCcm enc = new AesCcm();
                        AesCcm dec = new AesCcm();
                        byte[] cipher = null;
                        byte[] plain = null;
                        byte[] tag = new byte[8];

                        enc.setKey(k2);
                        dec.setKey(k2);

                        cipher = enc.encrypt(p2, iv2, tag, a2);
                        assertNotNull(cipher);
                        assertEquals(p2.length, cipher.length);

                        plain = dec.decrypt(cipher, iv2, tag, a2);
                        if (!Arrays.equals(p2, plain)) {
                            throw new Exception(
                                "Threading error in AES-CCM-192 thread test");
                        }

                        enc.releaseNativeStruct();
                        dec.releaseNativeStruct();

                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        service.shutdown();

        if (exceptions.size() > 0) {
            Iterator<Exception> iter = exceptions.iterator();
            while (iter.hasNext()) {
                Exception e = iter.next();
                e.printStackTrace();
            }
            fail("Threading error in AES-CCM-192 thread test");
        }
    }

    @Test
    public void testThreadedAes256() throws InterruptedException {

        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Exception> exceptions =
            new LinkedBlockingQueue<Exception>();

        if (!FeatureDetect.Aes256Enabled()) {
            return;
        }

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        AesCcm enc = new AesCcm();
                        AesCcm dec = new AesCcm();
                        byte[] cipher = null;
                        byte[] plain = null;
                        byte[] tag = new byte[8];

                        enc.setKey(k1);
                        dec.setKey(k1);

                        cipher = enc.encrypt(p1, iv1, tag, a1);
                        assertNotNull(cipher);
                        assertEquals(p1.length, cipher.length);

                        plain = dec.decrypt(cipher, iv1, tag, a1);
                        if (!Arrays.equals(p1, plain)) {
                            throw new Exception(
                                "Threading error in AES-CCM-256 thread test");
                        }

                        enc.releaseNativeStruct();
                        dec.releaseNativeStruct();

                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        service.shutdown();

        if (exceptions.size() > 0) {
            Iterator<Exception> iter = exceptions.iterator();
            while (iter.hasNext()) {
                Exception e = iter.next();
                e.printStackTrace();
            }
            fail("Threading error in AES-CCM-256 thread test");
        }
    }

    @Test
    public void testAesCcmEncryptDecrypt() throws WolfCryptException {

        AesCcm aes = new AesCcm();

        /* Test vector from wolfSSL test.c */
        byte[] key = {
            (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
            (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
            (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
            (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf
        };

        byte[] nonce = {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03,
            (byte)0x02, (byte)0x01, (byte)0x00, (byte)0xa0,
            (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4, (byte)0xa5
        };

        byte[] plaintext = {
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
            (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
            (byte)0x1c, (byte)0x1d, (byte)0x1e
        };

        byte[] authIn = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07
        };

        byte[] expectedCiphertext = {
            (byte)0x58, (byte)0x8c, (byte)0x97, (byte)0x9a,
            (byte)0x61, (byte)0xc6, (byte)0x63, (byte)0xd2,
            (byte)0xf0, (byte)0x66, (byte)0xd0, (byte)0xc2,
            (byte)0xc0, (byte)0xf9, (byte)0x89, (byte)0x80,
            (byte)0x6d, (byte)0x5f, (byte)0x6b, (byte)0x61,
            (byte)0xda, (byte)0xc3, (byte)0x84
        };

        byte[] expectedAuthTag = {
            (byte)0x17, (byte)0xe8, (byte)0xd1, (byte)0x2c,
            (byte)0xfd, (byte)0xf9, (byte)0x26, (byte)0xe0
        };

        /* Test encryption */
        aes.setKey(key);

        byte[] authTagOut = new byte[8];
        byte[] ciphertext = aes.encrypt(plaintext, nonce, authTagOut, authIn);

        assertNotNull(ciphertext);
        assertEquals(plaintext.length, ciphertext.length);
        assertTrue(Arrays.equals(expectedCiphertext, ciphertext));
        assertTrue(Arrays.equals(expectedAuthTag, authTagOut));

        /* Test decryption */
        AesCcm aes2 = new AesCcm();
        aes2.setKey(key);

        byte[] decryptedText = aes2.decrypt(ciphertext, nonce,
            expectedAuthTag, authIn);

        assertNotNull(decryptedText);
        assertEquals(plaintext.length, decryptedText.length);
        assertTrue(Arrays.equals(plaintext, decryptedText));

        aes.releaseNativeStruct();
        aes2.releaseNativeStruct();
    }

    @Test
    public void testAesCcmLongMessage() throws WolfCryptException {

        AesCcm aes = new AesCcm();

        /* Test vector from wolfSSL test.c - long message */
        byte[] key = {
            (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
            (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
            (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
            (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf
        };

        byte[] nonce = {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03,
            (byte)0x02, (byte)0x01, (byte)0x00, (byte)0xa0,
            (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4,
            (byte)0xa5
        };

        byte[] plaintext = {
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
            (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
            (byte)0x1c, (byte)0x1d, (byte)0x1e, (byte)0x1f,
            (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
            (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
            (byte)0x28, (byte)0x29, (byte)0x2a, (byte)0x2b,
            (byte)0x2c, (byte)0x2d, (byte)0x2e, (byte)0x2f,
            (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
            (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
            (byte)0x38, (byte)0x39, (byte)0x3a, (byte)0x3b,
            (byte)0x3c, (byte)0x3d, (byte)0x3e, (byte)0x3f,
            (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43,
            (byte)0x44, (byte)0x45, (byte)0x46, (byte)0x47,
            (byte)0x48, (byte)0x49, (byte)0x4a, (byte)0x4b,
            (byte)0x4c, (byte)0x4d, (byte)0x4e, (byte)0x4f,
            (byte)0x50
        };

        byte[] authIn = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07
        };

        byte[] expectedAuthTag = {
            (byte)0x89, (byte)0xd8, (byte)0xd2, (byte)0x02,
            (byte)0xc5, (byte)0xcf, (byte)0xae, (byte)0xf4
        };

        /* Test encryption and decryption with long message */
        aes.setKey(key);

        byte[] authTagOut = new byte[8];
        byte[] ciphertext = aes.encrypt(plaintext, nonce, authTagOut, authIn);

        assertNotNull(ciphertext);
        assertEquals(plaintext.length, ciphertext.length);
        assertTrue(Arrays.equals(expectedAuthTag, authTagOut));

        /* Test decryption */
        AesCcm aes2 = new AesCcm();
        aes2.setKey(key);

        byte[] decryptedText = aes2.decrypt(ciphertext, nonce,
            expectedAuthTag, authIn);

        assertNotNull(decryptedText);
        assertEquals(plaintext.length, decryptedText.length);
        assertTrue(Arrays.equals(plaintext, decryptedText));

        aes.releaseNativeStruct();
        aes2.releaseNativeStruct();
    }

    @Test
    public void testAesCcmEmptyMessage() throws WolfCryptException {

        /*
         * Note: Empty message testing for AES-CCM is implementation dependent.
         * Some versions of wolfSSL may return BAD_FUNC_ARG for empty messages,
         * which is acceptable behavior. This test verifies the implementation
         * handles empty messages consistently.
         */

        AesCcm aes = new AesCcm();

        /* Test vector from wolfSSL test.c - empty message */
        byte[] key = {
            (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
            (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
            (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
            (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf
        };

        byte[] nonce = {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03,
            (byte)0x02, (byte)0x01, (byte)0x00, (byte)0xa0,
            (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4,
            (byte)0xa5
        };

        byte[] plaintext = new byte[0]; /* explicitly empty */

        byte[] authIn = {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07
        };

        byte[] expectedAuthTag = {
            (byte)0xe4, (byte)0x28, (byte)0x8a, (byte)0xc3,
            (byte)0x78, (byte)0x00, (byte)0x0f, (byte)0xf5
        };

        /* Test encryption with empty message */
        aes.setKey(key);

        byte[] authTagOut = new byte[8];

        try {
            byte[] ciphertext = aes.encrypt(plaintext, nonce,
                authTagOut, authIn);

            /* If we reach here, empty messages are supported */
            assertNotNull(ciphertext);
            assertEquals(0, ciphertext.length);
            assertTrue(Arrays.equals(expectedAuthTag, authTagOut));

            /* Test decryption */
            AesCcm aes2 = new AesCcm();
            aes2.setKey(key);

            byte[] decryptedText = aes2.decrypt(ciphertext, nonce,
                expectedAuthTag, authIn);

            assertNotNull(decryptedText);
            assertEquals(0, decryptedText.length);

            aes2.releaseNativeStruct();

        } catch (WolfCryptException e) {
            if (e.getMessage().contains("Bad function argument")) {
                /* This is expected behavior for some wolfSSL configurations */
            } else {
                /* Re-throw other unexpected exceptions */
                throw e;
            }
        }

        aes.releaseNativeStruct();
    }

    @Test
    public void testStateChecking() {

        AesCcm aes = new AesCcm();

        byte[] key = {
            (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
            (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
            (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
            (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf
        };

        /* should not be able to use encrypt without setting key first */
        try {
            aes.encrypt(new byte[16], new byte[13], new byte[8], null);
            fail("encrypt should not work without setting key first");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* should not be able to use decrypt without setting key first */
        try {
            aes.decrypt(new byte[16], new byte[13], new byte[8], null);
            fail("decrypt should not work without setting key first");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* should be able to set key */
        aes.setKey(key);

        /* should not be able to set key again */
        try {
            aes.setKey(key);
            fail("should not be able to set key again");
        } catch (IllegalStateException e) {
            /* expected */
        }

        aes.releaseNativeStruct();

        /* should not be able to use after release */
        try {
            aes.encrypt(new byte[16], new byte[13], new byte[8], null);
            fail("should not work after releaseNativeStruct()");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void testThreading() throws InterruptedException {

        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Exception> exceptions =
            new LinkedBlockingQueue<Exception>();

        byte[] key = {
            (byte)0xc0, (byte)0xc1, (byte)0xc2, (byte)0xc3,
            (byte)0xc4, (byte)0xc5, (byte)0xc6, (byte)0xc7,
            (byte)0xc8, (byte)0xc9, (byte)0xca, (byte)0xcb,
            (byte)0xcc, (byte)0xcd, (byte)0xce, (byte)0xcf
        };

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        AesCcm aes = new AesCcm();

                        byte[] nonce = {
                            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03,
                            (byte)0x02, (byte)0x01, (byte)0x00, (byte)0xa0,
                            (byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0xa4,
                            (byte)0xa5
                        };

                        byte[] plaintext = {
                            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
                            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
                            (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                            (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
                            (byte)0x18, (byte)0x19, (byte)0x1a, (byte)0x1b,
                            (byte)0x1c, (byte)0x1d, (byte)0x1e
                        };

                        byte[] authIn = {
                            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07
                        };

                        aes.setKey(key);

                        byte[] authTagOut = new byte[8];
                        byte[] ciphertext = aes.encrypt(plaintext, nonce,
                            authTagOut, authIn);

                        byte[] decryptedText = aes.decrypt(ciphertext, nonce,
                            authTagOut, authIn);

                        if (!Arrays.equals(plaintext, decryptedText)) {
                            throw new Exception(
                                "AES-CCM threading test failed");
                        }

                        aes.releaseNativeStruct();

                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        service.shutdown();

        if (exceptions.size() > 0) {
            Iterator<Exception> iter = exceptions.iterator();
            while (iter.hasNext()) {
                Exception e = iter.next();
                e.printStackTrace();
            }
            fail("Threading test failed");
        }
    }
}
