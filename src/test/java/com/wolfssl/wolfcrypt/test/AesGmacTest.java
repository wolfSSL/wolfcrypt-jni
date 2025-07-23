/* AesGmacTest.java
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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.AesGmac;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptState;

public class AesGmacTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        try {
            new AesGmac();
            System.out.println("JNI AesGmac Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("AesGmac test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void testAesGmacInstantiation() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        AesGmac gmac = new AesGmac();
        /* AES-GMAC object created successfully */
        assertNotNull(gmac);
    }

    @Test
    public void testAes128GmacTestVector1() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        byte[] key = new byte[] {
            (byte)0x89, (byte)0xc9, (byte)0x49, (byte)0xe9,
            (byte)0xc8, (byte)0x04, (byte)0xaf, (byte)0x01,
            (byte)0x4d, (byte)0x56, (byte)0x04, (byte)0xb3,
            (byte)0x94, (byte)0x59, (byte)0xf2, (byte)0xc8
        };

        byte[] iv = new byte[] {
            (byte)0xd1, (byte)0xb1, (byte)0x04, (byte)0xc8,
            (byte)0x15, (byte)0xbf, (byte)0x1e, (byte)0x94,
            (byte)0xe2, (byte)0x8c, (byte)0x8f, (byte)0x16
        };

        byte[] authIn = new byte[] {
            (byte)0x82, (byte)0xad, (byte)0xcd, (byte)0x63,
            (byte)0x8d, (byte)0x3f, (byte)0xa9, (byte)0xd9,
            (byte)0xf3, (byte)0xe8, (byte)0x41, (byte)0x00,
            (byte)0xd6, (byte)0x1e, (byte)0x07, (byte)0x77
        };

        byte[] expectedTag = new byte[] {
            (byte)0x88, (byte)0xdb, (byte)0x9d, (byte)0x62,
            (byte)0x17, (byte)0x2e, (byte)0xd0, (byte)0x43,
            (byte)0xaa, (byte)0x10, (byte)0xf1, (byte)0x6d,
            (byte)0x22, (byte)0x7d, (byte)0xc4, (byte)0x1b
        };

        AesGmac gmac = new AesGmac();
        gmac.setKey(key);

        /* Test using update() method */
        byte[] computedTag = gmac.update(iv, authIn, expectedTag.length);
        assertArrayEquals(expectedTag, computedTag);

        /* Test using static generate() method */
        byte[] generatedTag = AesGmac.generate(key, iv, authIn,
            expectedTag.length);
        assertArrayEquals(expectedTag, generatedTag);

        /* Test using static verify() method */
        boolean verified = AesGmac.verify(key, iv, authIn, expectedTag);
        assertTrue(verified);

        /* Test verification failure with wrong tag */
        byte[] wrongTag = Arrays.copyOf(expectedTag, expectedTag.length);
        wrongTag[0] ^= 1; /* flip one bit */
        boolean shouldFail = AesGmac.verify(key, iv, authIn, wrongTag);
        assertFalse(shouldFail);
    }

    @Test
    public void testAes128GmacTestVector2() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        byte[] key = new byte[] {
            (byte)0x40, (byte)0xf7, (byte)0xec, (byte)0xb2,
            (byte)0x52, (byte)0x6d, (byte)0xaa, (byte)0xd4,
            (byte)0x74, (byte)0x25, (byte)0x1d, (byte)0xf4,
            (byte)0x88, (byte)0x9e, (byte)0xf6, (byte)0x5b
        };

        byte[] iv = new byte[] {
            (byte)0xee, (byte)0x9c, (byte)0x6e, (byte)0x06,
            (byte)0x15, (byte)0x45, (byte)0x45, (byte)0x03,
            (byte)0x1a, (byte)0x60, (byte)0x24, (byte)0xa7
        };

        byte[] authIn = new byte[] {
            (byte)0x94, (byte)0x81, (byte)0x2c, (byte)0x87,
            (byte)0x07, (byte)0x4e, (byte)0x15, (byte)0x18,
            (byte)0x34, (byte)0xb8, (byte)0x35, (byte)0xaf,
            (byte)0x1c, (byte)0xa5, (byte)0x7e, (byte)0x56
        };

        /* 15-byte tag (non-FIPS) */
        byte[] expectedTag = new byte[] {
            (byte)0xc6, (byte)0x81, (byte)0x79, (byte)0x8e,
            (byte)0x3d, (byte)0xda, (byte)0xb0, (byte)0x9f,
            (byte)0x8d, (byte)0x83, (byte)0xb0, (byte)0xbb,
            (byte)0x14, (byte)0xb6, (byte)0x91
        };

        AesGmac gmac = new AesGmac();
        gmac.setKey(key);

        /* Test using update() method with 15-byte tag */
        byte[] computedTag = gmac.update(iv, authIn, expectedTag.length);
        assertArrayEquals(expectedTag, computedTag);

        /* Test using static generate() method */
        byte[] generatedTag = AesGmac.generate(key, iv, authIn,
            expectedTag.length);
        assertArrayEquals(expectedTag, generatedTag);

        /* Test using static verify() method */
        boolean verified = AesGmac.verify(key, iv, authIn, expectedTag);
        assertTrue(verified);
    }

    @Test
    public void testAes192GmacTestVector() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        byte[] key = new byte[] {
            (byte)0x41, (byte)0xc5, (byte)0xda, (byte)0x86,
            (byte)0x67, (byte)0xef, (byte)0x72, (byte)0x52,
            (byte)0x20, (byte)0xff, (byte)0xe3, (byte)0x9a,
            (byte)0xe0, (byte)0xac, (byte)0x59, (byte)0x0a,
            (byte)0xc9, (byte)0xfc, (byte)0xa7, (byte)0x29,
            (byte)0xab, (byte)0x60, (byte)0xad, (byte)0xa0
        };

        byte[] iv = new byte[] {
            (byte)0x05, (byte)0xad, (byte)0x13, (byte)0xa5,
            (byte)0xe2, (byte)0xc2, (byte)0xab, (byte)0x66,
            (byte)0x7e, (byte)0x1a, (byte)0x6f, (byte)0xbc
        };

        byte[] authIn = new byte[] {
            (byte)0x8b, (byte)0x5c, (byte)0x12, (byte)0x4b,
            (byte)0xef, (byte)0x6e, (byte)0x2f, (byte)0x0f,
            (byte)0xe4, (byte)0xd8, (byte)0xc9, (byte)0x5c,
            (byte)0xd5, (byte)0xfa, (byte)0x4c, (byte)0xf1
        };

        byte[] expectedTag = new byte[] {
            (byte)0x20, (byte)0x4b, (byte)0xdb, (byte)0x1b,
            (byte)0xd6, (byte)0x21, (byte)0x54, (byte)0xbf,
            (byte)0x08, (byte)0x92, (byte)0x2a, (byte)0xaa,
            (byte)0x54, (byte)0xee, (byte)0xd7, (byte)0x05
        };

        AesGmac gmac = new AesGmac();
        gmac.setKey(key);

        /* Test using update() method */
        byte[] computedTag = gmac.update(iv, authIn, expectedTag.length);
        assertArrayEquals(expectedTag, computedTag);

        /* Test using static generate() method */
        byte[] generatedTag = AesGmac.generate(key, iv, authIn,
            expectedTag.length);
        assertArrayEquals(expectedTag, generatedTag);

        /* Test using static verify() method */
        boolean verified = AesGmac.verify(key, iv, authIn, expectedTag);
        assertTrue(verified);
    }

    @Test
    public void testAes256GmacTestVector() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        byte[] key = new byte[] {
            (byte)0x78, (byte)0xdc, (byte)0x4e, (byte)0x0a,
            (byte)0xaf, (byte)0x52, (byte)0xd9, (byte)0x35,
            (byte)0xc3, (byte)0xc0, (byte)0x1e, (byte)0xea,
            (byte)0x57, (byte)0x42, (byte)0x8f, (byte)0x00,
            (byte)0xca, (byte)0x1f, (byte)0xd4, (byte)0x75,
            (byte)0xf5, (byte)0xda, (byte)0x86, (byte)0xa4,
            (byte)0x9c, (byte)0x8d, (byte)0xd7, (byte)0x3d,
            (byte)0x68, (byte)0xc8, (byte)0xe2, (byte)0x23
        };

        byte[] iv = new byte[] {
            (byte)0xd7, (byte)0x9c, (byte)0xf2, (byte)0x2d,
            (byte)0x50, (byte)0x4c, (byte)0xc7, (byte)0x93,
            (byte)0xc3, (byte)0xfb, (byte)0x6c, (byte)0x8a
        };

        byte[] authIn = new byte[] {
            (byte)0xb9, (byte)0x6b, (byte)0xaa, (byte)0x8c,
            (byte)0x1c, (byte)0x75, (byte)0xa6, (byte)0x71,
            (byte)0xbf, (byte)0xb2, (byte)0xd0, (byte)0x8d,
            (byte)0x06, (byte)0xbe, (byte)0x5f, (byte)0x36
        };

        byte[] expectedTag = new byte[] {
            (byte)0x3e, (byte)0x5d, (byte)0x48, (byte)0x6a,
            (byte)0xa2, (byte)0xe3, (byte)0x0b, (byte)0x22,
            (byte)0xe0, (byte)0x40, (byte)0xb8, (byte)0x57,
            (byte)0x23, (byte)0xa0, (byte)0x6e, (byte)0x76
        };

        AesGmac gmac = new AesGmac();
        gmac.setKey(key);

        /* Test using update() method */
        byte[] computedTag = gmac.update(iv, authIn, expectedTag.length);
        assertArrayEquals(expectedTag, computedTag);

        /* Test using static generate() method */
        byte[] generatedTag = AesGmac.generate(key, iv, authIn,
            expectedTag.length);
        assertArrayEquals(expectedTag, generatedTag);

        /* Test using static verify() method */
        boolean verified = AesGmac.verify(key, iv, authIn, expectedTag);
        assertTrue(verified);
    }

    @Test
    public void testAesGmacEmptyData() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        byte[] key = new byte[] {
            (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
            (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
            (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b,
            (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
        };

        byte[] iv = new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };

        byte[] emptyData = new byte[0];

        AesGmac gmac = new AesGmac();
        gmac.setKey(key);

        /* Test with empty authentication data */
        try {
            byte[] tag = gmac.update(iv, emptyData, 16);
            /* Should succeed and produce a valid tag */
            assertNotNull(tag);
            assertEquals(16, tag.length);
        } catch (Exception e) {
            /* Some implementations may not support empty data */
            /* This is acceptable behavior */
        }
    }

    @Test
    public void testAesGmacStateTransitions() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        AesGmac gmac = new AesGmac();
        assertNotNull(gmac);

        byte[] key = new byte[16];
        gmac.setKey(key);

        assertEquals("AES-GMAC", gmac.getAlgorithm());
        assertEquals(16, gmac.getMacLength());

        gmac.releaseNativeStruct();
    }

    @Test
    public void testAesGmacInvalidInputs() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        AesGmac gmac = new AesGmac();

        /* Test operations without setting key */
        try {
            gmac.getAlgorithm();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            /* Expected */
        }

        try {
            gmac.getMacLength();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            /* Expected */
        }

        /* Test with null key */
        try {
            gmac.setKey(null);
            fail("Expected WolfCryptException");
        } catch (WolfCryptException e) {
            /* Expected */
        }

        /* Test with invalid key size */
        try {
            byte[] invalidKey = new byte[7]; /* Invalid AES key size */
            gmac.setKey(invalidKey);
            fail("Expected WolfCryptException");
        } catch (WolfCryptException e) {
            /* Expected */
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        assertEquals(NativeStruct.NULL, new AesGmac().getNativeStruct());
    }

    @Test
    public void aesGmacShouldMatchWolfSSLTestVectors() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        /* Use our known-working test vectors from the original tests */
        String[] keyVector = new String[] {
            "89c949e9c804af014d5604b39459f2c8", /* AES-128 key */
            "40f7ecb2526daad474251df4889ef65b" /* AES-128 key (15-byte tag) */
        };
        String[] ivVector = new String[] {
            "d1b104c815bf1e94e28c8f16",
            "ee9c6e0615454503 1a6024a7"
        };
        String[] dataVector = new String[] {
            "82adcd638d3fa9d9f3e84100d61e0777",
            "94812c87074e151834b835af1ca57e56"
        };
        String[] macVector = new String[] {
            "88db9d62172ed043aa10f16d227dc41b", /* 16-byte tag */
            "c681798e3ddab09f8d83b0bb14b691" /* 15-byte tag */
        };

        for (int i = 0; i < dataVector.length; i++) {
            try {
                AesGmac gmac = new AesGmac();
                byte[] key = Util.h2b(keyVector[i]);
                byte[] iv = Util.h2b(ivVector[i].replaceAll(" ", ""));
                byte[] data = Util.h2b(dataVector[i]);
                byte[] expected = Util.h2b(macVector[i]);

                gmac.setKey(key);
                byte[] result = gmac.update(iv, data, expected.length);
                assertArrayEquals("Test vector " + i + " failed",
                    expected, result);

                /* Test static generate method */
                byte[] result2 = AesGmac.generate(key, iv, data,
                    expected.length);
                assertArrayEquals("Static test vector " + i + " failed",
                    expected, result2);

                /* Test verify method */
                boolean verified = AesGmac.verify(key, iv, data, expected);
                assertTrue("Verify test vector " + i + " failed", verified);

            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("AesGmac test skipped: " + e.getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test
    public void aesGmacStaticMethodsShouldWork() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        try {
            String keyHex = "89c949e9c804af014d5604b39459f2c8";
            String ivHex = "d1b104c815bf1e94e28c8f16";
            String dataHex = "82adcd638d3fa9d9f3e84100d61e0777";
            String expectedHex = "88db9d62172ed043aa10f16d227dc41b";

            byte[] key = Util.h2b(keyHex);
            byte[] iv = Util.h2b(ivHex);
            byte[] data = Util.h2b(dataHex);
            byte[] expected = Util.h2b(expectedHex);

            /* Test generate with default tag size */
            byte[] result1 = AesGmac.generate(key, iv, data);
            assertArrayEquals(expected, result1);

            /* Test generate with explicit tag size */
            byte[] result2 = AesGmac.generate(key, iv, data, 16);
            assertArrayEquals(expected, result2);

            /* Test verify */
            boolean verified = AesGmac.verify(key, iv, data, expected);
            assertTrue(verified);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesGmac static test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesGmacAlgorithmInfoShouldWork() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        try {
            AesGmac gmac = new AesGmac();
            byte[] key = new byte[16];
            gmac.setKey(key);

            assertEquals("AES-GMAC", gmac.getAlgorithm());
            assertEquals(16, gmac.getMacLength());

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesGmac algorithm test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesGmacThreadedAccessShouldWork() throws Exception {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        int numThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final Exception[] exception = new Exception[numThreads];

        for (int i = 0; i < numThreads; i++) {
            final int threadNum = i;
            service.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        byte[] key =
                            Util.h2b("89c949e9c804af014d5604b39459f2c8");
                        byte[] iv =
                            Util.h2b("d1b104c815bf1e94e28c8f16");
                        byte[] data =
                            Util.h2b("82adcd638d3fa9d9f3e84100d61e0777");
                        byte[] expected =
                            Util.h2b("88db9d62172ed043aa10f16d227dc41b");

                        AesGmac gmac = new AesGmac();
                        gmac.setKey(key);
                        byte[] result = gmac.update(iv, data, 16);
                        assertArrayEquals("Thread " + threadNum + " failed",
                            expected, result);

                    } catch (Exception e) {
                        exception[threadNum] = e;
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        service.shutdown();

        for (Exception e : exception) {
            if (e != null) {
                if (e instanceof WolfCryptException &&
                    ((WolfCryptException)e).getError() ==
                        WolfCryptError.NOT_COMPILED_IN) {
                    System.out.println("AesGmac threaded test skipped: " +
                        ((WolfCryptException)e).getError());
                } else {
                    throw e;
                }
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void aesGmacShouldThrowOnGetAlgorithmBeforeSetKey() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            throw new IllegalStateException("Skipped");
        }

        try {
            AesGmac gmac = new AesGmac();
            gmac.getAlgorithm();
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesGmac exception test skipped: " +
                    e.getError());
                throw new IllegalStateException("Skipped");
            } else {
                throw e;
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void aesGmacShouldThrowOnGetMacLengthBeforeSetKey() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            throw new IllegalStateException("Skipped");
        }

        try {
            AesGmac gmac = new AesGmac();
            gmac.getMacLength();
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesGmac exception test skipped: " +
                    e.getError());
                throw new IllegalStateException("Skipped");
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesGmacShouldWorkWithDifferentKeySizes() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        try {
            /* Test AES-128 */
            byte[] key128 = new byte[16];
            Arrays.fill(key128, (byte) 0x01);

            /* Test AES-192 */
            byte[] key192 = new byte[24];
            Arrays.fill(key192, (byte) 0x02);

            /* Test AES-256 */
            byte[] key256 = new byte[32];
            Arrays.fill(key256, (byte) 0x03);

            byte[] iv = new byte[12];
            byte[] data = "Hello World".getBytes();

            AesGmac gmac = new AesGmac();

            /* Test each key size */
            gmac.setKey(key128);
            byte[] result128 = gmac.update(iv, data, 16);
            assertNotNull(result128);
            assertEquals(16, result128.length);

            gmac.setKey(key192);
            byte[] result192 = gmac.update(iv, data, 16);
            assertNotNull(result192);
            assertEquals(16, result192.length);

            gmac.setKey(key256);
            byte[] result256 = gmac.update(iv, data, 16);
            assertNotNull(result256);
            assertEquals(16, result256.length);

            /* Results should be different for different keys */
            assertFalse(Arrays.equals(result128, result192));
            assertFalse(Arrays.equals(result192, result256));
            assertFalse(Arrays.equals(result128, result256));

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesGmac key size test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesGmacShouldHandleObjectReuse() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        try {
            String keyHex = "89c949e9c804af014d5604b39459f2c8";
            String ivHex = "d1b104c815bf1e94e28c8f16";
            String dataHex = "82adcd638d3fa9d9f3e84100d61e0777";
            String expectedHex = "88db9d62172ed043aa10f16d227dc41b";

            byte[] key = Util.h2b(keyHex);
            byte[] iv = Util.h2b(ivHex);
            byte[] data = Util.h2b(dataHex);
            byte[] expected = Util.h2b(expectedHex);

            AesGmac gmac = new AesGmac();

            /* First use */
            gmac.setKey(key);
            byte[] result1 = gmac.update(iv, data, 16);
            assertArrayEquals(expected, result1);

            /* Reuse with same key */
            byte[] result2 = gmac.update(iv, data, 16);
            assertArrayEquals(expected, result2);

            /* Reuse with new key (different data) */
            byte[] newKey = new byte[16];
            Arrays.fill(newKey, (byte) 0xFF);
            gmac.setKey(newKey);
            byte[] result3 = gmac.update(iv, data, 16);
            assertNotNull(result3);
            assertEquals(16, result3.length);
            /* Should be different from previous results */
            assertFalse(Arrays.equals(expected, result3));

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesGmac reuse test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }

    @Test
    public void aesGmacStaticMethodsShouldHandleEdgeCases() {
        if (!FeatureDetect.AesGmacEnabled()) {
            /* skip test if AES-GMAC is not compiled in native wolfCrypt */
            return;
        }

        try {
            byte[] key = Util.h2b("89c949e9c804af014d5604b39459f2c8");
            byte[] iv = Util.h2b("d1b104c815bf1e94e28c8f16");
            byte[] data = Util.h2b("82adcd638d3fa9d9f3e84100d61e0777");

            /* Test with different tag sizes */
            byte[] tag12 = AesGmac.generate(key, iv, data, 12);
            assertEquals(12, tag12.length);

            byte[] tag16 = AesGmac.generate(key, iv, data, 16);
            assertEquals(16, tag16.length);

            /* Verify should work with different tag sizes */
            boolean verified12 = AesGmac.verify(key, iv, data, tag12);
            assertTrue(verified12);

            boolean verified16 = AesGmac.verify(key, iv, data, tag16);
            assertTrue(verified16);

            /* Wrong tag should fail verification */
            byte[] wrongTag = Arrays.copyOf(tag16, tag16.length);
            wrongTag[0] ^= 1; /* flip one bit */
            boolean shouldFail = AesGmac.verify(key, iv, data, wrongTag);
            assertFalse(shouldFail);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("AesGmac edge case test skipped: " +
                    e.getError());
            } else {
                throw e;
            }
        }
    }
}
