/* AesXtsTest.java
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

import java.util.Arrays;
import java.util.Random;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.nio.ByteBuffer;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.AesXts;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * AesXts JNI wrapper tests. Vectors are from native wolfSSL
 * wolfcrypt/test/test.c aes_xts_*_test().
 */
public class AesXtsTest {

    /* AES-128-XTS, test.c aes_xts_128_*_test() */

    /* NIST vector, one block */
    private static final byte[] KEY_128_1 = Util.h2b(
        "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f");
    private static final byte[] TWEAK_128_1 = Util.h2b(
        "4faef7117cda59c66e4b92013e768ad5");
    private static final byte[] PLAIN_128_1 = Util.h2b(
        "ebabce95b14d3c8d6fb350390790311c");
    private static final byte[] CIPHER_128_1 = Util.h2b(
        "778ae8b43cb98d5a825081d5be471c63");

    /* NIST vector, two blocks */
    private static final byte[] KEY_128_2 = Util.h2b(
        "39257905dfcc77766c870a806a60e3c093d12acfcb5142fa096989625b60db16");
    private static final byte[] TWEAK_128_2 = Util.h2b(
        "5cf79db6c5cd991a1c78814224951e84");
    private static final byte[] PLAIN_128_2 = Util.h2b(
        "bdc5468fbc8d50a10d1c857f791c5cbab3810d0d73cf8f2046b1d19e7d5d8a56");
    private static final byte[] CIPHER_128_2 = Util.h2b(
        "d6be046d41f23b5ed70b6b3d5c8e66232be6b807d4dcc60eff8dbc1d9f7fc822");

    /* 24 byte partial block vector, uses KEY_128_1 / TWEAK_128_1 */
    private static final byte[] PLAIN_128_PARTIAL = Util.h2b(
        "ebabce95b14d3c8d6fb350390790311c6e4b92013e768ad5");
    private static final byte[] CIPHER_128_PARTIAL = Util.h2b(
        "2bf72cf3eb85ef7b0b76a0aaf33f258b778ae8b43cb98d5a");

    /* 40 byte in-place vector */
    private static final byte[] KEY_128_3 = Util.h2b(
        "2020202020202020202020202020202020202020202020202020202020202021");
    private static final byte[] TWEAK_128_3 = Util.h2b(
        "20202020202020202020202020202020");
    private static final byte[] PLAIN_128_3 = Util.h2b(
        "20202020202020202020202020202020202020202020202020ff202020202020" +
        "2020202020202020");
    private static final byte[] CIPHER_128_3 = Util.h2b(
        "3906E7F3330B1B1D2B11B0B7AF43B18FE6BE7934BD31643DA116B5F09B1D41F2" +
        "3FED1137CB4DADA4");

    /* AES-192-XTS, test.c aes_xts_192_*_test() */

    private static final byte[] KEY_192_1 = Util.h2b(
        "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7c" +
        "d6e13ffdf2418d8d1911c004cda58da3");
    private static final byte[] TWEAK_192_1 = Util.h2b(
        "4faef7117cda59c66e4b92013e768ad5");
    private static final byte[] PLAIN_192_1 = Util.h2b(
        "ebabce95b14d3c8d6fb350390790311c");
    private static final byte[] CIPHER_192_1 = Util.h2b(
        "65371553f198abb4db4ed369df8e3ae0");

    private static final byte[] KEY_192_2 = Util.h2b(
        "ad504b85d751bfba6913b4cc79b65a62f7f39d360f35b5ec4a7e95bd9ba5f2ec" +
        "c1d77ea3c374bd4b131b078387dd555a");
    private static final byte[] TWEAK_192_2 = Util.h2b(
        "5cf79db6c5cd991a1c78814224951e84");
    private static final byte[] PLAIN_192_2 = Util.h2b(
        "bdc5468fbc8d50a10d1c857f791c5cbab3810d0d73cf8f2046b1d19e7d5d8a56");
    private static final byte[] CIPHER_192_2 = Util.h2b(
        "6ca6b57348f189fadd80721fb8560ca235d408bf24cbecdb81e0e64f3d1c5c46");

    /* 24 byte partial block vector, uses KEY_192_1 / TWEAK_192_1 */
    private static final byte[] PLAIN_192_PARTIAL = Util.h2b(
        "ebabce95b14d3c8d6fb350390790311c6e4b92013e768ad5");
    private static final byte[] CIPHER_192_PARTIAL = Util.h2b(
        "e958feab66b4f179913f91dc6fdfd6ac65371553f198abb4");

    /* 40 byte in-place vector */
    private static final byte[] KEY_192_3 = Util.h2b(
        "2020202020202020202020202020202020202020202020202020202020202020" +
        "20202020202020202020202020202021");
    private static final byte[] TWEAK_192_3 = Util.h2b(
        "20202020202020202020202020202020");
    private static final byte[] PLAIN_192_3 = Util.h2b(
        "20202020202020202020202020202020202020202020202020ff202020202020" +
        "2020202020202020");
    private static final byte[] CIPHER_192_3 = Util.h2b(
        "727ABC253720651EF845B016E7EEDA36AB4FF4DB3CFB7519A3017428D592097A" +
        "DB0D969FB7A2B757");

    /* AES-256-XTS, test.c aes_xts_256_*_test() */

    private static final byte[] KEY_256_1 = Util.h2b(
        "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7c" +
        "d6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08");
    private static final byte[] TWEAK_256_1 = Util.h2b(
        "adf8d92627464ad2f0428e84a9f87564");
    private static final byte[] PLAIN_256_1 = Util.h2b(
        "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e");
    private static final byte[] CIPHER_256_1 = Util.h2b(
        "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db");

    private static final byte[] KEY_256_2 = Util.h2b(
        "ad504b85d751bfba6913b4cc79b65a62f7f39d360f35b5ec4a7e95bd9ba5f2ec" +
        "c1d77ea3c374bd4b131b078387dd555ab5b0c7e52db50612d2b53acb478a53b4");
    private static final byte[] TWEAK_256_2 = Util.h2b(
        "e64219ede0e1c2a00ef5586ac49beb6f");
    private static final byte[] PLAIN_256_2 = Util.h2b(
        "24cb762255b5a800f46e8060569e0553bcfe86553bcad589c7541a73acc39abd" +
        "53c40776d8e822619ea9ad77a0134cfc");
    private static final byte[] CIPHER_256_2 = Util.h2b(
        "a3c6f3f382795b1087d70250db2cd3b1a162a8b6dc126061c10a84a5853f3a89" +
        "e66cdbb79ab4289bc3ead810e9c0af92");

    /* 24 byte partial input, round trip only in test.c */
    private static final byte[] PLAIN_256_PARTIAL = Util.h2b(
        "ebabce95b14d3c8d6fb350390790311c6e4b92013e768ad5");

    /* IEEE 1619-2007 Annex B vectors 15 to 18, AES-128-XTS data units of
     * 17 to 20 bytes (1 to 4 byte partial block). */
    private static final byte[] KEY_1619 = Util.h2b(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0");
    private static final byte[] TWEAK_1619 = Util.h2b(
        "9a785634120000000000000000000000");
    private static final byte[][] PLAIN_1619 = {
        Util.h2b("000102030405060708090a0b0c0d0e0f10"),
        Util.h2b("000102030405060708090a0b0c0d0e0f1011"),
        Util.h2b("000102030405060708090a0b0c0d0e0f101112"),
        Util.h2b("000102030405060708090a0b0c0d0e0f10111213")
    };
    private static final byte[][] CIPHER_1619 = {
        Util.h2b("6c1625db4671522d3d7599601de7ca09ed"),
        Util.h2b("d069444b7a7e0cab09e24447d24deb1fedbf"),
        Util.h2b("e5df1351c0544ba1350b3363cd8ef4beedbf9d"),
        Util.h2b("9d84c813f719aa2c7be3f66171c7c5c2edbf9dac")
    };

    /* Sector vectors, test.c aes_xts_sector_vector_test() */

    private static final byte[] KEY_SECTOR_128 = Util.h2b(
        "a3e40d5bd4b6bbedb2d18c700ad2db2210c81190646d673cbca53f133eab373c");
    private static final byte[] PLAIN_SECTOR_128 = Util.h2b(
        "20e0719405993f09a66ae5bb500e562c");
    private static final byte[] CIPHER_SECTOR_128 = Util.h2b(
        "74623551210216ac926b9650b6d3fa52");
    private static final long SECTOR_128 = 141;

    private static final byte[] KEY_SECTOR_256 = Util.h2b(
        "ef010ca1a3663e32534349bc0bae62232a1573348568fb9ef41768a7674f507a" +
        "727f98755397d0e0aa32f830338cc7a926c773f09e57b357cd156afbca46e1a0");
    private static final byte[] PLAIN_SECTOR_256 = Util.h2b(
        "ed98e01770a853b49db9e6aaf88f0a41b9b56e91a5a2b11d40529254f5523e75");
    private static final byte[] CIPHER_SECTOR_256 = Util.h2b(
        "ca20c55e8dc149687d2541de39c3df6300bb5a163c10ced3666b1357db8bd39d");
    private static final long SECTOR_256 = 187;

    /* fixed seed keeps random lengths and chunk boundaries reproducible */
    private static final long RAND_SEED = 0x5EED;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Skip each test when AES-XTS is not compiled in. A per test rule. */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule aesXtsAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    try {
                        new AesXts();
                    } catch (WolfCryptException e) {
                        Assume.assumeTrue("AES-XTS not compiled in: " +
                            e.getError(), false);
                    }
                    base.evaluate();
                }
            };
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        System.out.println("JNI AesXts Class");
    }

    /* One-shot operation with a fresh AesXts */
    private static byte[] oneShot(byte[] key, byte[] tweak, int mode,
        byte[] input) {

        AesXts aes = new AesXts();
        try {
            aes.setKey(key, tweak, mode);
            return aes.update(input);
        } finally {
            aes.releaseNativeStruct();
        }
    }

    /* Random key of size bytes, halves differ for even size >= 2 */
    private static byte[] randomKey(Random rand, int size) {
        byte[] key = new byte[size];

        rand.nextBytes(key);
        if (size >= 2 && (size % 2) == 0) {
            key[0] = (byte)(key[size / 2] + 1);
        }

        return key;
    }

    /* AES-192-XTS needs native AES-192 and is not allowed under FIPS */
    private static boolean aes192XtsAvailable() {
        return FeatureDetect.Aes192Enabled() && !Fips.enabled;
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesXts().getNativeStruct());
    }

    @Test
    public void keySizeConstantsMatchVectors() {
        assertEquals(AesXts.KEY_SIZE_128, KEY_128_1.length);
        assertEquals(AesXts.KEY_SIZE_192, KEY_192_1.length);
        assertEquals(AesXts.KEY_SIZE_256, KEY_256_1.length);
        assertEquals(AesXts.TWEAK_SIZE, TWEAK_128_1.length);
        assertEquals(AesXts.BLOCK_SIZE, PLAIN_128_1.length);
    }

    @Test
    public void tweakSetBeforeKeyIsKept() {
        AesXts aes = new AesXts();

        /* setTweak() first, then setKey() with null tweak keeps it */
        aes.setTweak(TWEAK_128_2);
        aes.setKey(KEY_128_2, null, AesXts.ENCRYPT_MODE);
        assertArrayEquals(TWEAK_128_2, aes.getTweak());
        assertArrayEquals(CIPHER_128_2, aes.update(PLAIN_128_2));
        aes.releaseNativeStruct();
    }

    @Test
    public void checkSectorAndStreamParams() {
        byte[] input = new byte[AesXts.BLOCK_SIZE * 2];
        byte[] output = new byte[AesXts.BLOCK_SIZE * 2];
        AesXts aes = new AesXts();

        /* no key */
        try {
            aes.updateSector(input, 0L);
            fail("updateSector() without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        aes.setKey(KEY_SECTOR_128, null, AesXts.ENCRYPT_MODE);

        try {
            aes.updateSector((byte[])null, 0L);
            fail("null input should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(input, 0, input.length, null, 0, 0L);
            fail("null output should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(input, 1, input.length, output, 0, 0L);
            fail("offset + length past input should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(input, 0, input.length, output, 1, 0L);
            fail("outputOffset + length past output should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector((ByteBuffer)null,
                ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE), 0L);
            fail("null ByteBuffer should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* no tweak set, ByteBuffer one-shot path */
        try {
            aes.update(ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE),
                ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE));
            fail("update() without tweak should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        if (AesXts.isStreamEnabled()) {
            aes.streamInit(TWEAK_128_1);
            try {
                aes.streamFinal(input, 0, input.length, null, 0);
                fail("null output should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                aes.streamUpdate((ByteBuffer)null,
                    ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE));
                fail("null ByteBuffer should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                aes.streamFinal(null,
                    ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE));
                fail("null ByteBuffer should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            assertEquals(input.length,
                aes.streamFinal(input, 0, input.length, output, 0));
        }

        aes.releaseNativeStruct();

        /* released object rejects everything without re-allocating */
        try {
            aes.updateSector(input, 0L);
            fail("updateSector() after release should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            aes.streamInit(TWEAK_128_1);
            fail("streamInit() after release should throw");
        } catch (IllegalStateException e) {
            /* expected */
        } catch (WolfCryptException e) {
            /* streaming not compiled in */
            assertFalse(AesXts.isStreamEnabled());
        }
        assertEquals(NativeStruct.NULL, aes.getNativeStruct());
    }

    @Test
    public void checkSetKeyParams() {
        AesXts aes = new AesXts();

        try {
            aes.setKey(null, TWEAK_128_1, AesXts.ENCRYPT_MODE);
            fail("key should not be null");
        } catch (WolfCryptException e) {
            /* expected */
        }
        assertEquals(NativeStruct.NULL, aes.getNativeStruct());

        int[] badKeySizes = { 0, 16, 24, 31, 33, 47, 49, 63, 65, 128 };
        for (int size : badKeySizes) {
            try {
                aes.setKey(new byte[size], TWEAK_128_1, AesXts.ENCRYPT_MODE);
                fail("key of " + size + " bytes should be rejected");
            } catch (WolfCryptException e) {
                assertTrue(e.getMessage().contains("AES-XTS key must be"));
            }
        }

        /* identical halves, rejected when native enforces distinct keys
         * (FIPS, and by default since wolfSSL 5.9.2), else usable */
        byte[] sameHalves = new byte[AesXts.KEY_SIZE_128];
        int half = AesXts.KEY_SIZE_128 / 2;
        System.arraycopy(KEY_128_1, 0, sameHalves, 0, half);
        System.arraycopy(KEY_128_1, 0, sameHalves, half, half);
        AesXts dup = new AesXts();
        try {
            dup.setKey(sameHalves, TWEAK_128_1, AesXts.ENCRYPT_MODE);
            assertEquals(PLAIN_128_1.length,
                dup.update(PLAIN_128_1).length);
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
        } finally {
            dup.releaseNativeStruct();
        }

        /* bad tweak lengths */
        try {
            aes.setKey(KEY_128_1, new byte[AesXts.TWEAK_SIZE - 1],
                AesXts.ENCRYPT_MODE);
            fail("short tweak should be rejected");
        } catch (WolfCryptException e) {
            assertTrue(e.getMessage().contains("AES-XTS tweak must be"));
        }
        try {
            aes.setKey(KEY_128_1, new byte[AesXts.TWEAK_SIZE + 1],
                AesXts.ENCRYPT_MODE);
            fail("long tweak should be rejected");
        } catch (WolfCryptException e) {
            assertTrue(e.getMessage().contains("AES-XTS tweak must be"));
        }

        /* bad opmode */
        try {
            aes.setKey(KEY_128_1, TWEAK_128_1, AesXts.DECRYPT_MODE + 1);
            fail("invalid opmode should be rejected");
        } catch (WolfCryptException e) {
            /* expected */
        }

        aes.setKey(KEY_128_1, null, AesXts.ENCRYPT_MODE);
        assertNull(aes.getTweak());

        try {
            aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.ENCRYPT_MODE);
            fail("setting key twice should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        aes.releaseNativeStruct();

        /* usable again after release */
        aes.setKey(KEY_128_1, TWEAK_128_1, AesXts.DECRYPT_MODE);
        assertArrayEquals(TWEAK_128_1, aes.getTweak());
        aes.releaseNativeStruct();

        assertNull(aes.getTweak());
    }

    @Test
    public void aes192KeyAcceptedOnlyWhenAvailable() {
        AesXts aes = new AesXts();

        try {
            aes.setKey(KEY_192_1, TWEAK_192_1, AesXts.ENCRYPT_MODE);
            if (!aes192XtsAvailable()) {
                fail("AES-192-XTS key should be rejected");
            }
            byte[] out = aes.update(PLAIN_192_1);
            assertArrayEquals("AES-192-XTS encrypt failed",
                CIPHER_192_1, out);

        } catch (WolfCryptException e) {
            if (aes192XtsAvailable()) {
                fail("AES-192-XTS key should be accepted: " +
                     e.getMessage());
            }
        } finally {
            aes.releaseNativeStruct();
        }
    }

    @Test
    public void checkUpdateParams() {
        byte[] input = new byte[AesXts.BLOCK_SIZE * 2];
        byte[] output = new byte[AesXts.BLOCK_SIZE * 2];
        AesXts aes = new AesXts();

        /* no key yet */
        try {
            aes.update(input);
            fail("update() without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* key but no tweak */
        aes.setKey(KEY_128_1, null, AesXts.ENCRYPT_MODE);
        try {
            aes.update(input);
            fail("update() without tweak should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        aes.setTweak(TWEAK_128_1);

        aes.update(input);

        try {
            aes.update((byte[])null);
            fail("input should not be null");
        } catch (WolfCryptException e) {
            /* expected */
        }

        try {
            aes.update(null, 0, input.length, output, 0);
            fail("input should not be null");
        } catch (WolfCryptException e) {
            /* expected */
        }

        try {
            aes.update(input, 0, input.length, null, 0);
            fail("output should not be null");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* ranges */
        try {
            aes.update(input, 1, input.length, output, 0);
            fail("offset + length past input should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.update(input, 0, input.length, output, 1);
            fail("outputOffset + length past output should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.update(input, -1, AesXts.BLOCK_SIZE, output, 0);
            fail("negative offset should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.update(input, 0, -1, output, 0);
            fail("negative length should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* output too small */
        try {
            ByteBuffer in = ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE);
            ByteBuffer out = ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE);
            aes.update(in, out);
            fail("ByteBuffer output too small should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* non-direct ByteBuffers */
        try {
            ByteBuffer in = ByteBuffer.allocate(2 * AesXts.BLOCK_SIZE);
            ByteBuffer out = ByteBuffer.allocate(2 * AesXts.BLOCK_SIZE);
            aes.update(in, out);
            fail("non-direct ByteBuffer should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        assertEquals(input.length,
            aes.update(input, 0, input.length, output, 0));

        aes.releaseNativeStruct();

        try {
            aes.update(input, 0, input.length, output, 0);
            fail("native struct should not be null");
        } catch (IllegalStateException e) {
            /* expected */
        }
        /* rejected without allocating a new native struct */
        assertEquals(NativeStruct.NULL, aes.getNativeStruct());
    }

    @Test
    public void checkMinimumInputLength() {
        AesXts aes = new AesXts();
        aes.setKey(KEY_128_1, TWEAK_128_1, AesXts.ENCRYPT_MODE);

        int[] tooShort = { 0, 1, AesXts.BLOCK_SIZE - 1 };
        for (int size : tooShort) {
            try {
                aes.update(new byte[size]);
                fail("XTS should require input length >= " +
                    AesXts.BLOCK_SIZE + ", got " + size);
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                aes.updateSector(new byte[size], 0);
                fail("XTS sector should require input length >= " +
                    AesXts.BLOCK_SIZE + ", got " + size);
            } catch (WolfCryptException e) {
                /* expected */
            }
        }

        byte[] result16 = aes.update(new byte[AesXts.BLOCK_SIZE]);
        assertEquals(AesXts.BLOCK_SIZE, result16.length);

        byte[] result17 = aes.update(new byte[AesXts.BLOCK_SIZE + 1]);
        assertEquals(AesXts.BLOCK_SIZE + 1, result17.length);

        aes.releaseNativeStruct();
    }

    @Test
    public void aes128XtsVectorTest() {
        assertArrayEquals("AES-128-XTS encrypt (32 bytes) failed",
            CIPHER_128_2, oneShot(KEY_128_2, TWEAK_128_2,
                AesXts.ENCRYPT_MODE, PLAIN_128_2));
        assertArrayEquals("AES-128-XTS decrypt (32 bytes) failed",
            PLAIN_128_2, oneShot(KEY_128_2, TWEAK_128_2,
                AesXts.DECRYPT_MODE, CIPHER_128_2));

        assertArrayEquals("AES-128-XTS encrypt (16 bytes) failed",
            CIPHER_128_1, oneShot(KEY_128_1, TWEAK_128_1,
                AesXts.ENCRYPT_MODE, PLAIN_128_1));
        assertArrayEquals("AES-128-XTS decrypt (16 bytes) failed",
            PLAIN_128_1, oneShot(KEY_128_1, TWEAK_128_1,
                AesXts.DECRYPT_MODE, CIPHER_128_1));
    }

    @Test
    public void aes128XtsPartialBlockTest() {
        assertArrayEquals("AES-128-XTS partial block encrypt failed",
            CIPHER_128_PARTIAL, oneShot(KEY_128_1, TWEAK_128_1,
                AesXts.ENCRYPT_MODE, PLAIN_128_PARTIAL));
        assertArrayEquals("AES-128-XTS partial block decrypt failed",
            PLAIN_128_PARTIAL, oneShot(KEY_128_1, TWEAK_128_1,
                AesXts.DECRYPT_MODE, CIPHER_128_PARTIAL));
    }

    @Test
    public void ieee1619PartialBlockVectors() {
        for (int i = 0; i < PLAIN_1619.length; i++) {
            assertArrayEquals("IEEE 1619 vector " + (15 + i) + " encrypt",
                CIPHER_1619[i], oneShot(KEY_1619, TWEAK_1619,
                    AesXts.ENCRYPT_MODE, PLAIN_1619[i]));
            assertArrayEquals("IEEE 1619 vector " + (15 + i) + " decrypt",
                PLAIN_1619[i], oneShot(KEY_1619, TWEAK_1619,
                    AesXts.DECRYPT_MODE, CIPHER_1619[i]));
        }

        if (AesXts.isStreamEnabled()) {
            /* whole data unit through the streaming final */
            AesXts aes = new AesXts();
            aes.setKey(KEY_1619, null, AesXts.ENCRYPT_MODE);
            for (int i = 0; i < PLAIN_1619.length; i++) {
                aes.streamInit(TWEAK_1619);
                assertArrayEquals("IEEE 1619 vector " + (15 + i) + " stream",
                    CIPHER_1619[i], aes.streamFinal(PLAIN_1619[i]));
            }
            aes.releaseNativeStruct();
        }
    }

    @Test
    public void aes128XtsInPlaceTest() {
        AesXts aes = new AesXts();
        byte[] buf = PLAIN_128_3.clone();

        /* input and output are the same array */
        aes.setKey(KEY_128_3, TWEAK_128_3, AesXts.ENCRYPT_MODE);
        assertEquals(buf.length,
            aes.update(buf, 0, buf.length, buf, 0));
        assertArrayEquals("AES-128-XTS in-place encrypt failed",
            CIPHER_128_3, buf);
        aes.releaseNativeStruct();

        aes.setKey(KEY_128_3, TWEAK_128_3, AesXts.DECRYPT_MODE);
        assertEquals(buf.length,
            aes.update(buf, 0, buf.length, buf, 0));
        assertArrayEquals("AES-128-XTS in-place decrypt failed",
            PLAIN_128_3, buf);
        aes.releaseNativeStruct();
    }

    @Test
    public void aes192XtsVectorTest() {
        Assume.assumeTrue("AES-192-XTS not available", aes192XtsAvailable());

        assertArrayEquals("AES-192-XTS encrypt (32 bytes) failed",
            CIPHER_192_2, oneShot(KEY_192_2, TWEAK_192_2,
                AesXts.ENCRYPT_MODE, PLAIN_192_2));
        assertArrayEquals("AES-192-XTS decrypt (32 bytes) failed",
            PLAIN_192_2, oneShot(KEY_192_2, TWEAK_192_2,
                AesXts.DECRYPT_MODE, CIPHER_192_2));

        assertArrayEquals("AES-192-XTS encrypt (16 bytes) failed",
            CIPHER_192_1, oneShot(KEY_192_1, TWEAK_192_1,
                AesXts.ENCRYPT_MODE, PLAIN_192_1));
        assertArrayEquals("AES-192-XTS decrypt (16 bytes) failed",
            PLAIN_192_1, oneShot(KEY_192_1, TWEAK_192_1,
                AesXts.DECRYPT_MODE, CIPHER_192_1));

        assertArrayEquals("AES-192-XTS partial block encrypt failed",
            CIPHER_192_PARTIAL, oneShot(KEY_192_1, TWEAK_192_1,
                AesXts.ENCRYPT_MODE, PLAIN_192_PARTIAL));
        assertArrayEquals("AES-192-XTS partial block decrypt failed",
            PLAIN_192_PARTIAL, oneShot(KEY_192_1, TWEAK_192_1,
                AesXts.DECRYPT_MODE, CIPHER_192_PARTIAL));

        /* in-place vector */
        AesXts aes = new AesXts();
        byte[] buf = PLAIN_192_3.clone();
        aes.setKey(KEY_192_3, TWEAK_192_3, AesXts.ENCRYPT_MODE);
        assertEquals(buf.length, aes.update(buf, 0, buf.length, buf, 0));
        assertArrayEquals("AES-192-XTS in-place encrypt failed",
            CIPHER_192_3, buf);
        aes.releaseNativeStruct();

        aes.setKey(KEY_192_3, TWEAK_192_3, AesXts.DECRYPT_MODE);
        assertEquals(buf.length, aes.update(buf, 0, buf.length, buf, 0));
        assertArrayEquals("AES-192-XTS in-place decrypt failed",
            PLAIN_192_3, buf);
        aes.releaseNativeStruct();
    }

    @Test
    public void aes256XtsVectorTest() {
        assertArrayEquals("AES-256-XTS encrypt (32 bytes) failed",
            CIPHER_256_1, oneShot(KEY_256_1, TWEAK_256_1,
                AesXts.ENCRYPT_MODE, PLAIN_256_1));
        assertArrayEquals("AES-256-XTS decrypt (32 bytes) failed",
            PLAIN_256_1, oneShot(KEY_256_1, TWEAK_256_1,
                AesXts.DECRYPT_MODE, CIPHER_256_1));

        assertArrayEquals("AES-256-XTS encrypt (48 bytes) failed",
            CIPHER_256_2, oneShot(KEY_256_2, TWEAK_256_2,
                AesXts.ENCRYPT_MODE, PLAIN_256_2));
        assertArrayEquals("AES-256-XTS decrypt (48 bytes) failed",
            PLAIN_256_2, oneShot(KEY_256_2, TWEAK_256_2,
                AesXts.DECRYPT_MODE, CIPHER_256_2));
    }

    @Test
    public void aes256XtsPartialBlockRoundTrip() {
        byte[] cipher = oneShot(KEY_256_1, TWEAK_256_1,
            AesXts.ENCRYPT_MODE, PLAIN_256_PARTIAL);

        assertEquals(PLAIN_256_PARTIAL.length, cipher.length);
        assertFalse("ciphertext should differ from plaintext",
            Arrays.equals(PLAIN_256_PARTIAL, cipher));
        assertArrayEquals("AES-256-XTS partial block round trip failed",
            PLAIN_256_PARTIAL, oneShot(KEY_256_1, TWEAK_256_1,
                AesXts.DECRYPT_MODE, cipher));
    }

    @Test
    public void wrongKeyDecryptShouldNotMatch() {
        /* test.c: decrypting c2 with k1 must not yield p2 */
        byte[] out = oneShot(KEY_128_1, TWEAK_128_2, AesXts.DECRYPT_MODE,
            CIPHER_128_2);
        assertFalse("decrypt with wrong key should not match plaintext",
            Arrays.equals(PLAIN_128_2, out));

        /* wrong tweak */
        out = oneShot(KEY_128_2, TWEAK_128_1, AesXts.DECRYPT_MODE,
            CIPHER_128_2);
        assertFalse("decrypt with wrong tweak should not match plaintext",
            Arrays.equals(PLAIN_128_2, out));
    }

    @Test
    public void setTweakTest() {
        AesXts aes = new AesXts();

        /* wrong tweak first, then the vector tweak */
        aes.setKey(KEY_128_2, TWEAK_128_1, AesXts.ENCRYPT_MODE);
        byte[] wrongTweakOut = aes.update(PLAIN_128_2);
        assertFalse("different tweak should give different ciphertext",
            Arrays.equals(CIPHER_128_2, wrongTweakOut));

        aes.setTweak(TWEAK_128_2);
        assertArrayEquals(TWEAK_128_2, aes.getTweak());
        assertArrayEquals("encrypt after setTweak() failed",
            CIPHER_128_2, aes.update(PLAIN_128_2));

        /* getTweak() returns a copy */
        byte[] copy = aes.getTweak();
        copy[0] ^= (byte)0xFF;
        assertArrayEquals("encrypt after modifying getTweak() copy failed",
            CIPHER_128_2, aes.update(PLAIN_128_2));

        /* bad tweaks leave the current tweak in place */
        try {
            aes.setTweak(null);
            fail("null tweak should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.setTweak(new byte[8]);
            fail("8 byte tweak should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        assertArrayEquals(CIPHER_128_2, aes.update(PLAIN_128_2));

        aes.releaseNativeStruct();
    }

    @Test
    public void offsetLengthUpdateTest() {
        AesXts aes = new AesXts();
        byte[] input = new byte[PLAIN_128_2.length + 10];
        byte[] output = new byte[CIPHER_128_2.length + 20];

        System.arraycopy(PLAIN_128_2, 0, input, 3, PLAIN_128_2.length);

        aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.ENCRYPT_MODE);
        int processed = aes.update(input, 3, PLAIN_128_2.length,
            output, 7);
        assertEquals(PLAIN_128_2.length, processed);
        assertArrayEquals("offset/length encrypt failed", CIPHER_128_2,
            Arrays.copyOfRange(output, 7, 7 + CIPHER_128_2.length));

        /* bytes outside the output window untouched */
        for (int i = 0; i < 7; i++) {
            assertEquals(0, output[i]);
        }
        for (int i = 7 + CIPHER_128_2.length; i < output.length; i++) {
            assertEquals(0, output[i]);
        }
        aes.releaseNativeStruct();

        aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.DECRYPT_MODE);
        assertArrayEquals("offset/length decrypt failed", PLAIN_128_2,
            aes.update(output, 7, CIPHER_128_2.length));
        aes.releaseNativeStruct();
    }

    @Test
    public void byteBufferUpdateTest() {
        AesXts aes = new AesXts();
        ByteBuffer input = ByteBuffer.allocateDirect(PLAIN_128_3.length + 8);
        ByteBuffer output = ByteBuffer.allocateDirect(PLAIN_128_3.length + 8);

        /* non-zero positions */
        input.position(5);
        input.put(PLAIN_128_3);
        input.flip();
        input.position(5);
        output.position(3);

        aes.setKey(KEY_128_3, TWEAK_128_3, AesXts.ENCRYPT_MODE);
        int processed = aes.update(input, output);
        assertEquals(PLAIN_128_3.length, processed);
        assertEquals(5 + PLAIN_128_3.length, input.position());
        assertEquals(3 + PLAIN_128_3.length, output.position());

        output.flip();
        output.position(3);
        byte[] cipher = new byte[output.remaining()];
        output.get(cipher);
        assertArrayEquals("ByteBuffer encrypt failed", CIPHER_128_3, cipher);
        aes.releaseNativeStruct();

        ByteBuffer cin = ByteBuffer.allocateDirect(cipher.length);
        ByteBuffer pout = ByteBuffer.allocateDirect(cipher.length);
        cin.put(cipher);
        cin.flip();

        aes.setKey(KEY_128_3, TWEAK_128_3, AesXts.DECRYPT_MODE);
        assertEquals(cipher.length, aes.update(cin, pout));
        pout.flip();
        byte[] plain = new byte[pout.remaining()];
        pout.get(plain);
        assertArrayEquals("ByteBuffer decrypt failed", PLAIN_128_3, plain);
        aes.releaseNativeStruct();
    }

    @Test
    public void aes128XtsSectorTest() {
        AesXts aes = new AesXts();

        aes.setKey(KEY_SECTOR_128, null, AesXts.ENCRYPT_MODE);
        assertArrayEquals("AES-128-XTS sector encrypt failed",
            CIPHER_SECTOR_128, aes.updateSector(PLAIN_SECTOR_128,
                SECTOR_128));

        assertFalse(Arrays.equals(CIPHER_SECTOR_128,
            aes.updateSector(PLAIN_SECTOR_128, SECTOR_128 + 1)));
        aes.releaseNativeStruct();

        aes.setKey(KEY_SECTOR_128, null, AesXts.DECRYPT_MODE);
        assertArrayEquals("AES-128-XTS sector decrypt failed",
            PLAIN_SECTOR_128, aes.updateSector(CIPHER_SECTOR_128,
                SECTOR_128));
        aes.releaseNativeStruct();
    }

    @Test
    public void aes256XtsSectorTest() {
        AesXts aes = new AesXts();
        byte[] output = new byte[PLAIN_SECTOR_256.length];

        aes.setKey(KEY_SECTOR_256, null, AesXts.ENCRYPT_MODE);
        assertEquals(PLAIN_SECTOR_256.length,
            aes.updateSector(PLAIN_SECTOR_256, 0, PLAIN_SECTOR_256.length,
                output, 0, SECTOR_256));
        assertArrayEquals("AES-256-XTS sector encrypt failed",
            CIPHER_SECTOR_256, output);
        aes.releaseNativeStruct();

        aes.setKey(KEY_SECTOR_256, null, AesXts.DECRYPT_MODE);
        assertArrayEquals("AES-256-XTS sector decrypt failed",
            PLAIN_SECTOR_256, aes.updateSector(CIPHER_SECTOR_256,
                SECTOR_256));
        aes.releaseNativeStruct();
    }

    @Test
    public void byteBufferSectorTest() {
        AesXts aes = new AesXts();
        int len = PLAIN_SECTOR_256.length;
        ByteBuffer input = ByteBuffer.allocateDirect(len + 4);
        ByteBuffer output = ByteBuffer.allocateDirect(len + 4);

        /* non-zero positions */
        input.position(2);
        input.put(PLAIN_SECTOR_256);
        input.flip();
        input.position(2);
        output.position(4);

        aes.setKey(KEY_SECTOR_256, null, AesXts.ENCRYPT_MODE);
        assertEquals(len, aes.updateSector(input, output, SECTOR_256));
        assertEquals(2 + len, input.position());
        assertEquals(4 + len, output.position());

        output.flip();
        output.position(4);
        byte[] cipher = new byte[output.remaining()];
        output.get(cipher);
        assertArrayEquals("ByteBuffer sector encrypt failed",
            CIPHER_SECTOR_256, cipher);

        /* non-direct, short input, small output */
        try {
            aes.updateSector(ByteBuffer.wrap(PLAIN_SECTOR_256),
                ByteBuffer.allocate(len), SECTOR_256);
            fail("non-direct ByteBuffer should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE - 1),
                ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE - 1), SECTOR_256);
            fail("15 byte input should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE),
                ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE), SECTOR_256);
            fail("output too small should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        aes.releaseNativeStruct();

        ByteBuffer cin = ByteBuffer.allocateDirect(cipher.length);
        ByteBuffer pout = ByteBuffer.allocateDirect(cipher.length);
        cin.put(cipher);
        cin.flip();

        aes.setKey(KEY_SECTOR_256, null, AesXts.DECRYPT_MODE);
        assertEquals(cipher.length, aes.updateSector(cin, pout, SECTOR_256));
        pout.flip();
        byte[] plain = new byte[pout.remaining()];
        pout.get(plain);
        assertArrayEquals("ByteBuffer sector decrypt failed",
            PLAIN_SECTOR_256, plain);
        aes.releaseNativeStruct();

        /* one buffer as both input and output, position advances once */
        ByteBuffer same = ByteBuffer.allocateDirect(len);
        same.put(PLAIN_SECTOR_256);
        same.flip();
        aes.setKey(KEY_SECTOR_256, null, AesXts.ENCRYPT_MODE);
        assertEquals(len, aes.updateSector(same, same, SECTOR_256));
        assertEquals(len, same.position());
        same.flip();
        byte[] inPlace = new byte[same.remaining()];
        same.get(inPlace);
        assertArrayEquals("in-place ByteBuffer sector encrypt failed",
            CIPHER_SECTOR_256, inPlace);
        aes.releaseNativeStruct();
    }

    @Test
    public void overlapAndReadOnlyBuffersRejected() {
        AesXts aes = new AesXts();
        byte[] buf = new byte[3 * AesXts.BLOCK_SIZE];
        ByteBuffer direct = ByteBuffer.allocateDirect(3 * AesXts.BLOCK_SIZE);
        ByteBuffer in;
        ByteBuffer out;

        aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.ENCRYPT_MODE);

        /* same array, different offsets, rejected in Java */
        try {
            aes.update(buf, 0, 2 * AesXts.BLOCK_SIZE, buf, AesXts.BLOCK_SIZE);
            fail("partially overlapping arrays should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(buf, AesXts.BLOCK_SIZE, 2 * AesXts.BLOCK_SIZE,
                buf, 0, 1L);
            fail("partially overlapping arrays should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* overlapping views of one direct buffer, positions unchanged */
        in = direct.duplicate();
        in.limit(2 * AesXts.BLOCK_SIZE);
        out = direct.duplicate();
        out.position(AesXts.BLOCK_SIZE);
        try {
            aes.update(in, out);
            fail("partially overlapping ByteBuffers should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(in, out, 1L);
            fail("partially overlapping ByteBuffers should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        assertEquals(0, in.position());
        assertEquals(AesXts.BLOCK_SIZE, out.position());

        /* read-only output */
        ByteBuffer readOnly =
            ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE).asReadOnlyBuffer();
        try {
            aes.update(ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE),
                readOnly);
            fail("read-only output should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* one buffer as both input and output, position advances once */
        ByteBuffer same = ByteBuffer.allocateDirect(PLAIN_128_2.length);
        same.put(PLAIN_128_2);
        same.flip();
        assertEquals(PLAIN_128_2.length, aes.update(same, same));
        assertEquals(PLAIN_128_2.length, same.position());
        same.flip();
        byte[] cipher = new byte[same.remaining()];
        same.get(cipher);
        assertArrayEquals(CIPHER_128_2, cipher);

        if (AesXts.isStreamEnabled()) {
            /* rejected in Java, stream stays active */
            aes.streamInit(TWEAK_128_2);
            try {
                aes.streamUpdate(buf, 0, 2 * AesXts.BLOCK_SIZE, buf,
                    AesXts.BLOCK_SIZE);
                fail("partially overlapping arrays should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                aes.streamFinal(buf, 0, 2 * AesXts.BLOCK_SIZE, buf,
                    AesXts.BLOCK_SIZE);
                fail("partially overlapping arrays should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                aes.streamFinal(ByteBuffer.wrap(new byte[AesXts.BLOCK_SIZE]),
                    ByteBuffer.allocate(AesXts.BLOCK_SIZE));
                fail("non-direct ByteBuffer streamFinal() should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            assertArrayEquals(CIPHER_128_2, aes.streamFinal(PLAIN_128_2));

            /* overlapping views are rejected natively, which abandons the
             * data unit until the next streamInit() */
            in = direct.duplicate();
            in.limit(2 * AesXts.BLOCK_SIZE);
            out = direct.duplicate();
            out.position(AesXts.BLOCK_SIZE);
            aes.streamInit(TWEAK_128_2);
            try {
                aes.streamUpdate(in, out);
                fail("partially overlapping ByteBuffers should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            try {
                aes.streamFinal(PLAIN_128_2);
                fail("stream should be abandoned after native error");
            } catch (IllegalStateException e) {
                /* expected */
            }
            aes.streamInit(TWEAK_128_2);
            try {
                aes.streamFinal(in, out);
                fail("partially overlapping ByteBuffers should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
            aes.streamInit(TWEAK_128_2);
            assertArrayEquals(CIPHER_128_2, aes.streamFinal(PLAIN_128_2));
        }

        aes.releaseNativeStruct();
    }

    @Test
    public void sectorMatchesExplicitTweak() {
        /* sector is an unsigned little-endian 64-bit tweak, zero padded */
        long[] sectors = { 0L, 0x0102030405060708L, Long.MAX_VALUE,
                           Long.MIN_VALUE, -1L };
        AesXts aes = new AesXts();
        aes.setKey(KEY_256_2, null, AesXts.ENCRYPT_MODE);

        for (long sector : sectors) {
            byte[] tweak = new byte[AesXts.TWEAK_SIZE];
            for (int i = 0; i < Long.BYTES; i++) {
                tweak[i] = (byte)(sector >>> (Byte.SIZE * i));
            }
            aes.setTweak(tweak);
            assertArrayEquals("sector " + sector + " differs from tweak",
                aes.update(PLAIN_256_2), aes.updateSector(PLAIN_256_2, sector));
        }

        aes.releaseNativeStruct();
    }

    @Test
    public void largeRandomRoundTrip() {
        Random rand = new Random(RAND_SEED);
        byte[] key = randomKey(rand, AesXts.KEY_SIZE_256);
        byte[] tweak = new byte[AesXts.TWEAK_SIZE];
        byte[] plain = new byte[(1024 * 1024) + 7];
        rand.nextBytes(tweak);
        rand.nextBytes(plain);

        byte[] cipher = oneShot(key, tweak, AesXts.ENCRYPT_MODE, plain);
        assertEquals(plain.length, cipher.length);
        assertFalse(Arrays.equals(plain, cipher));

        byte[] decrypted = oneShot(key, tweak, AesXts.DECRYPT_MODE, cipher);
        assertArrayEquals("large round trip failed", plain, decrypted);
    }

    @Test
    public void variousLengthsRoundTrip() {
        Random rand = new Random(RAND_SEED);
        int[] sizes = { 16, 17, 18, 31, 32, 33, 47, 48, 49, 63, 64, 65,
                        127, 128, 129, 255, 256, 257, 511, 512, 513,
                        4096, 4097 };
        int[] keySizes = aes192XtsAvailable() ?
            new int[] { AesXts.KEY_SIZE_128, AesXts.KEY_SIZE_192,
                        AesXts.KEY_SIZE_256 } :
            new int[] { AesXts.KEY_SIZE_128, AesXts.KEY_SIZE_256 };

        for (int keySize : keySizes) {
            byte[] key = randomKey(rand, keySize);
            byte[] tweak = new byte[AesXts.TWEAK_SIZE];
            rand.nextBytes(tweak);

            for (int size : sizes) {
                byte[] plain = new byte[size];
                rand.nextBytes(plain);

                byte[] cipher = oneShot(key, tweak, AesXts.ENCRYPT_MODE,
                    plain);
                assertEquals("output length mismatch for size " + size,
                    size, cipher.length);

                byte[] decrypted = oneShot(key, tweak, AesXts.DECRYPT_MODE,
                    cipher);
                assertArrayEquals("round trip failed for size " + size +
                    ", key size " + keySize, plain, decrypted);
            }
        }
    }

    @Test
    public void releaseAndReuseShouldWork() {
        AesXts aes = new AesXts();

        try {
            aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.ENCRYPT_MODE);
            aes.releaseNativeStruct();

            /* second release is a no-op */
            aes.releaseNativeStruct();

            aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.ENCRYPT_MODE);
            assertArrayEquals("encrypt after re-init failed",
                CIPHER_128_2, aes.update(PLAIN_128_2));
        } finally {
            aes.releaseNativeStruct();
        }
    }

    @Test
    public void reuseObjectForMultipleDataUnits() {
        AesXts aes = new AesXts();

        aes.setKey(KEY_128_1, TWEAK_128_1, AesXts.ENCRYPT_MODE);
        assertArrayEquals(CIPHER_128_1, aes.update(PLAIN_128_1));
        assertArrayEquals(CIPHER_128_PARTIAL, aes.update(PLAIN_128_PARTIAL));
        assertArrayEquals(CIPHER_128_1, aes.update(PLAIN_128_1));
        aes.releaseNativeStruct();

        aes.setKey(KEY_128_1, TWEAK_128_1, AesXts.DECRYPT_MODE);
        assertArrayEquals(PLAIN_128_PARTIAL, aes.update(CIPHER_128_PARTIAL));
        assertArrayEquals(PLAIN_128_1, aes.update(CIPHER_128_1));
        aes.releaseNativeStruct();
    }

    @Test
    public void threadedUseTest() throws InterruptedException {
        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<Integer>();
        final LinkedBlockingQueue<String> errors =
            new LinkedBlockingQueue<String>();

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    int failed = 0;
                    AesXts enc = null;
                    AesXts dec = null;

                    try {
                        enc = new AesXts();
                        enc.setKey(KEY_256_2, TWEAK_256_2,
                            AesXts.ENCRYPT_MODE);
                        dec = new AesXts();
                        dec.setKey(KEY_256_2, TWEAK_256_2,
                            AesXts.DECRYPT_MODE);

                        for (int j = 0; j < 20; j++) {
                            byte[] cipher = enc.update(PLAIN_256_2);
                            if (!Arrays.equals(CIPHER_256_2, cipher)) {
                                failed = 1;
                            }
                            byte[] plain = dec.update(cipher);
                            if (!Arrays.equals(PLAIN_256_2, plain)) {
                                failed = 1;
                            }
                        }
                    } catch (Exception e) {
                        errors.add(e.toString());
                        failed = 1;
                    } finally {
                        if (enc != null) {
                            enc.releaseNativeStruct();
                        }
                        if (dec != null) {
                            dec.releaseNativeStruct();
                        }
                    }

                    results.add(failed);
                    latch.countDown();
                }
            });
        }

        latch.await();
        service.shutdown();

        Iterator<Integer> it = results.iterator();
        while (it.hasNext()) {
            if (it.next() == 1) {
                fail("Threading error in AesXts thread test: " +
                    (errors.isEmpty() ? "output mismatch" : errors.peek()));
            }
        }
    }

    /* Streaming API */

    @Test
    public void streamApiNotCompiledIn() {
        Assume.assumeFalse(AesXts.isStreamEnabled());

        AesXts aes = new AesXts();
        aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.ENCRYPT_MODE);
        try {
            aes.streamInit(TWEAK_128_2);
            fail("streamInit() should throw when streaming not compiled in");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
        }
        try {
            aes.streamUpdate(PLAIN_128_2);
            fail("streamUpdate() should throw when streaming not compiled in");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
        }
        try {
            aes.streamFinal(PLAIN_128_2);
            fail("streamFinal() should throw when streaming not compiled in");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.NOT_COMPILED_IN, e.getError());
        } finally {
            aes.releaseNativeStruct();
        }
    }

    @Test
    public void streamVectorTest() {
        Assume.assumeTrue(AesXts.isStreamEnabled());

        AesXts aes = new AesXts();
        byte[] out = new byte[CIPHER_128_2.length];

        /* Update(16) + Final(16) */
        aes.setKey(KEY_128_2, null, AesXts.ENCRYPT_MODE);
        aes.streamInit(TWEAK_128_2);
        assertArrayEquals(TWEAK_128_2, aes.getTweak());
        assertEquals(AesXts.BLOCK_SIZE, aes.streamUpdate(PLAIN_128_2, 0,
            AesXts.BLOCK_SIZE, out, 0));
        assertEquals(AesXts.BLOCK_SIZE, aes.streamFinal(PLAIN_128_2,
            AesXts.BLOCK_SIZE, AesXts.BLOCK_SIZE, out, AesXts.BLOCK_SIZE));
        assertArrayEquals("stream encrypt (16 + 16) failed",
            CIPHER_128_2, out);

        /* Update(all) + Final(nothing) */
        aes.streamInit(TWEAK_128_2);
        byte[] part = aes.streamUpdate(PLAIN_128_2);
        byte[] tail = aes.streamFinal(new byte[0]);
        assertEquals(0, tail.length);
        assertArrayEquals("stream encrypt (32 + 0) failed",
            CIPHER_128_2, part);

        /* Final(null) after Update(all) */
        aes.streamInit(TWEAK_128_2);
        part = aes.streamUpdate(PLAIN_128_2);
        assertEquals(0, aes.streamFinal((byte[])null).length);
        assertArrayEquals(CIPHER_128_2, part);

        /* Final(all) only */
        aes.streamInit(TWEAK_128_2);
        assertArrayEquals("stream encrypt (0 + 32) failed",
            CIPHER_128_2, aes.streamFinal(PLAIN_128_2));
        aes.releaseNativeStruct();

        /* same shapes for decrypt */
        aes.setKey(KEY_128_2, null, AesXts.DECRYPT_MODE);
        aes.streamInit(TWEAK_128_2);
        Arrays.fill(out, (byte)0);
        assertEquals(AesXts.BLOCK_SIZE, aes.streamUpdate(CIPHER_128_2, 0,
            AesXts.BLOCK_SIZE, out, 0));
        assertEquals(AesXts.BLOCK_SIZE, aes.streamFinal(CIPHER_128_2,
            AesXts.BLOCK_SIZE, AesXts.BLOCK_SIZE, out, AesXts.BLOCK_SIZE));
        assertArrayEquals("stream decrypt (16 + 16) failed",
            PLAIN_128_2, out);

        aes.streamInit(TWEAK_128_2);
        assertArrayEquals("stream decrypt (0 + 32) failed",
            PLAIN_128_2, aes.streamFinal(CIPHER_128_2));
        aes.releaseNativeStruct();
    }

    @Test
    public void streamPartialBlockTest() {
        Assume.assumeTrue(AesXts.isStreamEnabled());

        AesXts aes = new AesXts();
        byte[] out = new byte[CIPHER_128_3.length];
        int tail = PLAIN_128_3.length - AesXts.BLOCK_SIZE;

        /* Update(16) + Final(24) */
        aes.setKey(KEY_128_3, null, AesXts.ENCRYPT_MODE);
        aes.streamInit(TWEAK_128_3);
        assertEquals(AesXts.BLOCK_SIZE, aes.streamUpdate(PLAIN_128_3, 0,
            AesXts.BLOCK_SIZE, out, 0));
        assertEquals(tail, aes.streamFinal(PLAIN_128_3, AesXts.BLOCK_SIZE,
            tail, out, AesXts.BLOCK_SIZE));
        assertArrayEquals("stream partial encrypt (16 + 24) failed",
            CIPHER_128_3, out);
        aes.releaseNativeStruct();

        aes.setKey(KEY_128_3, null, AesXts.DECRYPT_MODE);
        aes.streamInit(TWEAK_128_3);
        Arrays.fill(out, (byte)0);
        assertEquals(AesXts.BLOCK_SIZE, aes.streamUpdate(CIPHER_128_3, 0,
            AesXts.BLOCK_SIZE, out, 0));
        assertEquals(tail, aes.streamFinal(CIPHER_128_3, AesXts.BLOCK_SIZE,
            tail, out, AesXts.BLOCK_SIZE));
        assertArrayEquals("stream partial decrypt (16 + 24) failed",
            PLAIN_128_3, out);
        aes.releaseNativeStruct();

        /* Final(24) only */
        aes.setKey(KEY_128_1, null, AesXts.ENCRYPT_MODE);
        aes.streamInit(TWEAK_128_1);
        assertArrayEquals("stream partial encrypt (0 + 24) failed",
            CIPHER_128_PARTIAL, aes.streamFinal(PLAIN_128_PARTIAL));
        aes.releaseNativeStruct();

        aes.setKey(KEY_128_1, null, AesXts.DECRYPT_MODE);
        aes.streamInit(TWEAK_128_1);
        assertArrayEquals("stream partial decrypt (0 + 24) failed",
            PLAIN_128_PARTIAL, aes.streamFinal(CIPHER_128_PARTIAL));
        aes.releaseNativeStruct();
    }

    @Test
    public void streamMatchesOneShot() {
        Assume.assumeTrue(AesXts.isStreamEnabled());

        Random rand = new Random(RAND_SEED);
        int[] sizes = { 16, 17, 31, 32, 33, 47, 48, 49, 64, 65, 100, 255,
                        256, 1000, 4096, 4097, 65536 + 5 };
        byte[] key = randomKey(rand, AesXts.KEY_SIZE_256);
        byte[] tweak = new byte[AesXts.TWEAK_SIZE];
        rand.nextBytes(tweak);

        AesXts enc = new AesXts();
        AesXts dec = new AesXts();
        enc.setKey(key, tweak, AesXts.ENCRYPT_MODE);
        dec.setKey(key, tweak, AesXts.DECRYPT_MODE);

        for (int size : sizes) {
            byte[] plain = new byte[size];
            rand.nextBytes(plain);

            byte[] expected = enc.update(plain);

            /* random block aligned chunks, leaving >= one block for final */
            byte[] streamed = new byte[size];
            enc.streamInit(tweak);
            int off = 0;
            while ((size - off) > (2 * AesXts.BLOCK_SIZE)) {
                int maxBlocks = (size - off - AesXts.BLOCK_SIZE) /
                    AesXts.BLOCK_SIZE;
                int blocks = 1 + rand.nextInt(maxBlocks);
                int len = blocks * AesXts.BLOCK_SIZE;
                assertEquals(len,
                    enc.streamUpdate(plain, off, len, streamed, off));
                off += len;
            }
            assertEquals(size - off,
                enc.streamFinal(plain, off, size - off, streamed, off));
            assertArrayEquals("stream encrypt != one-shot for size " + size,
                expected, streamed);

            /* same chunking for decrypt */
            byte[] decrypted = new byte[size];
            dec.streamInit(tweak);
            off = 0;
            while ((size - off) > (2 * AesXts.BLOCK_SIZE)) {
                int maxBlocks = (size - off - AesXts.BLOCK_SIZE) /
                    AesXts.BLOCK_SIZE;
                int blocks = 1 + rand.nextInt(maxBlocks);
                int len = blocks * AesXts.BLOCK_SIZE;
                assertEquals(len,
                    dec.streamUpdate(streamed, off, len, decrypted, off));
                off += len;
            }
            assertEquals(size - off,
                dec.streamFinal(streamed, off, size - off, decrypted, off));
            assertArrayEquals("stream decrypt failed for size " + size,
                plain, decrypted);
        }

        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void streamErrorCases() {
        Assume.assumeTrue(AesXts.isStreamEnabled());

        AesXts aes = new AesXts();
        byte[] out = new byte[4 * AesXts.BLOCK_SIZE];

        try {
            aes.streamInit(TWEAK_128_2);
            fail("streamInit() without key should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        aes.setKey(KEY_128_2, TWEAK_128_2, AesXts.ENCRYPT_MODE);

        /* before streamInit() */
        try {
            aes.streamUpdate(PLAIN_128_2);
            fail("streamUpdate() before streamInit() should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            aes.streamFinal(PLAIN_128_2);
            fail("streamFinal() before streamInit() should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        try {
            aes.streamInit(null);
            fail("null tweak should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.streamInit(new byte[AesXts.TWEAK_SIZE - 1]);
            fail("15 byte tweak should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        aes.streamInit(TWEAK_128_2);

        /* non-zero multiple of block size only */
        int[] badUpdateSizes = { 0, 1, 15, 17, 31, 33 };
        for (int size : badUpdateSizes) {
            try {
                aes.streamUpdate(new byte[size], 0, size, out, 0);
                fail("streamUpdate() of " + size + " bytes should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
        }
        try {
            aes.streamUpdate((byte[])null);
            fail("null input should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.streamUpdate(PLAIN_128_2, 0, AesXts.BLOCK_SIZE, null, 0);
            fail("null output should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* 0 or at least one block only */
        int[] badFinalSizes = { 1, 8, 15 };
        for (int size : badFinalSizes) {
            try {
                aes.streamFinal(new byte[size], 0, size, out, 0);
                fail("streamFinal() of " + size + " bytes should throw");
            } catch (WolfCryptException e) {
                /* expected */
            }
        }

        /* still usable after rejected calls */
        assertEquals(AesXts.BLOCK_SIZE, aes.streamUpdate(PLAIN_128_2, 0,
            AesXts.BLOCK_SIZE, out, 0));
        assertEquals(AesXts.BLOCK_SIZE, aes.streamFinal(PLAIN_128_2,
            AesXts.BLOCK_SIZE, AesXts.BLOCK_SIZE, out, AesXts.BLOCK_SIZE));
        assertArrayEquals(CIPHER_128_2,
            Arrays.copyOf(out, PLAIN_128_2.length));

        /* nothing allowed after streamFinal() */
        try {
            aes.streamUpdate(PLAIN_128_2);
            fail("streamUpdate() after streamFinal() should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        try {
            aes.streamFinal(new byte[0]);
            fail("second streamFinal() should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        /* empty data unit, streamFinal() right after streamInit() is a
         * no-op that finishes the stream */
        aes.streamInit(TWEAK_128_2);
        assertEquals(0, aes.streamFinal(new byte[0]).length);
        try {
            aes.streamUpdate(PLAIN_128_2);
            fail("streamUpdate() after empty streamFinal() should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }

        aes.streamInit(TWEAK_128_2);
        assertArrayEquals(CIPHER_128_2, aes.streamFinal(PLAIN_128_2));

        /* streamInit() discards an active stream */
        aes.streamInit(TWEAK_128_2);
        aes.streamUpdate(PLAIN_128_2, 0, AesXts.BLOCK_SIZE, out, 0);
        aes.streamInit(TWEAK_128_2);
        assertArrayEquals(CIPHER_128_2, aes.streamFinal(PLAIN_128_2));

        aes.releaseNativeStruct();

        try {
            aes.streamUpdate(PLAIN_128_2);
            fail("streamUpdate() after release should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void streamByteBufferTest() {
        Assume.assumeTrue(AesXts.isStreamEnabled());

        AesXts aes = new AesXts();
        ByteBuffer input = ByteBuffer.allocateDirect(PLAIN_128_3.length);
        ByteBuffer output = ByteBuffer.allocateDirect(PLAIN_128_3.length);
        byte[] out = new byte[PLAIN_128_3.length];

        input.put(PLAIN_128_3);
        input.flip();

        /* Update(16) + Final(24), first chunk bounded by limit */
        aes.setKey(KEY_128_3, null, AesXts.ENCRYPT_MODE);
        aes.streamInit(TWEAK_128_3);
        input.limit(AesXts.BLOCK_SIZE);
        assertEquals(AesXts.BLOCK_SIZE, aes.streamUpdate(input, output));
        assertEquals(AesXts.BLOCK_SIZE, input.position());
        assertEquals(AesXts.BLOCK_SIZE, output.position());
        input.limit(PLAIN_128_3.length);
        assertEquals(PLAIN_128_3.length - AesXts.BLOCK_SIZE,
            aes.streamFinal(input, output));
        assertEquals(PLAIN_128_3.length, input.position());
        assertEquals(PLAIN_128_3.length, output.position());

        output.flip();
        output.get(out);
        assertArrayEquals("ByteBuffer stream encrypt (16 + 24) failed",
            CIPHER_128_3, out);

        /* errors, stream stays usable afterwards */
        aes.streamInit(TWEAK_128_3);
        try {
            aes.streamUpdate(ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE + 1),
                ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE + 1));
            fail("unaligned ByteBuffer streamUpdate() should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.streamUpdate(ByteBuffer.wrap(new byte[AesXts.BLOCK_SIZE]),
                ByteBuffer.allocate(AesXts.BLOCK_SIZE));
            fail("non-direct ByteBuffer should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.streamUpdate(ByteBuffer.allocateDirect(2 * AesXts.BLOCK_SIZE),
                ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE));
            fail("output too small should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.streamFinal(ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE / 2),
                ByteBuffer.allocateDirect(AesXts.BLOCK_SIZE / 2));
            fail("partial block ByteBuffer streamFinal() should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.streamFinal(ByteBuffer.wrap(new byte[AesXts.BLOCK_SIZE]),
                ByteBuffer.allocate(AesXts.BLOCK_SIZE));
            fail("non-direct ByteBuffer streamFinal() should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        assertArrayEquals(CIPHER_128_3, aes.streamFinal(PLAIN_128_3));
        aes.releaseNativeStruct();

        /* Update(all) + Final(empty) */
        ByteBuffer in2 = ByteBuffer.allocateDirect(PLAIN_128_2.length);
        ByteBuffer out2 = ByteBuffer.allocateDirect(PLAIN_128_2.length);
        ByteBuffer empty = ByteBuffer.allocateDirect(0);
        in2.put(PLAIN_128_2);
        in2.flip();

        aes.setKey(KEY_128_2, null, AesXts.ENCRYPT_MODE);
        aes.streamInit(TWEAK_128_2);
        assertEquals(PLAIN_128_2.length, aes.streamUpdate(in2, out2));
        assertEquals(0, aes.streamFinal(empty, out2));
        out2.flip();
        byte[] ct2 = new byte[out2.remaining()];
        out2.get(ct2);
        assertArrayEquals("ByteBuffer stream encrypt (32 + 0) failed",
            CIPHER_128_2, ct2);

        /* nothing allowed after final */
        try {
            aes.streamUpdate(in2, out2);
            fail("streamUpdate() after streamFinal() should throw");
        } catch (IllegalStateException e) {
            /* expected */
        }
        aes.releaseNativeStruct();

        /* Final only */
        ByteBuffer cin = ByteBuffer.allocateDirect(CIPHER_128_3.length);
        ByteBuffer pout = ByteBuffer.allocateDirect(CIPHER_128_3.length);
        cin.put(CIPHER_128_3);
        cin.flip();

        aes.setKey(KEY_128_3, null, AesXts.DECRYPT_MODE);
        aes.streamInit(TWEAK_128_3);
        assertEquals(CIPHER_128_3.length, aes.streamFinal(cin, pout));
        pout.flip();
        byte[] pt = new byte[pout.remaining()];
        pout.get(pt);
        assertArrayEquals("ByteBuffer stream decrypt failed",
            PLAIN_128_3, pt);
        aes.releaseNativeStruct();

        /* one buffer as both input and output, position advances once */
        ByteBuffer same = ByteBuffer.allocateDirect(PLAIN_128_3.length);
        same.put(PLAIN_128_3);
        same.flip();
        aes.setKey(KEY_128_3, null, AesXts.ENCRYPT_MODE);
        aes.streamInit(TWEAK_128_3);
        same.limit(AesXts.BLOCK_SIZE);
        assertEquals(AesXts.BLOCK_SIZE, aes.streamUpdate(same, same));
        assertEquals(AesXts.BLOCK_SIZE, same.position());
        same.limit(PLAIN_128_3.length);
        assertEquals(PLAIN_128_3.length - AesXts.BLOCK_SIZE,
            aes.streamFinal(same, same));
        assertEquals(PLAIN_128_3.length, same.position());
        same.flip();
        byte[] inPlace = new byte[same.remaining()];
        same.get(inPlace);
        assertArrayEquals("in-place ByteBuffer stream encrypt failed",
            CIPHER_128_3, inPlace);
        aes.releaseNativeStruct();
    }

    @Test
    public void streamAndOneShotOnSameObject() {
        Assume.assumeTrue(AesXts.isStreamEnabled());

        AesXts aes = new AesXts();
        aes.setKey(KEY_256_2, TWEAK_256_2, AesXts.ENCRYPT_MODE);

        /* one-shot, stream, one-shot */
        assertArrayEquals(CIPHER_256_2, aes.update(PLAIN_256_2));

        aes.streamInit(TWEAK_256_2);
        int split = 2 * AesXts.BLOCK_SIZE;
        byte[] head = aes.streamUpdate(Arrays.copyOf(PLAIN_256_2, split));
        byte[] tail = aes.streamFinal(Arrays.copyOfRange(PLAIN_256_2,
            split, PLAIN_256_2.length));
        byte[] streamed = new byte[PLAIN_256_2.length];
        System.arraycopy(head, 0, streamed, 0, split);
        System.arraycopy(tail, 0, streamed, split, tail.length);
        assertArrayEquals(CIPHER_256_2, streamed);

        assertArrayEquals(CIPHER_256_2, aes.update(PLAIN_256_2));

        /* sector API matches explicit tweak */
        byte[] tweak = new byte[AesXts.TWEAK_SIZE];
        tweak[0] = 5;
        aes.setTweak(tweak);
        assertArrayEquals(aes.update(PLAIN_256_2),
            aes.updateSector(PLAIN_256_2, 5));

        aes.releaseNativeStruct();
    }

    /* Threads sharing one keyed instance must all get the vector result */
    @Test
    public void sharedInstanceThreadedTest() throws InterruptedException {
        final int numThreads = 20;
        final AesXts aes = new AesXts();
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<String> errors =
            new LinkedBlockingQueue<String>();
        ExecutorService service = Executors.newFixedThreadPool(numThreads);

        aes.setKey(KEY_256_2, TWEAK_256_2, AesXts.ENCRYPT_MODE);

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int j = 0; j < 50; j++) {
                            if (!Arrays.equals(CIPHER_256_2,
                                    aes.update(PLAIN_256_2))) {
                                errors.add("ciphertext mismatch");
                            }
                        }
                    } catch (Exception e) {
                        errors.add(e.toString());
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        service.shutdown();
        aes.releaseNativeStruct();

        assertTrue("shared AesXts errors: " + errors, errors.isEmpty());
    }

    /* One-shot calls reject a data unit over the limit and accept one at it */
    @Test
    public void dataUnitLimitOneShot() {

        byte[] input = new byte[AesXts.MAX_DATA_UNIT_SIZE + AesXts.BLOCK_SIZE];
        AesXts aes = new AesXts();

        aes.setKey(KEY_128_1, TWEAK_128_1, AesXts.ENCRYPT_MODE);

        try {
            aes.update(input);
            fail("update() over the data unit limit should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.updateSector(input, 0L);
            fail("updateSector() over the data unit limit should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }

        assertEquals(AesXts.MAX_DATA_UNIT_SIZE,
            aes.update(input, 0, AesXts.MAX_DATA_UNIT_SIZE, input, 0));

        aes.releaseNativeStruct();
    }

    /* The call that would pass the limit fails, the stream stays active and
     * a new streamInit() counts from zero */
    @Test
    public void dataUnitLimitStream() {

        Assume.assumeTrue("AES-XTS streaming not compiled in",
            AesXts.isStreamEnabled());

        int chunkSize = AesXts.MAX_DATA_UNIT_SIZE / 4;
        byte[] chunk = new byte[chunkSize];
        AesXts aes = new AesXts();

        aes.setKey(KEY_128_1, TWEAK_128_1, AesXts.ENCRYPT_MODE);
        aes.streamInit(TWEAK_128_1);
        for (int i = 0; i < 4; i++) {
            assertEquals(chunkSize,
                aes.streamUpdate(chunk, 0, chunkSize, chunk, 0));
        }

        try {
            aes.streamUpdate(chunk, 0, AesXts.BLOCK_SIZE, chunk, 0);
            fail("streamUpdate() past the data unit limit should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        try {
            aes.streamFinal(chunk, 0, AesXts.BLOCK_SIZE, chunk, 0);
            fail("streamFinal() past the data unit limit should throw");
        } catch (WolfCryptException e) {
            /* expected */
        }
        assertEquals(0, aes.streamFinal(chunk, 0, 0, chunk, 0));

        aes.streamInit(TWEAK_128_1);
        assertEquals(AesXts.BLOCK_SIZE,
            aes.streamUpdate(chunk, 0, AesXts.BLOCK_SIZE, chunk, 0));
        assertEquals(0, aes.streamFinal(chunk, 0, 0, chunk, 0));

        aes.releaseNativeStruct();
    }
}
