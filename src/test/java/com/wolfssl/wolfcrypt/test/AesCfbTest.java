/* AesCfbTest.java
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

import java.nio.ByteBuffer;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import com.wolfssl.wolfcrypt.AesCfb;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class AesCfbTest {

    /* NIST SP 800-38A Appendix F.3 test vectors */
    private static final byte[] KEY_128 = Util.h2b(
        "2b7e151628aed2a6abf7158809cf4f3c");
    private static final byte[] KEY_192 = Util.h2b(
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    private static final byte[] KEY_256 = Util.h2b(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    private static final byte[] IV = Util.h2b(
        "000102030405060708090a0b0c0d0e0f");

    /* CFB128 (F.3.13 - F.3.18), 4 blocks of plaintext */
    private static final byte[] PT_CFB128 = Util.h2b(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    private static final byte[] CT_CFB128_128 = Util.h2b(
        "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b" +
        "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
    private static final byte[] CT_CFB128_192 = Util.h2b(
        "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a" +
        "2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff");
    private static final byte[] CT_CFB128_256 = Util.h2b(
        "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407b" +
        "df10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471");

    /* CFB8 (F.3.7 - F.3.12), 18 bytes of plaintext */
    private static final byte[] PT_CFB8 = Util.h2b(
        "6bc1bee22e409f96e93d7e117393172aae2d");
    private static final byte[] CT_CFB8_128 = Util.h2b(
        "3b79424c9c0dd436bace9e0ed4586a4f32b9");
    private static final byte[] CT_CFB8_192 = Util.h2b(
        "cda2521ef0a905ca44cd057cbf0d47a0678a");
    private static final byte[] CT_CFB8_256 = Util.h2b(
        "dc1f1a8520a64db55fcc8ac554844e889700");

    /* CFB1 (F.3.1 - F.3.6), 16 bits, processed as 2 bytes MSB first */
    private static final byte[] PT_CFB1 = Util.h2b("6bc1");
    private static final byte[] CT_CFB1_128 = Util.h2b("68b3");
    private static final byte[] CT_CFB1_192 = Util.h2b("9359");
    private static final byte[] CT_CFB1_256 = Util.h2b("9029");

    private static final byte[][] KEYS = {KEY_128, KEY_192, KEY_256};
    private static final byte[][] CTS_CFB128 =
        {CT_CFB128_128, CT_CFB128_192, CT_CFB128_256};
    private static final byte[][] CTS_CFB8 =
        {CT_CFB8_128, CT_CFB8_192, CT_CFB8_256};
    private static final byte[][] CTS_CFB1 =
        {CT_CFB1_128, CT_CFB1_192, CT_CFB1_256};

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Rule to check if AES-CFB is available. AesCfb() constructor does not
     * allocate native memory, so no need to release if it throws. */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule aesCfbAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    try {
                        new AesCfb();
                    } catch (WolfCryptException e) {
                        Assume.assumeTrue("AES-CFB not compiled in: " +
                            e.getError(), false);
                    }
                    base.evaluate();
                }
            };
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        System.out.println("JNI AesCfb Class");
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesCfb().getNativeStruct());
    }

    @Test
    public void constructorInvalidSegmentSizeThrows() {
        int[] badModes = {0, -1, 2, 7, 16, 64, 127, 129, 256};

        for (int mode : badModes) {
            try {
                new AesCfb(mode);
                fail("AesCfb(" + mode + ") should throw");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }

        assertEquals(AesCfb.CFB_MODE_128,
            new AesCfb(AesCfb.CFB_MODE_128).getCfbMode());
        assertEquals(AesCfb.CFB_MODE_128, new AesCfb().getCfbMode());
    }

    @Test
    public void checkSetKeyParams() {
        AesCfb aesCfb = new AesCfb();

        try {
            aesCfb.setKey(null, IV);
            fail("key should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCfb.setKey(KEY_128, null);
            fail("iv should not be null for CFB mode.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCfb.setKey(KEY_128, Util.h2b("0001020304050607"));
            fail("iv must be 16 bytes for CFB mode.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCfb.setKey(KEY_128, IV, 2);
            fail("invalid opmode should throw.");
        } catch (IllegalArgumentException e) {
            /* test must throw */
        }

        aesCfb.setKey(KEY_128, IV);
        aesCfb.releaseNativeStruct();
    }


    @Test
    public void checkEncryptDecryptParams() {
        byte[] input = new byte[AesCfb.BLOCK_SIZE];
        byte[] output = new byte[AesCfb.BLOCK_SIZE];

        AesCfb aesCfb = new AesCfb();
        aesCfb.setKey(KEY_128, IV);

        aesCfb.encrypt(input);

        try {
            aesCfb.encrypt(null, 0, AesCfb.BLOCK_SIZE, output, 0);
            fail("input should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCfb.encrypt(input, 0, AesCfb.BLOCK_SIZE, null, 0);
            fail("output should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw WolfCryptException for null output */
        }

        try {
            aesCfb.encrypt(input, 8, AesCfb.BLOCK_SIZE, output, 0);
            fail("offset + length beyond input should throw.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCfb.encrypt(input, 0, AesCfb.BLOCK_SIZE, output, 8);
            fail("outputOffset + length beyond output should throw.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCfb.encrypt(input, -1, AesCfb.BLOCK_SIZE, output, 0);
            fail("negative offset should throw.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aesCfb.encrypt(input, 0, AesCfb.BLOCK_SIZE, output, 0);

        /* Test decrypt as well */
        aesCfb.decrypt(input);
        aesCfb.decrypt(input, 0, AesCfb.BLOCK_SIZE, output, 0);

        aesCfb.releaseNativeStruct();

        try {
            aesCfb.encrypt(input, 0, AesCfb.BLOCK_SIZE, output, 0);
            fail("released object should not be usable.");
        } catch (IllegalStateException e) {
            /* test must throw */
        }
    }

    @Test
    public void releasedObjectCannotBeReused() {
        AesCfb aesCfb = new AesCfb();

        aesCfb.setKey(KEY_128, IV);
        aesCfb.encrypt(PT_CFB128);
        aesCfb.releaseNativeStruct();

        try {
            aesCfb.setKey(KEY_128, IV);
            fail("setKey after release should throw.");
        } catch (IllegalStateException e) {
            /* test must throw */
        }

        /* Double release should not throw */
        aesCfb.releaseNativeStruct();
    }

    @Test
    public void setKeyTwiceThrows() {
        AesCfb aesCfb = new AesCfb();

        aesCfb.setKey(KEY_128, IV);
        try {
            aesCfb.setKey(KEY_256, IV);
            fail("Should not be able to set key twice");
        } catch (IllegalStateException e) {
            /* expected behavior */
        }

        aesCfb.releaseNativeStruct();
    }

    @Test
    public void aesCfb128EncryptDecryptTest() {
        for (int i = 0; i < KEYS.length; i++) {
            AesCfb enc = new AesCfb(AesCfb.CFB_MODE_128);
            enc.setKey(KEYS[i], IV);
            byte[] ciphertext = enc.encrypt(PT_CFB128);
            assertArrayEquals("AES-CFB128 encrypt failed, key size " +
                KEYS[i].length, CTS_CFB128[i], ciphertext);
            enc.releaseNativeStruct();

            AesCfb dec = new AesCfb(AesCfb.CFB_MODE_128);
            dec.setKey(KEYS[i], IV);
            byte[] decrypted = dec.decrypt(CTS_CFB128[i]);
            assertArrayEquals("AES-CFB128 decrypt failed, key size " +
                KEYS[i].length, PT_CFB128, decrypted);
            dec.releaseNativeStruct();
        }
    }

    @Test
    public void aesCfb8EncryptDecryptTest() {
        Assume.assumeTrue("AES-CFB8 not compiled in",
            FeatureDetect.AesCfb8Enabled());

        for (int i = 0; i < KEYS.length; i++) {
            AesCfb enc = new AesCfb(AesCfb.CFB_MODE_8);
            enc.setKey(KEYS[i], IV);
            byte[] ciphertext = enc.encrypt(PT_CFB8);
            assertArrayEquals("AES-CFB8 encrypt failed, key size " +
                KEYS[i].length, CTS_CFB8[i], ciphertext);
            enc.releaseNativeStruct();

            AesCfb dec = new AesCfb(AesCfb.CFB_MODE_8);
            dec.setKey(KEYS[i], IV);
            byte[] decrypted = dec.decrypt(CTS_CFB8[i]);
            assertArrayEquals("AES-CFB8 decrypt failed, key size " +
                KEYS[i].length, PT_CFB8, decrypted);
            dec.releaseNativeStruct();
        }
    }

    @Test
    public void aesCfb1EncryptDecryptTest() {
        Assume.assumeTrue("AES-CFB1 not compiled in",
            FeatureDetect.AesCfb1Enabled());

        for (int i = 0; i < KEYS.length; i++) {
            AesCfb enc = new AesCfb(AesCfb.CFB_MODE_1);
            enc.setKey(KEYS[i], IV);
            byte[] ciphertext = enc.encrypt(PT_CFB1);
            assertArrayEquals("AES-CFB1 encrypt failed, key size " +
                KEYS[i].length, CTS_CFB1[i], ciphertext);
            enc.releaseNativeStruct();

            AesCfb dec = new AesCfb(AesCfb.CFB_MODE_1);
            dec.setKey(KEYS[i], IV);
            byte[] decrypted = dec.decrypt(CTS_CFB1[i]);
            assertArrayEquals("AES-CFB1 decrypt failed, key size " +
                KEYS[i].length, PT_CFB1, decrypted);
            dec.releaseNativeStruct();
        }
    }

    /* chunked calls must chain feedback state natively, matching a
     * one-shot call */
    @Test
    public void aesCfb128ChunkedUpdateTest() {
        int[] chunkSizes = {1, 3, 7, 9, 16, 21};

        for (int chunkSize : chunkSizes) {
            AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_128);
            aesCfb.setKey(KEY_128, IV);

            byte[] output = new byte[PT_CFB128.length];
            int outputOffset = 0;

            for (int i = 0; i < PT_CFB128.length; i += chunkSize) {
                int sz = Math.min(chunkSize, PT_CFB128.length - i);
                int processed = aesCfb.encrypt(PT_CFB128, i, sz,
                    output, outputOffset);
                outputOffset += processed;
            }

            assertArrayEquals("AES-CFB128 chunked encrypt failed, " +
                "chunk size " + chunkSize, CT_CFB128_128, output);

            aesCfb.releaseNativeStruct();
        }
    }

    @Test
    public void aesCfb8ChunkedUpdateTest() {
        Assume.assumeTrue("AES-CFB8 not compiled in",
            FeatureDetect.AesCfb8Enabled());

        AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_8);
        aesCfb.setKey(KEY_128, IV);

        byte[] output = new byte[PT_CFB8.length];

        for (int i = 0; i < PT_CFB8.length; i++) {
            aesCfb.encrypt(PT_CFB8, i, 1, output, i);
        }

        assertArrayEquals("AES-CFB8 chunked encrypt failed",
            CT_CFB8_128, output);

        aesCfb.releaseNativeStruct();
    }

    @Test
    public void aesCfb1ChunkedUpdateTest() {
        Assume.assumeTrue("AES-CFB1 not compiled in",
            FeatureDetect.AesCfb1Enabled());

        AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_1);
        aesCfb.setKey(KEY_128, IV);

        byte[] output = new byte[PT_CFB1.length];

        for (int i = 0; i < PT_CFB1.length; i++) {
            aesCfb.encrypt(PT_CFB1, i, 1, output, i);
        }

        assertArrayEquals("AES-CFB1 chunked encrypt failed",
            CT_CFB1_128, output);

        aesCfb.releaseNativeStruct();
    }

    @Test
    public void aesCfb128ByteBufferTest() {
        AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_128);
        aesCfb.setKey(KEY_128, IV);

        ByteBuffer input = ByteBuffer.allocateDirect(PT_CFB128.length);
        ByteBuffer output = ByteBuffer.allocateDirect(PT_CFB128.length);

        input.put(PT_CFB128);
        input.flip();

        int processed = aesCfb.encrypt(input, output);
        assertEquals("Processed length mismatch", PT_CFB128.length,
            processed);

        output.flip();
        byte[] result = new byte[output.remaining()];
        output.get(result);

        assertArrayEquals("AES-CFB128 ByteBuffer test failed",
            CT_CFB128_128, result);

        aesCfb.releaseNativeStruct();
    }

    @Test
    public void aesCfb128ByteBufferDecryptUpdateTest() {
        /* decrypt(ByteBuffer, ByteBuffer) */
        AesCfb dec = new AesCfb(AesCfb.CFB_MODE_128);
        dec.setKey(KEY_128, IV);

        ByteBuffer input = ByteBuffer.allocateDirect(CT_CFB128_128.length);
        ByteBuffer output = ByteBuffer.allocateDirect(CT_CFB128_128.length);
        input.put(CT_CFB128_128);
        input.flip();

        int processed = dec.decrypt(input, output);
        assertEquals("Processed length mismatch", CT_CFB128_128.length,
            processed);

        output.flip();
        byte[] result = new byte[output.remaining()];
        output.get(result);
        assertArrayEquals("AES-CFB128 ByteBuffer decrypt failed",
            PT_CFB128, result);
        dec.releaseNativeStruct();

        /* update(ByteBuffer, ByteBuffer) uses opmode from setKey */
        AesCfb upd = new AesCfb(AesCfb.CFB_MODE_128);
        upd.setKey(KEY_128, IV, AesCfb.DECRYPT_MODE);

        input = ByteBuffer.allocateDirect(CT_CFB128_128.length);
        output = ByteBuffer.allocateDirect(CT_CFB128_128.length);
        input.put(CT_CFB128_128);
        input.flip();

        processed = upd.update(input, output);
        assertEquals("Processed length mismatch", CT_CFB128_128.length,
            processed);

        output.flip();
        result = new byte[output.remaining()];
        output.get(result);
        assertArrayEquals("AES-CFB128 ByteBuffer update decrypt failed",
            PT_CFB128, result);
        upd.releaseNativeStruct();
    }

    @Test
    public void aesCfbByteBufferBadArgsTest() {
        AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_128);
        aesCfb.setKey(KEY_128, IV);

        /* non-direct (heap) ByteBuffers are rejected */
        try {
            aesCfb.encrypt(ByteBuffer.allocate(AesCfb.BLOCK_SIZE),
                ByteBuffer.allocate(AesCfb.BLOCK_SIZE));
            fail("non-direct ByteBuffer should throw");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        /* output limit smaller than input remaining is rejected */
        ByteBuffer input = ByteBuffer.allocateDirect(AesCfb.BLOCK_SIZE);
        ByteBuffer smallOut = ByteBuffer.allocateDirect(8);
        input.put(new byte[AesCfb.BLOCK_SIZE]);
        input.flip();
        try {
            aesCfb.encrypt(input, smallOut);
            fail("undersized output buffer should throw");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aesCfb.releaseNativeStruct();
    }

    @Test
    public void updateOffsetVariantTest() {
        AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_128);
        aesCfb.setKey(KEY_128, IV, AesCfb.ENCRYPT_MODE);

        byte[] output = new byte[PT_CFB128.length];
        int processed = aesCfb.update(PT_CFB128, 0, PT_CFB128.length,
            output, 0);
        assertEquals("Processed length mismatch", PT_CFB128.length,
            processed);
        assertArrayEquals("AES-CFB128 update offset variant failed",
            CT_CFB128_128, output);

        try {
            aesCfb.update(PT_CFB128, 0, PT_CFB128.length, null, 0);
            fail("null output should throw");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aesCfb.releaseNativeStruct();
    }

    /* DECRYPT_MODE setKey must still produce correct output, the
     * native layer always builds the encrypt key schedule */
    @Test
    public void updateUsesOpmodeFromSetKey() {
        AesCfb enc = new AesCfb(AesCfb.CFB_MODE_128);
        enc.setKey(KEY_128, IV, AesCfb.ENCRYPT_MODE);
        byte[] ciphertext = enc.update(PT_CFB128);
        assertArrayEquals("AES-CFB update encrypt failed",
            CT_CFB128_128, ciphertext);
        enc.releaseNativeStruct();

        AesCfb dec = new AesCfb(AesCfb.CFB_MODE_128);
        dec.setKey(KEY_128, IV, AesCfb.DECRYPT_MODE);
        byte[] decrypted = dec.update(CT_CFB128_128);
        assertArrayEquals("AES-CFB update decrypt failed",
            PT_CFB128, decrypted);
        dec.releaseNativeStruct();
    }

    @Test
    public void zeroLengthUpdateReturnsEmpty() {
        AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_128);
        aesCfb.setKey(KEY_128, IV);

        byte[] result = aesCfb.encrypt(new byte[0]);
        assertEquals("Zero length encrypt should return empty array",
            0, result.length);

        aesCfb.releaseNativeStruct();
    }

    @Test
    public void threadedAesCfbTest() throws InterruptedException {
        int numThreads = 10;
        Thread[] threads = new Thread[numThreads];
        final boolean[] failures = new boolean[numThreads];

        for (int i = 0; i < numThreads; i++) {
            final int idx = i;
            threads[i] = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        AesCfb aesCfb = new AesCfb(AesCfb.CFB_MODE_128);
                        aesCfb.setKey(KEY_128, IV);
                        byte[] ct = aesCfb.encrypt(PT_CFB128);
                        aesCfb.releaseNativeStruct();

                        if (!java.util.Arrays.equals(CT_CFB128_128, ct)) {
                            failures[idx] = true;
                        }
                    } catch (Exception e) {
                        failures[idx] = true;
                    }
                }
            });
            threads[i].start();
        }

        for (int i = 0; i < numThreads; i++) {
            threads[i].join();
        }

        for (int i = 0; i < numThreads; i++) {
            assertFalse("Threaded AES-CFB test failed in thread " + i,
                failures[i]);
        }
    }
}
