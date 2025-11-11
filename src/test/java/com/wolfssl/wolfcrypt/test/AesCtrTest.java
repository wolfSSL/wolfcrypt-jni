/* AesCtrTest.java
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
import java.nio.ByteBuffer;
import javax.crypto.ShortBufferException;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.AesCtr;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class AesCtrTest {

    /* Test vectors from NIST SP 800-38A */
    private static final byte[] KEY_128 = Util.h2b(
        "2b7e151628aed2a6abf7158809cf4f3c");
    private static final byte[] IV_128 = Util.h2b(
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    private static final byte[] PLAINTEXT = Util.h2b(
        "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710");
    private static final byte[] CIPHERTEXT_128 = Util.h2b(
        "874d6191b620e3261bef6864990db6ce" +
        "9806f66b7970fdff8617187bb9fffdff" +
        "5ae4df3edbd5d35e5b4f09020db03eab" +
        "1e031dda2fbe03d1792170a0f3009cee");

    private static final byte[] KEY_256 = Util.h2b(
        "603deb1015ca71be2b73aef0857d7781" +
        "1f352c073b6108d72d9810a30914dff4");
    private static final byte[] IV_256 = Util.h2b(
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    private static final byte[] CIPHERTEXT_256 = Util.h2b(
        "601ec313775789a5b7a7f504bbf3d228" +
        "f443e3ca4d62b59aca84e990cacaf5c5" +
        "2b0930daa23de94ce87017ba2d84988d" +
        "dfc9c58db67aada613c2dd08457941a6");

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {
        try {
            new AesCtr();
            System.out.println("JNI AesCtr Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("AesCtr test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesCtr().getNativeStruct());
    }

    @Test
    public void checkSetKeyParams() {
        AesCtr aesCtr = new AesCtr();

        try {
            aesCtr.setKey(null, IV_128);
            fail("key should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCtr.setKey(KEY_128, null);
            fail("iv should not be null for CTR mode.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aesCtr.setKey(KEY_128, IV_128);
        aesCtr.releaseNativeStruct();

        /* Should be able to set key again after release */
        aesCtr.setKey(KEY_128, IV_128);
        aesCtr.releaseNativeStruct();
    }

    @Test
    public void checkUpdateParams() {
        byte[] input = new byte[AesCtr.BLOCK_SIZE];
        byte[] output = new byte[AesCtr.BLOCK_SIZE];

        AesCtr aesCtr = new AesCtr();
        aesCtr.setKey(KEY_128, IV_128);

        aesCtr.update(input);

        try {
            aesCtr.update(null, 0, AesCtr.BLOCK_SIZE, output, 0);
            fail("input should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCtr.update(input, 0, AesCtr.BLOCK_SIZE, null, 0);
            fail("output should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw WolfCryptException for null output */
        }

        aesCtr.update(input, 0, AesCtr.BLOCK_SIZE, output, 0);

        aesCtr.releaseNativeStruct();

        try {
            aesCtr.update(input, 0, AesCtr.BLOCK_SIZE, output, 0);
            fail("native struct should not be null.");
        } catch (IllegalStateException e) {
            /* test must throw */
        }
    }

    @Test
    public void aes128CtrEncryptDecryptTest() {
        AesCtr aesCtr = new AesCtr();

        /* Test encryption */
        aesCtr.setKey(KEY_128, IV_128);
        byte[] ciphertext = aesCtr.update(PLAINTEXT);

        assertArrayEquals("AES-128-CTR encryption failed",
                         CIPHERTEXT_128, ciphertext);

        aesCtr.releaseNativeStruct();

        /* Test decryption (CTR mode uses same operation) */
        aesCtr = new AesCtr();
        aesCtr.setKey(KEY_128, IV_128);
        byte[] decrypted = aesCtr.update(CIPHERTEXT_128);

        assertArrayEquals("AES-128-CTR decryption failed",
                         PLAINTEXT, decrypted);

        aesCtr.releaseNativeStruct();
    }

    @Test
    public void aes256CtrEncryptDecryptTest() {
        AesCtr aesCtr = new AesCtr();

        /* Test encryption */
        aesCtr.setKey(KEY_256, IV_256);
        byte[] ciphertext = aesCtr.update(PLAINTEXT);

        assertArrayEquals("AES-256-CTR encryption failed",
                         CIPHERTEXT_256, ciphertext);

        aesCtr.releaseNativeStruct();

        /* Test decryption (CTR mode uses same operation) */
        aesCtr = new AesCtr();
        aesCtr.setKey(KEY_256, IV_256);
        byte[] decrypted = aesCtr.update(CIPHERTEXT_256);

        assertArrayEquals("AES-256-CTR decryption failed",
                         PLAINTEXT, decrypted);

        aesCtr.releaseNativeStruct();
    }

    @Test
    public void aes128CtrPartialUpdateTest() {
        AesCtr aesCtr = new AesCtr();
        aesCtr.setKey(KEY_128, IV_128);

        /* Test partial block updates */
        byte[] output = new byte[PLAINTEXT.length];
        int outputOffset = 0;

        /* Process in 16-byte chunks */
        for (int i = 0; i < PLAINTEXT.length; i += 16) {
            int chunkSize = Math.min(16, PLAINTEXT.length - i);
            int processed = aesCtr.update(PLAINTEXT, i, chunkSize,
                                        output, outputOffset);
            outputOffset += processed;
        }

        assertArrayEquals("AES-128-CTR partial update failed",
                         CIPHERTEXT_128, output);

        aesCtr.releaseNativeStruct();
    }

    @Test
    public void aes128CtrByteBufferTest() throws ShortBufferException {
        AesCtr aesCtr = new AesCtr();
        aesCtr.setKey(KEY_128, IV_128);

        ByteBuffer input = ByteBuffer.allocateDirect(PLAINTEXT.length);
        ByteBuffer output = ByteBuffer.allocateDirect(PLAINTEXT.length);

        input.put(PLAINTEXT);
        input.flip();

        int processed = aesCtr.update(input, output);
        assertEquals("Processed length mismatch", PLAINTEXT.length, processed);

        output.flip();
        byte[] result = new byte[output.remaining()];
        output.get(result);

        assertArrayEquals("AES-128-CTR ByteBuffer test failed",
                         CIPHERTEXT_128, result);

        aesCtr.releaseNativeStruct();
    }

    @Test
    public void releaseAndReInitObject() {
        AesCtr aesCtr = new AesCtr();

        aesCtr.setKey(KEY_128, IV_128);
        aesCtr.update(PLAINTEXT);
        aesCtr.releaseNativeStruct();

        /* Should be able to use again after re-initialization */
        aesCtr.setKey(KEY_128, IV_128);
        byte[] result = aesCtr.update(PLAINTEXT);

        assertArrayEquals("Re-initialization test failed",
                         CIPHERTEXT_128, result);

        aesCtr.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {
        AesCtr aesCtr = new AesCtr();

        /* First use */
        aesCtr.setKey(KEY_128, IV_128);
        byte[] result1 = aesCtr.update(PLAINTEXT);

        assertArrayEquals("First use failed", CIPHERTEXT_128, result1);

        /* Try to set key again - should throw exception */
        try {
            aesCtr.setKey(KEY_256, IV_256);
            fail("Should not be able to set key twice");
        } catch (IllegalStateException e) {
            /* Expected behavior */
        }

        aesCtr.releaseNativeStruct();
    }
}

