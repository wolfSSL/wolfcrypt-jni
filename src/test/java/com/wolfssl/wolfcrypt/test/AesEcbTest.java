/* AesEcbTest.java
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

import com.wolfssl.wolfcrypt.AesEcb;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class AesEcbTest {

    /* Test vectors from NIST SP 800-38A */
    private static final byte[] KEY_128 = Util.h2b(
        "2b7e151628aed2a6abf7158809cf4f3c");
    private static final byte[] PLAINTEXT = Util.h2b(
        "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710");
    private static final byte[] CIPHERTEXT_128 = Util.h2b(
        "3ad77bb40d7a3660a89ecaf32466ef97" +
        "f5d3d58503b9699de785895a96fdbaaf" +
        "43b1cd7f598ece23881b00e3ed030688" +
        "7b0c785e27e8ad3f8223207104725dd4");

    private static final byte[] KEY_256 = Util.h2b(
        "603deb1015ca71be2b73aef0857d7781" +
        "1f352c073b6108d72d9810a30914dff4");
    private static final byte[] CIPHERTEXT_256 = Util.h2b(
        "f3eed1bdb5d2a03c064b5a7e3db181f8" +
        "591ccb10d410ed26dc5ba74a31362870" +
        "b6ed21b99ca6f4f9f153e7b1beafed1d" +
        "23304b7a39f9f3ff067d8d8f9e24ecc7");

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        try {
            new AesEcb();
            System.out.println("JNI AesEcb Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("AesEcb test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesEcb().getNativeStruct());
    }

    @Test
    public void checkSetKeyParams() {
        AesEcb aesEcb = new AesEcb();

        try {
            aesEcb.setKey(null, AesEcb.ENCRYPT_MODE);
            fail("key should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);
        aesEcb.releaseNativeStruct();

        /* BlockCipher does not allow reinitialization after release */
        try {
            aesEcb.setKey(KEY_128, AesEcb.DECRYPT_MODE);
            fail("Should not be able to set key after release");
        } catch (IllegalStateException e) {
            /* Expected behavior for BlockCipher */
        }
    }

    @Test
    public void checkUpdateParams() throws ShortBufferException {
        byte[] input = new byte[AesEcb.BLOCK_SIZE];
        byte[] output = new byte[AesEcb.BLOCK_SIZE];

        AesEcb aesEcb = new AesEcb();
        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);

        aesEcb.update(input);

        try {
            aesEcb.update(null, 0, AesEcb.BLOCK_SIZE, output, 0);
            fail("input should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesEcb.update(input, 0, AesEcb.BLOCK_SIZE, null, 0);
            fail("output should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw WolfCryptException for null output */
        }

        aesEcb.update(input, 0, AesEcb.BLOCK_SIZE, output, 0);

        aesEcb.releaseNativeStruct();

        try {
            aesEcb.update(input, 0, AesEcb.BLOCK_SIZE, output, 0);
            fail("Should not be able to update after release");
        } catch (IllegalStateException e) {
            /* Expected behavior for BlockCipher after release */
        }
    }

    @Test
    public void aes128EcbEncryptDecryptTest() throws ShortBufferException {
        AesEcb aesEcb = new AesEcb();

        /* Test encryption */
        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);
        byte[] ciphertext = aesEcb.update(PLAINTEXT);

        assertArrayEquals("AES-128-ECB encryption failed",
                         CIPHERTEXT_128, ciphertext);

        aesEcb.releaseNativeStruct();

        /* Test decryption */
        aesEcb = new AesEcb();
        aesEcb.setKey(KEY_128, AesEcb.DECRYPT_MODE);
        byte[] decrypted = aesEcb.update(CIPHERTEXT_128);

        assertArrayEquals("AES-128-ECB decryption failed",
                         PLAINTEXT, decrypted);

        aesEcb.releaseNativeStruct();
    }

    @Test
    public void aes256EcbEncryptDecryptTest() throws ShortBufferException {
        AesEcb aesEcb = new AesEcb();

        /* Test encryption */
        aesEcb.setKey(KEY_256, AesEcb.ENCRYPT_MODE);
        byte[] ciphertext = aesEcb.update(PLAINTEXT);

        assertArrayEquals("AES-256-ECB encryption failed",
                         CIPHERTEXT_256, ciphertext);

        aesEcb.releaseNativeStruct();

        /* Test decryption */
        aesEcb = new AesEcb();
        aesEcb.setKey(KEY_256, AesEcb.DECRYPT_MODE);
        byte[] decrypted = aesEcb.update(CIPHERTEXT_256);

        assertArrayEquals("AES-256-ECB decryption failed",
                         PLAINTEXT, decrypted);

        aesEcb.releaseNativeStruct();
    }

    @Test
    public void aes128EcbPartialUpdateTest() throws ShortBufferException {
        AesEcb aesEcb = new AesEcb();
        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);

        /* Test partial block updates - ECB processes 16-byte blocks */
        byte[] output = new byte[PLAINTEXT.length];
        int outputOffset = 0;

        /* Process in 16-byte chunks */
        for (int i = 0; i < PLAINTEXT.length; i += 16) {
            int chunkSize = Math.min(16, PLAINTEXT.length - i);
            int processed = aesEcb.update(PLAINTEXT, i, chunkSize,
                                        output, outputOffset);
            outputOffset += processed;
        }

        assertArrayEquals("AES-128-ECB partial update failed",
                         CIPHERTEXT_128, output);

        aesEcb.releaseNativeStruct();
    }

    @Test
    public void aes128EcbByteBufferTest() throws ShortBufferException {
        AesEcb aesEcb = new AesEcb();
        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);

        ByteBuffer input = ByteBuffer.allocateDirect(PLAINTEXT.length);
        ByteBuffer output = ByteBuffer.allocateDirect(PLAINTEXT.length);

        input.put(PLAINTEXT);
        input.flip();

        int processed = aesEcb.update(input, output);
        assertEquals("Processed length mismatch", PLAINTEXT.length, processed);

        output.flip();
        byte[] result = new byte[output.remaining()];
        output.get(result);

        assertArrayEquals("AES-128-ECB ByteBuffer test failed",
                         CIPHERTEXT_128, result);

        aesEcb.releaseNativeStruct();
    }

    @Test
    public void releaseAndReInitObject() throws ShortBufferException {
        AesEcb aesEcb = new AesEcb();

        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);
        byte[] result1 = aesEcb.update(PLAINTEXT);

        assertArrayEquals("First encryption failed", CIPHERTEXT_128, result1);

        aesEcb.releaseNativeStruct();

        /* BlockCipher does not allow reinitialization after release */
        try {
            aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);
            fail("Should not be able to reinitialize after release");
        } catch (IllegalStateException e) {
            /* Expected behavior for BlockCipher */
        }

        try {
            aesEcb.update(PLAINTEXT);
            fail("Should not be able to update after release");
        } catch (IllegalStateException e) {
            /* Expected behavior for BlockCipher */
        }
    }

    @Test
    public void reuseObject() throws ShortBufferException {
        AesEcb aesEcb = new AesEcb();

        /* First use */
        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);
        byte[] result1 = aesEcb.update(PLAINTEXT);

        assertArrayEquals("First use failed", CIPHERTEXT_128, result1);

        /* Try to set key again - should throw exception */
        try {
            aesEcb.setKey(KEY_256, AesEcb.ENCRYPT_MODE);
            fail("Should not be able to set key twice");
        } catch (IllegalStateException e) {
            /* Expected behavior */
        }

        aesEcb.releaseNativeStruct();
    }

    @Test
    public void testBlockAlignment() throws ShortBufferException {
        AesEcb aesEcb = new AesEcb();
        aesEcb.setKey(KEY_128, AesEcb.ENCRYPT_MODE);

        /* ECB requires block-aligned data (16 bytes) */
        byte[] invalidInput = new byte[15]; /* Not block-aligned */

        try {
            aesEcb.update(invalidInput);
            fail("Should reject non-block-aligned data");
        } catch (WolfCryptException e) {
            /* Expected behavior for non-aligned data */
        }

        aesEcb.releaseNativeStruct();
    }
}

