/* AesOfbTest.java
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

import com.wolfssl.wolfcrypt.AesOfb;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class AesOfbTest {

    /* Test vectors from NIST CAVP OFBGFSbox test files */
    /* AES-128-OFB test vectors */
    private static final byte[] KEY_128 = Util.h2b(
        "00000000000000000000000000000000");
    private static final byte[] IV_128 = Util.h2b(
        "f34481ec3cc627bacd5dc3fb08f273e6");
    private static final byte[] PLAINTEXT_128 = Util.h2b(
        "00000000000000000000000000000000");
    private static final byte[] CIPHERTEXT_128 = Util.h2b(
        "0336763e966d92595a567cc9ce537f5e");

    /* Additional AES-128-OFB test vector for longer data */
    private static final byte[] KEY_128_2 = Util.h2b(
        "2b7e151628aed2a6abf7158809cf4f3c");
    private static final byte[] IV_128_2 = Util.h2b(
        "000102030405060708090a0b0c0d0e0f");
    private static final byte[] PLAINTEXT_LONG = Util.h2b(
        "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710");
    private static final byte[] CIPHERTEXT_LONG = Util.h2b(
        "3b3fd92eb72dad20333449f8e83cfb4a" +
        "7789508d16918f03f53c52dac54ed825" +
        "9740051e9c5fecf64344f7a82260edcc" +
        "304c6528f659c77866a510d9c1d6ae5e");

    /* AES-256-OFB test vectors */
    private static final byte[] KEY_256 = Util.h2b(
        "0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] IV_256 = Util.h2b(
        "014730f80ac625fe84f026c60bfd547d");
    private static final byte[] PLAINTEXT_256 = Util.h2b(
        "00000000000000000000000000000000");
    private static final byte[] CIPHERTEXT_256 = Util.h2b(
        "5c9d844ed46f9885085e5d6a4f94c7d7");

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {
        try {
            new AesOfb();
            System.out.println("JNI AesOfb Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("AesOfb test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesOfb().getNativeStruct());
    }

    @Test
    public void checkSetKeyParams() {
        AesOfb aesOfb = new AesOfb();

        try {
            aesOfb.setKey(null, IV_128);
            fail("key should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesOfb.setKey(KEY_128, null);
            fail("iv should not be null for OFB mode.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aesOfb.setKey(KEY_128, IV_128);
        aesOfb.releaseNativeStruct();

        /* Should be able to set key again after release */
        aesOfb.setKey(KEY_128, IV_128);
        aesOfb.releaseNativeStruct();
    }

    @Test
    public void checkEncryptDecryptParams() {
        byte[] input = new byte[AesOfb.BLOCK_SIZE];
        byte[] output = new byte[AesOfb.BLOCK_SIZE];

        AesOfb aesOfb = new AesOfb();
        aesOfb.setKey(KEY_128, IV_128);

        aesOfb.encrypt(input);

        try {
            aesOfb.encrypt(null, 0, AesOfb.BLOCK_SIZE, output, 0);
            fail("input should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesOfb.encrypt(input, 0, AesOfb.BLOCK_SIZE, null, 0);
            fail("output should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw WolfCryptException for null output */
        }

        aesOfb.encrypt(input, 0, AesOfb.BLOCK_SIZE, output, 0);

        /* Test decrypt as well */
        aesOfb.decrypt(input);
        aesOfb.decrypt(input, 0, AesOfb.BLOCK_SIZE, output, 0);

        aesOfb.releaseNativeStruct();

        try {
            aesOfb.encrypt(input, 0, AesOfb.BLOCK_SIZE, output, 0);
            fail("native struct should not be null.");
        } catch (IllegalStateException e) {
            /* test must throw */
        }
    }

    @Test
    public void aes128OfbEncryptDecryptTest() {
        AesOfb aesOfb = new AesOfb();

        /* Test encryption */
        aesOfb.setKey(KEY_128, IV_128);
        byte[] ciphertext = aesOfb.encrypt(PLAINTEXT_128);

        assertArrayEquals("AES-128-OFB encryption failed",
                         CIPHERTEXT_128, ciphertext);

        aesOfb.releaseNativeStruct();

        /* Test decryption */
        aesOfb = new AesOfb();
        aesOfb.setKey(KEY_128, IV_128);
        byte[] decrypted = aesOfb.decrypt(CIPHERTEXT_128);

        assertArrayEquals("AES-128-OFB decryption failed",
                         PLAINTEXT_128, decrypted);

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void aes128OfbLongDataTest() {
        AesOfb aesOfb = new AesOfb();

        /* Test encryption with longer data */
        aesOfb.setKey(KEY_128_2, IV_128_2);
        byte[] ciphertext = aesOfb.encrypt(PLAINTEXT_LONG);

        assertArrayEquals("AES-128-OFB long data encryption failed",
                         CIPHERTEXT_LONG, ciphertext);

        aesOfb.releaseNativeStruct();

        /* Test decryption */
        aesOfb = new AesOfb();
        aesOfb.setKey(KEY_128_2, IV_128_2);
        byte[] decrypted = aesOfb.decrypt(CIPHERTEXT_LONG);

        assertArrayEquals("AES-128-OFB long data decryption failed",
                         PLAINTEXT_LONG, decrypted);

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void aes256OfbEncryptDecryptTest() {
        AesOfb aesOfb = new AesOfb();

        /* Test encryption */
        aesOfb.setKey(KEY_256, IV_256);
        byte[] ciphertext = aesOfb.encrypt(PLAINTEXT_256);

        assertArrayEquals("AES-256-OFB encryption failed",
                         CIPHERTEXT_256, ciphertext);

        aesOfb.releaseNativeStruct();

        /* Test decryption */
        aesOfb = new AesOfb();
        aesOfb.setKey(KEY_256, IV_256);
        byte[] decrypted = aesOfb.decrypt(CIPHERTEXT_256);

        assertArrayEquals("AES-256-OFB decryption failed",
                         PLAINTEXT_256, decrypted);

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void aes128OfbPartialUpdateTest() {
        AesOfb aesOfb = new AesOfb();
        aesOfb.setKey(KEY_128_2, IV_128_2);

        /* Test partial block updates */
        byte[] output = new byte[PLAINTEXT_LONG.length];
        int outputOffset = 0;

        /* Process in 16-byte chunks */
        for (int i = 0; i < PLAINTEXT_LONG.length; i += 16) {
            int chunkSize = Math.min(16, PLAINTEXT_LONG.length - i);
            int processed = aesOfb.encrypt(PLAINTEXT_LONG, i, chunkSize,
                                        output, outputOffset);
            outputOffset += processed;
        }

        assertArrayEquals("AES-128-OFB partial update failed",
                         CIPHERTEXT_LONG, output);

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void aes128OfbByteBufferTest() throws ShortBufferException {
        AesOfb aesOfb = new AesOfb();
        aesOfb.setKey(KEY_128_2, IV_128_2);

        ByteBuffer input = ByteBuffer.allocateDirect(PLAINTEXT_LONG.length);
        ByteBuffer output = ByteBuffer.allocateDirect(PLAINTEXT_LONG.length);

        input.put(PLAINTEXT_LONG);
        input.flip();

        int processed = aesOfb.encrypt(input, output);
        assertEquals("Processed length mismatch", PLAINTEXT_LONG.length,
            processed);

        output.flip();
        byte[] result = new byte[output.remaining()];
        output.get(result);

        assertArrayEquals("AES-128-OFB ByteBuffer test failed",
                         CIPHERTEXT_LONG, result);

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void releaseAndReInitObject() {
        AesOfb aesOfb = new AesOfb();

        aesOfb.setKey(KEY_128, IV_128);
        aesOfb.encrypt(PLAINTEXT_128);
        aesOfb.releaseNativeStruct();

        /* Should be able to use again after re-initialization */
        aesOfb.setKey(KEY_128, IV_128);
        byte[] result = aesOfb.encrypt(PLAINTEXT_128);

        assertArrayEquals("Re-initialization test failed",
                         CIPHERTEXT_128, result);

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {
        AesOfb aesOfb = new AesOfb();

        /* First use */
        aesOfb.setKey(KEY_128, IV_128);
        byte[] result1 = aesOfb.encrypt(PLAINTEXT_128);

        assertArrayEquals("First use failed", CIPHERTEXT_128, result1);

        /* Try to set key again - should throw exception */
        try {
            aesOfb.setKey(KEY_256, IV_256);
            fail("Should not be able to set key twice");
        } catch (IllegalStateException e) {
            /* Expected behavior */
        }

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void testDeprecatedUpdateMethod() {
        AesOfb aesOfb = new AesOfb();
        aesOfb.setKey(KEY_128, IV_128);

        /* Test that deprecated update method still works */
        byte[] ciphertext = aesOfb.update(PLAINTEXT_128);
        assertArrayEquals("Deprecated update method failed",
                         CIPHERTEXT_128, ciphertext);

        aesOfb.releaseNativeStruct();
    }

    @Test
    public void testOpmodeSetKeyVariant() {
        /* Test that opmode setKey variant works */
        AesOfb aes = new AesOfb();

        /* Test encryption with ENCRYPT_MODE */
        aes.setKey(KEY_128, IV_128, AesOfb.ENCRYPT_MODE);
        byte[] encrypted = aes.update(PLAINTEXT_128);
        assertArrayEquals("AES-OFB encrypt mode failed",
                         CIPHERTEXT_128, encrypted);

        aes.releaseNativeStruct();
    }

    @Test
    public void testOpmodeWithExplicitMethods() {
        /* Test that encrypt() and decrypt() methods work with opmode */
        AesOfb aesEnc = new AesOfb();
        AesOfb aesDec = new AesOfb();

        /* encrypt() should set mode to ENCRYPT_MODE internally */
        aesEnc.setKey(KEY_128, IV_128);
        byte[] encrypted = aesEnc.encrypt(PLAINTEXT_128);
        assertArrayEquals("AES-OFB explicit encrypt failed",
                         CIPHERTEXT_128, encrypted);

        /* decrypt() should set mode to DECRYPT_MODE internally */
        aesDec.setKey(KEY_128, IV_128);
        byte[] decrypted = aesDec.decrypt(CIPHERTEXT_128);
        assertArrayEquals("AES-OFB explicit decrypt failed",
                         PLAINTEXT_128, decrypted);

        aesEnc.releaseNativeStruct();
        aesDec.releaseNativeStruct();
    }

}
