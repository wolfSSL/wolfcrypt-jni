/* AesCtsTest.java
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

import com.wolfssl.wolfcrypt.AesCts;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class AesCtsTest {

    private static final byte[] KEY_128 = Util.h2b(
        "636869636b656e207465726979616b69");
    private static final byte[] IV = Util.h2b(
        "00000000000000000000000000000000");

    /* Test case with 17 bytes (one block + 1 byte) */
    private static final byte[] PLAINTEXT_17 = Util.h2b(
        "4920776f756c64206c696b652074686520");
    private static final byte[] CIPHERTEXT_17 = Util.h2b(
        "c6353568f2bf8cb4d8a580362da7ff7f97");

    /* Test case with 31 bytes (one block + 15 bytes) */
    private static final byte[] PLAINTEXT_31 = Util.h2b(
        "4920776f756c64206c696b65207468652047656e6572616c2047" +
        "6175277320");
    private static final byte[] CIPHERTEXT_31 = Util.h2b(
        "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b" +
        "25e25ecfe5");

    /* Test case with 32 bytes (two full blocks) */
    private static final byte[] PLAINTEXT_32 = Util.h2b(
        "4920776f756c64206c696b65207468652047656e6572616c2047" +
        "617527732043");
    private static final byte[] CIPHERTEXT_32 = Util.h2b(
        "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b" +
        "25e25ecfe584");

    /* Test case with 48 bytes (three full blocks) */
    private static final byte[] PLAINTEXT_48 = Util.h2b(
        "4920776f756c64206c696b65207468652047656e6572616c2047" +
        "6175277320436869636b656e2c20706c656173652c20");
    private static final byte[] CIPHERTEXT_48 = Util.h2b(
        "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc1" +
        "03e1a194bbd839312523a78662d5be7fcbcc98ebf5a8");

    /* AES-256 test key */
    private static final byte[] KEY_256 = Util.h2b(
        "636869636b656e207465726979616b69636869636b" +
        "656e207465726979616b69");

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {
        try {
            new AesCts();
            System.out.println("JNI AesCts Class");

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("AesCts test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new AesCts().getNativeStruct());
    }

    @Test
    public void checkSetKeyParams() {
        AesCts aesCts = new AesCts();

        try {
            aesCts.setKey(null, IV, AesCts.ENCRYPT_MODE);
            fail("key should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCts.setKey(KEY_128, null, AesCts.ENCRYPT_MODE);
            fail("iv should not be null for CTS mode.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        aesCts.releaseNativeStruct();

        /* Should be able to set key again after release */
        aesCts.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        aesCts.releaseNativeStruct();
    }

    @Test
    public void checkUpdateParams() {
        /* CTS requires > 16 bytes */
        byte[] input = new byte[32];
        byte[] output = new byte[32];

        AesCts aesCts = new AesCts();
        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);

        aesCts.update(input);

        try {
            aesCts.update(null, 0, 32, output, 0);
            fail("input should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            aesCts.update(input, 0, 32, null, 0);
            fail("output should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw WolfCryptException for null output */
        }

        aesCts.update(input, 0, 32, output, 0);

        aesCts.releaseNativeStruct();

        try {
            aesCts.update(input, 0, 32, output, 0);
            fail("native struct should not be null.");
        } catch (IllegalStateException e) {
            /* test must throw */
        }
    }

    @Test
    public void checkMinimumInputLength() {
        AesCts aesCts = new AesCts();
        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);

        /* CTS requires > 16 bytes, test with 16 bytes should fail */
        byte[] input16 = new byte[16];

        try {
            aesCts.update(input16);
            fail("CTS should require input length > 16 bytes");
        } catch (WolfCryptException e) {
            /* Expected - input too small */
        }

        /* Test with 17 bytes should succeed */
        byte[] input17 = new byte[17];
        byte[] result = aesCts.update(input17);
        assertNotNull("17 byte input should succeed", result);
        assertEquals("Output length should match input length",
            17, result.length);

        aesCts.releaseNativeStruct();
    }

    @Test
    public void aes128CtsEncryptDecrypt17BytesTest() {
        AesCts aesCts = new AesCts();

        /* Test encryption */
        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        byte[] ciphertext = aesCts.update(PLAINTEXT_17);

        assertArrayEquals("AES-128-CTS encryption failed (17 bytes)",
            CIPHERTEXT_17, ciphertext);

        aesCts.releaseNativeStruct();

        /* Test decryption - this is the critical round-trip test */
        aesCts = new AesCts();
        aesCts.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesCts.update(ciphertext);

        assertArrayEquals("AES-128-CTS round-trip failed (17 bytes)",
            PLAINTEXT_17, decrypted);

        aesCts.releaseNativeStruct();
    }

    @Test
    public void aes128CtsEncryptDecrypt31BytesTest() {
        AesCts aesCts = new AesCts();

        /* Test encryption */
        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        byte[] ciphertext = aesCts.update(PLAINTEXT_31);

        assertArrayEquals("AES-128-CTS encryption failed (31 bytes)",
            CIPHERTEXT_31, ciphertext);

        aesCts.releaseNativeStruct();

        /* Test decryption - round-trip test */
        aesCts = new AesCts();
        aesCts.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesCts.update(ciphertext);

        assertArrayEquals("AES-128-CTS round-trip failed (31 bytes)",
            PLAINTEXT_31, decrypted);

        aesCts.releaseNativeStruct();
    }

    @Test
    public void aes128CtsEncryptDecrypt32BytesTest() {
        AesCts aesCts = new AesCts();

        /* Test encryption */
        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        byte[] ciphertext = aesCts.update(PLAINTEXT_32);

        assertArrayEquals("AES-128-CTS encryption failed (32 bytes)",
            CIPHERTEXT_32, ciphertext);

        aesCts.releaseNativeStruct();

        /* Test decryption - round-trip test */
        aesCts = new AesCts();
        aesCts.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesCts.update(ciphertext);

        assertArrayEquals("AES-128-CTS round-trip failed (32 bytes)",
            PLAINTEXT_32, decrypted);

        aesCts.releaseNativeStruct();
    }

    @Test
    public void aes128CtsEncryptDecrypt48BytesTest() {
        AesCts aesCts = new AesCts();

        /* Test encryption */
        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        byte[] ciphertext = aesCts.update(PLAINTEXT_48);

        assertArrayEquals("AES-128-CTS encryption failed (48 bytes)",
            CIPHERTEXT_48, ciphertext);

        aesCts.releaseNativeStruct();

        /* Test decryption - round-trip test */
        aesCts = new AesCts();
        aesCts.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesCts.update(ciphertext);

        assertArrayEquals("AES-128-CTS round-trip failed (48 bytes)",
            PLAINTEXT_48, decrypted);

        aesCts.releaseNativeStruct();
    }

    @Test
    public void aes256CtsEncryptDecryptTest() {
        AesCts aesCts = new AesCts();

        /* Test encryption with AES-256 */
        aesCts.setKey(KEY_256, IV, AesCts.ENCRYPT_MODE);
        byte[] ciphertext = aesCts.update(PLAINTEXT_48);

        /* Verify output length matches input */
        assertEquals("Output length should match input length",
            PLAINTEXT_48.length, ciphertext.length);

        aesCts.releaseNativeStruct();

        /* Test decryption */
        aesCts = new AesCts();
        aesCts.setKey(KEY_256, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesCts.update(ciphertext);

        assertArrayEquals("AES-256-CTS round-trip failed",
            PLAINTEXT_48, decrypted);

        aesCts.releaseNativeStruct();
    }

    @Test
    public void aes128CtsPartialUpdateTest() {
        AesCts aesEnc = new AesCts();
        aesEnc.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);

        /* Process using offset/length API */
        byte[] output = new byte[PLAINTEXT_48.length];
        int processed = aesEnc.update(
            PLAINTEXT_48, 0, PLAINTEXT_48.length, output, 0);

        assertEquals("Processed length should match input length",
            PLAINTEXT_48.length, processed);

        assertArrayEquals("AES-128-CTS offset/length encryption failed",
            CIPHERTEXT_48, output);

        aesEnc.releaseNativeStruct();

        AesCts aesDec = new AesCts();
        aesDec.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesDec.update(output);

        assertArrayEquals("AES-128-CTS offset/length round-trip failed",
            PLAINTEXT_48, decrypted);

        aesDec.releaseNativeStruct();
    }

    @Test
    public void aes128CtsByteBufferTest() throws ShortBufferException {
        AesCts aesEnc = new AesCts();
        aesEnc.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);

        ByteBuffer input = ByteBuffer.allocateDirect(PLAINTEXT_48.length);
        ByteBuffer output = ByteBuffer.allocateDirect(PLAINTEXT_48.length);

        input.put(PLAINTEXT_48);
        input.flip();

        int processed = aesEnc.update(input, output);
        assertEquals("Processed length mismatch",
            PLAINTEXT_48.length, processed);

        output.flip();
        byte[] ciphertext = new byte[output.remaining()];
        output.get(ciphertext);

        assertArrayEquals("AES-128-CTS ByteBuffer encryption failed",
            CIPHERTEXT_48, ciphertext);

        aesEnc.releaseNativeStruct();

        AesCts aesDec = new AesCts();
        aesDec.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesDec.update(ciphertext);

        assertArrayEquals("AES-128-CTS ByteBuffer round-trip failed",
            PLAINTEXT_48, decrypted);

        aesDec.releaseNativeStruct();
    }

    @Test
    public void releaseAndReInitObject() {
        AesCts aesCts = new AesCts();

        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        byte[] ciphertext = aesCts.update(PLAINTEXT_48);
        aesCts.releaseNativeStruct();

        /* Should be able to use again after re-initialization */
        aesCts.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        byte[] result = aesCts.update(PLAINTEXT_48);

        /* Just verify consistency */
        assertArrayEquals("Re-initialization consistency check failed",
            ciphertext, result);

        aesCts.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {
        AesCts aesEnc = new AesCts();

        /* First use - encrypt */
        aesEnc.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        byte[] ciphertext = aesEnc.update(PLAINTEXT_48);

        /* Try to set key again - should throw exception */
        try {
            aesEnc.setKey(KEY_256, IV, AesCts.ENCRYPT_MODE);
            fail("Should not be able to set key twice");
        } catch (IllegalStateException e) {
            /* Expected behavior */
        }

        aesEnc.releaseNativeStruct();

        /* Verify round-trip */
        AesCts aesDec = new AesCts();
        aesDec.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);
        byte[] decrypted = aesDec.update(ciphertext);
        assertArrayEquals("Round-trip failed", PLAINTEXT_48, decrypted);
        aesDec.releaseNativeStruct();
    }

    @Test
    public void testEncryptDecryptModes() {
        AesCts aesEnc = new AesCts();
        AesCts aesDec = new AesCts();

        /* Set up encrypt and decrypt contexts */
        aesEnc.setKey(KEY_128, IV, AesCts.ENCRYPT_MODE);
        aesDec.setKey(KEY_128, IV, AesCts.DECRYPT_MODE);

        /* Encrypt */
        byte[] ciphertext = aesEnc.update(PLAINTEXT_48);

        /* Decrypt */
        byte[] plaintext = aesDec.update(ciphertext);

        assertArrayEquals("Encrypt/Decrypt mode test failed",
            PLAINTEXT_48, plaintext);

        aesEnc.releaseNativeStruct();
        aesDec.releaseNativeStruct();
    }
}

