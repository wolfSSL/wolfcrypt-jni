/* AesTest.java
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
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import javax.crypto.ShortBufferException;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class AesTest {

    private static final byte[] KEY = Util
            .h2b("00112233445566778899AABBCCDDEEFF");
    private static final byte[] IV = Util
            .h2b("000102030405060708090A0B0C0D0E0F");

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Aes();
            System.out.println("JNI Aes Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("Aes test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new Aes().getNativeStruct());
    }

    @Test
    public void deprecatedConstructorThrows() {
        try {
            Aes aes = new Aes(null, null, Aes.ENCRYPT_MODE);
            fail("Failed to throw expected exception");
        } catch (WolfCryptException e) {
            /* expected */
        }
    }

    @Test
    public void checkSetKeyParams() {
        /* iv is optional, should not raise. */
        Aes aes = new Aes();

        try {
            aes.setKey(null, IV, Aes.ENCRYPT_MODE);
            fail("key should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        aes.setKey(KEY, IV, Aes.ENCRYPT_MODE);
        aes.releaseNativeStruct();

        try {
            aes.setKey(KEY, IV, Aes.ENCRYPT_MODE);
            fail("setKey() after release should throw exception");
        } catch (IllegalStateException e) {
            /* test must throw */
        }
    }

    @Test
    public void checkUpdateParams() throws ShortBufferException {
        byte[] input = new byte[Aes.BLOCK_SIZE];
        byte[] output = new byte[Aes.BLOCK_SIZE];

        Aes enc = new Aes();
        Aes dec = new Aes();

        enc.setKey(KEY, IV, Aes.ENCRYPT_MODE);
        dec.setKey(KEY, IV, Aes.DECRYPT_MODE);

        enc.update(input);
        dec.update(input);

        try {
            enc.update(null, 0, Aes.BLOCK_SIZE, output, 0);
            fail("input should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            dec.update(null, 0, Aes.BLOCK_SIZE, output, 0);
            fail("input should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        try {
            enc.update(input, 0, Aes.BLOCK_SIZE, null, 0);
            fail("output should not be null.");
        } catch (NullPointerException e) {
            /* test must throw */
        }

        try {
            dec.update(input, 0, Aes.BLOCK_SIZE, null, 0);
            fail("output should not be null.");
        } catch (NullPointerException e) {
            /* test must throw */
        }

        enc.update(input, 0, Aes.BLOCK_SIZE, output, 0);
        dec.update(input, 0, Aes.BLOCK_SIZE, output, 0);

        enc.releaseNativeStruct();
        dec.releaseNativeStruct();

        try {
            enc.update(input, 0, Aes.BLOCK_SIZE, output, 0);
            fail("native struct should not be null.");
        } catch (IllegalStateException e) {
            /* test must throw */
        }

        try {
            dec.update(input, 0, Aes.BLOCK_SIZE, output, 0);
            fail("native struct should not be null.");
        } catch (IllegalStateException e) {
            /* test must throw */
        }
    }

    @Test(expected = IllegalStateException.class)
    public void inputShouldNotBeNull() {
        Aes aes = new Aes();

        try {
            aes.setKey(Util.h2b("2b7e151628aed2a6abf7158809cf4f3c"), null,
                    Aes.ENCRYPT_MODE);
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.BAD_FUNC_ARG)
                fail("iv should be optional when setting key.");
        }

        aes.setKey(null, null, Aes.ENCRYPT_MODE);
    }

    @Test(expected = ShortBufferException.class)
    public void updateShouldMatchUsingByteByffer() throws ShortBufferException {
        String[] keys = new String[] {
                "2b7e151628aed2a6abf7158809cf4f3c",
                "2b7e151628aed2a6abf7158809cf4f3c",
                "2b7e151628aed2a6abf7158809cf4f3c",
                "2b7e151628aed2a6abf7158809cf4f3c",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", };
        String[] ivs = new String[] {
                "000102030405060708090A0B0C0D0E0F",
                "7649ABAC8119B246CEE98E9B12E9197D",
                "5086CB9B507219EE95DB113A917678B2",
                "73BED6B8E3C1743B7116E69E22229516",
                "000102030405060708090A0B0C0D0E0F",
                "4F021DB243BC633D7178183A9FA071E8",
                "B4D9ADA9AD7DEDF4E5E738763F69145A",
                "571B242012FB7AE07FA9BAAC3DF102E0",
                "000102030405060708090A0B0C0D0E0F",
                "F58C4C04D6E5F1BA779EABFB5F7BFBD6",
                "9CFC4E967EDB808D679F777BC6702C7D",
                "39F23369A9D9BACFA530E26304231461" };
        String[] inputs = new String[] {
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710",
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710",
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710" };
        String[] outputs = new String[] {
                "7649abac8119b246cee98e9b12e9197d",
                "5086cb9b507219ee95db113a917678b2",
                "73bed6b8e3c1743b7116e69e22229516",
                "3ff1caa1681fac09120eca307586e1a7",
                "4f021db243bc633d7178183a9fa071e8",
                "b4d9ada9ad7dedf4e5e738763f69145a",
                "571b242012fb7ae07fa9baac3df102e0",
                "08b0e27988598881d920a9e64f5615cd",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
                "9cfc4e967edb808d679f777bc6702c7d",
                "39f23369a9d9bacfa530e26304231461",
                "b2eb05e2c39be9fcda6c19078c6a9d1b" };

        ByteBuffer input = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
        ByteBuffer output = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
        ByteBuffer plain = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);
        ByteBuffer cipher = ByteBuffer.allocateDirect(Aes.BLOCK_SIZE);

        for (int i = 0; i < inputs.length; i++) {
            Aes enc = new Aes();
            Aes dec = new Aes();

            enc.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Aes.ENCRYPT_MODE);
            dec.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Aes.DECRYPT_MODE);

            input.put(Util.h2b(inputs[i])).rewind();
            output.put(Util.h2b(outputs[i])).rewind();

            try {
                assertEquals(Aes.BLOCK_SIZE, enc.update(input, cipher));
                assertEquals(Aes.BLOCK_SIZE, dec.update(output, plain));
            } catch (ShortBufferException e) {
                e.printStackTrace();
                fail();
            }

            assertEquals(Aes.BLOCK_SIZE, input.position());
            assertEquals(0, input.remaining());
            assertEquals(Aes.BLOCK_SIZE, output.position());
            assertEquals(0, output.remaining());
            assertEquals(Aes.BLOCK_SIZE, cipher.position());
            assertEquals(0, cipher.remaining());
            assertEquals(Aes.BLOCK_SIZE, plain.position());
            assertEquals(0, plain.remaining());

            input.rewind();
            output.rewind();
            cipher.rewind();
            plain.rewind();

            assertEquals(output, cipher);
            assertEquals(input, plain);

            /* tests ShortBufferException */
            if (i == inputs.length - 1) {
                cipher.position(cipher.limit());
                enc.update(input, cipher);
            }
        }
    }

    @Test(expected = ShortBufferException.class)
    public void updateShouldMatchUsingByteArray() throws ShortBufferException {
        String[] keys = new String[] {
                "2b7e151628aed2a6abf7158809cf4f3c",
                "2b7e151628aed2a6abf7158809cf4f3c",
                "2b7e151628aed2a6abf7158809cf4f3c",
                "2b7e151628aed2a6abf7158809cf4f3c",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", };
        String[] ivs = new String[] {
                "000102030405060708090A0B0C0D0E0F",
                "7649ABAC8119B246CEE98E9B12E9197D",
                "5086CB9B507219EE95DB113A917678B2",
                "73BED6B8E3C1743B7116E69E22229516",
                "000102030405060708090A0B0C0D0E0F",
                "4F021DB243BC633D7178183A9FA071E8",
                "B4D9ADA9AD7DEDF4E5E738763F69145A",
                "571B242012FB7AE07FA9BAAC3DF102E0",
                "000102030405060708090A0B0C0D0E0F",
                "F58C4C04D6E5F1BA779EABFB5F7BFBD6",
                "9CFC4E967EDB808D679F777BC6702C7D",
                "39F23369A9D9BACFA530E26304231461" };
        String[] inputs = new String[] {
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710",
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710",
                "6bc1bee22e409f96e93d7e117393172a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "f69f2445df4f9b17ad2b417be66c3710" };
        String[] outputs = new String[] {
                "7649abac8119b246cee98e9b12e9197d",
                "5086cb9b507219ee95db113a917678b2",
                "73bed6b8e3c1743b7116e69e22229516",
                "3ff1caa1681fac09120eca307586e1a7",
                "4f021db243bc633d7178183a9fa071e8",
                "b4d9ada9ad7dedf4e5e738763f69145a",
                "571b242012fb7ae07fa9baac3df102e0",
                "08b0e27988598881d920a9e64f5615cd",
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
                "9cfc4e967edb808d679f777bc6702c7d",
                "39f23369a9d9bacfa530e26304231461",
                "b2eb05e2c39be9fcda6c19078c6a9d1b" };

        for (int i = 0; i < inputs.length; i++) {
            byte[] input = Util.h2b(inputs[i]);
            byte[] output = Util.h2b(outputs[i]);
            byte[] cipher = new byte[Aes.BLOCK_SIZE];
            byte[] plain = new byte[Aes.BLOCK_SIZE];

            Aes enc = new Aes();
            Aes dec = new Aes();

            enc.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Aes.ENCRYPT_MODE);
            dec.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Aes.DECRYPT_MODE);

            if (i % 2 == 0) {
                cipher = enc.update(input, 0, input.length);
                plain = dec.update(output, 0, output.length);
            } else {
                try {
                    assertEquals(Aes.BLOCK_SIZE,
                            enc.update(input, 0, input.length, cipher, 0));
                    assertEquals(Aes.BLOCK_SIZE,
                            dec.update(output, 0, output.length, plain, 0));
                } catch (ShortBufferException e) {
                    e.printStackTrace();
                    fail();
                }
            }

            assertArrayEquals(output, cipher);
            assertArrayEquals(input, plain);

            /* tests ShortBufferException */
            if (i == inputs.length - 1)
                enc.update(input, 0, input.length, cipher, Aes.BLOCK_SIZE);
        }
    }

    @Test
    public void releaseAndReInitObject() {

        byte[] key = Util.h2b("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Util.h2b("000102030405060708090A0B0C0D0E0F");
        byte[] in = Util.h2b("6bc1bee22e409f96e93d7e117393172a");
        byte[] expected = Util.h2b("7649abac8119b246cee98e9b12e9197d");

        byte[] cipher = null;
        byte[] plain = null;

        Aes enc = new Aes();
        enc.setKey(key, iv, Aes.ENCRYPT_MODE);
        cipher = enc.update(in, 0, in.length);
        assertArrayEquals(expected, cipher);

        Aes dec = new Aes();
        dec.setKey(key, iv, Aes.DECRYPT_MODE);
        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in, plain);

        /* free objects */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();

        /* try to re-init and re-use them */
        enc = new Aes();
        enc.setKey(key, iv, Aes.ENCRYPT_MODE);
        cipher = enc.update(in, 0, in.length);
        assertArrayEquals(expected, cipher);

        dec = new Aes();
        dec.setKey(key, iv, Aes.DECRYPT_MODE);
        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in, plain);

        /* free again */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {

        byte[] key = Util.h2b("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Util.h2b("000102030405060708090A0B0C0D0E0F");
        byte[] in = Util.h2b("6bc1bee22e409f96e93d7e117393172a");
        byte[] in2 = Util.h2b("ae2d8a571e03ac9c9eb76fac45af8e51");
        byte[] expected = Util.h2b("7649abac8119b246cee98e9b12e9197d");
        byte[] expected2 = Util.h2b("5086cb9b507219ee95db113a917678b2");

        byte[] cipher = null;
        byte[] plain = null;

        Aes enc = new Aes();
        enc.setKey(key, iv, Aes.ENCRYPT_MODE);
        cipher = enc.update(in, 0, in.length);
        assertArrayEquals(expected, cipher);

        Aes dec = new Aes();
        dec.setKey(key, iv, Aes.DECRYPT_MODE);
        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in, plain);

        /* now, try to reuse existing enc/dec objects */
        cipher = enc.update(in2, 0, in2.length);
        assertArrayEquals(expected2, cipher);

        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in2, plain);

        /* free again */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void testPadPKCS7() {

        int padSz = 0;
        int expectedPadSz = 0;
        byte[] input = null;
        byte[] padded = null;
        byte[] unpadded = null;

        /* Test calculated pad size matches expected for input sizes
         * from 1 to Aes.BLOCK_SIZE */
        for (int i = 0; i < Aes.BLOCK_SIZE; i++) {
            padSz = Aes.getPKCS7PadSize(i + 1, Aes.BLOCK_SIZE);
            expectedPadSz = Aes.BLOCK_SIZE - ((i + 1) % Aes.BLOCK_SIZE);
            assertEquals(padSz, expectedPadSz);
        }

        /* Test pad/unpad of arrays sized 1 to 2 * Aes.BLOCK SIZE bytes,
         * Fill test arrays with 0xAA */
        for (int i = 0; i < 2 * Aes.BLOCK_SIZE; i++) {
            input = new byte[i+1];
            Arrays.fill(input, 0, input.length, (byte)0xAA);

            padded = Aes.padPKCS7(input, Aes.BLOCK_SIZE);
            unpadded = Aes.unPadPKCS7(padded, Aes.BLOCK_SIZE);

            assertEquals(input.length, unpadded.length);
            assertArrayEquals(input, unpadded);
        }

        /* Test padPKCS7() with null input */
        try {
            padded = Aes.padPKCS7(null, Aes.BLOCK_SIZE);
            fail("null input should throw WolfCryptException");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test padPKCS7() with zero length input */
        input = new byte[0];
        padded = Aes.padPKCS7(input, Aes.BLOCK_SIZE);
        assertNotNull(padded);
        assertEquals(16, padded.length);

        /* Test padPKCS7() with zero length block size */
        try {
            input = new byte[10];
            padded = Aes.padPKCS7(input, 0);
            fail("zero length block size should throw WolfCryptException");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test unPadPKCS7() with null input */
        try {
            unpadded = Aes.unPadPKCS7(null, Aes.BLOCK_SIZE);
            fail("null input should throw WolfCryptException");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test unPadPKCS7() with zero length input */
        try {
            input = new byte[0];
            unpadded = Aes.unPadPKCS7(input, Aes.BLOCK_SIZE);
            fail("zero length input should throw WolfCryptException");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test unPadPKCS7() with zero length block size */
        try {
            input = new byte[10];
            unpadded = Aes.unPadPKCS7(input, 0);
            fail("zero length block size should throw WolfCryptException");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test unPadPKCS7() with inconsistent pad value */
        try {
            padded = Util.h2b("00112233445566778899AABBCC020303");
            unpadded = Aes.unPadPKCS7(padded, Aes.BLOCK_SIZE);
            fail("inconsistent padding should throw WolfCryptException");
        } catch (WolfCryptException e) {
            /* expected */
        }

        /* Test unPadPKCS7() with pad value larger than block size */
        try {
            padded = Util.h2b("00112233445566778899AABBCC111111");
            unpadded = Aes.unPadPKCS7(padded, Aes.BLOCK_SIZE);
            fail("pad value larger than block size should " +
                 "throw WolfCryptException");
        } catch (WolfCryptException e) {
            /* expected */
        }
    }

    @Test
    public void threadedAesTest() throws InterruptedException {

        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
        final byte[] rand2kBuf = new byte[2048];
        final byte[] key = Util.h2b("2b7e151628aed2a6abf7158809cf4f3c");
        final byte[] iv = Util.h2b("000102030405060708090A0B0C0D0E0F");

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand2kBuf);

        /* encrypt / decrypt input data, make sure decrypted matches original */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int ret = 0;
                    byte[] encrypted = new byte[2048];
                    byte[] plaintext = new byte[2048];

                    Aes enc = new Aes();
                    Aes dec = new Aes();
                    enc.setKey(key, iv, Aes.ENCRYPT_MODE);
                    dec.setKey(key, iv, Aes.DECRYPT_MODE);

                    try {
                        /* encrypt in 128-byte chunks */
                        Arrays.fill(encrypted, (byte)0);
                        for (int j = 0; j < rand2kBuf.length; j+= 128) {
                            ret = enc.update(rand2kBuf, j, 128, encrypted, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Aes.update(ENCRYPT_MODE) returned " + ret);
                            }
                        }

                        /* decrypt in 128-byte chunks */
                        Arrays.fill(plaintext, (byte)0);
                        for (int j = 0; j < encrypted.length; j+= 128) {
                            ret = dec.update(encrypted, j, 128, plaintext, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Aes.update(DECRYPT_MODE) returned " + ret);
                            }
                        }

                        /* make sure decrypted is same as input */
                        if (Arrays.equals(rand2kBuf, plaintext)) {
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
                fail("Threading error in AES thread test");
            }
        }
    }
}

