/* Des3Test.java
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
import java.nio.ByteBuffer;

import javax.crypto.ShortBufferException;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Des3;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class Des3Test {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Des3();
            System.out.println("JNI Des3 Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("Des3 test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new Des3().getNativeStruct());
    }

    @Test
    public void deprecatedConstructorThrows() {
        try {
            new Des3(null, null, Des3.ENCRYPT_MODE);
            fail("Failed to throw expected exception");
        } catch (WolfCryptException e) {
            /* expected */
        }
    }

    @Test(expected=ShortBufferException.class)
    public void updateShouldMatchUsingByteByffer() throws ShortBufferException {
        String[] keys = new String[] {
                "e61a38548694f1fd8cef251c518cc70bb613751c1ce52aa8",
                "2ff4e5c1cda84946798cc4ea8a1cf8df579e8a70f438b554",
                "9151232c854cf7977562a4e098d9d6ce892a80f79b408934",
                "9715c173b0a89292b3a88acbc7522085d5a1522f32109ea1" };
        String[] ivs = new String[] { "48a8ceb8551fd4ad",
                "76b779525bb0d1c0", "0e04ab4e1171451d", "19e6a2b2a690f026" };
        String[] inputs = new String[] { "e8fb0ceb4e912e16",
                "77340331c9c8e4f4", "2dab916e1b72c578", "7a3d5228d200e322" };
        String[] outputs = new String[] { "d2190e296a0bfc56",
                "b7f1fd226680a6ee", "f50d41fc9fe9ba71", "5e124bc1d28414e7" };


        ByteBuffer input = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);
        ByteBuffer output = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);
        ByteBuffer plain = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);
        ByteBuffer cipher = ByteBuffer.allocateDirect(Des3.BLOCK_SIZE);

        for (int i = 0; i < inputs.length; i++) {
            Des3 enc = new Des3();
            Des3 dec = new Des3();

            enc.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Des3.ENCRYPT_MODE);
            dec.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Des3.DECRYPT_MODE);

            input.put(Util.h2b(inputs[i])).rewind();
            output.put(Util.h2b(outputs[i])).rewind();

            try {
                assertEquals(Des3.BLOCK_SIZE, enc.update(input, cipher));
                assertEquals(Des3.BLOCK_SIZE, dec.update(output, plain));
            } catch (ShortBufferException e) {
                e.printStackTrace();
                fail();
            }

            assertEquals(Des3.BLOCK_SIZE, input.position());
            assertEquals(0, input.remaining());
            assertEquals(Des3.BLOCK_SIZE, output.position());
            assertEquals(0, output.remaining());
            assertEquals(Des3.BLOCK_SIZE, cipher.position());
            assertEquals(0, cipher.remaining());
            assertEquals(Des3.BLOCK_SIZE, plain.position());
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

    @Test(expected=ShortBufferException.class)
    public void updateShouldMatchUsingByteArray() throws ShortBufferException {
        String[] keys = new String[] {
                "e61a38548694f1fd8cef251c518cc70bb613751c1ce52aa8",
                "2ff4e5c1cda84946798cc4ea8a1cf8df579e8a70f438b554",
                "9151232c854cf7977562a4e098d9d6ce892a80f79b408934",
                "9715c173b0a89292b3a88acbc7522085d5a1522f32109ea1" };
        String[] ivs = new String[] { "48a8ceb8551fd4ad",
                "76b779525bb0d1c0", "0e04ab4e1171451d", "19e6a2b2a690f026" };
        String[] inputs = new String[] { "e8fb0ceb4e912e16",
                "77340331c9c8e4f4", "2dab916e1b72c578", "7a3d5228d200e322" };
        String[] outputs = new String[] { "d2190e296a0bfc56",
                "b7f1fd226680a6ee", "f50d41fc9fe9ba71", "5e124bc1d28414e7" };

        for (int i = 0; i < inputs.length; i++) {
            byte[] input = Util.h2b(inputs[i]);
            byte[] output = Util.h2b(outputs[i]);
            byte[] cipher = new byte[Des3.BLOCK_SIZE];
            byte[] plain = new byte[Des3.BLOCK_SIZE];

            Des3 enc = new Des3();
            Des3 dec = new Des3();

            enc.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Des3.ENCRYPT_MODE);
            dec.setKey(Util.h2b(keys[i]), Util.h2b(ivs[i]), Des3.DECRYPT_MODE);

            if (i % 2 == 0) {
                cipher = enc.update(input, 0, input.length);
                plain = dec.update(output, 0, output.length);
            } else {
                try {
                    assertEquals(Des3.BLOCK_SIZE,
                            enc.update(input, 0, input.length, cipher, 0));
                    assertEquals(Des3.BLOCK_SIZE,
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
                enc.update(input, 0, input.length, cipher, Des3.BLOCK_SIZE);
        }
    }

    @Test
    public void releaseAndReInitObject() {

        byte[] key = Util.h2b("e61a38548694f1fd8cef251c518" +
                              "cc70bb613751c1ce52aa8");
        byte[] iv = Util.h2b("48a8ceb8551fd4ad");
        byte[] in = Util.h2b("e8fb0ceb4e912e16");
        byte[] expected = Util.h2b("d2190e296a0bfc56");

        byte[] cipher = null;
        byte[] plain = null;

        Des3 enc = new Des3();
        enc.setKey(key, iv, Des3.ENCRYPT_MODE);
        cipher = enc.update(in, 0, in.length);
        assertArrayEquals(expected, cipher);

        Des3 dec = new Des3();
        dec.setKey(key, iv, Des3.DECRYPT_MODE);
        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in, plain);

        /* free objects */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();

        /* try to re-init and re-use them */
        enc = new Des3();
        enc.setKey(key, iv, Des3.ENCRYPT_MODE);
        cipher = enc.update(in, 0, in.length);
        assertArrayEquals(expected, cipher);

        dec = new Des3();
        dec.setKey(key, iv, Des3.DECRYPT_MODE);
        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in, plain);

        /* free again */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {

        byte[] key = Util.h2b("e61a38548694f1fd8cef251c518" +
                              "cc70bb613751c1ce52aa8");
        byte[] iv = Util.h2b("48a8ceb8551fd4ad");
        byte[] in = Util.h2b("e8fb0ceb4e912e16");
        byte[] in2 = Util.h2b("77340331c9c8e4f4");
        byte[] expected = Util.h2b("d2190e296a0bfc56");
        byte[] expected2 = Util.h2b("fa10d9e478fc63f0");

        byte[] cipher = null;
        byte[] plain = null;

        Des3 enc = new Des3();
        enc.setKey(key, iv, Des3.ENCRYPT_MODE);
        cipher = enc.update(in, 0, in.length);
        assertArrayEquals(expected, cipher);

        Des3 dec = new Des3();
        dec.setKey(key, iv, Des3.DECRYPT_MODE);
        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in, plain);

        /* now, try to reuse existing enc/dec objects */
        cipher = enc.update(in2, 0, in2.length);
        assertArrayEquals(expected2, cipher);

        plain = dec.update(cipher, 0, cipher.length);
        assertArrayEquals(in2, plain);

        /* free objects */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }

    @Test
    public void threadedDes3Test() throws InterruptedException {

        int numThreads = 50;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results = new LinkedBlockingQueue<>();
        final byte[] rand2kBuf = new byte[2048];
        final byte[] key = Util.h2b("e61a38548694f1fd8cef251c518" +
                                    "cc70bb613751c1ce52aa8");
        final byte[] iv = Util.h2b("48a8ceb8551fd4ad");

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand2kBuf);

        /* encrypt / decrypt input data, make sure decrypted matches original */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int ret = 0;
                    byte[] encrypted = new byte[2048];
                    byte[] plaintext = new byte[2048];
                    Des3 enc = new Des3();
                    Des3 dec = new Des3();

                    try {
                        enc.setKey(key, iv, Des3.ENCRYPT_MODE);
                        dec.setKey(key, iv, Des3.DECRYPT_MODE);

                        /* encrypt in 128-byte chunks */
                        Arrays.fill(encrypted, (byte)0);
                        for (int j = 0; j < rand2kBuf.length; j+= 128) {
                            ret = enc.update(rand2kBuf, j, 128, encrypted, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Des3.update(ENCRYPT_MODE) returned " + ret);
                            }
                        }

                        /* decrypt in 128-byte chunks */
                        Arrays.fill(plaintext, (byte)0);
                        for (int j = 0; j < encrypted.length; j+= 128) {
                            ret = dec.update(encrypted, j, 128, plaintext, j);
                            if (ret != 128) {
                                throw new Exception(
                                    "Des3.update(DECRYPT_MODE) returned " + ret);
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
                fail("Threading error in 3DES thread test");
            }
        }
    }
}

