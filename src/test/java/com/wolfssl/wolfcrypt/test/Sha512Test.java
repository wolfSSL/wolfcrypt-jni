/* Sha512Test.java
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
import java.util.Random;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import javax.crypto.ShortBufferException;

import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class Sha512Test {
    private ByteBuffer data = ByteBuffer.allocateDirect(32);
    private ByteBuffer result = ByteBuffer.allocateDirect(Sha512.DIGEST_SIZE);
    private ByteBuffer expected = ByteBuffer.allocateDirect(Sha512.DIGEST_SIZE);

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkSha512IsAvailable() {
        try {
            Sha512 sha = new Sha512();
            assertNotNull(sha);
            System.out.println("JNI Sha512 Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("Sha512Test skipped: " + e.getError());
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new Sha512().getNativeStruct());
    }

    @Test
    public void hashShouldMatchUsingByteBuffer() throws ShortBufferException {
        String[] dataVector = new String[] { "", "20580a530f01e771",
                "f4be10fcc53147e49c3ac0fb14da0cda",
                "6377e356cb3319bac8f9c6f1b0de83b995b994dc69c22662",
                "805bd99e436ae027083476d01634378e17be35fec9e54a61f69bade4a61ac426" };
        String[] hashVector = new String[] {
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d"
                        + "13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "f3c5257278d189af8e68cebe64a8ead462a577df25d770d4bfc8b2285fd60a370d836"
                        + "80871a16f2d3828e2d0a7de0eec4a1dbd6922bbdd71ac2e5ac0dfa41bf4",
                "bc6f9552456006d89038b6d1c347ba02590e663ab9f65e5a129f654d272cb4b225853"
                        + "37df92ef005fda7da2b86c04155db1eb66d6daa5611eaf6e60c03c859b9",
                "7298bbe4a960ad987685f056dcc5fffe855bb903c61de9fb73f305a875035d88a06ca"
                        + "d10239af89f0d993ff5a1dbbfa9fdf18453be23a25a43474948dfa877d7",
                "9de0ab4a241d6de77efe158a69d2caef41c11224e7b7f82426b7ba231bd02ef31f184"
                        + "72220636e48f708872c1ce8c05c53a2c47731d332ee43d7866ca01b26cf" };

        for (int i = 0; i < dataVector.length; i++) {
            Sha512 sha = new Sha512();

            data.put(Util.h2b(dataVector[i])).rewind();
            expected.put(Util.h2b(hashVector[i])).rewind();

            sha.update(data, dataVector[i].length() / 2);
            sha.digest(result);
            data.rewind();
            result.rewind();

            assertEquals(expected, result);
        }
    }

    @Test
    public void hashShouldMatchUsingByteArray() {
        String[] dataVector = new String[] { "", "20580a530f01e771",
                "f4be10fcc53147e49c3ac0fb14da0cda",
                "6377e356cb3319bac8f9c6f1b0de83b995b994dc69c22662",
                "805bd99e436ae027083476d01634378e17be35fec9e54a61f69bade4a61ac426" };
        String[] hashVector = new String[] {
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d"
                        + "13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                "f3c5257278d189af8e68cebe64a8ead462a577df25d770d4bfc8b2285fd60a370d836"
                        + "80871a16f2d3828e2d0a7de0eec4a1dbd6922bbdd71ac2e5ac0dfa41bf4",
                "bc6f9552456006d89038b6d1c347ba02590e663ab9f65e5a129f654d272cb4b225853"
                        + "37df92ef005fda7da2b86c04155db1eb66d6daa5611eaf6e60c03c859b9",
                "7298bbe4a960ad987685f056dcc5fffe855bb903c61de9fb73f305a875035d88a06ca"
                        + "d10239af89f0d993ff5a1dbbfa9fdf18453be23a25a43474948dfa877d7",
                "9de0ab4a241d6de77efe158a69d2caef41c11224e7b7f82426b7ba231bd02ef31f184"
                        + "72220636e48f708872c1ce8c05c53a2c47731d332ee43d7866ca01b26cf" };

        for (int i = 0; i < dataVector.length; i++) {
            Sha512 sha = new Sha512();

            byte[] data = Util.h2b(dataVector[i]);
            byte[] expected = Util.h2b(hashVector[i]);

            sha.update(data);
            byte[] result = sha.digest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    public void releaseAndReInitObject() {

        Sha512 sha = new Sha512();
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] expected = Util.h2b("B7B70A0B14D7FA213C6CCD3CBFFC8BB8" +
                                   "F8E11A85F1113B0EB26A00208F2B9B3A" +
                                   "1DD4AAF39962861E16AB062274342A1C" +
                                   "E1F9DBA3654F36FC338245589F296C28");
        byte[] result = null;

        sha.update(data);
        result = sha.digest();
        assertArrayEquals(expected, result);
        sha.releaseNativeStruct();

        /* test re-initializing object */
        sha = new Sha512();
        result = null;
        sha.update(data);
        result = sha.digest();
        sha.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {

        Sha512 sha = new Sha512();
        byte[] data  = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] data2 = new byte[] { 0x05, 0x06, 0x07, 0x08, 0x09 };
        byte[] expected = Util.h2b("B7B70A0B14D7FA213C6CCD3CBFFC8BB8" +
                                   "F8E11A85F1113B0EB26A00208F2B9B3A" +
                                   "1DD4AAF39962861E16AB062274342A1C" +
                                   "E1F9DBA3654F36FC338245589F296C28");
        byte[] expected2 = Util.h2b("5D42B9D10118B3410DF5F36AEDE79C1C" +
                                    "67F465CD95AF05D69D91CBDB7606E21A" +
                                    "D8618E64380DEA45741D9D4AA3D42106" +
                                    "EC5513BC01C61A14E5B027D05EB0CC56");
        byte[] result = null;
        byte[] result2 = null;

        sha.update(data);
        result = sha.digest();
        assertArrayEquals(expected, result);

        /* test reusing existing object after a call to digest() */
        sha.update(data2);
        result2 = sha.digest();
        assertArrayEquals(expected2, result2);

        sha.releaseNativeStruct();
    }

    @Test
    public void copyObject() {

        Sha512 sha = null;
        Sha512 shaCopy = null;
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] expected = Util.h2b("B7B70A0B14D7FA213C6CCD3CBFFC8BB8" +
                                   "F8E11A85F1113B0EB26A00208F2B9B3A" +
                                   "1DD4AAF39962861E16AB062274342A1C" +
                                   "E1F9DBA3654F36FC338245589F296C28");
        byte[] result = null;
        byte[] result2 = null;

        sha = new Sha512();
        sha.update(data);

        /* test making copy of Sha512, should retain same state */
        shaCopy = (Sha512)sha.clone();

        result = sha.digest();
        result2 = shaCopy.digest();

        assertArrayEquals(expected, result);
        assertArrayEquals(expected, result2);

        sha.releaseNativeStruct();
        shaCopy.releaseNativeStruct();
    }

    @Test
    public void threadedHashTest() throws InterruptedException {

        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();
        final byte[] rand10kBuf = new byte[10240];

        /* fill large input buffer with random bytes */
        new Random().nextBytes(rand10kBuf);

        /* generate hash over input data concurrently across numThreads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    Sha512 sha = new Sha512();

                    /* process/update in 1024-byte chunks */
                    for (int j = 0; j < rand10kBuf.length; j+= 1024) {
                        sha.update(rand10kBuf, j, 1024);
                    }

                    /* get final hash */
                    byte[] hash = sha.digest();
                    results.add(hash.clone());

                    sha.releaseNativeStruct();
                    latch.countDown();
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<byte[]> listIterator = results.iterator();
        byte[] current = listIterator.next();
        while (listIterator.hasNext()) {
            byte[] next = listIterator.next();
            if (!Arrays.equals(current, next)) {
                fail("Found two non-identical digests in thread test");
            }
            if (listIterator.hasNext()) {
                current = listIterator.next();
            }
        }
    }
}
