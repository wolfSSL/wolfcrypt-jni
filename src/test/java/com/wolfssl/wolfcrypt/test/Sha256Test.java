/* Sha256Test.java
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

import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.WolfCryptError;

public class Sha256Test {
    private ByteBuffer data = ByteBuffer.allocateDirect(32);
    private ByteBuffer result = ByteBuffer.allocateDirect(Sha256.DIGEST_SIZE);
    private ByteBuffer expected = ByteBuffer.allocateDirect(Sha256.DIGEST_SIZE);

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void checkSha256IsAvailable() {
        try {
            Sha256 sha = new Sha256();
            System.out.println("JNI Sha256 Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("Sha256Test skipped: " + e.getError());
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new Sha256().getNativeStruct());
    }

    @Test
    public void hashShouldMatchUsingByteBuffer() throws ShortBufferException {
        String[] dataVector = new String[] {
                "",
                "8bf43fbc59b1cefb",
                "68596a39b6b1dbbce92983d0c87811f9",
                "695f0bcfd8b1799a7519c182c55baaffe66a664ac5d06ad7",
                "b9c325ed83e582d315a03d191d3a99c5178d1a1dc4aa9669d8c28ffaf347c06b" };
        String[] hashVector = new String[] {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "47291036995e041cd53d640190002ab9b56fec8faf647a8df3b278fe445ab05e",
                "041f246778af35809a4e8d06d41ba3e3c73f54050149d13e821e5ca45178e88b",
                "afa01304f7356d5d946304c7aef0c5190716eeacee6a837edd431906aa50e5ec",
                "731cf20719a0838dc15a33293ad977855bd28f5d2c768e7c0b632bf65d6c84e0" };

        for (int i = 0; i < dataVector.length; i++) {
            Sha256 sha = new Sha256();

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
        String[] dataVector = new String[] { "", "8bf43fbc59b1cefb",
                "68596a39b6b1dbbce92983d0c87811f9",
                "695f0bcfd8b1799a7519c182c55baaffe66a664ac5d06ad7",
                "b9c325ed83e582d315a03d191d3a99c5178d1a1dc4aa9669d8c28ffaf347c06b" };
        String[] hashVector = new String[] {
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "47291036995e041cd53d640190002ab9b56fec8faf647a8df3b278fe445ab05e",
                "041f246778af35809a4e8d06d41ba3e3c73f54050149d13e821e5ca45178e88b",
                "afa01304f7356d5d946304c7aef0c5190716eeacee6a837edd431906aa50e5ec",
                "731cf20719a0838dc15a33293ad977855bd28f5d2c768e7c0b632bf65d6c84e0" };

        for (int i = 0; i < dataVector.length; i++) {
            Sha256 sha = new Sha256();

            byte[] data = Util.h2b(dataVector[i]);
            byte[] expected = Util.h2b(hashVector[i]);

            sha.update(data);
            byte[] result = sha.digest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    public void releaseAndReInitObject() {

        Sha256 sha = new Sha256();
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] expected = Util.h2b("08BB5E5D6EAAC1049EDE0893D30ED022" +
                                   "B1A4D9B5B48DB414871F51C9CB35283D");
        byte[] result = null;

        sha.update(data);
        result = sha.digest();
        assertArrayEquals(expected, result);
        sha.releaseNativeStruct();

        /* test re-initializing object */
        sha = new Sha256();
        result = null;
        sha.update(data);
        result = sha.digest();
        sha.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {

        Sha256 sha = new Sha256();
        byte[] data  = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] data2 = new byte[] { 0x05, 0x06, 0x07, 0x08, 0x09 };
        byte[] expected = Util.h2b("08BB5E5D6EAAC1049EDE0893D30ED022" +
                                   "B1A4D9B5B48DB414871F51C9CB35283D");
        byte[] expected2 = Util.h2b("761CA8FD7DD51248E00A7DC1C746BBDE" +
                                    "94E51CB06AA67194843C495A863E0106");
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

        Sha256 sha = null;
        Sha256 shaCopy = null;
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] expected = Util.h2b("08BB5E5D6EAAC1049EDE0893D30ED022" +
                                   "B1A4D9B5B48DB414871F51C9CB35283D");
        byte[] result = null;
        byte[] result2 = null;

        sha = new Sha256();
        sha.update(data);

        /* test making copy of Sha256, should retain same state */
        shaCopy = (Sha256)sha.clone();

        result = sha.digest();
        result2 = shaCopy.digest();

        assertArrayEquals(expected, result);
        assertArrayEquals(expected, result2);

        sha.releaseNativeStruct();
        shaCopy.releaseNativeStruct();
    }

    @Test
    public void threadedHashTest() throws InterruptedException {

        int numThreads = 100;
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
                    Sha256 sha = new Sha256();

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

