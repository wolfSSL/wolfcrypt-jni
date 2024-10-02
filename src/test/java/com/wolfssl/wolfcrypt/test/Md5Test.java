/* Md5Test.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

import com.wolfssl.wolfcrypt.Md5;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class Md5Test {
    private ByteBuffer data = ByteBuffer.allocateDirect(128);
    private ByteBuffer result = ByteBuffer.allocateDirect(Md5.DIGEST_SIZE);
    private ByteBuffer expected = ByteBuffer.allocateDirect(Md5.DIGEST_SIZE);

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void checkMd5IsAvailable() {
        try {
            Md5 md5 = new Md5();
            System.out.println("JNI Md5 Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("MD5 skipped: " + e.getError());
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void constructorShouldNotInitializeNativeStruct() {
        assertEquals(NativeStruct.NULL, new Md5().getNativeStruct());
    }

    @Test
    public void hashShouldMatchUsingByteBuffer() throws ShortBufferException {
        String[] dataVector = new String[] {
            "",
            "616263",
            "6D65737361676520646967657374",
            "6162636465666768696A6B6C6D6E6F707172737475767778797A",
            "4142434445464748494A4B4C4D4E4F505152535455565758595A" +
                "6162636465666768696A6B6C6D6E6F707172737475767778" +
                "797A30313233343536373839",
            "3132333435363738393031323334353637383930313233343536" +
                "373839303132333435363738393031323334353637383930" +
                "313233343536373839303132333435363738393031323334" +
                "353637383930"
        };
        String[] hashVector = new String[] {
            "d41d8cd98f00b204e9800998ecf8427e",
            "900150983cd24fb0d6963f7d28e17f72",
            "f96b697d7cb7938d525a2f31aaf161d0",
            "c3fcd3d76192e4007dfb496cca67e13b",
            "d174ab98d277d9f5a5611c2c9f419d9f",
            "57edf4a22be3c955ac49da2e2107b67a"
        };

        for (int i = 0; i < dataVector.length; i++) {
            Md5 md5 = new Md5();

            data.put(Util.h2b(dataVector[i])).rewind();
            expected.put(Util.h2b(hashVector[i])).rewind();

            md5.update(data, dataVector[i].length() / 2);
            md5.digest(result);
            data.rewind();
            result.rewind();

            assertEquals(expected, result);
        }
    }

    @Test
    public void hashShouldMatchUsingByteArray() {
        String[] dataVector = new String[] {
            "",
            "616263",
            "6D65737361676520646967657374",
            "6162636465666768696A6B6C6D6E6F707172737475767778797A",
            "4142434445464748494A4B4C4D4E4F505152535455565758595A" +
                "6162636465666768696A6B6C6D6E6F707172737475767778" +
                "797A30313233343536373839",
            "3132333435363738393031323334353637383930313233343536" +
                "373839303132333435363738393031323334353637383930" +
                "313233343536373839303132333435363738393031323334" +
                "353637383930"
        };
        String[] hashVector = new String[] {
            "d41d8cd98f00b204e9800998ecf8427e",
            "900150983cd24fb0d6963f7d28e17f72",
            "f96b697d7cb7938d525a2f31aaf161d0",
            "c3fcd3d76192e4007dfb496cca67e13b",
            "d174ab98d277d9f5a5611c2c9f419d9f",
            "57edf4a22be3c955ac49da2e2107b67a"
        };

        for (int i = 0; i < dataVector.length; i++) {
            Md5 md5 = new Md5();

            byte[] data = Util.h2b(dataVector[i]);
            byte[] expected = Util.h2b(hashVector[i]);

            md5.update(data);
            byte[] result = md5.digest();

            assertArrayEquals(expected, result);
        }
    }

    @Test
    public void releaseAndReInitObject() {

        Md5 md5 = new Md5();
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] expected = Util.h2b("D05374DC381D9B52806446A71C8E79B1");
        byte[] result = null;

        md5.update(data);
        result = md5.digest();
        assertArrayEquals(expected, result);
        md5.releaseNativeStruct();

        /* test re-initializing object */
        md5 = new Md5();
        result = null;
        md5.update(data);
        result = md5.digest();
        md5.releaseNativeStruct();
    }

    @Test
    public void reuseObject() {

        Md5 md5 = new Md5();
        byte[] data  = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] data2 = new byte[] { 0x05, 0x06, 0x07, 0x08, 0x09 };
        byte[] expected = Util.h2b("D05374DC381D9B52806446A71C8E79B1");
        byte[] expected2 = Util.h2b("AAB3A52AB69EC2B75102EF3A7059EAC2");
        byte[] result = null;
        byte[] result2 = null;

        md5.update(data);
        result = md5.digest();
        assertArrayEquals(expected, result);

        /* test reusing existing object after a call to digest() */
        md5.update(data2);
        result2 = md5.digest();
        assertArrayEquals(expected2, result2);

        md5.releaseNativeStruct();
    }

    @Test
    public void copyObject() {

        Md5 md5 = null;
        Md5 md5Copy = null;
        byte[] data = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04 };
        byte[] expected = Util.h2b("D05374DC381D9B52806446A71C8E79B1");
        byte[] result = null;
        byte[] result2 = null;

        md5 = new Md5();
        md5.update(data);

        /* test making copy of Md5, should retain same state */
        md5Copy = (Md5)md5.clone();

        result = md5.digest();
        result2 = md5Copy.digest();

        assertArrayEquals(expected, result);
        assertArrayEquals(expected, result2);

        md5.releaseNativeStruct();
        md5Copy.releaseNativeStruct();
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
                    Md5 md5 = new Md5();

                    /* process/update in 1024-byte chunks */
                    for (int j = 0; j < rand10kBuf.length; j+= 1024) {
                        md5.update(rand10kBuf, j, 1024);
                    }

                    /* get final hash */
                    byte[] hash = md5.digest();
                    results.add(hash.clone());

                    md5.releaseNativeStruct();
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

