/* RngTest.java
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

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import java.util.Arrays;
import java.util.Iterator;
import java.nio.ByteBuffer;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class RngTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void setupClass() {
        System.out.println("JNI Rng Class");
    }

    @Test
    public void constructorShouldInitializeNativeStruct() {
        assertNotEquals(NativeStruct.NULL, new Rng().getNativeStruct());
    }

    @Test
    public void testInitFree() {
        Rng wcRng = new Rng();
        assertNotNull(wcRng);
        wcRng.init();
        wcRng.free();

        /* double init should be ok */
        wcRng.init();
        wcRng.init();

        /* double free should be ok */
        wcRng.free();
        wcRng.free();
    }

    @Test
    public void testGenerateBlockByteBuffer() {
        ByteBuffer tmpBlockA = ByteBuffer.allocateDirect(32);
        ByteBuffer tmpBlockB = ByteBuffer.allocateDirect(32);
        ByteBuffer nonDirect = ByteBuffer.allocate(32);
        byte[] tmpA = new byte[32];
        byte[] tmpB = new byte[32];
        Rng wcRng = new Rng();

        assertNotNull(tmpBlockA);
        assertNotNull(tmpBlockB);
        assertNotNull(wcRng);

        wcRng.init();

        wcRng.generateBlock(tmpBlockA);
        wcRng.generateBlock(tmpBlockB);

        /* Should get exception if input ByteBuffer is not direct */
        try {
            wcRng.generateBlock(nonDirect);
            fail("Rng.generateBlock should fail if ByteBuffer is not direct");
        } catch (WolfCryptException e) {
            /* expected */
        }

        assertEquals(tmpBlockA.position(), 32);
        assertEquals(tmpBlockB.position(), 32);
        assertEquals(tmpBlockA.remaining(), 0);
        assertEquals(tmpBlockA.remaining(), 0);

        tmpBlockA.flip();
        tmpBlockB.flip();

        tmpBlockA.get(tmpA);
        tmpBlockB.get(tmpB);

        assertNotNull(tmpA);
        assertNotNull(tmpB);

        assertFalse(Arrays.equals(tmpA, tmpB));

        wcRng.free();
    }

    @Test
    public void testGenerateBlockByteArrayOffsetLength() {
        byte[] tmpBlockA = new byte[32];
        byte[] tmpBlockB = new byte[32];

        Rng wcRng = new Rng();

        wcRng.init();

        /* generate two arrays of size 30 using offset and length */
        wcRng.generateBlock(tmpBlockA, 0, 30);
        wcRng.generateBlock(tmpBlockB, 0, 30);

        /* make sure two arrays are not equal */
        assertFalse(Arrays.equals(tmpBlockA, tmpBlockB));

        wcRng.free();
    }

    @Test
    public void testGenerateBlockByteArray() {
        byte[] tmpBlockA = new byte[32];
        byte[] tmpBlockB = new byte[32];

        Rng wcRng = new Rng();

        wcRng.init();

        /* fill arrays with random data, up to buffer.length */
        wcRng.generateBlock(tmpBlockA);
        wcRng.generateBlock(tmpBlockB);

        /* make sure two arrays are not equal */
        assertFalse(Arrays.equals(tmpBlockA, tmpBlockB));

        wcRng.free();
    }

    @Test
    public void testGenerateBlockReturnArray() {
        byte[] tmpBlockA = null;
        byte[] tmpBlockB = null;

        Rng wcRng = new Rng();

        wcRng.init();

        /* generate two arrays of data */
        tmpBlockA = wcRng.generateBlock(32);
        tmpBlockB = wcRng.generateBlock(32);

        assertNotNull(tmpBlockA);
        assertNotNull(tmpBlockB);

        assertEquals(tmpBlockA.length, 32);
        assertEquals(tmpBlockB.length, 32);

        /* make sure two arrays are not equal */
        assertFalse(Arrays.equals(tmpBlockA, tmpBlockB));

        wcRng.free();
    }

    @Test
    public void testThreadedUse() throws InterruptedException {
        int numThreads = 15;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    Rng wcRng = new Rng();
                    byte[] tmp = new byte[16];
                    wcRng.init();
                    /* generate 1000 random 16-byte arrays per thread */
                    for (int j = 0; j < 1000; j++) {
                        wcRng.generateBlock(tmp);
                        results.add(tmp.clone());
                    }
                    wcRng.free();
                    latch.countDown();
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        Iterator<byte[]> listIterator = results.iterator();
        byte[] current = listIterator.next();
        while (listIterator.hasNext()) {
            byte[] next = listIterator.next();
            if (Arrays.equals(current, next)) {
                fail("Found two identical random arrays in threading test:\n" +
                     Util.b2h(current) + "\n" + Util.b2h(next));
            }
            if (listIterator.hasNext()) {
                current = listIterator.next();
            }
        }
    }
}

