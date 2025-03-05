/* wolfCryptRandomTest.java
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.Test;
import org.junit.BeforeClass;

import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.wolfcrypt.test.Util;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptRandomTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        System.out.println("JCE WolfCryptRandom Class");

        /* install wolfJCE provider at runtime, highest priority */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);
    }

    @Test
    public void testGetRandomFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        SecureRandom rand = null;

        /* HashDRBG */
        rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");
        assertNotNull(rand);

        /* DEFAULT */
        rand = SecureRandom.getInstance("DEFAULT", "wolfJCE");
        assertNotNull(rand);
    }

    @Test
    public void testNextBytes()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] valuesA = new byte[128];
        byte[] valuesB = new byte[128];

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");

        rand.nextBytes(valuesA);
        for (int i = 0; i < 10; i++) {
            rand.nextBytes(valuesB);

            if(Arrays.equals(valuesA, valuesB))
                fail("SecureRandom generated two equal consecutive arrays");

            valuesA = Arrays.copyOf(valuesB, valuesB.length);
        }
    }

    @Test
    public void testThreadedNextBytes()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

        int numThreads = 15;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();
        final SecureRandom rand = SecureRandom.getInstance(
                                        "HashDRBG", "wolfJCE");

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    byte[] tmp = new byte[16];

                    /* generate 1000 random arrays per thread */
                    for (int j = 0; j < 1000; j++) {
                        rand.nextBytes(tmp);
                        results.add(tmp.clone());
                    }
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
                fail("Found two identical random arrays in threaded test:\n" +
                     Util.b2h(current) + "\n" + Util.b2h(next));
            }
            if (listIterator.hasNext()) {
                current = listIterator.next();
            }
        }
    }

    @Test
    public void testGenerateSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] valuesA = new byte[128];
        byte[] valuesB = new byte[128];

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");

        valuesA = rand.generateSeed(valuesA.length);
        for (int i = 0; i < 10; i++) {
            valuesB = rand.generateSeed(valuesB.length);

            if(Arrays.equals(valuesA, valuesB))
                fail("SecureRandom generated two equal consecutive arrays");

            valuesA = Arrays.copyOf(valuesB, valuesB.length);
        }
    }

    @Test
    public void testThreadedGenerateSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

        int numThreads = 15;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();
        final SecureRandom rand = SecureRandom.getInstance(
                                        "HashDRBG", "wolfJCE");

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    byte[] tmp = new byte[16];

                    /* generate 1000 random arrays per thread */
                    for (int j = 0; j < 1000; j++) {
                        tmp = rand.generateSeed(tmp.length);
                        results.add(tmp.clone());
                    }
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
                fail("Found two identical random arrays in threaded test:\n" +
                     Util.b2h(current) + "\n" + Util.b2h(next));
            }
            if (listIterator.hasNext()) {
                current = listIterator.next();
            }
        }
    }

    @Test
    public void testGetSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] valuesA = new byte[128];
        byte[] valuesB = new byte[128];

        valuesA = SecureRandom.getSeed(valuesA.length);
        for (int i = 0; i < 10; i++) {
            valuesB = SecureRandom.getSeed(valuesB.length);

            if(Arrays.equals(valuesA, valuesB))
                fail("SecureRandom generated two equal consecutive arrays");

            valuesA = Arrays.copyOf(valuesB, valuesB.length);
        }
    }

    @Test
    public void testThreadedGetSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

        int numThreads = 15;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();

        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {
                    byte[] tmp = new byte[16];

                    /* generate 1000 random arrays per thread */
                    for (int j = 0; j < 1000; j++) {
                        tmp = SecureRandom.getSeed(tmp.length);
                        results.add(tmp.clone());
                    }
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
                fail("Found two identical random arrays in threaded test:\n" +
                     Util.b2h(current) + "\n" + Util.b2h(next));
            }
            if (listIterator.hasNext()) {
                current = listIterator.next();
            }
        }
    }

    @Test
    public void testSetSeed()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        long seed = 123456789;

        SecureRandom rand = SecureRandom.getInstance("HashDRBG", "wolfJCE");
        rand.setSeed(seed);
    }

}

