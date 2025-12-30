/* DhTest.java
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

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicIntegerArray;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class DhTest {
    private static Rng rng = new Rng();
    private final Object rngLock = new Rng();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUpRng() {
        rng.init();

        if (Fips.enabled) {
            Fips.setPrivateKeyReadEnable(1, Fips.WC_KEYTYPE_ALL);
        }
    }

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Dh();
            System.out.println("JNI Dh Class");
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("Dh test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void sharedSecretShouldMatch() {
        /* This test uses 1024-bit DH parameters. Some platforms (eg Android)
         * may have wolfSSL compiled with minimum key size requirements that
         * don't allow 1024-bit DH keys. Skip test if key size not supported. */
        byte[] p = Util.h2b("E6969D3D495BE32C7CF180C3BDD4798E91B7818251BB055E"
                + "2A2064904A79A770FA15A259CBD523A6A6EF09C43048D5A22F971F3C20"
                + "129B48000E6EDD061CBC053E371D794E5327DF611EBBBE1BAC9B5C6044"
                + "CF023D76E05EEA9BAD991B13A63C974E9EF1839EB5DB125136F7262E56"
                + "A8871538DFD823C6505085E21F0DD5C86B");

        byte[] g = Util.h2b("02");

        Dh alice = new Dh(p, g);
        Dh bob = new Dh();

        bob.setParams(p, g);

        assertNull(alice.getPublicKey());
        assertNull(bob.getPublicKey());

        try {
            synchronized (rngLock) {
                alice.makeKey(rng);
                bob.makeKey(rng);
            }
        } catch (WolfCryptException e) {
            if (e.getMessage() != null &&
                e.getMessage().contains("Key size error")) {
                /* Key size not supported on this platform, skip test */
                Assume.assumeTrue("DH key size not supported", false);
            }
            throw e;
        }

        assertNotNull(alice.getPublicKey());
        assertNotNull(bob.getPublicKey());

        byte[] sharedSecretA = alice.makeSharedSecret(bob);
        byte[] sharedSecretB = bob.makeSharedSecret(alice);

        assertNotNull(sharedSecretA);
        assertNotNull(sharedSecretB);
        assertArrayEquals(sharedSecretA, sharedSecretB);
    }

    @Test
    public void bufferOverflowRegressionTest() {
        /*
         * Regression test for heap buffer overflow in wc_DhAgree JNI wrapper.
         * The issue was that buffer allocation used pubSz instead of the
         * maximum possible DH secret size (mp_unsigned_bin_size(&key->p)).
         * This test uses a smaller public key with a larger DH group to
         * trigger the condition where the computed secret is larger than
         * the input public key size.
         */

        /* 2048-bit DH prime (256 bytes) */
        byte[] p = Util.h2b("E6969D3D495BE32C7CF180C3BDD4798E91B7818251BB055E"
                + "2A2064904A79A770FA15A259CBD523A6A6EF09C43048D5A22F971F3C20"
                + "129B48000E6EDD061CBC053E371D794E5327DF611EBBBE1BAC9B5C6044"
                + "CF023D76E05EEA9BAD991B13A63C974E9EF1839EB5DB125136F7262E56"
                + "A8871538DFD823C6505085E21F0DD5C86B");

        byte[] g = Util.h2b("02");

        /* Create Alice with full-size DH group */
        Dh alice = new Dh(p, g);
        try {
            synchronized (rngLock) {
                alice.makeKey(rng);
            }
        } catch (WolfCryptException e) {
            if (e.getMessage() != null &&
                e.getMessage().contains("Key size error")) {
                /* Key size not supported on this platform, skip test */
                Assume.assumeTrue("DH key size not supported", false);
            }
            throw e;
        }

        /* Create a deliberately small public key (127 bytes). This simulates
         * receiving a public key that is smaller than the maximum possible
         * secret size. */
        byte[] smallPubKey = new byte[127];
        /* Initialize with a valid but small public key value */
        smallPubKey[0] = 0x02; /* Make it a valid small value */
        for (int i = 1; i < smallPubKey.length; i++) {
            smallPubKey[i] = 0x00;
        }

        try {
            byte[] sharedSecret = alice.makeSharedSecret(smallPubKey);
            /* We don't verify the mathematical correctness here since this
             * is primarily a memory safety regression test. */
            assertNotNull("Shared secret should not be null", sharedSecret);
            assertTrue("Shared secret should not be empty",
                      sharedSecret.length > 0);
        } catch (WolfCryptException e) {
            /* Expected mathematical error (not a buffer overflow) */
        } finally {
            alice.releaseNativeStruct();
        }
    }

    @Test
    public void threadedDhSharedSecretTest() throws InterruptedException {

        final byte[] p = Util.h2b(
                "E6969D3D495BE32C7CF180C3BDD4798E91B7818251BB055E"
              + "2A2064904A79A770FA15A259CBD523A6A6EF09C43048D5A22F971F3C20"
              + "129B48000E6EDD061CBC053E371D794E5327DF611EBBBE1BAC9B5C6044"
              + "CF023D76E05EEA9BAD991B13A63C974E9EF1839EB5DB125136F7262E56"
              + "A8871538DFD823C6505085E21F0DD5C86B");
        final byte[] g = Util.h2b("02");

        /* Test if this key size is supported before starting threads.
         * Some platforms (eg Android) may have minimum key size requirements
         * that don't allow 1024-bit DH keys. */
        Dh testDh = new Dh(p, g);
        try {
            synchronized (rngLock) {
                testDh.makeKey(rng);
            }
        } catch (WolfCryptException e) {
            if (e.getMessage() != null &&
                e.getMessage().contains("Key size error")) {
                /* Key size not supported on this platform, skip test */
                testDh.releaseNativeStruct();
                Assume.assumeTrue("DH key size not supported", false);
            }
            testDh.releaseNativeStruct();
            throw e;
        }
        testDh.releaseNativeStruct();

        int numThreads = 10;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);

        /* Used to detect timeout of CountDownLatch, don't run indefinitely
         * if threads are stalled out or deadlocked */
        boolean returnWithoutTimeout = true;

        /* Keep track of failure and success count */
        final AtomicIntegerArray failures = new AtomicIntegerArray(1);
        final AtomicIntegerArray success = new AtomicIntegerArray(1);
        failures.set(0, 0);
        success.set(0, 0);

        /* make sure alice and bob shared secret generation matches when done
         * in parallel over numThreads threads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    Dh alice = null;
                    Dh bob = null;

                    try {
                        alice = new Dh(p, g);
                        bob = new Dh();

                        bob.setParams(p, g);

                        /* keys should be null before generation */
                        if (alice.getPublicKey() != null ||
                            bob.getPublicKey() != null) {
                            throw new Exception(
                                "keys not null before generation");
                        }

                        /* generate Dh keys */
                        synchronized (rngLock) {
                            alice.makeKey(rng);
                            bob.makeKey(rng);
                        }

                        /* keys should not be null after generation */
                        if (alice.getPublicKey() == null ||
                            bob.getPublicKey() == null) {
                            throw new Exception(
                                "keys null after generation");
                        }

                        byte[] sharedSecretA = alice.makeSharedSecret(bob);
                        byte[] sharedSecretB = bob.makeSharedSecret(alice);

                        if (sharedSecretA == null ||
                            sharedSecretB == null ||
                            !Arrays.equals(sharedSecretA, sharedSecretB)) {
                            throw new Exception(
                                "shared secrets null or not equal");
                        }

                        /* Log success */
                        success.incrementAndGet(0);

                    } catch (Exception e) {
                        e.printStackTrace();

                        /* Log failure */
                        failures.incrementAndGet(0);

                    } finally {
                        alice.releaseNativeStruct();
                        bob.releaseNativeStruct();
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        returnWithoutTimeout = latch.await(10, TimeUnit.SECONDS);
        service.shutdown();

        /* Check failure count and success count against thread count */
        if ((failures.get(0) != 0) ||
            (success.get(0) != numThreads)) {
            if (returnWithoutTimeout == true) {
                fail("DH shared secret test threading error: " +
                    failures.get(0) + " failures, " +
                    success.get(0) + " success, " +
                    numThreads + " num threads total");
            } else {
                fail("DH shared secret test error, threads timed out");
            }
        }
    }
}
