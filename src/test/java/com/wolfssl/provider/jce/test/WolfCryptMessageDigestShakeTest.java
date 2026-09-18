/* WolfCryptMessageDigestShakeTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
import org.junit.Test;
import org.junit.Assume;
import org.junit.BeforeClass;

import java.util.Random;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.LinkedBlockingQueue;

import java.security.Security;
import java.security.Provider;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

public class WolfCryptMessageDigestShakeTest {

    /* SHAKE128("abc"), 32-byte output (JCE "SHAKE128-256") */
    private static final String SHAKE128_ABC =
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8";

    /* SHAKE128(""), 32-byte output */
    private static final String SHAKE128_EMPTY =
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";

    /* SHAKE256("abc"), 64-byte output (JCE "SHAKE256-512") */
    private static final String SHAKE256_ABC =
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";

    /* SHAKE256(""), 64-byte output */
    private static final String SHAKE256_EMPTY =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";

    @Rule(order = Integer.MIN_VALUE)
    public TestRule watcher = TimedTestWatcher.create();

    private static boolean shakeEnabled = false;

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptMessageDigestShake Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        shakeEnabled = FeatureDetect.Shake128Enabled() ||
            FeatureDetect.Shake256Enabled();
        if (!shakeEnabled) {
            System.out.println("wolfJCE SHAKE Test skipped");
        }
    }

    /* Tests pinned to one variant have their own Assume guards */
    private void assumeEnabled() {
        Assume.assumeTrue("SHAKE not compiled in", shakeEnabled);
    }

    @Test
    public void testShake128SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Assume.assumeTrue(FeatureDetect.Shake128Enabled());

        MessageDigest shake =
            MessageDigest.getInstance("SHAKE128-256", "wolfJCE");

        shake.update("abc".getBytes());
        byte[] output = shake.digest();

        assertEquals(32, output.length);
        assertArrayEquals(Util.h2b(SHAKE128_ABC), output);
    }

    @Test
    public void testShake256SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        MessageDigest shake =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");

        shake.update("abc".getBytes());
        byte[] output = shake.digest();

        assertEquals(64, output.length);
        assertArrayEquals(Util.h2b(SHAKE256_ABC), output);
    }

    @Test
    public void testShakeAliases()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        assumeEnabled();

        /* Short-name and OID aliases must resolve to the same digests */
        if (FeatureDetect.Shake128Enabled()) {
            String[] aliases = new String[] {
                "SHAKE128",
                "2.16.840.1.101.3.4.2.11",
                "OID.2.16.840.1.101.3.4.2.11"
            };

            for (String alias : aliases) {
                MessageDigest shake =
                    MessageDigest.getInstance(alias, "wolfJCE");
                shake.update("abc".getBytes());
                assertArrayEquals("alias: " + alias,
                    Util.h2b(SHAKE128_ABC), shake.digest());
            }
        }

        if (FeatureDetect.Shake256Enabled()) {
            String[] aliases = new String[] {
                "SHAKE256",
                "2.16.840.1.101.3.4.2.12",
                "OID.2.16.840.1.101.3.4.2.12"
            };

            for (String alias : aliases) {
                MessageDigest shake =
                    MessageDigest.getInstance(alias, "wolfJCE");
                shake.update("abc".getBytes());
                assertArrayEquals("alias: " + alias,
                    Util.h2b(SHAKE256_ABC), shake.digest());
            }
        }
    }

    @Test
    public void testShakeGetDigestLength()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        assumeEnabled();

        if (FeatureDetect.Shake128Enabled()) {
            MessageDigest shake128 =
                MessageDigest.getInstance("SHAKE128-256", "wolfJCE");
            assertEquals(32, shake128.getDigestLength());

            MessageDigest alias128 =
                MessageDigest.getInstance("SHAKE128", "wolfJCE");
            assertEquals(32, alias128.getDigestLength());
        }

        if (FeatureDetect.Shake256Enabled()) {
            MessageDigest shake256 =
                MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
            assertEquals(64, shake256.getDigestLength());

            MessageDigest alias256 =
                MessageDigest.getInstance("SHAKE256", "wolfJCE");
            assertEquals(64, alias256.getDigestLength());
        }
    }

    @Test
    public void testShakeReset()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        MessageDigest shake =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");

        shake.update("unrelated data".getBytes());
        shake.reset();

        shake.update("abc".getBytes());
        assertArrayEquals(Util.h2b(SHAKE256_ABC), shake.digest());
    }

    @Test
    public void testShakeClone()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               CloneNotSupportedException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        byte[] inArray = "abc".getBytes();

        MessageDigest shake =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            shake.update(inArray[i]);
        }

        /* Try to clone existing MessageDigest, should copy over state */
        MessageDigest shakeCopy = (MessageDigest)shake.clone();

        byte[] output = shake.digest();
        byte[] output2 = shakeCopy.digest();

        assertArrayEquals(Util.h2b(SHAKE256_ABC), output);
        assertArrayEquals(Util.h2b(SHAKE256_ABC), output2);
    }

    @Test
    public void testShakeEmptyInput()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        assumeEnabled();

        if (FeatureDetect.Shake128Enabled()) {
            MessageDigest shake =
                MessageDigest.getInstance("SHAKE128-256", "wolfJCE");
            assertArrayEquals(Util.h2b(SHAKE128_EMPTY), shake.digest());
        }

        if (FeatureDetect.Shake256Enabled()) {
            MessageDigest shake =
                MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
            assertArrayEquals(Util.h2b(SHAKE256_EMPTY), shake.digest());
        }
    }

    @Test
    public void testShakeByteByByteUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Assume.assumeTrue(FeatureDetect.Shake128Enabled());

        byte[] input = "abc".getBytes();

        MessageDigest shake =
            MessageDigest.getInstance("SHAKE128-256", "wolfJCE");

        for (int i = 0; i < input.length; i++) {
            shake.update(input[i]);
        }

        assertArrayEquals(Util.h2b(SHAKE128_ABC), shake.digest());
    }

    @Test
    public void testShakeDigestAfterDigest()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        MessageDigest shake =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
        shake.update((byte)0x00);
        shake.digest();

        /* Digest again without update, should return empty input answer */
        assertArrayEquals(Util.h2b(SHAKE256_EMPTY), shake.digest());
    }

    @Test
    public void testShakeUpdateAfterDigest()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        MessageDigest shake =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
        shake.update("abc".getBytes());
        shake.digest();

        /* Try to update after digest, should implicitly reset */
        shake.update("abc".getBytes());
        assertArrayEquals(Util.h2b(SHAKE256_ABC), shake.digest());
    }

    @Test
    public void testShakeLargeInput()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        /* Chunked updates must match a one-shot digest */
        byte[] largeInput = new byte[1024 * 1024];
        new Random().nextBytes(largeInput);

        MessageDigest chunked =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
        for (int i = 0; i < largeInput.length; i += 4096) {
            chunked.update(largeInput, i, 4096);
        }
        byte[] chunkedOut = chunked.digest();

        MessageDigest oneShot =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
        byte[] oneShotOut = oneShot.digest(largeInput);

        assertArrayEquals(chunkedOut, oneShotOut);
    }

    @Test
    public void testShakeDomainSeparation()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Different FIPS 202 domain separation, outputs must differ */
        Assume.assumeTrue(FeatureDetect.Sha3Enabled());
        Assume.assumeTrue(FeatureDetect.Shake128Enabled());
        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        byte[] input = "domain separation".getBytes();

        MessageDigest shake128 =
            MessageDigest.getInstance("SHAKE128-256", "wolfJCE");
        MessageDigest shake256 =
            MessageDigest.getInstance("SHAKE256-512", "wolfJCE");
        MessageDigest sha3_256 =
            MessageDigest.getInstance("SHA3-256", "wolfJCE");

        byte[] out128 = shake128.digest(input);
        byte[] out256 = shake256.digest(input);
        byte[] outSha3 = sha3_256.digest(input);

        assertFalse(Arrays.equals(out128,
            Arrays.copyOf(out256, out128.length)));
        assertFalse(Arrays.equals(out128, outSha3));
        assertFalse(Arrays.equals(outSha3,
            Arrays.copyOf(out256, outSha3.length)));
    }

    @Test
    public void testShakeThreaded()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

        Assume.assumeTrue(FeatureDetect.Shake256Enabled());

        /* Use fewer threads in CI environments to avoid resource limits */
        int numThreads = System.getenv("CI") != null ? 20 : 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();
        final LinkedBlockingQueue<String> errors =
            new LinkedBlockingQueue<>();
        final byte[] rand10kBuf = new byte[10240];

        /* Fill large input buffer with random bytes */
        new Random().nextBytes(rand10kBuf);

        /* Generate hash over input data concurrently across numThreads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    try {
                        MessageDigest shake = null;

                        try {
                            shake = MessageDigest.getInstance(
                                "SHAKE256-512", "wolfJCE");
                        } catch (NoSuchAlgorithmException |
                                 NoSuchProviderException e) {
                            errors.add(e.toString());
                            return;
                        }

                        /* Process/update in 1024-byte chunks */
                        for (int j = 0; j < rand10kBuf.length; j+= 1024) {
                            shake.update(rand10kBuf, j, 1024);
                        }

                        /* Get final hash */
                        byte[] hash = shake.digest();
                        results.add(hash.clone());

                    } catch (Exception e) {
                        errors.add(e.toString());
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        /* Wait for all threads to complete */
        assertTrue("timed out waiting for threads to finish",
            latch.await(120, TimeUnit.SECONDS));
        service.shutdown();

        /* a failed worker must fail the test, not blend in */
        assertTrue("worker errors: " + errors, errors.isEmpty());
        assertEquals(numThreads, results.size());

        /* Compare all digests, all should be the same across threads */
        Iterator<byte[]> listIterator = results.iterator();
        byte[] current = listIterator.next();
        while (listIterator.hasNext()) {
            byte[] next = listIterator.next();
            if (!Arrays.equals(current, next)) {
                fail("Found two non-identical digests in thread test");
            }
            current = next;
        }
    }

    @Test
    public void testShakeInterop()
        throws NoSuchProviderException, NoSuchAlgorithmException {
        assumeEnabled();

        String input = "Bozeman, MT";
        String input2 = "wolfSSL is an Open Source Internet security " +
                       "company, focused primarily on SSL/TLS and " +
                       "cryptography. Main products include the wolfSSL " +
                       "embedded SSL/TLS library, wolfCrypt cryptography " +
                       "library, wolfMQTT, and wolfSSH. Products are " +
                       "dual licensed under both GPLv3 and a commercial" +
                       "license.";

        String[] algos = new String[] { "SHAKE128-256", "SHAKE256-512" };

        for (String algo : algos) {
            if (algo.equals("SHAKE128-256") &&
                !FeatureDetect.Shake128Enabled()) {
                continue;
            }
            if (algo.equals("SHAKE256-512") &&
                !FeatureDetect.Shake256Enabled()) {
                continue;
            }

            byte[] wolfOutput;
            byte[] interopOutput;

            /* Get SUN SHAKE implementation, available JDK 25+ */
            MessageDigest sunShake = null;
            try {
                sunShake = MessageDigest.getInstance(algo, "SUN");
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                /* Skip if SUN SHAKE not available (JDK < 25) */
                continue;
            }

            MessageDigest wolfShake =
                MessageDigest.getInstance(algo, "wolfJCE");

            /* short message */
            sunShake.update(input.getBytes());
            interopOutput = sunShake.digest();

            wolfShake.update(input.getBytes());
            wolfOutput = wolfShake.digest();

            assertArrayEquals(wolfOutput, interopOutput);

            /* long message */
            sunShake.update(input2.getBytes());
            interopOutput = sunShake.digest();

            wolfShake.update(input2.getBytes());
            wolfOutput = wolfShake.digest();

            assertArrayEquals(wolfOutput, interopOutput);
        }
    }
}
