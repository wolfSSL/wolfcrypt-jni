/* wolfCryptMessageDigestSha512Test.java
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
import org.junit.Assume;
import org.junit.BeforeClass;

import java.util.Random;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;

import java.security.Security;
import java.security.Provider;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;

import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;

public class WolfCryptMessageDigestSha512Test {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptMessageDigestSha512 Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512",
                                                             "wolfJCE");
            assertNotNull(sha512);

        } catch (NoSuchAlgorithmException e) {
            /* if we also detect algo is compiled out, skip tests */
            if (FeatureDetect.Sha512Enabled() == false) {
                System.out.println("JSSE SHA-512 Test skipped");
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testSha512SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            new DigestVector(
                new String("abc").getBytes(),
                new byte[] {
                    (byte)0xdd, (byte)0xaf, (byte)0x35, (byte)0xa1,
                    (byte)0x93, (byte)0x61, (byte)0x7a, (byte)0xba,
                    (byte)0xcc, (byte)0x41, (byte)0x73, (byte)0x49,
                    (byte)0xae, (byte)0x20, (byte)0x41, (byte)0x31,
                    (byte)0x12, (byte)0xe6, (byte)0xfa, (byte)0x4e,
                    (byte)0x89, (byte)0xa9, (byte)0x7e, (byte)0xa2,
                    (byte)0x0a, (byte)0x9e, (byte)0xee, (byte)0xe6,
                    (byte)0x4b, (byte)0x55, (byte)0xd3, (byte)0x9a,
                    (byte)0x21, (byte)0x92, (byte)0x99, (byte)0x2a,
                    (byte)0x27, (byte)0x4f, (byte)0xc1, (byte)0xa8,
                    (byte)0x36, (byte)0xba, (byte)0x3c, (byte)0x23,
                    (byte)0xa3, (byte)0xfe, (byte)0xeb, (byte)0xbd,
                    (byte)0x45, (byte)0x4d, (byte)0x44, (byte)0x23,
                    (byte)0x64, (byte)0x3c, (byte)0xe8, (byte)0x0e,
                    (byte)0x2a, (byte)0x9a, (byte)0xc9, (byte)0x4f,
                    (byte)0xa5, (byte)0x4c, (byte)0xa4, (byte)0x9f
                }
            ),
            new DigestVector(
                new String("abcdefghbcdefghicdefghijdefghijkefgh" +
                           "ijklfghijklmghijklmnhijklmnoijklmnop" +
                           "jklmnopqklmnopqrlmnopqrsmnopqrstnopq" +
                           "rstu").getBytes(),
                new byte[] {
                    (byte)0x8e, (byte)0x95, (byte)0x9b, (byte)0x75,
                    (byte)0xda, (byte)0xe3, (byte)0x13, (byte)0xda,
                    (byte)0x8c, (byte)0xf4, (byte)0xf7, (byte)0x28,
                    (byte)0x14, (byte)0xfc, (byte)0x14, (byte)0x3f,
                    (byte)0x8f, (byte)0x77, (byte)0x79, (byte)0xc6,
                    (byte)0xeb, (byte)0x9f, (byte)0x7f, (byte)0xa1,
                    (byte)0x72, (byte)0x99, (byte)0xae, (byte)0xad,
                    (byte)0xb6, (byte)0x88, (byte)0x90, (byte)0x18,
                    (byte)0x50, (byte)0x1d, (byte)0x28, (byte)0x9e,
                    (byte)0x49, (byte)0x00, (byte)0xf7, (byte)0xe4,
                    (byte)0x33, (byte)0x1b, (byte)0x99, (byte)0xde,
                    (byte)0xc4, (byte)0xb5, (byte)0x43, (byte)0x3a,
                    (byte)0xc7, (byte)0xd3, (byte)0x29, (byte)0xee,
                    (byte)0xb6, (byte)0xdd, (byte)0x26, (byte)0x54,
                    (byte)0x5e, (byte)0x96, (byte)0xe5, (byte)0x5b,
                    (byte)0x87, (byte)0x4b, (byte)0xe9, (byte)0x09
                }
            )
        };

        byte[] output;

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha512.update(vectors[i].getInput());
            output = sha512.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha512SingleByteUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x2c, (byte)0x74, (byte)0xfd, (byte)0x17,
            (byte)0xed, (byte)0xaf, (byte)0xd8, (byte)0x0e,
            (byte)0x84, (byte)0x47, (byte)0xb0, (byte)0xd4,
            (byte)0x67, (byte)0x41, (byte)0xee, (byte)0x24,
            (byte)0x3b, (byte)0x7e, (byte)0xb7, (byte)0x4d,
            (byte)0xd2, (byte)0x14, (byte)0x9a, (byte)0x0a,
            (byte)0xb1, (byte)0xb9, (byte)0x24, (byte)0x6f,
            (byte)0xb3, (byte)0x03, (byte)0x82, (byte)0xf2,
            (byte)0x7e, (byte)0x85, (byte)0x3d, (byte)0x85,
            (byte)0x85, (byte)0x71, (byte)0x9e, (byte)0x0e,
            (byte)0x67, (byte)0xcb, (byte)0xda, (byte)0x0d,
            (byte)0xaa, (byte)0x8f, (byte)0x51, (byte)0x67,
            (byte)0x10, (byte)0x64, (byte)0x61, (byte)0x5d,
            (byte)0x64, (byte)0x5a, (byte)0xe2, (byte)0x7a,
            (byte)0xcb, (byte)0x15, (byte)0xbf, (byte)0xb1,
            (byte)0x44, (byte)0x7f, (byte)0x45, (byte)0x9b
        };

        byte[] output;

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha512.update(inArray[i]);
        }
        output = sha512.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testSha512Reset()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x2c, (byte)0x74, (byte)0xfd, (byte)0x17,
            (byte)0xed, (byte)0xaf, (byte)0xd8, (byte)0x0e,
            (byte)0x84, (byte)0x47, (byte)0xb0, (byte)0xd4,
            (byte)0x67, (byte)0x41, (byte)0xee, (byte)0x24,
            (byte)0x3b, (byte)0x7e, (byte)0xb7, (byte)0x4d,
            (byte)0xd2, (byte)0x14, (byte)0x9a, (byte)0x0a,
            (byte)0xb1, (byte)0xb9, (byte)0x24, (byte)0x6f,
            (byte)0xb3, (byte)0x03, (byte)0x82, (byte)0xf2,
            (byte)0x7e, (byte)0x85, (byte)0x3d, (byte)0x85,
            (byte)0x85, (byte)0x71, (byte)0x9e, (byte)0x0e,
            (byte)0x67, (byte)0xcb, (byte)0xda, (byte)0x0d,
            (byte)0xaa, (byte)0x8f, (byte)0x51, (byte)0x67,
            (byte)0x10, (byte)0x64, (byte)0x61, (byte)0x5d,
            (byte)0x64, (byte)0x5a, (byte)0xe2, (byte)0x7a,
            (byte)0xcb, (byte)0x15, (byte)0xbf, (byte)0xb1,
            (byte)0x44, (byte)0x7f, (byte)0x45, (byte)0x9b
        };

        byte[] output;

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha512.update(inArray[i]);
        }

        sha512.reset();

        for (int i = 0; i < inArray.length; i++) {
            sha512.update(inArray[i]);
        }
        output = sha512.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testSha512Clone()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               CloneNotSupportedException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x2c, (byte)0x74, (byte)0xfd, (byte)0x17,
            (byte)0xed, (byte)0xaf, (byte)0xd8, (byte)0x0e,
            (byte)0x84, (byte)0x47, (byte)0xb0, (byte)0xd4,
            (byte)0x67, (byte)0x41, (byte)0xee, (byte)0x24,
            (byte)0x3b, (byte)0x7e, (byte)0xb7, (byte)0x4d,
            (byte)0xd2, (byte)0x14, (byte)0x9a, (byte)0x0a,
            (byte)0xb1, (byte)0xb9, (byte)0x24, (byte)0x6f,
            (byte)0xb3, (byte)0x03, (byte)0x82, (byte)0xf2,
            (byte)0x7e, (byte)0x85, (byte)0x3d, (byte)0x85,
            (byte)0x85, (byte)0x71, (byte)0x9e, (byte)0x0e,
            (byte)0x67, (byte)0xcb, (byte)0xda, (byte)0x0d,
            (byte)0xaa, (byte)0x8f, (byte)0x51, (byte)0x67,
            (byte)0x10, (byte)0x64, (byte)0x61, (byte)0x5d,
            (byte)0x64, (byte)0x5a, (byte)0xe2, (byte)0x7a,
            (byte)0xcb, (byte)0x15, (byte)0xbf, (byte)0xb1,
            (byte)0x44, (byte)0x7f, (byte)0x45, (byte)0x9b
        };

        byte[] output;
        byte[] output2;

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha512.update(inArray[i]);
        }

        /* Try to clone existing MessageDigest, should copy over same state */
        MessageDigest sha512Copy = (MessageDigest)sha512.clone();

        output = sha512.digest();
        output2 = sha512Copy.digest();

        assertEquals(expected.length, output.length);
        assertEquals(expected.length, output2.length);

        assertArrayEquals(expected, output);
        assertArrayEquals(expected, output2);
    }

    @Test
    public void testSha512Interop()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Bozeman, MT";
        String input2 = "wolfSSL is an Open Source Internet security " +
                        "company, focused primarily on SSL/TLS and " +
                        "cryptography. Main products include the wolfSSL " +
                        "embedded SSL/TLS library, wolfCrypt cryptography " +
                        "library, wolfMQTT, and wolfSSH. Products are " +
                        "dual licensed under both GPLv2 and a commercial" +
                        "license.";

        byte[] wolfOutput;
        byte[] interopOutput;

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        Provider provider = sha512.getProvider();

        /* if we have another MessageDigest provider, test against it */
        if (!provider.equals("wolfJCE")) {

            /* short message */
            sha512.update(input.getBytes());
            interopOutput = sha512.digest();

            MessageDigest wolfSha512 =
                MessageDigest.getInstance("SHA-512", "wolfJCE");

            wolfSha512.update(input.getBytes());
            wolfOutput = wolfSha512.digest();

            assertArrayEquals(wolfOutput, interopOutput);

            /* long message */
            sha512.update(input2.getBytes());
            interopOutput = sha512.digest();

            wolfSha512.update(input2.getBytes());
            wolfOutput = wolfSha512.digest();

            assertArrayEquals(wolfOutput, interopOutput);
        }

    }

    @Test
    public void testSha512GetDigestLength()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512", "wolfJCE");
        assertEquals(Sha512.DIGEST_SIZE, sha512.getDigestLength());
    }

    @Test
    public void testSha512Threaded()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

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

                    MessageDigest sha = null;

                    try {
                        sha = MessageDigest.getInstance(
                            "SHA-512", "wolfJCE");
                    } catch (NoSuchAlgorithmException |
                             NoSuchProviderException e) {
                        /* add empty array on failure, will error out below */
                        results.add(new byte[] {0});
                    }

                    /* process/update in 1024-byte chunks */
                    for (int j = 0; j < rand10kBuf.length; j+= 1024) {
                        sha.update(rand10kBuf, j, 1024);
                    }

                    /* get final hash */
                    byte[] hash = sha.digest();
                    results.add(hash.clone());

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

