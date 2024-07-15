/* wolfCryptMessageDigestShaTest.java
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
import java.lang.CloneNotSupportedException;

import com.wolfssl.wolfcrypt.Sha;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;

public class WolfCryptMessageDigestShaTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptMessageDigestSha Class");

        /* install wolfJCE provider at runtime */
        Security.addProvider(new WolfCryptProvider());

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            /* Try "SHA" and "SHA1" cipher strings, for SUN interop */
            MessageDigest sha = MessageDigest.getInstance("SHA",
                                                          "wolfJCE");

            MessageDigest sha1 = MessageDigest.getInstance("SHA1",
                                                          "wolfJCE");

            MessageDigest shaDash1 = MessageDigest.getInstance("SHA-1",
                                                               "wolfJCE");
        } catch (NoSuchAlgorithmException e) {
            /* if we also detect algo is compiled out, skip tests */
            if (FeatureDetect.ShaEnabled() == false) {
                System.out.println("JSSE SHA-1 Test skipped");
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testShaSingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            new DigestVector(
                "abc".getBytes(),
                new byte[] {
                    (byte)0xa9, (byte)0x99, (byte)0x3e, (byte)0x36,
                    (byte)0x47, (byte)0x06, (byte)0x81, (byte)0x6a,
                    (byte)0xba, (byte)0x3e, (byte)0x25, (byte)0x71,
                    (byte)0x78, (byte)0x50, (byte)0xc2, (byte)0x6c,
                    (byte)0x9c, (byte)0xd0, (byte)0xd8, (byte)0x9d
                }
            ),
            new DigestVector(
                new String("abcdbcdecdefdefgefghfghighijhijkijkl" +
                           "jklmklmnlmnomnopnopq").getBytes(),
                new byte[] {
                    (byte)0x84, (byte)0x98, (byte)0x3e, (byte)0x44,
                    (byte)0x1c, (byte)0x3b, (byte)0xd2, (byte)0x6e,
                    (byte)0xba, (byte)0xae, (byte)0x4a, (byte)0xa1,
                    (byte)0xf9, (byte)0x51, (byte)0x29, (byte)0xe5,
                    (byte)0xe5, (byte)0x46, (byte)0x70, (byte)0xf1
                }
            ),
            new DigestVector(
                new String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaa").getBytes(),
                new byte[] {
                    (byte)0x00, (byte)0x98, (byte)0xba, (byte)0x82,
                    (byte)0x4b, (byte)0x5c, (byte)0x16, (byte)0x42,
                    (byte)0x7b, (byte)0xd7, (byte)0xa1, (byte)0x12,
                    (byte)0x2a, (byte)0x5a, (byte)0x44, (byte)0x2a,
                    (byte)0x25, (byte)0xec, (byte)0x64, (byte)0x4d
                }
            ),
            new DigestVector(
                new String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                           "aaaaaaaaaaaaaaaaaaaa").getBytes(),
                new byte[] {
                    (byte)0xad, (byte)0x5b, (byte)0x3f, (byte)0xdb,
                    (byte)0xcb, (byte)0x52, (byte)0x67, (byte)0x78,
                    (byte)0xc2, (byte)0x83, (byte)0x9d, (byte)0x2f,
                    (byte)0x15, (byte)0x1e, (byte)0xa7, (byte)0x53,
                    (byte)0x99, (byte)0x5e, (byte)0x26, (byte)0xa0
                }
            )
        };

        byte[] output;

        MessageDigest sha = MessageDigest.getInstance("SHA-1", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha.update(vectors[i].getInput());
            output = sha.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testShaSingleByteUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x0a, (byte)0x4d, (byte)0x55, (byte)0xa8,
            (byte)0xd7, (byte)0x78, (byte)0xe5, (byte)0x02,
            (byte)0x2f, (byte)0xab, (byte)0x70, (byte)0x19,
            (byte)0x77, (byte)0xc5, (byte)0xd8, (byte)0x40,
            (byte)0xbb, (byte)0xc4, (byte)0x86, (byte)0xd0
        };

        byte[] output;

        MessageDigest sha = MessageDigest.getInstance("SHA-1", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha.update(inArray[i]);
        }
        output = sha.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testShaReset()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x0a, (byte)0x4d, (byte)0x55, (byte)0xa8,
            (byte)0xd7, (byte)0x78, (byte)0xe5, (byte)0x02,
            (byte)0x2f, (byte)0xab, (byte)0x70, (byte)0x19,
            (byte)0x77, (byte)0xc5, (byte)0xd8, (byte)0x40,
            (byte)0xbb, (byte)0xc4, (byte)0x86, (byte)0xd0
        };

        byte[] output;

        MessageDigest sha = MessageDigest.getInstance("SHA-1", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha.update(inArray[i]);
        }

        sha.reset();

        for (int i = 0; i < inArray.length; i++) {
            sha.update(inArray[i]);
        }
        output = sha.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testShaClone()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               CloneNotSupportedException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x0a, (byte)0x4d, (byte)0x55, (byte)0xa8,
            (byte)0xd7, (byte)0x78, (byte)0xe5, (byte)0x02,
            (byte)0x2f, (byte)0xab, (byte)0x70, (byte)0x19,
            (byte)0x77, (byte)0xc5, (byte)0xd8, (byte)0x40,
            (byte)0xbb, (byte)0xc4, (byte)0x86, (byte)0xd0
        };

        byte[] output;
        byte[] output2;

        MessageDigest sha = MessageDigest.getInstance("SHA-1", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha.update(inArray[i]);
        }

        /* Try to clone existing MessageDigest, should copy over same state */
        MessageDigest shaCopy = (MessageDigest)sha.clone();

        output = sha.digest();
        output2 = shaCopy.digest();

        assertEquals(expected.length, output.length);
        assertEquals(expected.length, output2.length);

        assertArrayEquals(expected, output);
        assertArrayEquals(expected, output2);
    }

    @Test
    public void testShaInterop()
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

        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        Provider provider = sha.getProvider();

        /* if we have another MessageDigest provider, test against it */
        if (!provider.equals("wolfJCE")) {

            /* short message */
            sha.update(input.getBytes());
            interopOutput = sha.digest();

            MessageDigest wolfSha =
                MessageDigest.getInstance("SHA-1", "wolfJCE");

            wolfSha.update(input.getBytes());
            wolfOutput = wolfSha.digest();

            assertArrayEquals(wolfOutput, interopOutput);

            /* long message */
            sha.update(input2.getBytes());
            interopOutput = sha.digest();

            wolfSha.update(input2.getBytes());
            wolfOutput = wolfSha.digest();

            assertArrayEquals(wolfOutput, interopOutput);
        }
    }

    @Test
    public void testShaGetDigestLength()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha = MessageDigest.getInstance("SHA-1", "wolfJCE");
        assertEquals(Sha.DIGEST_SIZE, sha.getDigestLength());
    }

    @Test
    public void testShaThreaded()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

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

                    MessageDigest sha = null;

                    try {
                        sha = MessageDigest.getInstance(
                            "SHA-1", "wolfJCE");
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

