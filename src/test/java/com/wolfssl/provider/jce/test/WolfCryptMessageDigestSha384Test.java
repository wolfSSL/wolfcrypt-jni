/* wolfCryptMessageDigestSha384Test.java
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

import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;

public class WolfCryptMessageDigestSha384Test {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptMessageDigestSha384 Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            MessageDigest sha384 = MessageDigest.getInstance("SHA-384",
                                                             "wolfJCE");
            assertNotNull(sha384);

        } catch (NoSuchAlgorithmException e) {
            /* if we also detect algo is compiled out, skip tests */
            if (FeatureDetect.Sha384Enabled() == false) {
                System.out.println("JSSE SHA-384 Test skipped");
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testSha384SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            new DigestVector(
                new String("abc").getBytes(),
                new byte[] {
                    (byte)0xcb, (byte)0x00, (byte)0x75, (byte)0x3f,
                    (byte)0x45, (byte)0xa3, (byte)0x5e, (byte)0x8b,
                    (byte)0xb5, (byte)0xa0, (byte)0x3d, (byte)0x69,
                    (byte)0x9a, (byte)0xc6, (byte)0x50, (byte)0x07,
                    (byte)0x27, (byte)0x2c, (byte)0x32, (byte)0xab,
                    (byte)0x0e, (byte)0xde, (byte)0xd1, (byte)0x63,
                    (byte)0x1a, (byte)0x8b, (byte)0x60, (byte)0x5a,
                    (byte)0x43, (byte)0xff, (byte)0x5b, (byte)0xed,
                    (byte)0x80, (byte)0x86, (byte)0x07, (byte)0x2b,
                    (byte)0xa1, (byte)0xe7, (byte)0xcc, (byte)0x23,
                    (byte)0x58, (byte)0xba, (byte)0xec, (byte)0xa1,
                    (byte)0x34, (byte)0xc8, (byte)0x25, (byte)0xa7
                }
            ),
            new DigestVector(
                new String("abcdefghbcdefghicdefghijdefghijkefgh" +
                           "ijklfghijklmghijklmnhijklmnoijklmnop" +
                           "jklmnopqklmnopqrlmnopqrsmnopqrstnopq" +
                           "rstu").getBytes(),
                new byte[] {
                    (byte)0x09, (byte)0x33, (byte)0x0c, (byte)0x33,
                    (byte)0xf7, (byte)0x11, (byte)0x47, (byte)0xe8,
                    (byte)0x3d, (byte)0x19, (byte)0x2f, (byte)0xc7,
                    (byte)0x82, (byte)0xcd, (byte)0x1b, (byte)0x47,
                    (byte)0x53, (byte)0x11, (byte)0x1b, (byte)0x17,
                    (byte)0x3b, (byte)0x3b, (byte)0x05, (byte)0xd2,
                    (byte)0x2f, (byte)0xa0, (byte)0x80, (byte)0x86,
                    (byte)0xe3, (byte)0xb0, (byte)0xf7, (byte)0x12,
                    (byte)0xfc, (byte)0xc7, (byte)0xc7, (byte)0x1a,
                    (byte)0x55, (byte)0x7e, (byte)0x2d, (byte)0xb9,
                    (byte)0x66, (byte)0xc3, (byte)0xe9, (byte)0xfa,
                    (byte)0x91, (byte)0x74, (byte)0x60, (byte)0x39
                }
            )
        };

        byte[] output;

        MessageDigest sha384 = MessageDigest.getInstance("SHA-384", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha384.update(vectors[i].getInput());
            output = sha384.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha384SingleByteUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x99, (byte)0x51, (byte)0x43, (byte)0x29,
            (byte)0x18, (byte)0x6b, (byte)0x2f, (byte)0x6a,
            (byte)0xe4, (byte)0xa1, (byte)0x32, (byte)0x9e,
            (byte)0x7e, (byte)0xe6, (byte)0xc6, (byte)0x10,
            (byte)0xa7, (byte)0x29, (byte)0x63, (byte)0x63,
            (byte)0x35, (byte)0x17, (byte)0x4a, (byte)0xc6,
            (byte)0xb7, (byte)0x40, (byte)0xf9, (byte)0x02,
            (byte)0x83, (byte)0x96, (byte)0xfc, (byte)0xc8,
            (byte)0x03, (byte)0xd0, (byte)0xe9, (byte)0x38,
            (byte)0x63, (byte)0xa7, (byte)0xc3, (byte)0xd9,
            (byte)0x0f, (byte)0x86, (byte)0xbe, (byte)0xee,
            (byte)0x78, (byte)0x2f, (byte)0x4f, (byte)0x3f
        };

        byte[] output;

        MessageDigest sha384 = MessageDigest.getInstance("SHA-384", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha384.update(inArray[i]);
        }
        output = sha384.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testSha384Reset()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x99, (byte)0x51, (byte)0x43, (byte)0x29,
            (byte)0x18, (byte)0x6b, (byte)0x2f, (byte)0x6a,
            (byte)0xe4, (byte)0xa1, (byte)0x32, (byte)0x9e,
            (byte)0x7e, (byte)0xe6, (byte)0xc6, (byte)0x10,
            (byte)0xa7, (byte)0x29, (byte)0x63, (byte)0x63,
            (byte)0x35, (byte)0x17, (byte)0x4a, (byte)0xc6,
            (byte)0xb7, (byte)0x40, (byte)0xf9, (byte)0x02,
            (byte)0x83, (byte)0x96, (byte)0xfc, (byte)0xc8,
            (byte)0x03, (byte)0xd0, (byte)0xe9, (byte)0x38,
            (byte)0x63, (byte)0xa7, (byte)0xc3, (byte)0xd9,
            (byte)0x0f, (byte)0x86, (byte)0xbe, (byte)0xee,
            (byte)0x78, (byte)0x2f, (byte)0x4f, (byte)0x3f
        };

        byte[] output;

        MessageDigest sha384 = MessageDigest.getInstance("SHA-384", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha384.update(inArray[i]);
        }

        sha384.reset();

        for (int i = 0; i < inArray.length; i++) {
            sha384.update(inArray[i]);
        }
        output = sha384.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testSha384Clone()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               CloneNotSupportedException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x99, (byte)0x51, (byte)0x43, (byte)0x29,
            (byte)0x18, (byte)0x6b, (byte)0x2f, (byte)0x6a,
            (byte)0xe4, (byte)0xa1, (byte)0x32, (byte)0x9e,
            (byte)0x7e, (byte)0xe6, (byte)0xc6, (byte)0x10,
            (byte)0xa7, (byte)0x29, (byte)0x63, (byte)0x63,
            (byte)0x35, (byte)0x17, (byte)0x4a, (byte)0xc6,
            (byte)0xb7, (byte)0x40, (byte)0xf9, (byte)0x02,
            (byte)0x83, (byte)0x96, (byte)0xfc, (byte)0xc8,
            (byte)0x03, (byte)0xd0, (byte)0xe9, (byte)0x38,
            (byte)0x63, (byte)0xa7, (byte)0xc3, (byte)0xd9,
            (byte)0x0f, (byte)0x86, (byte)0xbe, (byte)0xee,
            (byte)0x78, (byte)0x2f, (byte)0x4f, (byte)0x3f
        };

        byte[] output;
        byte[] output2;

        MessageDigest sha384 = MessageDigest.getInstance("SHA-384", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha384.update(inArray[i]);
        }

        /* Try to clone existing MessageDigest, should copy over same state */
        MessageDigest sha384Copy = (MessageDigest)sha384.clone();

        output = sha384.digest();
        output2 = sha384Copy.digest();

        assertEquals(expected.length, output.length);
        assertEquals(expected.length, output2.length);

        assertArrayEquals(expected, output);
        assertArrayEquals(expected, output2);
    }

    @Test
    public void testSha384Interop()
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

        MessageDigest sha384 = MessageDigest.getInstance("SHA-384");
        Provider provider = sha384.getProvider();

        /* if we have another MessageDigest provider, test against it */
        if (!provider.equals("wolfJCE")) {

            /* short message */
            sha384.update(input.getBytes());
            interopOutput = sha384.digest();

            MessageDigest wolfSha384 =
                MessageDigest.getInstance("SHA-384", "wolfJCE");

            wolfSha384.update(input.getBytes());
            wolfOutput = wolfSha384.digest();

            assertArrayEquals(wolfOutput, interopOutput);

            /* long message */
            sha384.update(input2.getBytes());
            interopOutput = sha384.digest();

            wolfSha384.update(input2.getBytes());
            wolfOutput = wolfSha384.digest();

            assertArrayEquals(wolfOutput, interopOutput);
        }

    }

    @Test
    public void testSha384GetDigestLength()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha384 = MessageDigest.getInstance("SHA-384", "wolfJCE");
        assertEquals(Sha384.DIGEST_SIZE, sha384.getDigestLength());
    }

    @Test
    public void testSha384Threaded()
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
                            "SHA-384", "wolfJCE");
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

