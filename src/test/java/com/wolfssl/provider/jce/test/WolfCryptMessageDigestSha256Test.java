/* wolfCryptMessageDigestSha256Test.java
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

import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;

public class WolfCryptMessageDigestSha256Test {

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        /* install wolfJCE provider at runtime */
        Security.addProvider(new WolfCryptProvider());

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256",
                                                             "wolfJCE");
        } catch (NoSuchAlgorithmException e) {
            /* if we also detect algo is compiled out, skip tests */
            if (FeatureDetect.Sha256Enabled() == false) {
                System.out.println("JSSE SHA-256 Test skipped");
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testSha256SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            new DigestVector(
                new String("abc").getBytes(),
                new byte[] {
                    (byte)0xba, (byte)0x78, (byte)0x16, (byte)0xbf,
                    (byte)0x8f, (byte)0x01, (byte)0xcf, (byte)0xea,
                    (byte)0x41, (byte)0x41, (byte)0x40, (byte)0xde,
                    (byte)0x5d, (byte)0xae, (byte)0x22, (byte)0x23,
                    (byte)0xb0, (byte)0x03, (byte)0x61, (byte)0xa3,
                    (byte)0x96, (byte)0x17, (byte)0x7a, (byte)0x9c,
                    (byte)0xb4, (byte)0x10, (byte)0xff, (byte)0x61,
                    (byte)0xf2, (byte)0x00, (byte)0x15, (byte)0xad
                }
            ),
            new DigestVector(
                new String("abcdbcdecdefdefgefghfghighijhijkijkljkl" +
                           "mklmnlmnomnopnopq").getBytes(),
                new byte[] {
                    (byte)0x24, (byte)0x8d, (byte)0x6a, (byte)0x61,
                    (byte)0xd2, (byte)0x06, (byte)0x38, (byte)0xb8,
                    (byte)0xe5, (byte)0xc0, (byte)0x26, (byte)0x93,
                    (byte)0x0c, (byte)0x3e, (byte)0x60, (byte)0x39,
                    (byte)0xa3, (byte)0x3c, (byte)0xe4, (byte)0x59,
                    (byte)0x64, (byte)0xff, (byte)0x21, (byte)0x67,
                    (byte)0xf6, (byte)0xec, (byte)0xed, (byte)0xd4,
                    (byte)0x19, (byte)0xdb, (byte)0x06, (byte)0xc1
                }
            ),
        };

        byte[] output;

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha256.update(vectors[i].getInput());
            output = sha256.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha256SingleByteUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0xa5, (byte)0x91, (byte)0xa6, (byte)0xd4,
            (byte)0x0b, (byte)0xf4, (byte)0x20, (byte)0x40,
            (byte)0x4a, (byte)0x01, (byte)0x17, (byte)0x33,
            (byte)0xcf, (byte)0xb7, (byte)0xb1, (byte)0x90,
            (byte)0xd6, (byte)0x2c, (byte)0x65, (byte)0xbf,
            (byte)0x0B, (byte)0xcd, (byte)0xa3, (byte)0x2b,
            (byte)0x57, (byte)0xb2, (byte)0x77, (byte)0xd9,
            (byte)0xad, (byte)0x9f, (byte)0x14, (byte)0x6e
        };

        byte[] output;

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha256.update(inArray[i]);
        }
        output = sha256.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testSha256Reset()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0xa5, (byte)0x91, (byte)0xa6, (byte)0xd4,
            (byte)0x0b, (byte)0xf4, (byte)0x20, (byte)0x40,
            (byte)0x4a, (byte)0x01, (byte)0x17, (byte)0x33,
            (byte)0xcf, (byte)0xb7, (byte)0xb1, (byte)0x90,
            (byte)0xd6, (byte)0x2c, (byte)0x65, (byte)0xbf,
            (byte)0x0B, (byte)0xcd, (byte)0xa3, (byte)0x2b,
            (byte)0x57, (byte)0xb2, (byte)0x77, (byte)0xd9,
            (byte)0xad, (byte)0x9f, (byte)0x14, (byte)0x6e
        };

        byte[] output;

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha256.update(inArray[i]);
        }

        sha256.reset();

        for (int i = 0; i < inArray.length; i++) {
            sha256.update(inArray[i]);
        }
        output = sha256.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testSha256Clone()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               CloneNotSupportedException {

        String input = "Hello World";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0xa5, (byte)0x91, (byte)0xa6, (byte)0xd4,
            (byte)0x0b, (byte)0xf4, (byte)0x20, (byte)0x40,
            (byte)0x4a, (byte)0x01, (byte)0x17, (byte)0x33,
            (byte)0xcf, (byte)0xb7, (byte)0xb1, (byte)0x90,
            (byte)0xd6, (byte)0x2c, (byte)0x65, (byte)0xbf,
            (byte)0x0B, (byte)0xcd, (byte)0xa3, (byte)0x2b,
            (byte)0x57, (byte)0xb2, (byte)0x77, (byte)0xd9,
            (byte)0xad, (byte)0x9f, (byte)0x14, (byte)0x6e
        };

        byte[] output;
        byte[] output2;

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha256.update(inArray[i]);
        }

        /* Try to clone existing MessageDigest, should copy over same state */
        MessageDigest sha256Copy = (MessageDigest)sha256.clone();

        output = sha256.digest();
        output2 = sha256Copy.digest();

        assertEquals(expected.length, output.length);
        assertEquals(expected.length, output2.length);

        assertArrayEquals(expected, output);
        assertArrayEquals(expected, output2);
    }

    @Test
    public void testSha256Interop()
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

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        Provider provider = sha256.getProvider();

        /* if we have another MessageDigest provider, test against it */
        if (!provider.equals("wolfJCE")) {

            /* short message */
            sha256.update(input.getBytes());
            interopOutput = sha256.digest();

            MessageDigest wolfSha256 =
                MessageDigest.getInstance("SHA-256", "wolfJCE");

            wolfSha256.update(input.getBytes());
            wolfOutput = wolfSha256.digest();

            assertArrayEquals(wolfOutput, interopOutput);

            /* long message */
            sha256.update(input2.getBytes());
            interopOutput = sha256.digest();

            wolfSha256.update(input2.getBytes());
            wolfOutput = wolfSha256.digest();

            assertArrayEquals(wolfOutput, interopOutput);
        }
    }

    @Test
    public void testSha256GetDigestLength()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "wolfJCE");
        assertEquals(Sha256.DIGEST_SIZE, sha256.getDigestLength());
    }

    @Test
    public void testSha256Threaded()
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
                            "SHA-256", "wolfJCE");
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

