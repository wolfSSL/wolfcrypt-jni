/* WolfCryptMessageDigestSha3Test.java
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

import com.wolfssl.wolfcrypt.Sha3;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;

public class WolfCryptMessageDigestSha3Test {

    @Rule
    public TestRule watcher = new TestWatcher() {
        protected void starting(Description description) {
            System.out.println("\t" + description.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptMessageDigestSha3 Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            MessageDigest.getInstance("SHA3-256", "wolfJCE");

        } catch (NoSuchAlgorithmException e) {
            /* If algo is compiled out, skip tests */
            if (FeatureDetect.Sha3Enabled() == false) {
                System.out.println("wolfJCE SHA3 Test skipped");
                Assume.assumeTrue(false);
            }
        }
    }

    @Test
    public void testSha3_224SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            /* NIST FIPS 202 test vector */
            new DigestVector(
                new String("abc").getBytes(),
                new byte[] {
                    (byte)0xe6, (byte)0x42, (byte)0x82, (byte)0x4c,
                    (byte)0x3f, (byte)0x8c, (byte)0xf2, (byte)0x4a,
                    (byte)0xd0, (byte)0x92, (byte)0x34, (byte)0xee,
                    (byte)0x7d, (byte)0x3c, (byte)0x76, (byte)0x6f,
                    (byte)0xc9, (byte)0xa3, (byte)0xa5, (byte)0x16,
                    (byte)0x8d, (byte)0x0c, (byte)0x94, (byte)0xad,
                    (byte)0x73, (byte)0xb4, (byte)0x6f, (byte)0xdf
                }
            ),
        };

        byte[] output;

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-224", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha3.update(vectors[i].getInput());
            output = sha3.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha3_256SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            /* NIST FIPS 202 test vector */
            new DigestVector(
                new String("abc").getBytes(),
                new byte[] {
                    (byte)0x3a, (byte)0x98, (byte)0x5d, (byte)0xa7,
                    (byte)0x4f, (byte)0xe2, (byte)0x25, (byte)0xb2,
                    (byte)0x04, (byte)0x5c, (byte)0x17, (byte)0x2d,
                    (byte)0x6b, (byte)0xd3, (byte)0x90, (byte)0xbd,
                    (byte)0x85, (byte)0x5f, (byte)0x08, (byte)0x6e,
                    (byte)0x3e, (byte)0x9d, (byte)0x52, (byte)0x5b,
                    (byte)0x46, (byte)0xbf, (byte)0xe2, (byte)0x45,
                    (byte)0x11, (byte)0x43, (byte)0x15, (byte)0x32
                }
            ),
        };

        byte[] output;

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha3.update(vectors[i].getInput());
            output = sha3.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha3_384SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            /* NIST FIPS 202 test vector */
            new DigestVector(
                new String("abc").getBytes(),
                new byte[] {
                    (byte)0xec, (byte)0x01, (byte)0x49, (byte)0x82,
                    (byte)0x88, (byte)0x51, (byte)0x6f, (byte)0xc9,
                    (byte)0x26, (byte)0x45, (byte)0x9f, (byte)0x58,
                    (byte)0xe2, (byte)0xc6, (byte)0xad, (byte)0x8d,
                    (byte)0xf9, (byte)0xb4, (byte)0x73, (byte)0xcb,
                    (byte)0x0f, (byte)0xc0, (byte)0x8c, (byte)0x25,
                    (byte)0x96, (byte)0xda, (byte)0x7c, (byte)0xf0,
                    (byte)0xe4, (byte)0x9b, (byte)0xe4, (byte)0xb2,
                    (byte)0x98, (byte)0xd8, (byte)0x8c, (byte)0xea,
                    (byte)0x92, (byte)0x7a, (byte)0xc7, (byte)0xf5,
                    (byte)0x39, (byte)0xf1, (byte)0xed, (byte)0xf2,
                    (byte)0x28, (byte)0x37, (byte)0x6d, (byte)0x25
                }
            ),
        };

        byte[] output;

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-384", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha3.update(vectors[i].getInput());
            output = sha3.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha3_512SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        DigestVector vectors[] = new DigestVector[] {
            /* NIST FIPS 202 test vector */
            new DigestVector(
                new String("abc").getBytes(),
                new byte[] {
                    (byte)0xb7, (byte)0x51, (byte)0x85, (byte)0x0b,
                    (byte)0x1a, (byte)0x57, (byte)0x16, (byte)0x8a,
                    (byte)0x56, (byte)0x93, (byte)0xcd, (byte)0x92,
                    (byte)0x4b, (byte)0x6b, (byte)0x09, (byte)0x6e,
                    (byte)0x08, (byte)0xf6, (byte)0x21, (byte)0x82,
                    (byte)0x74, (byte)0x44, (byte)0xf7, (byte)0x0d,
                    (byte)0x88, (byte)0x4f, (byte)0x5d, (byte)0x02,
                    (byte)0x40, (byte)0xd2, (byte)0x71, (byte)0x2e,
                    (byte)0x10, (byte)0xe1, (byte)0x16, (byte)0xe9,
                    (byte)0x19, (byte)0x2a, (byte)0xf3, (byte)0xc9,
                    (byte)0x1a, (byte)0x7e, (byte)0xc5, (byte)0x76,
                    (byte)0x47, (byte)0xe3, (byte)0x93, (byte)0x40,
                    (byte)0x57, (byte)0x34, (byte)0x0b, (byte)0x4c,
                    (byte)0xf4, (byte)0x08, (byte)0xd5, (byte)0xa5,
                    (byte)0x65, (byte)0x92, (byte)0xf8, (byte)0x27,
                    (byte)0x4e, (byte)0xec, (byte)0x53, (byte)0xf0
                }
            ),
        };

        byte[] output;

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-512", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha3.update(vectors[i].getInput());
            output = sha3.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha3Reset()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input = "abc";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x3a, (byte)0x98, (byte)0x5d, (byte)0xa7,
            (byte)0x4f, (byte)0xe2, (byte)0x25, (byte)0xb2,
            (byte)0x04, (byte)0x5c, (byte)0x17, (byte)0x2d,
            (byte)0x6b, (byte)0xd3, (byte)0x90, (byte)0xbd,
            (byte)0x85, (byte)0x5f, (byte)0x08, (byte)0x6e,
            (byte)0x3e, (byte)0x9d, (byte)0x52, (byte)0x5b,
            (byte)0x46, (byte)0xbf, (byte)0xe2, (byte)0x45,
            (byte)0x11, (byte)0x43, (byte)0x15, (byte)0x32
        };

        byte[] output;

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha3.update(inArray[i]);
        }

        sha3.reset();

        for (int i = 0; i < inArray.length; i++) {
            sha3.update(inArray[i]);
        }
        output = sha3.digest();
        assertEquals(expected.length, output.length);
        assertArrayEquals(expected, output);
    }

    @Test
    public void testSha3Clone()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               CloneNotSupportedException {

        String input = "abc";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            (byte)0x3a, (byte)0x98, (byte)0x5d, (byte)0xa7,
            (byte)0x4f, (byte)0xe2, (byte)0x25, (byte)0xb2,
            (byte)0x04, (byte)0x5c, (byte)0x17, (byte)0x2d,
            (byte)0x6b, (byte)0xd3, (byte)0x90, (byte)0xbd,
            (byte)0x85, (byte)0x5f, (byte)0x08, (byte)0x6e,
            (byte)0x3e, (byte)0x9d, (byte)0x52, (byte)0x5b,
            (byte)0x46, (byte)0xbf, (byte)0xe2, (byte)0x45,
            (byte)0x11, (byte)0x43, (byte)0x15, (byte)0x32
        };

        byte[] output;
        byte[] output2;

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256", "wolfJCE");

        for (int i = 0; i < inArray.length; i++) {
            sha3.update(inArray[i]);
        }

        /* Try to clone existing MessageDigest, should copy over same state */
        MessageDigest sha3Copy = (MessageDigest)sha3.clone();

        output = sha3.digest();
        output2 = sha3Copy.digest();

        assertEquals(expected.length, output.length);
        assertEquals(expected.length, output2.length);

        assertArrayEquals(expected, output);
        assertArrayEquals(expected, output2);
    }

    @Test
    public void testSha3GetDigestLength()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha3_224 =
            MessageDigest.getInstance("SHA3-224", "wolfJCE");
        assertEquals(Sha3.DIGEST_SIZE_224, sha3_224.getDigestLength());

        MessageDigest sha3_256 =
            MessageDigest.getInstance("SHA3-256", "wolfJCE");
        assertEquals(Sha3.DIGEST_SIZE_256, sha3_256.getDigestLength());

        MessageDigest sha3_384 =
            MessageDigest.getInstance("SHA3-384", "wolfJCE");
        assertEquals(Sha3.DIGEST_SIZE_384, sha3_384.getDigestLength());

        MessageDigest sha3_512 =
            MessageDigest.getInstance("SHA3-512", "wolfJCE");
        assertEquals(Sha3.DIGEST_SIZE_512, sha3_512.getDigestLength());
    }

    @Test
    public void testSha3Threaded()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InterruptedException {

        int numThreads = 100;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<byte[]> results = new LinkedBlockingQueue<>();
        final byte[] rand10kBuf = new byte[10240];

        /* Fill large input buffer with random bytes */
        new Random().nextBytes(rand10kBuf);

        /* Generate hash over input data concurrently across numThreads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    MessageDigest sha3 = null;

                    try {
                        sha3 = MessageDigest.getInstance("SHA3-256", "wolfJCE");
                    } catch (NoSuchAlgorithmException |
                             NoSuchProviderException e) {
                        /* Add empty array on failure, will error out below */
                        results.add(new byte[] {0});
                    }

                    /* Process/update in 1024-byte chunks */
                    for (int j = 0; j < rand10kBuf.length; j+= 1024) {
                        sha3.update(rand10kBuf, j, 1024);
                    }

                    /* Get final hash */
                    byte[] hash = sha3.digest();
                    results.add(hash.clone());

                    latch.countDown();
                }
            });
        }

        /* Wait for all threads to complete */
        latch.await();

        /* Compare all digests, all should be the same across threads */
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

    @Test
    public void testSha3EmptyInput()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* NIST FIPS 202 test vectors for empty input */
        byte[] empty224 = new byte[] {
            (byte)0x6b, (byte)0x4e, (byte)0x03, (byte)0x42,
            (byte)0x36, (byte)0x67, (byte)0xdb, (byte)0xb7,
            (byte)0x3b, (byte)0x6e, (byte)0x15, (byte)0x45,
            (byte)0x4f, (byte)0x0e, (byte)0xb1, (byte)0xab,
            (byte)0xd4, (byte)0x59, (byte)0x7f, (byte)0x9a,
            (byte)0x1b, (byte)0x07, (byte)0x8e, (byte)0x3f,
            (byte)0x5b, (byte)0x5a, (byte)0x6b, (byte)0xc7
        };

        byte[] empty256 = new byte[] {
            (byte)0xa7, (byte)0xff, (byte)0xc6, (byte)0xf8,
            (byte)0xbf, (byte)0x1e, (byte)0xd7, (byte)0x66,
            (byte)0x51, (byte)0xc1, (byte)0x47, (byte)0x56,
            (byte)0xa0, (byte)0x61, (byte)0xd6, (byte)0x62,
            (byte)0xf5, (byte)0x80, (byte)0xff, (byte)0x4d,
            (byte)0xe4, (byte)0x3b, (byte)0x49, (byte)0xfa,
            (byte)0x82, (byte)0xd8, (byte)0x0a, (byte)0x4b,
            (byte)0x80, (byte)0xf8, (byte)0x43, (byte)0x4a
        };

        byte[] empty384 = new byte[] {
            (byte)0x0c, (byte)0x63, (byte)0xa7, (byte)0x5b,
            (byte)0x84, (byte)0x5e, (byte)0x4f, (byte)0x7d,
            (byte)0x01, (byte)0x10, (byte)0x7d, (byte)0x85,
            (byte)0x2e, (byte)0x4c, (byte)0x24, (byte)0x85,
            (byte)0xc5, (byte)0x1a, (byte)0x50, (byte)0xaa,
            (byte)0xaa, (byte)0x94, (byte)0xfc, (byte)0x61,
            (byte)0x99, (byte)0x5e, (byte)0x71, (byte)0xbb,
            (byte)0xee, (byte)0x98, (byte)0x3a, (byte)0x2a,
            (byte)0xc3, (byte)0x71, (byte)0x38, (byte)0x31,
            (byte)0x26, (byte)0x4a, (byte)0xdb, (byte)0x47,
            (byte)0xfb, (byte)0x6b, (byte)0xd1, (byte)0xe0,
            (byte)0x58, (byte)0xd5, (byte)0xf0, (byte)0x04
        };

        byte[] empty512 = new byte[] {
            (byte)0xa6, (byte)0x9f, (byte)0x73, (byte)0xcc,
            (byte)0xa2, (byte)0x3a, (byte)0x9a, (byte)0xc5,
            (byte)0xc8, (byte)0xb5, (byte)0x67, (byte)0xdc,
            (byte)0x18, (byte)0x5a, (byte)0x75, (byte)0x6e,
            (byte)0x97, (byte)0xc9, (byte)0x82, (byte)0x16,
            (byte)0x4f, (byte)0xe2, (byte)0x58, (byte)0x59,
            (byte)0xe0, (byte)0xd1, (byte)0xdc, (byte)0xc1,
            (byte)0x47, (byte)0x5c, (byte)0x80, (byte)0xa6,
            (byte)0x15, (byte)0xb2, (byte)0x12, (byte)0x3a,
            (byte)0xf1, (byte)0xf5, (byte)0xf9, (byte)0x4c,
            (byte)0x11, (byte)0xe3, (byte)0xe9, (byte)0x40,
            (byte)0x2c, (byte)0x3a, (byte)0xc5, (byte)0x58,
            (byte)0xf5, (byte)0x00, (byte)0x19, (byte)0x9d,
            (byte)0x95, (byte)0xb6, (byte)0xd3, (byte)0xe3,
            (byte)0x01, (byte)0x75, (byte)0x85, (byte)0x86,
            (byte)0x28, (byte)0x1d, (byte)0xcd, (byte)0x26
        };

        byte[] output;

        /* Test SHA3-224 empty input */
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-224", "wolfJCE");
        output = sha3.digest();
        assertEquals(empty224.length, output.length);
        assertArrayEquals(empty224, output);

        /* Test SHA3-256 empty input */
        sha3 = MessageDigest.getInstance("SHA3-256", "wolfJCE");
        output = sha3.digest();
        assertEquals(empty256.length, output.length);
        assertArrayEquals(empty256, output);

        /* Test SHA3-384 empty input */
        sha3 = MessageDigest.getInstance("SHA3-384", "wolfJCE");
        output = sha3.digest();
        assertEquals(empty384.length, output.length);
        assertArrayEquals(empty384, output);

        /* Test SHA3-512 empty input */
        sha3 = MessageDigest.getInstance("SHA3-512", "wolfJCE");
        output = sha3.digest();
        assertEquals(empty512.length, output.length);
        assertArrayEquals(empty512, output);
    }

    @Test
    public void testSha3ByteByByteUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        String input =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        byte[] inArray = input.getBytes();
        final byte expected[] = new byte[] {
            /* NIST FIPS 202 test vector for above input with SHA3-256 */
            (byte)0x41, (byte)0xc0, (byte)0xdb, (byte)0xa2,
            (byte)0xa9, (byte)0xd6, (byte)0x24, (byte)0x08,
            (byte)0x49, (byte)0x10, (byte)0x03, (byte)0x76,
            (byte)0xa8, (byte)0x23, (byte)0x5e, (byte)0x2c,
            (byte)0x82, (byte)0xe1, (byte)0xb9, (byte)0x99,
            (byte)0x8a, (byte)0x99, (byte)0x9e, (byte)0x21,
            (byte)0xdb, (byte)0x32, (byte)0xdd, (byte)0x97,
            (byte)0x49, (byte)0x6d, (byte)0x33, (byte)0x76
        };

        byte[] output;
        byte[] output2;

        MessageDigest sha3 =
            MessageDigest.getInstance("SHA3-256", "wolfJCE");
        MessageDigest sha3Bulk =
            MessageDigest.getInstance("SHA3-256", "wolfJCE");

        /* Update one byte at a time */
        for (int i = 0; i < inArray.length; i++) {
            sha3.update(inArray[i]);
        }

        /* Update all at once */
        sha3Bulk.update(inArray);

        output = sha3.digest();
        output2 = sha3Bulk.digest();

        /* Both methods should produce same digest */
        assertEquals(expected.length, output.length);
        assertEquals(expected.length, output2.length);
        assertArrayEquals(expected, output);
        assertArrayEquals(expected, output2);
        assertArrayEquals(output, output2);
    }

    @Test
    public void testSha3LargeInput()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Test with 1MB of random data */
        byte[] largeInput = new byte[1024 * 1024];
        new Random().nextBytes(largeInput);

        MessageDigest sha3_224 =
            MessageDigest.getInstance("SHA3-224", "wolfJCE");
        MessageDigest sha3_256 =
            MessageDigest.getInstance("SHA3-256", "wolfJCE");
        MessageDigest sha3_384 =
            MessageDigest.getInstance("SHA3-384", "wolfJCE");
        MessageDigest sha3_512 =
            MessageDigest.getInstance("SHA3-512", "wolfJCE");

        /* Hash same input with all SHA-3 variants */
        byte[] hash224 = sha3_224.digest(largeInput);
        byte[] hash256 = sha3_256.digest(largeInput);
        byte[] hash384 = sha3_384.digest(largeInput);
        byte[] hash512 = sha3_512.digest(largeInput);

        /* Verify expected digest sizes */
        assertEquals(Sha3.DIGEST_SIZE_224, hash224.length);
        assertEquals(Sha3.DIGEST_SIZE_256, hash256.length);
        assertEquals(Sha3.DIGEST_SIZE_384, hash384.length);
        assertEquals(Sha3.DIGEST_SIZE_512, hash512.length);

        /* Verify digests are different */
        assertFalse(Arrays.equals(hash224, hash256));
        assertFalse(Arrays.equals(hash224, hash384));
        assertFalse(Arrays.equals(hash224, hash512));
        assertFalse(Arrays.equals(hash256, hash384));
        assertFalse(Arrays.equals(hash256, hash512));
        assertFalse(Arrays.equals(hash384, hash512));
    }

    @Test
    public void testSha3Interop()
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

        /* Get SUN SHA3 implementation */
        MessageDigest sunSha3 = null;
        try {
            sunSha3 = MessageDigest.getInstance("SHA3-256", "SUN");
            Provider provider = sunSha3.getProvider();
            if (!provider.getName().equals("SUN")) {
                /* Skip test if SUN SHA3-256 provider name mismatch */
                return;
            }
        } catch (NoSuchAlgorithmException e) {
            /* Skip test if SUN SHA3-256 provider available */
            return;
        }

        MessageDigest wolfSha3 =
            MessageDigest.getInstance("SHA3-256", "wolfJCE");

        /* short message */
        sunSha3.update(input.getBytes());
        interopOutput = sunSha3.digest();

        wolfSha3.update(input.getBytes());
        wolfOutput = wolfSha3.digest();

        assertArrayEquals(wolfOutput, interopOutput);

        /* long message */
        sunSha3.update(input2.getBytes());
        interopOutput = sunSha3.digest();

        wolfSha3.update(input2.getBytes());
        wolfOutput = wolfSha3.digest();

        assertArrayEquals(wolfOutput, interopOutput);
    }

    @Test
    public void testSha3DigestAfterDigest()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256", "wolfJCE");
        sha3.update((byte)0x00);
        sha3.digest();

        /* Try to digest again without update, should return empty hash */
        byte[] emptyHash = sha3.digest();
        byte[] expectedEmptyHash = new byte[] {
            (byte)0xa7, (byte)0xff, (byte)0xc6, (byte)0xf8,
            (byte)0xbf, (byte)0x1e, (byte)0xd7, (byte)0x66,
            (byte)0x51, (byte)0xc1, (byte)0x47, (byte)0x56,
            (byte)0xa0, (byte)0x61, (byte)0xd6, (byte)0x62,
            (byte)0xf5, (byte)0x80, (byte)0xff, (byte)0x4d,
            (byte)0xe4, (byte)0x3b, (byte)0x49, (byte)0xfa,
            (byte)0x82, (byte)0xd8, (byte)0x0a, (byte)0x4b,
            (byte)0x80, (byte)0xf8, (byte)0x43, (byte)0x4a
        };
        assertArrayEquals(expectedEmptyHash, emptyHash);
    }

    @Test
    public void testSha3UpdateAfterDigest()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256", "wolfJCE");
        sha3.update((byte)0x00);
        sha3.digest();

        /* Try to update after digest, should implicitly reset */
        sha3.update((byte)0x00);
        byte[] output = sha3.digest();

        /* Verify we get expected output for single 0x00 byte */
        byte[] expected = new byte[] {
            (byte)0x5d, (byte)0x53, (byte)0x46, (byte)0x9f,
            (byte)0x20, (byte)0xfe, (byte)0xf4, (byte)0xf8,
            (byte)0xea, (byte)0xb5, (byte)0x2b, (byte)0x88,
            (byte)0x04, (byte)0x4e, (byte)0xde, (byte)0x69,
            (byte)0xc7, (byte)0x7a, (byte)0x6a, (byte)0x68,
            (byte)0xa6, (byte)0x07, (byte)0x28, (byte)0x60,
            (byte)0x9f, (byte)0xc4, (byte)0xa6, (byte)0x5f,
            (byte)0xf5, (byte)0x31, (byte)0xe7, (byte)0xd0
        };
        assertArrayEquals(expected, output);
    }
} 
