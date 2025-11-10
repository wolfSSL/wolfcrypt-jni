/* wolfCryptMessageDigestSha224Test.java
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

import com.wolfssl.wolfcrypt.Sha224;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;

public class WolfCryptMessageDigestSha224Test {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        System.out.println("JCE WolfCryptMessageDigestSha224 Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            MessageDigest.getInstance("SHA-224", "wolfJCE");

        } catch (NoSuchAlgorithmException e) {
            /* if we also detect algo is compiled out, skip tests */
            if (FeatureDetect.Sha224Enabled() == false) {
                System.out.println("JSSE SHA-224 Test skipped");
                Assume.assumeTrue(false);
            }
        }
    }

    static DigestVector vectors[] = new DigestVector[] {
        new DigestVector(
            new String("").getBytes(),
            new byte[] {
                (byte)0xd1, (byte)0x4a, (byte)0x02, (byte)0x8c,
                (byte)0x2a, (byte)0x3a, (byte)0x2b, (byte)0xc9,
                (byte)0x47, (byte)0x61, (byte)0x02, (byte)0xbb,
                (byte)0x28, (byte)0x82, (byte)0x34, (byte)0xc4,
                (byte)0x15, (byte)0xa2, (byte)0xb0, (byte)0x1f,
                (byte)0x82, (byte)0x8e, (byte)0xa6, (byte)0x2a,
                (byte)0xc5, (byte)0xb3, (byte)0xe4, (byte)0x2f
            }
        ),
        new DigestVector(
            new String("abc").getBytes(),
            new byte[] {
                (byte)0x23, (byte)0x09, (byte)0x7d, (byte)0x22,
                (byte)0x34, (byte)0x05, (byte)0xd8, (byte)0x22,
                (byte)0x86, (byte)0x42, (byte)0xa4, (byte)0x77,
                (byte)0xbd, (byte)0xa2, (byte)0x55, (byte)0xb3,
                (byte)0x2a, (byte)0xad, (byte)0xbc, (byte)0xe4,
                (byte)0xbd, (byte)0xa0, (byte)0xb3, (byte)0xf7,
                (byte)0xe3, (byte)0x6c, (byte)0x9d, (byte)0xa7
            }
        ),
        new DigestVector(
            new String("abcdbcdecdefdefgefghfghighijhij" +
                       "kijkljklmklmnlmnomnopnopq").getBytes(),
            new byte[] {
                (byte)0x75, (byte)0x38, (byte)0x8b, (byte)0x16,
                (byte)0x51, (byte)0x27, (byte)0x76, (byte)0xcc,
                (byte)0x5d, (byte)0xba, (byte)0x5d, (byte)0xa1,
                (byte)0xfd, (byte)0x89, (byte)0x01, (byte)0x50,
                (byte)0xb0, (byte)0xc6, (byte)0x45, (byte)0x5c,
                (byte)0xb4, (byte)0xf5, (byte)0x8b, (byte)0x19,
                (byte)0x52, (byte)0x52, (byte)0x25, (byte)0x25
            }
        )
    };

    @Test
    public void testSha224SingleUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] output;

        MessageDigest sha224 = MessageDigest.getInstance("SHA-224", "wolfJCE");

        for (int i = 0; i < vectors.length; i++) {
            sha224.update(vectors[i].getInput());
            output = sha224.digest();
            assertEquals(vectors[i].getOutput().length, output.length);
            assertArrayEquals(vectors[i].getOutput(), output);
        }
    }

    @Test
    public void testSha224SingleByteUpdate()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] output;

        MessageDigest sha224 = MessageDigest.getInstance("SHA-224", "wolfJCE");

        for (int i = 0; i < vectors[1].getInput().length; i++) {
            sha224.update(vectors[1].getInput()[i]);
        }
        output = sha224.digest();
        assertEquals(vectors[1].getOutput().length, output.length);
        assertArrayEquals(vectors[1].getOutput(), output);
    }

    @Test
    public void testSha224Reset()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] output;

        MessageDigest sha224 = MessageDigest.getInstance("SHA-224", "wolfJCE");

        for (int i = 0; i < vectors[1].getInput().length; i++) {
            sha224.update(vectors[1].getInput()[i]);
        }

        sha224.reset();

        for (int i = 0; i < vectors[1].getInput().length; i++) {
            sha224.update(vectors[1].getInput()[i]);
        }
        output = sha224.digest();
        assertEquals(vectors[1].getOutput().length, output.length);
        assertArrayEquals(vectors[1].getOutput(), output);
    }

    @Test
    public void testSha224Clone()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               CloneNotSupportedException {

        byte[] output;
        byte[] output2;

        MessageDigest sha224 = MessageDigest.getInstance("SHA-224", "wolfJCE");

        for (int i = 0; i < vectors[1].getInput().length; i++) {
            sha224.update(vectors[1].getInput()[i]);
        }

        /* Try to clone existing MessageDigest, should copy over same state */
        MessageDigest sha224Copy = (MessageDigest)sha224.clone();

        output = sha224.digest();
        output2 = sha224Copy.digest();

        assertEquals(vectors[1].getOutput().length, output.length);
        assertEquals(vectors[1].getOutput().length, output2.length);

        assertArrayEquals(vectors[1].getOutput(), output);
        assertArrayEquals(vectors[1].getOutput(), output2);
    }

    @Test
    public void testSha224Interop()
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

        MessageDigest sha224 = MessageDigest.getInstance("SHA-224");
        Provider provider = sha224.getProvider();

        /* if we have another MessageDigest provider, test against it */
        if (!provider.equals("wolfJCE")) {

            /* short message */
            sha224.update(input.getBytes());
            interopOutput = sha224.digest();

            MessageDigest wolfSha224 =
                MessageDigest.getInstance("SHA-224", "wolfJCE");

            wolfSha224.update(input.getBytes());
            wolfOutput = wolfSha224.digest();

            assertArrayEquals(wolfOutput, interopOutput);

            /* long message */
            sha224.update(input2.getBytes());
            interopOutput = sha224.digest();

            wolfSha224.update(input2.getBytes());
            wolfOutput = wolfSha224.digest();

            assertArrayEquals(wolfOutput, interopOutput);
        }
    }

    @Test
    public void testSha224GetDigestLength()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        MessageDigest sha224 = MessageDigest.getInstance("SHA-224", "wolfJCE");
        assertEquals(Sha224.DIGEST_SIZE, sha224.getDigestLength());
    }

    @Test
    public void testSha224OidAlias()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        byte[] input = "1234567890".getBytes();

        /* Get MessageDigest using algorithm name */
        MessageDigest mdAlgorithm = MessageDigest.getInstance(
            "SHA-224", "wolfJCE");
        assertNotNull(mdAlgorithm);

        /* Get MessageDigest using OID */
        MessageDigest mdOid = MessageDigest.getInstance(
            "2.16.840.1.101.3.4.2.4", "wolfJCE");
        assertNotNull(mdOid);

        /* Verify algorithm name matches */
        assertEquals("SHA-224", mdAlgorithm.getAlgorithm());

        /* Compute digests */
        mdAlgorithm.update(input);
        mdOid.update(input);

        /* Verify digests match */
        assertTrue(Arrays.equals(mdAlgorithm.digest(), mdOid.digest()));
    }
} 