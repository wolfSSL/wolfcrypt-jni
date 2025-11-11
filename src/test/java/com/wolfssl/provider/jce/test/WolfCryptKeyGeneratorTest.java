/* wolfCryptKeyGeneratorTest.java
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

import java.security.Security;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidParameterException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Sha224;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.Sha3;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

public class WolfCryptKeyGeneratorTest {

    private static String[] keyAlgorithms = {
        "AES",
        "HmacSHA1",
        "HmacSHA224",
        "HmacSHA256",
        "HmacSHA384",
        "HmacSHA512",
        "HmacSHA3-224",
        "HmacSHA3-256",
        "HmacSHA3-384",
        "HmacSHA3-512"
    };

    private static int[] aesKeySizes = { 128, 192, 256 };
    private static SecureRandom rand = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchAlgorithmException, NoSuchProviderException {

        System.out.println("JCE WolfCryptKeyGeneratorTest Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        /* Get single static SecureRandom for use in this class */
        rand = SecureRandom.getInstance("DEFAULT");
    }

    @Test
    public void testGetKeyGeneratorFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyGenerator kg;

        for (String alg : keyAlgorithms) {
            /* Skip HmacSHA224 if not supported by native wolfSSL */
            if (alg.equals("HmacSHA224") &&
                !FeatureDetect.HmacSha224Enabled()) {
                continue;
            }
            /* Skip HmacSHA3 algorithms if not supported by native wolfSSL */
            if (alg.equals("HmacSHA3-224") &&
                !FeatureDetect.HmacSha3_224Enabled()) {
                continue;
            }
            if (alg.equals("HmacSHA3-256") &&
                !FeatureDetect.HmacSha3_256Enabled()) {
                continue;
            }
            if (alg.equals("HmacSHA3-384") &&
                !FeatureDetect.HmacSha3_384Enabled()) {
                continue;
            }
            if (alg.equals("HmacSHA3-512") &&
                !FeatureDetect.HmacSha3_512Enabled()) {
                continue;
            }
            kg = KeyGenerator.getInstance(alg, "wolfJCE");
            assertNotNull(kg);
        }

        /* getting a garbage algorithm should throw an exception */
        try {
            kg = KeyGenerator.getInstance("NotValid", "wolfJCE");

            fail("KeyGenerator.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    @Test
    public void testAESKeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        testKeyGeneration("AES", aesKeySizes);
        /* Default SunJCE key size for AES is 256 bits as of JDK bug 8267319 */
        testKeyGenerationDefaultKeySize("AES", 256);
    }

    @Test
    public void testHmacSHA1KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        testKeyGeneration("HmacSHA1", new int[] { 160 });
        /* SunJCE default key size for HmacSHA1 is 64 bytes, we match theirs */
        testKeyGenerationDefaultKeySize("HmacSHA1", Sha512.DIGEST_SIZE * 8);
    }

    @Test
    public void testHmacSHA224KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Skip test if HmacSHA224 is not supported by native wolfSSL */
        if (!FeatureDetect.HmacSha224Enabled()) {
            return;
        }

        testKeyGeneration("HmacSHA224", new int[] { 224 });
        testKeyGenerationDefaultKeySize("HmacSHA224", Sha224.DIGEST_SIZE * 8);
    }

    @Test
    public void testHmacSHA256KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        testKeyGeneration("HmacSHA256", new int[] { 256 });
        testKeyGenerationDefaultKeySize("HmacSHA256", Sha256.DIGEST_SIZE * 8);
    }

    @Test
    public void testHmacSHA384KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        testKeyGeneration("HmacSHA384", new int[] { 384 });
        testKeyGenerationDefaultKeySize("HmacSHA384", Sha384.DIGEST_SIZE * 8);
    }

    @Test
    public void testHmacSHA512KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        testKeyGeneration("HmacSHA512", new int[] { 512 });
        testKeyGenerationDefaultKeySize("HmacSHA512", Sha512.DIGEST_SIZE * 8);
    }

    @Test
    public void testHmacSHA3_224KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Skip test if HmacSHA3-224 is not supported by native wolfSSL */
        if (!FeatureDetect.HmacSha3_224Enabled()) {
            return;
        }

        testKeyGeneration("HmacSHA3-224", new int[] { 224 });
        testKeyGenerationDefaultKeySize("HmacSHA3-224",
            Sha3.DIGEST_SIZE_224 * 8);
    }

    @Test
    public void testHmacSHA3_256KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Skip test if HmacSHA3-256 is not supported by native wolfSSL */
        if (!FeatureDetect.HmacSha3_256Enabled()) {
            return;
        }

        testKeyGeneration("HmacSHA3-256", new int[] { 256 });
        testKeyGenerationDefaultKeySize("HmacSHA3-256",
            Sha3.DIGEST_SIZE_256 * 8);
    }

    @Test
    public void testHmacSHA3_384KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Skip test if HmacSHA3-384 is not supported by native wolfSSL */
        if (!FeatureDetect.HmacSha3_384Enabled()) {
            return;
        }

        testKeyGeneration("HmacSHA3-384", new int[] { 384 });
        testKeyGenerationDefaultKeySize("HmacSHA3-384",
            Sha3.DIGEST_SIZE_384 * 8);
    }

    @Test
    public void testHmacSHA3_512KeyGeneration()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        /* Skip test if HmacSHA3-512 is not supported by native wolfSSL */
        if (!FeatureDetect.HmacSha3_512Enabled()) {
            return;
        }

        testKeyGeneration("HmacSHA3-512", new int[] { 512 });
        testKeyGenerationDefaultKeySize("HmacSHA3-512",
            Sha3.DIGEST_SIZE_512 * 8);
    }

    /**
     * Test that KeyGenerator generates expected default sized keys when
     * no size is explicitly given.
     */
    private void testKeyGenerationDefaultKeySize(String algorithm,
        int expectedSize) throws NoSuchProviderException,
        NoSuchAlgorithmException {

        KeyGenerator kg = null;
        SecretKey key = null;

        kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
        assertNotNull(kg);

        key = kg.generateKey();
        assertNotNull(key);
        assertEquals(expectedSize, key.getEncoded().length * 8);
    }

    private void testKeyGeneration(String algorithm, int[] keySizes)
        throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyGenerator kg = null;
        SecretKey key = null;

        /* Testing generation with init(int keysize) */
        for (int size : keySizes) {
            kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
            assertNotNull(kg);

            kg.init(size);
            key = kg.generateKey();

            assertNotNull(key);
            assertEquals(size / 8, key.getEncoded().length);
        }

        /* Testing generation with init(int keysize, SecureRandom random) */
        for (int size : keySizes) {
            kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
            assertNotNull(kg);

            kg.init(size, rand);
            key = kg.generateKey();

            assertNotNull(key);
            assertEquals(size / 8, key.getEncoded().length);
        }

        /* Test invalid AES size */
        if (algorithm.equals("AES")) {
            kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
            assertNotNull(kg);
            try {
                kg.init(0);
                fail("KeyGenerator.init should throw " +
                     "InvalidParameterException when given invalid key size");
            } catch (InvalidParameterException e) {
                /* expected */
            }
        }

        /* If running under wolfCrypt FIPS, we should fail if SecureRandom is
         * not wolfJCE */
        if (Fips.enabled) {
            try {
                rand = SecureRandom.getInstance("SHA1PRNG", "SUN");
            } catch (NoSuchProviderException e) {
                /* skip, SUN provider not available */
                return;
            }

            kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
            assertNotNull(kg);
            try {
                kg.init(keySizes[0], rand);
                fail("KeyGenerator.init should throw " +
                     "InvalidParameterException when given non-FIPS wolfJCE " +
                     "SecureRandom when in FIPS mode");
            } catch (InvalidParameterException e) {
                /* expected */
            }

            /* Reset SecureRandom to our own (or default) */
            rand = SecureRandom.getInstance("DEFAULT");
        }

        /* Test that we fail if given null AlgorithmParameters */
        kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
        assertNotNull(kg);
        try {
            kg.init((AlgorithmParameterSpec)null);
            fail("KeyGenerator.init should throw InvalidParameterException " +
                 "when given AlgorithmParameters");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }

        try {
            kg.init(null, rand);
            fail("KeyGenerator.init should throw InvalidParameterException " +
                 "when given null AlgorithmParameters and SecureRandom");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }

        /* Test that we fail if given valid non-null AlgorithmParameters */
        kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
        assertNotNull(kg);
        try {
            AlgorithmParameterSpec ap = new AlgorithmParameterSpec() {};
            kg.init(ap);
            fail("KeyGenerator.init should throw InvalidParameterException " +
                 "when given AlgorithmParameters");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }

        /* Generate 10 keys and make sure they are different, sanity check */
        kg = KeyGenerator.getInstance(algorithm, "wolfJCE");
        assertNotNull(kg);
        kg.init(keySizes[0], rand);

        SecretKey[] keys = new SecretKey[10];
        for (int i = 0; i < 10; i++) {
            keys[i] = kg.generateKey();
            assertNotNull(keys[i]);
        }

        for (int i = 0; i < 10; i++) {
            for (int j = i + 1; j < keys.length; j++) {
                assertFalse(keys[i].equals(keys[j]));
                assertFalse(java.util.Arrays.equals(keys[i].getEncoded(),
                                                    keys[j].getEncoded()));
            }
        }
    }

    /**
     * Verify that AES KeyGenerator supports default initialization when
     * init() is not called, and that the default key size is 256 bits.
     */
    @Test
    public void testAESDefaultKeySize256Bits()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyGenerator kg = KeyGenerator.getInstance("AES", "wolfJCE");
        assertNotNull(kg);

        /* Generate key without calling init() - should use default size */
        SecretKey keyWithDefaultSize = kg.generateKey();
        assertNotNull(keyWithDefaultSize);

        byte[] encoding = keyWithDefaultSize.getEncoded();
        assertNotNull(encoding);

        int defKeyLen = encoding.length;
        assertTrue("default key length is 0!", defKeyLen > 0);

        /* Default key size should be 256 bits (32 bytes) as of
         * JDK bug 8267319 */
        assertEquals("default key length mismatch! Expected 32 bytes " +
            "(256 bits), got " + defKeyLen + " bytes",
            32, defKeyLen);

        /* Test that we can explicitly generate all valid sizes */
        int[] validSizes = { 128, 192, 256 };
        for (int size : validSizes) {
            kg.init(size);
            SecretKey key = kg.generateKey();
            assertNotNull(key);
            assertEquals("key generated with wrong length for size " + size,
                size / 8, key.getEncoded().length);
        }

        /* Test that invalid key size throws exception */
        try {
            kg.init(257); /* invalid - not 128, 192, or 256 */
            fail("init() should throw InvalidParameterException for " +
                "invalid key size");
        } catch (InvalidParameterException e) {
            /* expected */
        }
    }
}

