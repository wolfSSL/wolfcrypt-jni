/* wolfCryptSecretKeyFactoryTest.java
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

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.security.Security;
import java.security.Provider;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Cipher;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfCryptSecretKeyFactoryTest {

    /* Test provider, switching this here will run all tests below
     * against the given provider. */
    private static final String provider = "wolfJCE";

    private static String wolfJCEAlgos[] = {
        "PBKDF2WithHmacSHA1",
        "PBKDF2WithHmacSHA224",
        "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA384",
        "PBKDF2WithHmacSHA512",
        "PBKDF2WithHmacSHA3-224",
        "PBKDF2WithHmacSHA3-256",
        "PBKDF2WithHmacSHA3-384",
        "PBKDF2WithHmacSHA3-512",
        "AES"
    };

    private static ArrayList<String> enabledAlgos =
        new ArrayList<String>();

    private boolean algoSupported(String algo) {
        return enabledAlgos.contains(algo);
    }

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void testProviderInstallationAtRuntime()
        throws NoSuchProviderException {

        SecretKeyFactory kf;

        System.out.println("JCE WolfCryptSecretKeyFactory Class");

        /* Install wolfJCE provider at runtime. Not registering as top priority
         * provider so we can still likely get SunJCE or platform provider
         * when not specifying wolfJCE explicitly. */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider(provider);
        assertNotNull(p);

        /* populate enabledAlgos, some native features may be compiled out */
        for (int i = 0; i < wolfJCEAlgos.length; i++) {
            try {
                kf = SecretKeyFactory.getInstance(wolfJCEAlgos[i], provider);
                assertNotNull(kf);
                enabledAlgos.add(wolfJCEAlgos[i]);
            } catch (NoSuchAlgorithmException e) {
                /* algo not compiled in */
            }
        }
    }

    @Test
    public void testGetSecretKeyFactoryFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        SecretKeyFactory kf;

        /* try to get all available options we expect to have */
        for (int i = 0; i < enabledAlgos.size(); i++) {
            kf = SecretKeyFactory.getInstance(enabledAlgos.get(i), provider);
        }

        /* getting a garbage algorithm should throw an exception */
        try {
            kf = SecretKeyFactory.getInstance("NotValid", provider);
            assertNotNull(kf);

            fail("SecretKeyFactory.getInstance should throw " +
                 "NoSuchAlgorithmException when given bad algorithm value");

        } catch (NoSuchAlgorithmException e) { }
    }

    /**
     * PBKDF2-HMAC-SHA1 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA1()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0xba, (byte)0x9b, (byte)0x3b, (byte)0x95,
            (byte)0x04, (byte)0x4d, (byte)0x78, (byte)0x11,
            (byte)0xec, (byte)0xa1, (byte)0xff, (byte)0x3f,
            (byte)0xea, (byte)0x3a, (byte)0xdb, (byte)0x55,
            (byte)0x3e, (byte)0x54, (byte)0x0b, (byte)0xa0,
            (byte)0x9f, (byte)0xad, (byte)0xe6, (byte)0x81
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacShaEnabled() ||
            !algoSupported("PBKDF2WithHmacSHA1")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA1) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA224 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA224()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0xeb, (byte)0xa2, (byte)0x2b, (byte)0x95,
            (byte)0x0d, (byte)0x5b, (byte)0xf5, (byte)0x74,
            (byte)0x2b, (byte)0xa2, (byte)0x8d, (byte)0xb0,
            (byte)0x6e, (byte)0x19, (byte)0xe7, (byte)0x61,
            (byte)0x57, (byte)0xa3, (byte)0x19, (byte)0xe7,
            (byte)0x5f, (byte)0xfa, (byte)0x22, (byte)0xb2
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha224Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA224")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA224) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA224", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA256 basic test vector.
     *
     * This test vector comes directly from native wolfCrypt
     * wolfcrypt/test/test.c.
     */
    @Test
    public void testPBKDF2WithHmacSHA256()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x43, (byte)0x6d, (byte)0xb5, (byte)0xe8,
            (byte)0xd0, (byte)0xfb, (byte)0x3f, (byte)0x35,
            (byte)0x42, (byte)0x48, (byte)0x39, (byte)0xbc,
            (byte)0x2d, (byte)0xd4, (byte)0xf9, (byte)0x37,
            (byte)0xd4, (byte)0x95, (byte)0x16, (byte)0xa7,
            (byte)0x2a, (byte)0x9a, (byte)0x21, (byte)0xd1
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA256) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA384 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA384()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0xa4, (byte)0xf5, (byte)0x63, (byte)0x91,
            (byte)0x66, (byte)0xd9, (byte)0xe6, (byte)0xec,
            (byte)0xa2, (byte)0x52, (byte)0x58, (byte)0x06,
            (byte)0xa9, (byte)0x8c, (byte)0x18, (byte)0xc1,
            (byte)0x81, (byte)0x2e, (byte)0xc2, (byte)0xfa,
            (byte)0x8d, (byte)0x3d, (byte)0xb8, (byte)0x38
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha384Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA384")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA384) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA384", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA512 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA512()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0xa9, (byte)0x2f, (byte)0x3e, (byte)0x9c,
            (byte)0xb1, (byte)0xcd, (byte)0x5b, (byte)0xab,
            (byte)0xb6, (byte)0x43, (byte)0xe6, (byte)0x70,
            (byte)0x2f, (byte)0x91, (byte)0x29, (byte)0x03,
            (byte)0x93, (byte)0xdb, (byte)0x48, (byte)0x69,
            (byte)0x93, (byte)0x01, (byte)0x29, (byte)0x42
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha512Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA512")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA512) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA3-224 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA3_224()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x66, (byte)0x63, (byte)0x94, (byte)0xe8,
            (byte)0x75, (byte)0x02, (byte)0xdb, (byte)0xad,
            (byte)0x64, (byte)0x5b, (byte)0xcd, (byte)0x28,
            (byte)0xae, (byte)0x59, (byte)0xe5, (byte)0x89,
            (byte)0x97, (byte)0x35, (byte)0xb4, (byte)0x8c,
            (byte)0xc3, (byte)0xe9, (byte)0x02, (byte)0x0e
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha3_224Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA3-224")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA3-224) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA3-224", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA3-256 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA3_256()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0xc3, (byte)0xdb, (byte)0x13, (byte)0x90,
            (byte)0x0f, (byte)0x34, (byte)0x54, (byte)0xcf,
            (byte)0x44, (byte)0x8a, (byte)0xae, (byte)0xda,
            (byte)0x6f, (byte)0xa4, (byte)0x98, (byte)0xad,
            (byte)0x8e, (byte)0x2d, (byte)0x73, (byte)0xb2,
            (byte)0x8b, (byte)0xfd, (byte)0x27, (byte)0x46
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha3_256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA3-256")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA3-256) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA3-256", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA3-384 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA3_384()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x81, (byte)0x76, (byte)0xf5, (byte)0x57,
            (byte)0x38, (byte)0x0d, (byte)0x76, (byte)0x32,
            (byte)0x62, (byte)0xf1, (byte)0xb0, (byte)0xc2,
            (byte)0xe6, (byte)0x66, (byte)0xbf, (byte)0xc3,
            (byte)0x9f, (byte)0xc3, (byte)0x7b, (byte)0x3b,
            (byte)0x44, (byte)0x11, (byte)0x81, (byte)0x5b
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha3_384Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA3-384")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA3-384) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA3-384", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * PBKDF2-HMAC-SHA3-512 basic test vector.
     *
     * This test vector was generated from native wolfCrypt, based off
     * the same parameters as the PBKDF2-HMAC-SHA256 vector in
     * wolfcrypt/test/test.c. This is meant to test basic functionality.
     */
    @Test
    public void testPBKDF2WithHmacSHA3_512()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x90, (byte)0x6e, (byte)0x60, (byte)0xce,
            (byte)0xdf, (byte)0xcb, (byte)0xcd, (byte)0x56,
            (byte)0x44, (byte)0xc7, (byte)0xf6, (byte)0x9a,
            (byte)0xbb, (byte)0x68, (byte)0x63, (byte)0x77,
            (byte)0xc4, (byte)0x4b, (byte)0x83, (byte)0x7d,
            (byte)0x11, (byte)0x97, (byte)0x67, (byte)0xc8
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha3_512Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA3-512")) {
            System.out.println(
                "Skipped: SecretKeyFactory(PBKDF2WithHmacSHA3-512) test");
            Assume.assumeTrue(false);
        }

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA3-512", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * Test that calling generateSecret() with null or invalid
     * KeySpec throws exception.
     */
    @Test
    public void testPBKDF2WithHmacSHA256_InvalidKeySpec()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            /* skip */
            Assume.assumeTrue(false);
        }

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider);
        assertNotNull(sf);

        /* null KeySpec should throw exception */
        try {
            sf.generateSecret(spec);
            fail("generateSecret() should fail with null KeySpec");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    /**
     * Test calling generateSecret() with null password.
     */
    @Test
    public void testPBKDF2WithHmacSHA256_NullPassword()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0xf7, (byte)0x39, (byte)0xde, (byte)0x5c,
            (byte)0x50, (byte)0x14, (byte)0xf5, (byte)0xc3,
            (byte)0x19, (byte)0xae, (byte)0x5e, (byte)0x13,
            (byte)0x24, (byte)0x83, (byte)0xa2, (byte)0x39,
            (byte)0xca, (byte)0xf5, (byte)0x34, (byte)0xbf,
            (byte)0xed, (byte)0x2e, (byte)0xa0, (byte)0x32
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256") ||
            Fips.enabled) {
            /* skip if algo not available for in FIPS mode, since HMAC
             * minimum key size (14) won't allow use of zero length pass. */
            Assume.assumeTrue(false);
        }

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider);
        assertNotNull(sf);

        /* test with null password */
        spec = new PBEKeySpec(null, salt, iterations, kLen);
        assertNotNull(spec);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));

        /* test with empty (new char[0]) password */
        spec = new PBEKeySpec(new char[0], salt, iterations, kLen);
        assertNotNull(spec);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    @Test
    public void testPBKDF2WithHmacSHA256_Interop()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        PBEKeySpec spec = null;
        SecretKey key = null;

        SecretKeyFactory sysFact = null;
        SecretKeyFactory wolfFact = null;
        byte[] sysResult = null;
        byte[] wolfResult = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            /* skipped */
            Assume.assumeTrue(false);
        }

        sysFact = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        Provider provider = sysFact.getProvider();

        if (!provider.equals("wolfJCE")) {

            wolfFact = SecretKeyFactory.getInstance(
                "PBKDF2WithHmacSHA256", "wolfJCE");

            /* Set up one KeySpec for both providers to use */
            spec = new PBEKeySpec(pass, salt, iterations, kLen);
            assertNotNull(spec);

            /* Generate secret from system provider */
            key = sysFact.generateSecret(spec);
            sysResult = key.getEncoded();

            /* Generate secret from wolfJCE provider */
            key = wolfFact.generateSecret(spec);
            wolfResult = key.getEncoded();

            assertTrue(Arrays.equals(sysResult, wolfResult));
        }
    }

    /**
     * Test getting KeySpec from SecretKey object using
     * SecretKeyFactory.getKeySpec().
     */
    @Test
    public void testGetKeySpec()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException, InterruptedException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x43, (byte)0x6d, (byte)0xb5, (byte)0xe8,
            (byte)0xd0, (byte)0xfb, (byte)0x3f, (byte)0x35,
            (byte)0x42, (byte)0x48, (byte)0x39, (byte)0xbc,
            (byte)0x2d, (byte)0xd4, (byte)0xf9, (byte)0x37,
            (byte)0xd4, (byte)0x95, (byte)0x16, (byte)0xa7,
            (byte)0x2a, (byte)0x9a, (byte)0x21, (byte)0xd1
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        KeySpec spec2 = null;
        PBEKeySpec pbSpec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            /* skipped */
            Assume.assumeTrue(false);
        }

        /* Generate secret, setting up known PBEKeySpec */
        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider);
        assertNotNull(sf);

        key = sf.generateSecret(spec);
        assertNotNull(key);
        result = key.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));

        /* Try to get KeySpec directly from generated SecretKey */
        spec2 = sf.getKeySpec(key, PBEKeySpec.class);
        assertNotNull(spec2);

        /* Test that the KeySpec we got is as expected */
        assertTrue(spec2 instanceof PBEKeySpec);
        pbSpec = (PBEKeySpec)spec2;
        assertTrue(Arrays.equals(pbSpec.getPassword(), pass));
        assertTrue(Arrays.equals(pbSpec.getSalt(), salt));
        assertEquals(pbSpec.getIterationCount(), iterations);
    }

    /**
     * Test that getKeySpec() returns PBEKeySpec with key length in bits.
     */
    @Test
    public void testGetKeySpecReturnsKeyLengthInBits()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int[] keySizes = { 128, 192, 256 }; /* key sizes in bits */
        PBEKeySpec spec = null;
        PBEKeySpec retrievedSpec = null;
        SecretKeyFactory sf = null;
        SecretKey key = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            /* skipped */
            Assume.assumeTrue(false);
        }

        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider);
        assertNotNull(sf);

        /* Test multiple key sizes */
        for (int kLen : keySizes) {
            /* Generate secret with key length in bits */
            spec = new PBEKeySpec(pass, salt, iterations, kLen);
            assertNotNull(spec);

            key = sf.generateSecret(spec);
            assertNotNull(key);

            /* Get KeySpec back from SecretKey */
            retrievedSpec = (PBEKeySpec)sf.getKeySpec(key, PBEKeySpec.class);
            assertNotNull(retrievedSpec);

            /* Verify all parameters match, including key length in bits */
            assertTrue(Arrays.equals(retrievedSpec.getPassword(), pass));
            assertTrue(Arrays.equals(retrievedSpec.getSalt(), salt));
            assertEquals(retrievedSpec.getIterationCount(), iterations);

            assertEquals("Key length should be in bits, not bytes",
                kLen, retrievedSpec.getKeyLength());
        }
    }

    /**
     * Test translating existing SecretKey object to one generated
     * by SecretKeyFactory using translateKey().
     */
    @Test
    public void testTranslateKey()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException, InterruptedException,
               InvalidKeyException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x43, (byte)0x6d, (byte)0xb5, (byte)0xe8,
            (byte)0xd0, (byte)0xfb, (byte)0x3f, (byte)0x35,
            (byte)0x42, (byte)0x48, (byte)0x39, (byte)0xbc,
            (byte)0x2d, (byte)0xd4, (byte)0xf9, (byte)0x37,
            (byte)0xd4, (byte)0x95, (byte)0x16, (byte)0xa7,
            (byte)0x2a, (byte)0x9a, (byte)0x21, (byte)0xd1
        };
        byte[] result = null;
        PBEKeySpec spec = null;
        SecretKeyFactory sf = null;
        SecretKey keyA = null;
        SecretKey keyB = null;

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            /* skipped */
            Assume.assumeTrue(false);
        }

        /* Generate SecretKey from SecretKeyFactory without specifying
         * provider. This will use system provider if wolfJCE is not registered
         * as top priority in system, otherwise will use wolfJCE. Still a good
         * test, but not as accurate as testing translation between different
         * providers */
        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        assertNotNull(sf);

        spec = new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        keyA = sf.generateSecret(spec);
        assertNotNull(keyA);
        result = keyA.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));

        /* Try translating SecretKey to SecretKeyFactory of type wolfJCE */
        sf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "wolfJCE");
        assertNotNull(sf);

        keyB = sf.translateKey(keyA);
        assertNotNull(keyB);
        result = keyB.getEncoded();
        assertNotNull(result);
        assertTrue(Arrays.equals(result, verify));
    }

    /**
     * Set up one SecretKeyFactory and KeySpec, then test parallel
     * threaded calls to generateSecret.
     */
    @Test
    public void testPBKDF2WithHmacSHA256_ThreadedGenerateSecret()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException, InterruptedException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x43, (byte)0x6d, (byte)0xb5, (byte)0xe8,
            (byte)0xd0, (byte)0xfb, (byte)0x3f, (byte)0x35,
            (byte)0x42, (byte)0x48, (byte)0x39, (byte)0xbc,
            (byte)0x2d, (byte)0xd4, (byte)0xf9, (byte)0x37,
            (byte)0xd4, (byte)0x95, (byte)0x16, (byte)0xa7,
            (byte)0x2a, (byte)0x9a, (byte)0x21, (byte)0xd1
        };

        int numThreads = 30;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            System.out.println(
                "Skipped: SecretKeyFactory(generateSecret) threaded test");
            Assume.assumeTrue(false);
        }

        /* Set up one SecretKeyFactory and KeySpec, we want to test
         * threaded call to generateSecret() */
        final SecretKeyFactory sf =
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", provider);
        assertNotNull(sf);

        final PBEKeySpec spec =
            new PBEKeySpec(pass, salt, iterations, kLen);
        assertNotNull(spec);

        /* Insert/store/load/verify from numThreads parallel threads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int ret = 0;
                    byte[] result = null;
                    SecretKey key = null;
                    try {
                        try {
                            key = sf.generateSecret(spec);
                            if (key == null) {
                                ret = 1;
                            }
                        } catch (InvalidKeySpecException e) {
                            ret = 1;
                        }

                        if (ret == 0) {
                            result = key.getEncoded();
                            if (result == null) {
                                ret = 1;
                            }
                        }
                        if (ret == 0) {
                            if (!Arrays.equals(result, verify)) {
                                ret = 1;
                            }
                        }

                        /* record error if we got one */
                        if (ret != 0) {
                            results.add(1);
                        }
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in generateSecret() threaded test");
            }
        }
    }

    /**
     * Test creating SecretKeyFactory/KeySpec in parallel across multiple
     * threads, with each one calling generateSecret().
     */
    @Test
    public void testPBKDF2WithHmacSHA256_ThreadedSecretKeyFactory()
        throws NoSuchAlgorithmException, InvalidKeySpecException,
               NoSuchProviderException, InterruptedException {

        char[] pass = "passwordpassword".toCharArray();
        byte[] salt = {
            (byte)0x78, (byte)0x57, (byte)0x8E, (byte)0x5a,
            (byte)0x5d, (byte)0x63, (byte)0xcb, (byte)0x06
        };
        int iterations = 2048;
        int kLen = 192;
        byte[] verify = {
            (byte)0x43, (byte)0x6d, (byte)0xb5, (byte)0xe8,
            (byte)0xd0, (byte)0xfb, (byte)0x3f, (byte)0x35,
            (byte)0x42, (byte)0x48, (byte)0x39, (byte)0xbc,
            (byte)0x2d, (byte)0xd4, (byte)0xf9, (byte)0x37,
            (byte)0xd4, (byte)0x95, (byte)0x16, (byte)0xa7,
            (byte)0x2a, (byte)0x9a, (byte)0x21, (byte)0xd1
        };

        int numThreads = 30;
        ExecutorService service = Executors.newFixedThreadPool(numThreads);
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final LinkedBlockingQueue<Integer> results =
            new LinkedBlockingQueue<>();

        if (!FeatureDetect.Pbkdf2Enabled() ||
            !FeatureDetect.HmacSha256Enabled() ||
            !algoSupported("PBKDF2WithHmacSHA256")) {
            System.out.println(
                "Skipped: SecretKeyFactory threaded test");
            Assume.assumeTrue(false);
        }

        /* Insert/store/load/verify from numThreads parallel threads */
        for (int i = 0; i < numThreads; i++) {
            service.submit(new Runnable() {
                @Override public void run() {

                    int ret = 0;
                    byte[] result = null;
                    SecretKey key = null;
                    SecretKeyFactory sf = null;
                    PBEKeySpec spec = null;

                    try {
                        try {
                            sf = SecretKeyFactory.getInstance(
                                "PBKDF2WithHmacSHA256", provider);
                            if (sf == null) {
                                throw new InvalidKeySpecException("fail");
                            }

                            spec = new PBEKeySpec(pass, salt, iterations, kLen);
                            if (spec == null) {
                                throw new InvalidKeySpecException("fail");
                            }

                            key = sf.generateSecret(spec);
                            if (key == null) {
                                throw new InvalidKeySpecException("fail");
                            }

                        } catch (InvalidKeySpecException |
                                 NoSuchAlgorithmException |
                                 NoSuchProviderException e) {
                            ret = 1;
                        }

                        if (ret == 0) {
                            result = key.getEncoded();
                            if (result == null) {
                                ret = 1;
                            }
                        }
                        if (ret == 0) {
                            if (!Arrays.equals(result, verify)) {
                                ret = 1;
                            }
                        }

                        /* record error if we got one */
                        if (ret != 0) {
                            results.add(1);
                        }
                    } finally {
                        latch.countDown();
                    }
                }
            });
        }

        /* wait for all threads to complete */
        latch.await();

        /* compare all digests, all should be the same across threads */
        Iterator<Integer> listIterator = results.iterator();
        while (listIterator.hasNext()) {
            Integer cur = listIterator.next();
            if (cur == 1) {
                fail("Threading error in generateSecret() threaded test");
            }
        }
    }

    @Test
    public void testGetAESSecretKeyFactoryFromProvider()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        if (!algoSupported("AES")) {
            return;
        }

        SecretKeyFactory skf = SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        /* test invalid algorithm */
        try {
            skf = SecretKeyFactory.getInstance("NotValidAlgo", provider);
            fail("SecretKeyFactory.getInstance should throw " +
                 "NoSuchAlgorithmException");
        } catch (NoSuchAlgorithmException e) {
            /* expected */
        }
    }

    @Test
    public void testAESGenerateSecret128bit()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        if (!algoSupported("AES")) {
            return;
        }

        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes, (byte)0x2A);

        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        SecretKey key = skf.generateSecret(spec);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertTrue(Arrays.equals(keyBytes, key.getEncoded()));
    }

    @Test
    public void testAESGenerateSecret192bit()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        if (!algoSupported("AES")) {
            return;
        }

        byte[] keyBytes = new byte[Aes.KEY_SIZE_192];
        Arrays.fill(keyBytes, (byte)0x2A);

        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        SecretKey key = skf.generateSecret(spec);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertTrue(Arrays.equals(keyBytes, key.getEncoded()));
    }

    @Test
    public void testAESGenerateSecret256bit()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        if (!algoSupported("AES")) {
            return;
        }

        byte[] keyBytes = new byte[Aes.KEY_SIZE_256];
        Arrays.fill(keyBytes, (byte)0x2A);

        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        SecretKey key = skf.generateSecret(spec);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
        assertTrue(Arrays.equals(keyBytes, key.getEncoded()));
    }

    @Test
    public void testAESGenerateSecretInvalidKeySize()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        if (!algoSupported("AES")) {
            return;
        }

        byte[][] invalidSizes = {
            new byte[8],   /* too small */
            new byte[Aes.KEY_SIZE_128 - 1],  /* one less than 128-bit */
            new byte[Aes.KEY_SIZE_128 + 1],  /* one more than 128-bit */
            new byte[Aes.KEY_SIZE_256 - 1],  /* one less than 256-bit */
            new byte[Aes.KEY_SIZE_256 + 1]   /* one more than 256-bit */
        };

        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        for (byte[] keyBytes : invalidSizes) {
            try {
                SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
                skf.generateSecret(spec);
                fail("generateSecret should throw InvalidKeySpecException " +
                     "for invalid key size: " + keyBytes.length);
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testAESGenerateSecretNullSpec()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        if (!algoSupported("AES")) {
            return;
        }

        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        try {
            skf.generateSecret(null);
            fail("generateSecret should throw InvalidKeySpecException " +
                 "for null KeySpec");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void testAESGenerateSecretWrongSpecType()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        if (!algoSupported("AES")) {
            return;
        }

        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        /* Try to use PBEKeySpec with AES factory */
        try {
            PBEKeySpec pbeSpec = new PBEKeySpec(
                "password".toCharArray(),
                new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
                1000, Aes.KEY_SIZE_128 * 8);
            skf.generateSecret(pbeSpec);
            fail("generateSecret should throw InvalidKeySpecException " +
                 "for wrong KeySpec type");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void testAESGetKeySpec()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        if (!algoSupported("AES")) {
            return;
        }

        byte[] keyBytes = new byte[16];
        Arrays.fill(keyBytes, (byte)0x2A);

        SecretKeySpec originalSpec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        SecretKey key = skf.generateSecret(originalSpec);
        assertNotNull(key);

        SecretKeySpec retrievedSpec =
            (SecretKeySpec)skf.getKeySpec(key, SecretKeySpec.class);
        assertNotNull(retrievedSpec);

        assertEquals("AES", retrievedSpec.getAlgorithm());
        assertTrue(Arrays.equals(keyBytes, retrievedSpec.getEncoded()));
    }

    @Test
    public void testAESGetKeySpecInvalidType()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        if (!algoSupported("AES")) {
            return;
        }

        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes, (byte)0x2A);

        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        SecretKey key = skf.generateSecret(spec);
        assertNotNull(key);

        /* Try to get PBEKeySpec from AES key */
        try {
            skf.getKeySpec(key, PBEKeySpec.class);
            fail("getKeySpec should throw InvalidKeySpecException " +
                 "for incompatible spec type");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void testAESTranslateKey()
        throws NoSuchProviderException, NoSuchAlgorithmException,
               InvalidKeySpecException, InvalidKeyException {

        if (!algoSupported("AES")) {
            return;
        }

        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes, (byte)0x2A);

        /* Create key from one factory instance */
        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory skf1 =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf1);

        SecretKey key1 = skf1.generateSecret(spec);
        assertNotNull(key1);

        /* Translate to another factory instance */
        SecretKeyFactory skf2 =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf2);

        SecretKey key2 = skf2.translateKey(key1);
        assertNotNull(key2);

        /* Verify keys are equal */
        assertEquals("AES", key2.getAlgorithm());
        assertTrue(Arrays.equals(key1.getEncoded(), key2.getEncoded()));
    }

    @Test
    public void testAESTranslateKeyNullKey()
        throws NoSuchProviderException, NoSuchAlgorithmException {

        if (!algoSupported("AES")) {
            return;
        }

        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        try {
            skf.translateKey(null);
            fail("translateKey should throw InvalidKeyException " +
                 "for null key");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void testAESSecretKeyWithCipher()
        throws Exception {

        if (!algoSupported("AES")) {
            return;
        }

        byte[] keyBytes = new byte[Aes.KEY_SIZE_128];
        Arrays.fill(keyBytes, (byte)0x2A);
        byte[] iv = new byte[Aes.BLOCK_SIZE];
        Arrays.fill(iv, (byte)0x01);

        /* Generate AES key using SecretKeyFactory */
        SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("AES", provider);
        assertNotNull(skf);

        SecretKey key = skf.generateSecret(spec);
        assertNotNull(key);

        /* Use key with Cipher */
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider);
        assertNotNull(cipher);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] plaintext = "Hello World!".getBytes();

        /* Encrypt */
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        assertNotNull(ciphertext);

        /* Decrypt */
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        assertNotNull(decrypted);

        /* Verify round-trip */
        assertTrue(Arrays.equals(plaintext, decrypted));
    }
}

