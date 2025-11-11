/* WolfCryptRSAKeyFactoryTest.java
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

import java.util.ArrayList;
import java.util.Arrays;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit4 test cases for WolfCryptRSAKeyFactory
 */
public class WolfCryptRSAKeyFactoryTest {

    /* Test with multiple RSA key sizes */
    private static int[] testKeySizes = {
        2048,
        3072,
        4096
    };

    /* Minimum RSA key size supported by wolfSSL */
    private static int minRsaKeySize = Rsa.RSA_MIN_SIZE;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallation() {

        /* Install wolfJCE provider for testing */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        System.out.println("JCE WolfCryptRSAKeyFactory Class");

        if (!FeatureDetect.RsaEnabled()) {
            System.out.println("RSA support not compiled in, skipping");
            return;
        }

        if (!FeatureDetect.WolfSSLPublicMpEnabled()) {
            System.out.println(
                "WOLFSSL_PUBLIC_MP not defined, RSA KeyFactory " +
                "unavailable, skipping");
            return;
        }
    }

    /**
     * Helper method to check if RSA KeyFactory is available.
     * RSA KeyFactory requires both RSA support and WOLFSSL_PUBLIC_MP.
     *
     * @return true if RSA KeyFactory is available, false otherwise
     */
    private static boolean rsaKeyFactoryAvailable() {
        return FeatureDetect.RsaEnabled() &&
               FeatureDetect.WolfSSLPublicMpEnabled();
    }

    @Test
    public void testGetInstanceRSA() throws NoSuchAlgorithmException {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA");
        assertNotNull(kf);
        assertEquals("RSA", kf.getAlgorithm());

        Provider prov = kf.getProvider();
        assertNotNull(prov);
        assertEquals("wolfJCE", prov.getName());
    }

    @Test
    public void testGeneratePublicFromX509Spec()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        for (int keySize : testKeySizes) {
            if (keySize < minRsaKeySize) {
                continue;
            }

            /* Generate RSA key pair using standard provider */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            KeyPair pair = kpg.generateKeyPair();
            assertNotNull(pair);

            /* Get X509 encoded public key */
            PublicKey pub = pair.getPublic();
            assertNotNull(pub);
            byte[] encoded = pub.getEncoded();
            assertNotNull(encoded);

            /* Create X509EncodedKeySpec and generate public key */
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
            PublicKey generated = kf.generatePublic(spec);
            assertNotNull(generated);
            assertTrue(generated instanceof RSAPublicKey);

            /* Verify encoded forms match */
            assertArrayEquals(encoded, generated.getEncoded());
        }
    }

    @Test
    public void testGeneratePrivateFromPKCS8Spec()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        for (int keySize : testKeySizes) {
            if (keySize < minRsaKeySize) {
                continue;
            }

            /* Generate RSA key pair using standard provider */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            KeyPair pair = kpg.generateKeyPair();
            assertNotNull(pair);

            /* Get PKCS8 encoded private key */
            PrivateKey priv = pair.getPrivate();
            assertNotNull(priv);
            byte[] encoded = priv.getEncoded();
            assertNotNull(encoded);

            /* Create PKCS8EncodedKeySpec and generate private key */
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
            PrivateKey generated = kf.generatePrivate(spec);
            assertNotNull(generated);
            assertTrue(generated instanceof RSAPrivateCrtKey);

            /* Verify encoded forms match */
            assertArrayEquals(encoded, generated.getEncoded());
        }
    }

    @Test
    public void testGeneratePublicFromRSAPublicKeySpec()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        for (int keySize : testKeySizes) {
            if (keySize < minRsaKeySize) {
                continue;
            }

            /* Generate RSA key pair */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            KeyPair pair = kpg.generateKeyPair();
            RSAPublicKey pubKey = (RSAPublicKey)pair.getPublic();
            assertNotNull(pubKey);

            /* Extract modulus and public exponent */
            BigInteger n = pubKey.getModulus();
            BigInteger e = pubKey.getPublicExponent();
            assertNotNull(n);
            assertNotNull(e);

            /* Create RSAPublicKeySpec and generate public key */
            RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
            PublicKey generated = kf.generatePublic(spec);
            assertNotNull(generated);
            assertTrue(generated instanceof RSAPublicKey);

            /* Verify components match */
            RSAPublicKey genPub = (RSAPublicKey)generated;
            assertEquals(n, genPub.getModulus());
            assertEquals(e, genPub.getPublicExponent());
        }
    }

    @Test
    public void testGetKeySpecPublicX509()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        /* Generate RSA key pair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        PublicKey pub = pair.getPublic();
        byte[] origEncoded = pub.getEncoded();

        /* Import into wolfJCE */
        X509EncodedKeySpec inSpec = new X509EncodedKeySpec(origEncoded);
        PublicKey wolfPub = kf.generatePublic(inSpec);

        /* Extract X509EncodedKeySpec */
        X509EncodedKeySpec outSpec =
            kf.getKeySpec(wolfPub, X509EncodedKeySpec.class);
        assertNotNull(outSpec);

        /* Verify encoded forms match */
        assertArrayEquals(origEncoded, outSpec.getEncoded());
    }

    @Test
    public void testGetKeySpecPrivatePKCS8()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        /* Generate RSA key pair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        byte[] origEncoded = priv.getEncoded();

        /* Import into wolfJCE */
        PKCS8EncodedKeySpec inSpec = new PKCS8EncodedKeySpec(origEncoded);
        PrivateKey wolfPriv = kf.generatePrivate(inSpec);

        /* Extract PKCS8EncodedKeySpec */
        PKCS8EncodedKeySpec outSpec =
            kf.getKeySpec(wolfPriv, PKCS8EncodedKeySpec.class);
        assertNotNull(outSpec);

        /* Verify encoded forms match */
        assertArrayEquals(origEncoded, outSpec.getEncoded());
    }

    @Test
    public void testGetKeySpecPublicRSAPublicKeySpec()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        /* Generate RSA key pair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey)pair.getPublic();
        BigInteger origN = pub.getModulus();
        BigInteger origE = pub.getPublicExponent();

        /* Import into wolfJCE */
        X509EncodedKeySpec inSpec =
            new X509EncodedKeySpec(pub.getEncoded());
        PublicKey wolfPub = kf.generatePublic(inSpec);

        /* Extract RSAPublicKeySpec */
        RSAPublicKeySpec spec =
            kf.getKeySpec(wolfPub, RSAPublicKeySpec.class);
        assertNotNull(spec);

        /* Verify components match */
        assertEquals(origN, spec.getModulus());
        assertEquals(origE, spec.getPublicExponent());
    }

    @Test
    public void testGetKeySpecPrivateRSAPrivateCrtKeySpec()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        /* Generate RSA key pair */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        RSAPrivateCrtKey priv = (RSAPrivateCrtKey)pair.getPrivate();
        BigInteger origN = priv.getModulus();
        BigInteger origE = priv.getPublicExponent();
        BigInteger origD = priv.getPrivateExponent();
        BigInteger origP = priv.getPrimeP();
        BigInteger origQ = priv.getPrimeQ();
        BigInteger origDP = priv.getPrimeExponentP();
        BigInteger origDQ = priv.getPrimeExponentQ();
        BigInteger origQInv = priv.getCrtCoefficient();

        /* Import into wolfJCE */
        PKCS8EncodedKeySpec inSpec =
            new PKCS8EncodedKeySpec(priv.getEncoded());
        PrivateKey wolfPriv = kf.generatePrivate(inSpec);

        /* Extract RSAPrivateCrtKeySpec */
        RSAPrivateCrtKeySpec spec =
            kf.getKeySpec(wolfPriv, RSAPrivateCrtKeySpec.class);
        assertNotNull(spec);

        /* Verify all CRT components match */
        assertEquals(origN, spec.getModulus());
        assertEquals(origE, spec.getPublicExponent());
        assertEquals(origD, spec.getPrivateExponent());
        assertEquals(origP, spec.getPrimeP());
        assertEquals(origQ, spec.getPrimeQ());
        assertEquals(origDP, spec.getPrimeExponentP());
        assertEquals(origDQ, spec.getPrimeExponentQ());
        assertEquals(origQInv, spec.getCrtCoefficient());
    }

    @Test
    public void testTranslatePublicKey()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        /* Generate RSA key pair using SunRsaSign provider */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        PublicKey pub = pair.getPublic();
        byte[] origEncoded = pub.getEncoded();

        /* Translate key to wolfJCE provider */
        PublicKey translated = (PublicKey)kf.translateKey(pub);
        assertNotNull(translated);
        assertTrue(translated instanceof RSAPublicKey);

        /* Verify encoded forms match */
        assertArrayEquals(origEncoded, translated.getEncoded());

        /* Verify provider is wolfJCE */
        assertEquals("wolfJCE", kf.getProvider().getName());
    }

    @Test
    public void testTranslatePrivateKey()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        /* Generate RSA key pair using SunRsaSign provider */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        PrivateKey priv = pair.getPrivate();
        byte[] origEncoded = priv.getEncoded();

        /* Translate key to wolfJCE provider */
        PrivateKey translated = (PrivateKey)kf.translateKey(priv);
        assertNotNull(translated);
        assertTrue(translated instanceof RSAPrivateCrtKey);

        /* Verify encoded forms match */
        assertArrayEquals(origEncoded, translated.getEncoded());

        /* Verify provider is wolfJCE */
        assertEquals("wolfJCE", kf.getProvider().getName());
    }

    @Test
    public void testRoundTripPublicKey()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        for (int keySize : testKeySizes) {
            if (keySize < minRsaKeySize) {
                continue;
            }

            /* Generate RSA key pair */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            KeyPair pair = kpg.generateKeyPair();
            PublicKey orig = pair.getPublic();
            byte[] origEncoded = orig.getEncoded();

            /* Convert to X509 spec and back */
            X509EncodedKeySpec x509Spec =
                new X509EncodedKeySpec(origEncoded);
            PublicKey key1 = kf.generatePublic(x509Spec);

            /* Convert to RSAPublicKeySpec and back */
            RSAPublicKeySpec rsaSpec =
                kf.getKeySpec(key1, RSAPublicKeySpec.class);
            PublicKey key2 = kf.generatePublic(rsaSpec);

            /* Verify encoded forms match after round trip */
            assertArrayEquals(origEncoded, key1.getEncoded());
            assertArrayEquals(origEncoded, key2.getEncoded());
        }
    }

    @Test
    public void testRoundTripPrivateKey()
        throws Exception {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
        assertNotNull(kf);

        for (int keySize : testKeySizes) {
            if (keySize < minRsaKeySize) {
                continue;
            }

            /* Generate RSA key pair */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            KeyPair pair = kpg.generateKeyPair();
            PrivateKey orig = pair.getPrivate();
            byte[] origEncoded = orig.getEncoded();

            /* Convert to PKCS8 spec and back */
            PKCS8EncodedKeySpec pkcs8Spec =
                new PKCS8EncodedKeySpec(origEncoded);
            PrivateKey key1 = kf.generatePrivate(pkcs8Spec);

            /* Verify encoded forms match after round trip */
            assertArrayEquals(origEncoded, key1.getEncoded());
        }
    }

    @Test
    public void testNullKeySpec() {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
            kf.generatePublic(null);
            fail("Expected InvalidKeySpecException for null KeySpec");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        } catch (Exception e) {
            fail("Unexpected exception: " + e);
        }
    }

    @Test
    public void testInvalidKeySpec() {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");
            /* X509 with invalid/corrupt DER data */
            X509EncodedKeySpec spec =
                new X509EncodedKeySpec(new byte[] {0x00, 0x01, 0x02});
            kf.generatePublic(spec);
            fail("Expected InvalidKeySpecException for invalid DER");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        } catch (Exception e) {
            fail("Unexpected exception: " + e);
        }
    }

    @Test
    public void testGeneratePrivateFromRSAPrivateCrtKeySpec() {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");

            /* Generate a new RSA key pair to get CRT parameters */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair pair = kpg.generateKeyPair();
            RSAPrivateCrtKey originalPriv = (RSAPrivateCrtKey)pair.getPrivate();

            /* Extract all CRT parameters */
            RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
                originalPriv.getModulus(),
                originalPriv.getPublicExponent(),
                originalPriv.getPrivateExponent(),
                originalPriv.getPrimeP(),
                originalPriv.getPrimeQ(),
                originalPriv.getPrimeExponentP(),
                originalPriv.getPrimeExponentQ(),
                originalPriv.getCrtCoefficient());

            /* Generate private key from CRT spec */
            PrivateKey reconstructed = kf.generatePrivate(spec);
            assertNotNull(reconstructed);
            assertTrue(reconstructed instanceof RSAPrivateCrtKey);

            /* Verify the reconstructed key has same parameters */
            RSAPrivateCrtKey reconstructedCrt =
                (RSAPrivateCrtKey)reconstructed;
            assertEquals(originalPriv.getModulus(),
                reconstructedCrt.getModulus());
            assertEquals(originalPriv.getPublicExponent(),
                reconstructedCrt.getPublicExponent());
            assertEquals(originalPriv.getPrivateExponent(),
                reconstructedCrt.getPrivateExponent());
            assertEquals(originalPriv.getPrimeP(),
                reconstructedCrt.getPrimeP());
            assertEquals(originalPriv.getPrimeQ(),
                reconstructedCrt.getPrimeQ());
            assertEquals(originalPriv.getPrimeExponentP(),
                reconstructedCrt.getPrimeExponentP());
            assertEquals(originalPriv.getPrimeExponentQ(),
                reconstructedCrt.getPrimeExponentQ());
            assertEquals(originalPriv.getCrtCoefficient(),
                reconstructedCrt.getCrtCoefficient());

            /* Verify we can use the reconstructed key for crypto operations */
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
            byte[] plaintext = "test message".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);

            cipher.init(Cipher.DECRYPT_MODE, reconstructed);
            byte[] decrypted = cipher.doFinal(ciphertext);
            assertArrayEquals(plaintext, decrypted);

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e);
        }
    }

    @Test
    public void testGeneratePrivateFromRSAPrivateKeySpec() {

        if (!rsaKeyFactoryAvailable()) {
            return;
        }

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA", "wolfJCE");

            /* Generate a new RSA key pair to get parameters */
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair pair = kpg.generateKeyPair();
            RSAPrivateCrtKey originalPriv = (RSAPrivateCrtKey)pair.getPrivate();

            /* Test 1: RSAPrivateCrtKeySpec passed as RSAPrivateKeySpec
             * (upcasted). This is common in generic code and should work. */
            RSAPrivateKeySpec crtAsBase = new RSAPrivateCrtKeySpec(
                originalPriv.getModulus(),
                originalPriv.getPublicExponent(),
                originalPriv.getPrivateExponent(),
                originalPriv.getPrimeP(),
                originalPriv.getPrimeQ(),
                originalPriv.getPrimeExponentP(),
                originalPriv.getPrimeExponentQ(),
                originalPriv.getCrtCoefficient());

            /* This should work because it detects RSAPrivateCrtKeySpec */
            PrivateKey reconstructed = kf.generatePrivate(crtAsBase);
            assertNotNull(reconstructed);
            assertTrue(reconstructed instanceof RSAPrivateKey);

            /* Verify basic crypto operations work */
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
            byte[] plaintext = "test message".getBytes();
            byte[] ciphertext = cipher.doFinal(plaintext);

            cipher.init(Cipher.DECRYPT_MODE, reconstructed);
            byte[] decrypted = cipher.doFinal(ciphertext);
            assertArrayEquals(plaintext, decrypted);

            /* Test 2: Plain RSAPrivateKeySpec with only n and d
             * Following Sun JCE behavior, this should work by creating a
             * key with zero values for missing parameters. */
            RSAPrivateKeySpec basicSpec = new RSAPrivateKeySpec(
                originalPriv.getModulus(),
                originalPriv.getPrivateExponent());

            PrivateKey basicKey = kf.generatePrivate(basicSpec);
            assertNotNull("Should create key from basic RSAPrivateKeySpec",
                basicKey);
            assertTrue(basicKey instanceof RSAPrivateKey);

            /* Verify the key has correct n and d values */
            RSAPrivateKey basicRsa = (RSAPrivateKey)basicKey;
            assertEquals("Modulus should match",
                originalPriv.getModulus(), basicRsa.getModulus());
            assertEquals("Private exponent should match",
                originalPriv.getPrivateExponent(),
                basicRsa.getPrivateExponent());

            /* Verify it can be encoded to DER */
            byte[] encoded = basicKey.getEncoded();
            assertNotNull("Key should have DER encoding", encoded);
            assertTrue("Encoded key should have reasonable length",
                encoded.length > 100);

            /* Note: wolfCrypt's PKCS#8 decoder validates that p and q are
             * non-zero, so we cannot round-trip decode this key. This is
             * acceptable - the key can be created and encoded (matching Sun
             * JCE behavior) but has limitations. The primary use case for
             * RSAPrivateKeySpec is for compatibility with code that uses the
             * base class type, which we handle via the instanceof check */

        } catch (Exception e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e);
        }
    }
}

