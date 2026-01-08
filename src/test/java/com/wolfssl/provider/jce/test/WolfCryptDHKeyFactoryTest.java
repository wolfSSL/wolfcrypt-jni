/* WolfCryptDHKeyFactoryTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit4 test cases for WolfCryptDHKeyFactory
 */
public class WolfCryptDHKeyFactoryTest {

    /* Standard DH key sizes to test */
    private static int[] keySizes = {512, 1024, 2048};

    private static ArrayList<Integer> enabledKeySizes =
        new ArrayList<Integer>();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallation() {

        /* Install wolfJCE provider for testing */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        System.out.println("JCE WolfCryptDHKeyFactory Class");

        if (!FeatureDetect.DhEnabled()) {
            System.out.println("DH support not compiled in, skipping tests");
            return;
        }

        /* Build list of enabled key sizes */
        for (int i = 0; i < keySizes.length; i++) {
            try {
                /* Test if this key size works */
                KeyPairGenerator kpg =
                    KeyPairGenerator.getInstance("DH", "wolfJCE");
                kpg.initialize(keySizes[i]);
                KeyPair kp = kpg.generateKeyPair();

                if (kp != null) {
                    enabledKeySizes.add(keySizes[i]);
                }

            } catch (Exception e) {
                System.out.println("Skipping DH key size: " + keySizes[i] +
                    " bits - " + e.getMessage());
            }
        }
    }

    @Test
    public void testDHKeyFactoryInstantiation() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Test that we can get a DH KeyFactory instance */
        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");
        assertNotNull("KeyFactory should not be null", kf);
        assertEquals("Provider should be wolfJCE", "wolfJCE",
            kf.getProvider().getName());

        /* Test DiffieHellman alias */
        KeyFactory kf2 = KeyFactory.getInstance("DiffieHellman", "wolfJCE");
        assertNotNull("KeyFactory should not be null", kf2);
        assertEquals("Provider should be wolfJCE", "wolfJCE",
            kf2.getProvider().getName());
    }

    @Test
    public void testPKCS8PrivateKeyConversion() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        DHPrivateKey privKey = (DHPrivateKey) kp.getPrivate();

        /* Get the encoded form */
        byte[] encoded = privKey.getEncoded();
        assertNotNull("Encoded key should not be null", encoded);

        /* Convert back using our KeyFactory */
        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey convertedKey = kf.generatePrivate(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be DHPrivateKey",
            convertedKey instanceof DHPrivateKey);

        /* Compare the encoded forms */
        byte[] convertedEncoded = convertedKey.getEncoded();
        assertNotNull("Converted encoded key should not be null",
            convertedEncoded);
        assertArrayEquals("Encoded forms should match", encoded,
            convertedEncoded);
    }

    @Test
    public void testX509PublicKeyConversion() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        DHPublicKey pubKey = (DHPublicKey) kp.getPublic();

        /* Get the encoded form */
        byte[] encoded = pubKey.getEncoded();
        assertNotNull("Encoded key should not be null", encoded);

        /* Convert back using our KeyFactory */
        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        PublicKey convertedKey = kf.generatePublic(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be DHPublicKey",
            convertedKey instanceof DHPublicKey);

        /* Compare the encoded forms */
        byte[] convertedEncoded = convertedKey.getEncoded();
        assertNotNull("Converted encoded key should not be null",
            convertedEncoded);
        assertArrayEquals("Encoded forms should match", encoded,
            convertedEncoded);
    }

    @Test
    public void testDHPrivateKeySpecConversion() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using system provider for reference */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        DHPrivateKey privKey = (DHPrivateKey) kp.getPrivate();

        /* Extract DHPrivateKeySpec using system KeyFactory */
        KeyFactory sysKF = KeyFactory.getInstance("DH");
        DHPrivateKeySpec keySpec = sysKF.getKeySpec(privKey,
            DHPrivateKeySpec.class);

        /* Convert using our KeyFactory */
        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");
        PrivateKey convertedKey = wolfKF.generatePrivate(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be DHPrivateKey",
            convertedKey instanceof DHPrivateKey);

        /* Verify key parameters match */
        DHPrivateKey convertedDHKey = (DHPrivateKey) convertedKey;
        assertEquals("Private key values should match",
             privKey.getX(), convertedDHKey.getX());
        assertEquals("DH parameter p should match",
             privKey.getParams().getP(), convertedDHKey.getParams().getP());
        assertEquals("DH parameter g should match",
             privKey.getParams().getG(), convertedDHKey.getParams().getG());
    }

    @Test
    public void testDHPublicKeySpecConversion() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using system provider for reference */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        DHPublicKey pubKey = (DHPublicKey) kp.getPublic();

        /* Extract DHPublicKeySpec using system KeyFactory */
        KeyFactory sysKF = KeyFactory.getInstance("DH");
        DHPublicKeySpec keySpec = sysKF.getKeySpec(pubKey,
            DHPublicKeySpec.class);

        /* Convert using our KeyFactory */
        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");
        PublicKey convertedKey = wolfKF.generatePublic(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be DHPublicKey",
            convertedKey instanceof DHPublicKey);

        /* Verify key parameters match */
        DHPublicKey convertedDHKey = (DHPublicKey) convertedKey;
        assertEquals("Public key values should match",
             pubKey.getY(), convertedDHKey.getY());
        assertEquals("DH parameter p should match",
             pubKey.getParams().getP(), convertedDHKey.getParams().getP());
        assertEquals("DH parameter g should match",
             pubKey.getParams().getG(), convertedDHKey.getParams().getG());
    }

    @Test
    public void testKeySpecExtraction() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");

        /* Test PKCS8EncodedKeySpec extraction */
        PKCS8EncodedKeySpec privSpec = kf.getKeySpec(kp.getPrivate(),
            PKCS8EncodedKeySpec.class);
        assertNotNull("PKCS8EncodedKeySpec should not be null", privSpec);
        assertNotNull("Encoded bytes should not be null",
            privSpec.getEncoded());

        /* Test X509EncodedKeySpec extraction */
        X509EncodedKeySpec pubSpec = kf.getKeySpec(kp.getPublic(),
            X509EncodedKeySpec.class);
        assertNotNull("X509EncodedKeySpec should not be null", pubSpec);
        assertNotNull("Encoded bytes should not be null",
            pubSpec.getEncoded());

        /* Test DHPrivateKeySpec extraction */
        DHPrivateKeySpec dhPrivSpec = kf.getKeySpec(kp.getPrivate(),
            DHPrivateKeySpec.class);
        assertNotNull("DHPrivateKeySpec should not be null", dhPrivSpec);

        /* Test DHPublicKeySpec extraction */
        DHPublicKeySpec dhPubSpec = kf.getKeySpec(kp.getPublic(),
            DHPublicKeySpec.class);
        assertNotNull("DHPublicKeySpec should not be null", dhPubSpec);
    }

    @Test
    public void testKeyTranslation() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using system provider */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        kpg.initialize(2048);
        KeyPair systemKP = kpg.generateKeyPair();

        /* Translate keys using wolfJCE KeyFactory */
        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");

        PrivateKey translatedPriv =
            (PrivateKey)wolfKF.translateKey(systemKP.getPrivate());
        assertNotNull("Translated private key should not be null",
            translatedPriv);
        assertTrue("Should be DHPrivateKey",
            translatedPriv instanceof DHPrivateKey);

        PublicKey translatedPub =
            (PublicKey)wolfKF.translateKey(systemKP.getPublic());
        assertNotNull("Translated public key should not be null",
            translatedPub);
        assertTrue("Should be DHPublicKey",
            translatedPub instanceof DHPublicKey);

        /* Verify translated keys work by comparing encoded forms */
        assertArrayEquals("Private key encoded forms should match",
            systemKP.getPrivate().getEncoded(), translatedPriv.getEncoded());
        assertArrayEquals("Public key encoded forms should match",
            systemKP.getPublic().getEncoded(), translatedPub.getEncoded());
    }

    @Test
    public void testRoundTripConversion() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair originalKP = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");

        /* Round trip: Key -> KeySpec -> Key */
        PKCS8EncodedKeySpec privSpec = kf.getKeySpec(originalKP.getPrivate(),
            PKCS8EncodedKeySpec.class);
        PrivateKey roundTripPriv = kf.generatePrivate(privSpec);

        X509EncodedKeySpec pubSpec = kf.getKeySpec(originalKP.getPublic(),
            X509EncodedKeySpec.class);
        PublicKey roundTripPub = kf.generatePublic(pubSpec);

        /* Verify the round trip worked */
        assertArrayEquals("Private key round trip failed",
            originalKP.getPrivate().getEncoded(),
            roundTripPriv.getEncoded());
        assertArrayEquals("Public key round trip failed",
            originalKP.getPublic().getEncoded(),
            roundTripPub.getEncoded());
    }

    @Test
    public void testMultipleKeySizes() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");

        for (Integer keySize : enabledKeySizes) {
            try {
                /* Generate key pair for this key size */
                KeyPairGenerator kpg =
                    KeyPairGenerator.getInstance("DH", "wolfJCE");
                kpg.initialize(keySize);
                KeyPair kp = kpg.generateKeyPair();

                /* Test conversion works for this key size */
                byte[] privEncoded = kp.getPrivate().getEncoded();
                byte[] pubEncoded = kp.getPublic().getEncoded();

                PKCS8EncodedKeySpec privSpec =
                    new PKCS8EncodedKeySpec(privEncoded);
                PrivateKey convertedPriv = kf.generatePrivate(privSpec);

                X509EncodedKeySpec pubSpec =
                    new X509EncodedKeySpec(pubEncoded);
                PublicKey convertedPub = kf.generatePublic(pubSpec);

                assertNotNull("Converted private key should not be null for "
                    + keySize + " bits", convertedPriv);
                assertNotNull("Converted public key should not be null for "
                    + keySize + " bits", convertedPub);

            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to test key size " + keySize + ": " +
                    e.getMessage());
            }
        }
    }

    @Test
    public void testInvalidKeySpecs() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");

        /* Test null KeySpecs */
        try {
            kf.generatePrivate(null);
            fail("Should throw InvalidKeySpecException for null KeySpec");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        }

        try {
            kf.generatePublic(null);
            fail("Should throw InvalidKeySpecException for null KeySpec");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        }

        /* Test invalid encoded data */
        try {
            PKCS8EncodedKeySpec invalidSpec =
                new PKCS8EncodedKeySpec(new byte[]{1, 2, 3});
            kf.generatePrivate(invalidSpec);
            fail("Should throw InvalidKeySpecException for invalid " +
                "PKCS8 data");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        }

        try {
            X509EncodedKeySpec invalidSpec =
                new X509EncodedKeySpec(new byte[]{1, 2, 3});
            kf.generatePublic(invalidSpec);
            fail("Should throw InvalidKeySpecException for invalid " +
                "X509 data");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        }
    }

    @Test
    public void testDHPrivateKeySpecConversionWithoutSunJCE()
        throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Remove SunJCE provider temporarily if present */
        Provider sunJCE = Security.getProvider("SunJCE");
        if (sunJCE != null) {
            Security.removeProvider("SunJCE");
        }

        try {
            /* Generate key using wolfJCE only */
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("DH", "wolfJCE");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            DHPrivateKey privKey = (DHPrivateKey) kp.getPrivate();

            /* Extract DHPrivateKeySpec and convert back */
            KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");
            DHPrivateKeySpec keySpec =
                wolfKF.getKeySpec(privKey, DHPrivateKeySpec.class);
            PrivateKey convertedKey = wolfKF.generatePrivate(keySpec);

            /* Verify conversion worked */
            assertNotNull("Converted key should not be null", convertedKey);
            assertTrue("Should be DHPrivateKey",
                convertedKey instanceof DHPrivateKey);

            DHPrivateKey convertedDHKey = (DHPrivateKey) convertedKey;
            assertEquals("Private key values should match",
                 privKey.getX(), convertedDHKey.getX());

        } finally {
            /* Restore SunJCE provider if it was present */
            if (sunJCE != null) {
                Security.addProvider(sunJCE);
            }
        }
    }

    @Test
    public void testBigIntegerEdgeCases() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a reference key to get the DHParameterSpec */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair refKP = kpg.generateKeyPair();
        DHPrivateKey refPrivKey = (DHPrivateKey) refKP.getPrivate();
        DHParameterSpec params = refPrivKey.getParams();

        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");

        /* Test case 1: Private key with leading zeros (small value) */
        BigInteger smallPrivateValue = BigInteger.valueOf(1);
        DHPrivateKeySpec smallKeySpec =
            new DHPrivateKeySpec(smallPrivateValue, params.getP(),
                params.getG());
        PrivateKey smallKey = wolfKF.generatePrivate(smallKeySpec);
        assertNotNull("Small private key should be created", smallKey);
        assertTrue("Should be DHPrivateKey", smallKey instanceof DHPrivateKey);

        /* Test case 2: Private key with MSB set
         * (requires sign bit handling) */
        BigInteger largeMSBValue =
            new BigInteger("FF00000000000000000000000000000000000000" +
                           "00000000000000000000000000000001", 16);
        DHPrivateKeySpec largeMSBKeySpec =
            new DHPrivateKeySpec(largeMSBValue, params.getP(), params.getG());

        try {
            PrivateKey largeMSBKey = wolfKF.generatePrivate(largeMSBKeySpec);
            assertNotNull("Large MSB private key should be created",
                largeMSBKey);
            assertTrue("Should be DHPrivateKey",
                largeMSBKey instanceof DHPrivateKey);

        } catch (InvalidKeySpecException e) {
            /* This might fail if the value is invalid for DH,
             * which is expected */
            assertTrue("Error should be crypto-related",
                e.getMessage().contains("too large") ||
                e.getMessage().contains("positive") ||
                e.getMessage().contains("Invalid"));
        }

        /* Test case 3: Zero private key (should fail) */
        BigInteger zeroPrivateValue = BigInteger.ZERO;
        DHPrivateKeySpec zeroKeySpec =
            new DHPrivateKeySpec(zeroPrivateValue, params.getP(),
                params.getG());

        try {
            wolfKF.generatePrivate(zeroKeySpec);
            fail("Should throw InvalidKeySpecException for zero " +
                "private key");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention positive value",
                e.getMessage().contains("positive"));
        }

        /* Test case 4: Negative private key (should fail) */
        BigInteger negativePrivateValue = BigInteger.valueOf(-1);
        DHPrivateKeySpec negativeKeySpec =
            new DHPrivateKeySpec(negativePrivateValue, params.getP(),
                params.getG());

        try {
            wolfKF.generatePrivate(negativeKeySpec);
            fail("Should throw InvalidKeySpecException for negative " +
                 "private key");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention positive value",
                e.getMessage().contains("positive"));
        }
    }

    @Test
    public void testParameterValidation() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");

        /* Generate a reference key to get valid DH parameters */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        DHPrivateKey privKey = (DHPrivateKey) kp.getPrivate();
        DHParameterSpec params = privKey.getParams();

        /* Test null private value */
        try {
            DHPrivateKeySpec nullPrivateSpec =
                new DHPrivateKeySpec(null, params.getP(), params.getG());
            wolfKF.generatePrivate(nullPrivateSpec);
            fail("Should throw exception for null private value");

        } catch (Exception e) {
            /* Expected - either NPE or InvalidKeySpecException */
            assertTrue("Should be NPE or InvalidKeySpecException",
                e instanceof NullPointerException ||
                e instanceof InvalidKeySpecException);
        }

        /* Test null p parameter */
        try {
            DHPrivateKeySpec nullPSpec =
                new DHPrivateKeySpec(BigInteger.valueOf(100), null,
                    params.getG());
            wolfKF.generatePrivate(nullPSpec);
            fail("Should throw exception for null p parameter");

        } catch (Exception e) {
            /* Expected - either NPE or InvalidKeySpecException */
            assertTrue("Should be NPE or InvalidKeySpecException",
                e instanceof NullPointerException ||
                e instanceof InvalidKeySpecException);
        }

        /* Test null g parameter */
        try {
            DHPrivateKeySpec nullGSpec =
                new DHPrivateKeySpec(BigInteger.valueOf(100), params.getP(),
                    null);
            wolfKF.generatePrivate(nullGSpec);
            fail("Should throw exception for null g parameter");

        } catch (Exception e) {
            /* Expected - either NPE or InvalidKeySpecException */
            assertTrue("Should be NPE or InvalidKeySpecException",
                e instanceof NullPointerException ||
                e instanceof InvalidKeySpecException);
        }
    }

    @Test
    public void testPrivateKeyBoundaryValues() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a reference key to get the DHParameterSpec */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair refKP = kpg.generateKeyPair();
        DHPrivateKey refPrivKey = (DHPrivateKey) refKP.getPrivate();
        DHParameterSpec params = refPrivKey.getParams();

        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");

        /* Test minimum valid private key (1) */
        BigInteger minValue = BigInteger.ONE;
        DHPrivateKeySpec minKeySpec = new DHPrivateKeySpec(minValue,
            params.getP(), params.getG());
        PrivateKey minKey = wolfKF.generatePrivate(minKeySpec);
        assertNotNull("Minimum private key should be created", minKey);

        DHPrivateKey minDHKey = (DHPrivateKey) minKey;
        assertEquals("Private key value should match", minValue,
            minDHKey.getX());

        /* Test very large value that should be invalid */
        BigInteger veryLargeValue =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        DHPrivateKeySpec largeKeySpec =
            new DHPrivateKeySpec(veryLargeValue, params.getP(),
                params.getG());
        try {
            wolfKF.generatePrivate(largeKeySpec);
            /* If this succeeds, the value might be valid for this key size */

        } catch (InvalidKeySpecException e) {
            /* Check for valid error messages */
            assertTrue("Error should be crypto-related: " + e.getMessage(),
                 e.getMessage().contains("too large") ||
                 e.getMessage().contains("large") ||
                 e.getMessage().contains("size") ||
                 e.getMessage().contains("Invalid") ||
                 e.getMessage().contains("key value") ||
                 e.getMessage().contains("not valid") ||
                 e.getMessage().contains("error"));
        }
    }

    @Test
    public void testMemoryCleanup() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");

        /* Generate many keys to test for memory leaks */
        for (int i = 0; i < 50; i++) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("DH", "wolfJCE");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            DHPrivateKey privKey = (DHPrivateKey) kp.getPrivate();
            DHPrivateKeySpec keySpec =
                new DHPrivateKeySpec(privKey.getX(), privKey.getParams().getP(),
                    privKey.getParams().getG());

            PrivateKey convertedKey = wolfKF.generatePrivate(keySpec);
            assertNotNull("Key " + i + " should be created", convertedKey);
        }

        /* Force garbage collection to help detect leaks */
        System.gc();
        Thread.sleep(100);  /* Allow GC to run */

        /* If we get here without running out of memory or native handles,
         * the test passes */
        assertTrue("Memory cleanup test completed successfully", true);
    }

    @Test
    public void testBackwardCompatibility() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate key using standard approach */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair originalKP = kpg.generateKeyPair();
        DHPrivateKey originalPrivKey = (DHPrivateKey) originalKP.getPrivate();

        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");

        /* Test that DHPrivateKeySpec conversion produces consistent
         * results */
        DHPrivateKeySpec keySpec = new DHPrivateKeySpec(originalPrivKey.getX(),
            originalPrivKey.getParams().getP(),
            originalPrivKey.getParams().getG());
        PrivateKey convertedKey1 = wolfKF.generatePrivate(keySpec);
        PrivateKey convertedKey2 = wolfKF.generatePrivate(keySpec);

        /* Both conversions should produce identical encoded results */
        assertArrayEquals("Multiple conversions should produce " +
            "identical results", convertedKey1.getEncoded(),
            convertedKey2.getEncoded());

        /* The converted key should have the same private value */
        DHPrivateKey convertedDHKey = (DHPrivateKey) convertedKey1;
        assertEquals("Private values should match",
            originalPrivKey.getX(), convertedDHKey.getX());
    }

    @Test
    public void testErrorHandling() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");

        /* Test null KeySpec */
        try {
            wolfKF.generatePrivate(null);
            fail("Should throw InvalidKeySpecException for null KeySpec");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention KeySpec",
                e.getMessage().contains("KeySpec"));
        }

        /* Generate reference key for valid parameters */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        DHPrivateKey privKey = (DHPrivateKey) kp.getPrivate();
        DHParameterSpec params = privKey.getParams();

        /* Test zero private value (should be rejected) */
        try {
            DHPrivateKeySpec zeroSpec = new DHPrivateKeySpec(BigInteger.ZERO,
                params.getP(), params.getG());
            wolfKF.generatePrivate(zeroSpec);
            fail("Should throw InvalidKeySpecException for zero " +
                "private value");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention private key value",
                e.getMessage().contains("Private") ||
                e.getMessage().contains("positive"));
        }

        /* Test negative private value (should be rejected) */
        try {
            DHPrivateKeySpec negativeSpec =
                new DHPrivateKeySpec(BigInteger.valueOf(-1),
                    params.getP(), params.getG());
            wolfKF.generatePrivate(negativeSpec);
            fail("Should throw InvalidKeySpecException for negative " +
                 "private value");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention private key value",
                e.getMessage().contains("Private") ||
                e.getMessage().contains("positive"));
        }
    }

    @Test
    public void testInteroperabilityWithSunJCE() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate key pair using SunJCE */
        KeyPairGenerator sunKpg = KeyPairGenerator.getInstance("DH");
        sunKpg.initialize(2048);
        KeyPair sunKP = sunKpg.generateKeyPair();

        /* Convert to wolfJCE using KeyFactory.translateKey() */
        KeyFactory wolfKF = KeyFactory.getInstance("DH", "wolfJCE");
        PrivateKey wolfPriv = (PrivateKey)wolfKF.translateKey(
            sunKP.getPrivate());
        PublicKey wolfPub = (PublicKey)wolfKF.translateKey(
            sunKP.getPublic());

        assertNotNull("Translated private key should not be null", wolfPriv);
        assertNotNull("Translated public key should not be null", wolfPub);
        assertTrue("Should be DHPrivateKey",
            wolfPriv instanceof DHPrivateKey);
        assertTrue("Should be DHPublicKey", wolfPub instanceof DHPublicKey);

        /* Verify parameters match */
        DHPrivateKey sunPrivKey = (DHPrivateKey)sunKP.getPrivate();
        DHPrivateKey wolfPrivKey = (DHPrivateKey)wolfPriv;
        assertEquals("Private values should match",
            sunPrivKey.getX(), wolfPrivKey.getX());

        /* Generate key pair using wolfJCE and convert to SunJCE specs */
        KeyPairGenerator wolfKpg =
            KeyPairGenerator.getInstance("DH", "wolfJCE");
        wolfKpg.initialize(2048);
        KeyPair wolfKP = wolfKpg.generateKeyPair();

        /* Extract KeySpecs that SunJCE can use */
        DHPrivateKeySpec wolfPrivSpec =
            wolfKF.getKeySpec(wolfKP.getPrivate(), DHPrivateKeySpec.class);
        DHPublicKeySpec wolfPubSpec =
            wolfKF.getKeySpec(wolfKP.getPublic(), DHPublicKeySpec.class);

        /* Create SunJCE keys from wolfJCE KeySpecs */
        KeyFactory sunKF = KeyFactory.getInstance("DH");
        PrivateKey sunPrivFromWolf = sunKF.generatePrivate(wolfPrivSpec);
        PublicKey sunPubFromWolf = sunKF.generatePublic(wolfPubSpec);

        assertNotNull("SunJCE private key from wolfJCE spec should not " +
            "be null", sunPrivFromWolf);
        assertNotNull("SunJCE public key from wolfJCE spec should not " +
            "be null", sunPubFromWolf);

        /* Verify round-trip conversion */
        DHPrivateKey originalWolfPriv = (DHPrivateKey)wolfKP.getPrivate();
        DHPrivateKey sunPrivConverted = (DHPrivateKey)sunPrivFromWolf;
        assertEquals("Private values should match after round-trip",
            originalWolfPriv.getX(), sunPrivConverted.getX());
    }

    @Test
    public void testRoundTripWithDHKeySpec() throws Exception {

        if (!FeatureDetect.DhEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "wolfJCE");
        kpg.initialize(2048);
        KeyPair originalKP = kpg.generateKeyPair();

        DHPrivateKey originalPriv = (DHPrivateKey)originalKP.getPrivate();
        DHPublicKey originalPub = (DHPublicKey)originalKP.getPublic();

        KeyFactory kf = KeyFactory.getInstance("DH", "wolfJCE");

        /* Round trip private key: Key -> DHPrivateKeySpec -> Key */
        DHPrivateKeySpec privSpec = new DHPrivateKeySpec(
            originalPriv.getX(),
            originalPriv.getParams().getP(),
            originalPriv.getParams().getG());
        PrivateKey roundTripPriv = kf.generatePrivate(privSpec);

        /* Round trip public key: Key -> DHPublicKeySpec -> Key */
        DHPublicKeySpec pubSpec = new DHPublicKeySpec(
            originalPub.getY(),
            originalPub.getParams().getP(),
            originalPub.getParams().getG());
        PublicKey roundTripPub = kf.generatePublic(pubSpec);

        /* Verify the round trip worked */
        DHPrivateKey roundTripPrivDH = (DHPrivateKey)roundTripPriv;
        DHPublicKey roundTripPubDH = (DHPublicKey)roundTripPub;

        assertEquals("Private key values should match after round trip",
            originalPriv.getX(), roundTripPrivDH.getX());
        assertEquals("Public key values should match after round trip",
            originalPub.getY(), roundTripPubDH.getY());
        assertEquals("Private key p should match",
            originalPriv.getParams().getP(),
            roundTripPrivDH.getParams().getP());
        assertEquals("Public key p should match",
            originalPub.getParams().getP(), roundTripPubDH.getParams().getP());
    }
}

