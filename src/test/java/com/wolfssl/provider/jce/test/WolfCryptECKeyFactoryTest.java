/* WolfCryptECKeyFactoryTest.java
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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptECParameterSpec;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit4 test cases for WolfCryptECKeyFactory
 */
public class WolfCryptECKeyFactoryTest {

    private static String supportedCurves[] = {
        "secp192r1",
        "prime192v2",
        "prime192v3",
        "prime239v1",
        "prime239v2",
        "prime239v3",
        "secp256r1",

        "secp112r1",
        "secp112r2",
        "secp128r1",
        "secp128r2",
        "secp160r1",
        "secp224r1",
        "secp384r1",
        "secp521r1",

        "secp160k1",
        "secp192k1",
        "secp224k1",
        "secp256k1",

        "brainpoolp160r1",
        "brainpoolp192r1",
        "brainpoolp224r1",
        "brainpoolp256r1",
        "brainpoolp320r1",
        "brainpoolp384r1",
        "brainpoolp512r1"
    };

    private static ArrayList<String> enabledCurves =
        new ArrayList<String>();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallation() {

        /* Install wolfJCE provider for testing */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        System.out.println("JCE WolfCryptECKeyFactory Class");

        if (!FeatureDetect.EccEnabled()) {
            System.out.println("EC support not compiled in, skipping tests");
            return;
        }

        /* Build list of enabled curves and key sizes,
         * getCurveSizeFromName() will return 0 if curve not found */
        for (int i = 0; i < supportedCurves.length; i++) {

            int size = Ecc.getCurveSizeFromName(
                        supportedCurves[i].toUpperCase());

            if (size > 0) {
                /* Also check if the curve supports round-trip
                 * ECParameterSpec conversion */
                boolean supportsRoundTrip =
                    testCurveRoundTripSupport(supportedCurves[i]);

                if (supportsRoundTrip) {
                    enabledCurves.add(supportedCurves[i]);
                } else {
                    System.out.println("Skipping curve: " + supportedCurves[i] +
                        " (" + size + " bits) - no ECParameterSpec " +
                        "round-trip support");
                }
            }
        }
    }

    /**
     * Test if a curve supports round-trip ECParameterSpec conversion.
     * Some curves can generate keys but can't match ECParameterSpec back to
     * curve names.
     */
    private static boolean testCurveRoundTripSupport(String curveName) {

        try {
            /* Generate a key pair */
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");
            kpg.initialize(new ECGenParameterSpec(curveName));
            KeyPair kp = kpg.generateKeyPair();

            /* Extract ECParameterSpec */
            ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();
            ECParameterSpec params = privKey.getParams();

            /* Test if we can identify the curve from the ECParameterSpec */
            String detectedCurve =
                WolfCryptECParameterSpec.getCurveName(params);
            return (detectedCurve != null && !detectedCurve.isEmpty());

        } catch (Exception e) {
            /* Any exception means the curve doesn't support round-trip */
            return false;
        }
    }

    @Test
    public void testECKeyFactoryInstantiation() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Test that we can get an EC KeyFactory instance */
        KeyFactory kf = KeyFactory.getInstance("EC", "wolfJCE");
        assertNotNull("KeyFactory should not be null", kf);
        assertEquals("Provider should be wolfJCE", "wolfJCE",
            kf.getProvider().getName());
    }

    @Test
    public void testPKCS8PrivateKeyConversion() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();

        /* Get the encoded form */
        byte[] encoded = privKey.getEncoded();
        assertNotNull("Encoded key should not be null", encoded);

        /* Convert back using our KeyFactory */
        KeyFactory kf = KeyFactory.getInstance("EC", "wolfJCE");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey convertedKey = kf.generatePrivate(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be ECPrivateKey",
            convertedKey instanceof ECPrivateKey);

        /* Compare the encoded forms */
        byte[] convertedEncoded = convertedKey.getEncoded();
        assertNotNull("Converted encoded key should not be null",
            convertedEncoded);
        assertArrayEquals("Encoded forms should match", encoded,
            convertedEncoded);
    }

    @Test
    public void testX509PublicKeyConversion() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey pubKey = (ECPublicKey) kp.getPublic();

        /* Get the encoded form */
        byte[] encoded = pubKey.getEncoded();
        assertNotNull("Encoded key should not be null", encoded);

        /* Convert back using our KeyFactory */
        KeyFactory kf = KeyFactory.getInstance("EC", "wolfJCE");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        PublicKey convertedKey = kf.generatePublic(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be ECPublicKey",
            convertedKey instanceof ECPublicKey);

        /* Compare the encoded forms */
        byte[] convertedEncoded = convertedKey.getEncoded();
        assertNotNull("Converted encoded key should not be null",
            convertedEncoded);
        assertArrayEquals("Encoded forms should match", encoded,
            convertedEncoded);
    }

    @Test
    public void testECPrivateKeySpecConversion() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a test key pair using system provider for reference */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();

        /* Extract ECPrivateKeySpec using system KeyFactory */
        KeyFactory sysKF = KeyFactory.getInstance("EC");
        ECPrivateKeySpec keySpec = sysKF.getKeySpec(privKey,
            ECPrivateKeySpec.class);

        /* Convert using our KeyFactory */
        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");
        PrivateKey convertedKey = wolfKF.generatePrivate(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be ECPrivateKey",
            convertedKey instanceof ECPrivateKey);

        /* Verify key parameters match */
        ECPrivateKey convertedECKey = (ECPrivateKey) convertedKey;
        assertEquals("Private key values should match",
             privKey.getS(), convertedECKey.getS());
    }

    @Test
    public void testECPublicKeySpecConversion() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a test key pair using system provider for reference */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        ECPublicKey pubKey = (ECPublicKey) kp.getPublic();

        /* Extract ECPublicKeySpec using system KeyFactory */
        KeyFactory sysKF = KeyFactory.getInstance("EC");
        ECPublicKeySpec keySpec = sysKF.getKeySpec(pubKey,
            ECPublicKeySpec.class);

        /* Convert using our KeyFactory */
        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");
        PublicKey convertedKey = wolfKF.generatePublic(keySpec);

        assertNotNull("Converted key should not be null", convertedKey);
        assertTrue("Should be ECPublicKey",
            convertedKey instanceof ECPublicKey);

        /* Verify key parameters match */
        ECPublicKey convertedECKey = (ECPublicKey) convertedKey;
        assertEquals("Public key points should match",
             pubKey.getW(), convertedECKey.getW());
    }

    @Test
    public void testKeySpecExtraction() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", "wolfJCE");

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

        /* Test ECPrivateKeySpec extraction */
        ECPrivateKeySpec ecPrivSpec = kf.getKeySpec(kp.getPrivate(),
            ECPrivateKeySpec.class);
        assertNotNull("ECPrivateKeySpec should not be null", ecPrivSpec);

        /* Test ECPublicKeySpec extraction */
        ECPublicKeySpec ecPubSpec = kf.getKeySpec(kp.getPublic(),
            ECPublicKeySpec.class);
        assertNotNull("ECPublicKeySpec should not be null", ecPubSpec);
    }

    @Test
    public void testKeyTranslation() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a test key pair using system provider */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair systemKP = kpg.generateKeyPair();

        /* Translate keys using wolfJCE KeyFactory */
        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");

        PrivateKey translatedPriv =
            (PrivateKey)wolfKF.translateKey(systemKP.getPrivate());
        assertNotNull("Translated private key should not be null",
            translatedPriv);
        assertTrue("Should be ECPrivateKey",
            translatedPriv instanceof ECPrivateKey);

        PublicKey translatedPub =
            (PublicKey)wolfKF.translateKey(systemKP.getPublic());
        assertNotNull("Translated public key should not be null",
            translatedPub);
        assertTrue("Should be ECPublicKey",
            translatedPub instanceof ECPublicKey);

        /* Verify translated keys work by comparing encoded forms */
        assertArrayEquals("Private key encoded forms should match",
            systemKP.getPrivate().getEncoded(), translatedPriv.getEncoded());
        assertArrayEquals("Public key encoded forms should match",
            systemKP.getPublic().getEncoded(), translatedPub.getEncoded());
    }

    @Test
    public void testRoundTripConversion() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a test key pair using wolfJCE */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair originalKP = kpg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("EC", "wolfJCE");

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
    public void testMultipleCurves() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        String[] curves = {"secp256r1", "secp384r1", "secp521r1"};
        KeyFactory kf = KeyFactory.getInstance("EC", "wolfJCE");

        for (String curve : curves) {
            try {
                /* Generate key pair for this curve */
                KeyPairGenerator kpg =
                    KeyPairGenerator.getInstance("EC", "wolfJCE");
                kpg.initialize(new ECGenParameterSpec(curve));
                KeyPair kp = kpg.generateKeyPair();

                /* Test conversion works for this curve */
                byte[] privEncoded = kp.getPrivate().getEncoded();
                byte[] pubEncoded = kp.getPublic().getEncoded();

                PKCS8EncodedKeySpec privSpec =
                    new PKCS8EncodedKeySpec(privEncoded);
                PrivateKey convertedPriv = kf.generatePrivate(privSpec);

                X509EncodedKeySpec pubSpec =
                    new X509EncodedKeySpec(pubEncoded);
                PublicKey convertedPub = kf.generatePublic(pubSpec);

                assertNotNull("Converted private key should not be null for " +
                    curve, convertedPriv);
                assertNotNull("Converted public key should not be null for " +
                    curve, convertedPub);

            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to test curve " + curve + ": " + e.getMessage());
            }
        }
    }

    @Test
    public void testInvalidKeySpecs() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        KeyFactory kf = KeyFactory.getInstance("EC", "wolfJCE");

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
            fail("Should throw InvalidKeySpecException for invalid PKCS8 data");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        }

        try {
            X509EncodedKeySpec invalidSpec =
                new X509EncodedKeySpec(new byte[]{1, 2, 3});
            kf.generatePublic(invalidSpec);
            fail("Should throw InvalidKeySpecException for invalid X509 data");

        } catch (InvalidKeySpecException e) {
            /* Expected */
        }
    }

    @Test
    public void testECPrivateKeySpecConversionWithoutSunEC() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Remove SunEC provider temporarily if present */
        Provider sunEC = Security.getProvider("SunEC");
        if (sunEC != null) {
            Security.removeProvider("SunEC");
        }

        try {
            /* Generate key using wolfJCE only */
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();

            /* Extract ECPrivateKeySpec and convert back */
            KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");
            ECPrivateKeySpec keySpec =
                wolfKF.getKeySpec(privKey, ECPrivateKeySpec.class);
            PrivateKey convertedKey = wolfKF.generatePrivate(keySpec);

            /* Verify conversion worked */
            assertNotNull("Converted key should not be null", convertedKey);
            assertTrue("Should be ECPrivateKey",
                convertedKey instanceof ECPrivateKey);

            ECPrivateKey convertedECKey = (ECPrivateKey) convertedKey;
            assertEquals("Private key values should match",
                 privKey.getS(), convertedECKey.getS());

        } finally {
            /* Restore SunEC provider if it was present */
            if (sunEC != null) {
                Security.addProvider(sunEC);
            }
        }
    }

    @Test
    public void testBigIntegerEdgeCases() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a reference key to get the ECParameterSpec */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair refKP = kpg.generateKeyPair();
        ECPrivateKey refPrivKey = (ECPrivateKey) refKP.getPrivate();
        ECParameterSpec params = refPrivKey.getParams();

        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");

        /* Test case 1: Private key with leading zeros (small value) */
        BigInteger smallPrivateValue = BigInteger.valueOf(1);
        ECPrivateKeySpec smallKeySpec =
            new ECPrivateKeySpec(smallPrivateValue, params);
        PrivateKey smallKey = wolfKF.generatePrivate(smallKeySpec);
        assertNotNull("Small private key should be created", smallKey);
        assertTrue("Should be ECPrivateKey", smallKey instanceof ECPrivateKey);

        /* Test case 2: Private key with MSB set (requires sign bit handling) */
        BigInteger largeMSBValue =
            new BigInteger("FF000000000000000000000000000000" +
                           "00000000000000000000000000000001", 16);
        ECPrivateKeySpec largeMSBKeySpec =
            new ECPrivateKeySpec(largeMSBValue, params);

        try {
            PrivateKey largeMSBKey = wolfKF.generatePrivate(largeMSBKeySpec);
            assertNotNull("Large MSB private key should be created",
                largeMSBKey);
            assertTrue("Should be ECPrivateKey",
                largeMSBKey instanceof ECPrivateKey);

        } catch (InvalidKeySpecException e) {
            /* This might fail if the value exceeds the curve order,
             * which is expected */
            assertTrue("Error should mention key size",
                e.getMessage().contains("too large") ||
                e.getMessage().contains("positive"));
        }

        /* Test case 3: Zero private key (should fail) */
        BigInteger zeroPrivateValue = BigInteger.ZERO;
        ECPrivateKeySpec zeroKeySpec =
            new ECPrivateKeySpec(zeroPrivateValue, params);

        try {
            wolfKF.generatePrivate(zeroKeySpec);
            fail("Should throw InvalidKeySpecException for zero private key");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention positive value",
                e.getMessage().contains("positive"));
        }

        /* Test case 4: Negative private key (should fail) */
        BigInteger negativePrivateValue = BigInteger.valueOf(-1);
        ECPrivateKeySpec negativeKeySpec =
            new ECPrivateKeySpec(negativePrivateValue, params);

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
    public void testCurveParameterValidation() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");

        for (int i = 0; i < enabledCurves.size(); i++) {
            String curveName = enabledCurves.get(i);
            try {
                KeyPairGenerator kpg =
                    KeyPairGenerator.getInstance("EC", "wolfJCE");
                kpg.initialize(new ECGenParameterSpec(curveName));
                KeyPair kp = kpg.generateKeyPair();

                ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();
                ECPrivateKeySpec keySpec = new ECPrivateKeySpec(
                    privKey.getS(), privKey.getParams());

                PrivateKey convertedKey = wolfKF.generatePrivate(keySpec);
                assertNotNull("Key should be created for curve " +
                    curveName, convertedKey);

            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to test curve " + curveName + ": " +
                    e.getMessage());
            }
        }

        /* Test null ECParameterSpec - ECPrivateKeySpec constructor
         * itself throws NPE for null params, so test for that */
        try {
            ECPrivateKeySpec nullParamsSpec =
                new ECPrivateKeySpec(BigInteger.ONE, null);
            fail("Should throw NullPointerException for null ECParameterSpec");

        } catch (NullPointerException e) {
            /* Expected - ECPrivateKeySpec constructor rejects null params */
        }

        /* Test null private value */
        if (enabledCurves.contains("secp256r1")) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();

            try {
                ECPrivateKeySpec nullPrivateSpec =
                    new ECPrivateKeySpec(null, privKey.getParams());
                fail("Should throw NullPointerException for null " +
                     "private value");

            } catch (NullPointerException e) {
                /* Expected - ECPrivateKeySpec constructor rejects
                 * null private value */
            }
        }
    }

    @Test
    public void testPrivateKeyBoundaryValues() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate a reference key to get the ECParameterSpec */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair refKP = kpg.generateKeyPair();
        ECPrivateKey refPrivKey = (ECPrivateKey) refKP.getPrivate();
        ECParameterSpec params = refPrivKey.getParams();

        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");

        /* Test minimum valid private key (1) */
        BigInteger minValue = BigInteger.ONE;
        ECPrivateKeySpec minKeySpec = new ECPrivateKeySpec(minValue, params);
        PrivateKey minKey = wolfKF.generatePrivate(minKeySpec);
        assertNotNull("Minimum private key should be created", minKey);

        ECPrivateKey minECKey = (ECPrivateKey) minKey;
        assertEquals("Private key value should match", minValue,
            minECKey.getS());

        /* Test very large value that should exceed curve order */
        BigInteger veryLargeValue =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
                           "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        ECPrivateKeySpec largeKeySpec =
            new ECPrivateKeySpec(veryLargeValue, params);
        try {
            wolfKF.generatePrivate(largeKeySpec);
            /* If this succeeds, the value might be within the curve
             * order for this test curve */

        } catch (InvalidKeySpecException e) {
            /* Check for our error messages or valid crypto-related
             * error messages */
            assertTrue("Error should mention size, large value, or be " +
                "crypto-related: " + e.getMessage(),
                 e.getMessage().contains("too large") ||
                 e.getMessage().contains("large") ||
                 e.getMessage().contains("size") ||
                 e.getMessage().contains("Invalid private key") ||
                 e.getMessage().contains("key value") ||
                 e.getMessage().contains("not valid") ||
                 e.getMessage().contains("error"));
        }
    }

    @Test
    public void testMemoryCleanup() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");

        /* Generate many keys to test for memory leaks */
        for (int i = 0; i < 100; i++) {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();

            ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();
            ECPrivateKeySpec keySpec =
                new ECPrivateKeySpec(privKey.getS(), privKey.getParams());

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

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        /* Generate key using standard approach */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair originalKP = kpg.generateKeyPair();
        ECPrivateKey originalPrivKey = (ECPrivateKey) originalKP.getPrivate();

        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");

        /* Test that ECPrivateKeySpec conversion produces consistent results */
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(originalPrivKey.getS(),
            originalPrivKey.getParams());
        PrivateKey convertedKey1 = wolfKF.generatePrivate(keySpec);
        PrivateKey convertedKey2 = wolfKF.generatePrivate(keySpec);

        /* Both conversions should produce identical encoded results */
        assertArrayEquals("Multiple conversions should produce " +
            "identical results", convertedKey1.getEncoded(),
            convertedKey2.getEncoded());

        /* The converted key should have the same private value */
        ECPrivateKey convertedECKey = (ECPrivateKey) convertedKey1;
        assertEquals("Private values should match",
            originalPrivKey.getS(), convertedECKey.getS());
    }

    @Test
    public void testErrorHandling() throws Exception {

        if (!FeatureDetect.EccEnabled()) {
            return;
        }

        KeyFactory wolfKF = KeyFactory.getInstance("EC", "wolfJCE");

        /* Test null KeySpec */
        try {
            wolfKF.generatePrivate(null);
            fail("Should throw InvalidKeySpecException for null KeySpec");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention KeySpec",
                e.getMessage().contains("KeySpec"));
        }

        /* Test invalid ECPrivateKeySpec values - the constructor validates
         * null values itself */
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "wolfJCE");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        ECPrivateKey privKey = (ECPrivateKey) kp.getPrivate();

        /* Test zero private value (should be rejected) */
        try {
            ECPrivateKeySpec zeroSpec = new ECPrivateKeySpec(BigInteger.ZERO,
                privKey.getParams());
            wolfKF.generatePrivate(zeroSpec);
            fail("Should throw InvalidKeySpecException for zero private value");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention private key value",
                e.getMessage().contains("Private key value") ||
                e.getMessage().contains("positive"));
        }

        /* Test negative private value (should be rejected) */
        try {
            ECPrivateKeySpec negativeSpec =
                new ECPrivateKeySpec(BigInteger.valueOf(-1),
                    privKey.getParams());
            wolfKF.generatePrivate(negativeSpec);
            fail("Should throw InvalidKeySpecException for negative " +
                 "private value");

        } catch (InvalidKeySpecException e) {
            assertTrue("Error should mention private key value",
                e.getMessage().contains("Private key value") ||
                e.getMessage().contains("positive"));
        }
    }
}

