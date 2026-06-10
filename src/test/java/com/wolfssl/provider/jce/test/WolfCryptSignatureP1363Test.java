/* WolfCryptSignatureP1363Test.java
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

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.util.ArrayList;
import java.security.Security;
import java.security.Provider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit4 test cases for WolfCryptSignature P1363 format support
 */
public class WolfCryptSignatureP1363Test {

    private static String PROVIDER = "wolfJCE";
    private static Provider provider;

    /* Standard curves to test for P1363 support */
    private static String supportedCurves[] = {
        "secp256r1",
        "secp384r1",
        "secp521r1"
    };

    /* Track which curves are actually available in native wolfSSL */
    private static ArrayList<String> enabledCurves =
        new ArrayList<String>();

    /* Track which signature algorithms are available */
    private static ArrayList<String> availableAlgorithms =
        new ArrayList<String>();

    /* Pre-generated key pairs to share across all tests to reduce test
     * execution time. Key generation is expensive, especially for large
     * ECC curves. These are generated once in @BeforeClass and reused
     * across all P1363 signature tests. */
    private static java.util.HashMap<String, KeyPair> curveKeyPairs =
        new java.util.HashMap<String, KeyPair>();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallationAtRuntime() {

        System.out.println("JCE WolfCryptSignatureP1363Test Class");

        /* install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        provider = Security.getProvider(PROVIDER);
        Assert.assertNotNull(provider);

        /* Test which curves are enabled in native wolfSSL */
        for (int i = 0; i < supportedCurves.length; i++) {
            int size = Ecc.getCurveSizeFromName(
                supportedCurves[i].toUpperCase());
            if (size > 0) {
                enabledCurves.add(supportedCurves[i]);
            }
        }

        /* Test which signature algorithms are available */
        String[] algorithmsToTest = {
            "SHA256withECDSAinP1363Format",
            "SHA384withECDSAinP1363Format",
            "SHA512withECDSAinP1363Format",
            "SHA3-256withECDSAinP1363Format",
            "SHA3-384withECDSAinP1363Format",
            "SHA3-512withECDSAinP1363Format"
        };

        for (String algorithm : algorithmsToTest) {
            if (isAlgorithmAvailable(algorithm)) {
                availableAlgorithms.add(algorithm);
            }
        }

        /* Generate key pairs once up front to reduce test execution time. */
        try {
            for (String curve : enabledCurves) {
                KeyPairGenerator keyGen =
                    KeyPairGenerator.getInstance("EC", provider);
                keyGen.initialize(new ECGenParameterSpec(curve));
                KeyPair keyPair = keyGen.generateKeyPair();
                curveKeyPairs.put(curve, keyPair);
            }
        } catch (Exception e) {
            /* If key generation fails, tests will fail with appropriate
             * error when they try to use the null key pairs */
            System.err.println("Failed to generate key pairs in " +
                "@BeforeClass: " + e.getMessage());
        }
    }

    /* Helper method to check if signature algorithm is available */
    private static boolean isAlgorithmAvailable(String algorithm) {
        try {
            Signature.getInstance(algorithm, provider);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /* Helper method to get expected P1363 signature length for curve */
    private int getExpectedP1363Length(String curveName) {
        switch (curveName) {
            case "secp256r1": return 64;  /* 32 * 2 */
            case "secp384r1": return 96;  /* 48 * 2 */
            case "secp521r1": return 132; /* 66 * 2 */
            default:
                /* For other curves, calculate from curve size */
                int curveSize = Ecc.getCurveSizeFromName(
                    curveName.toUpperCase());
                return curveSize * 2;
        }
    }

    @Test
    public void testP1363AlgorithmAvailability() throws Exception {

        /* Test SHA256withECDSAinP1363Format availability */
        if (availableAlgorithms.contains("SHA256withECDSAinP1363Format")) {
            Signature sig256 = Signature.getInstance(
                "SHA256withECDSAinP1363Format", provider);
            Assert.assertNotNull(sig256);
            Assert.assertEquals(PROVIDER, sig256.getProvider().getName());
        }

        /* Test SHA384withECDSAinP1363Format availability */
        if (availableAlgorithms.contains("SHA384withECDSAinP1363Format")) {
            Signature sig384 = Signature.getInstance(
                "SHA384withECDSAinP1363Format", provider);
            Assert.assertNotNull(sig384);
            Assert.assertEquals(PROVIDER, sig384.getProvider().getName());
        }

        /* Test SHA3-256withECDSAinP1363Format availability */
        if (availableAlgorithms.contains("SHA3-256withECDSAinP1363Format")) {
            Signature sigSha3_256 = Signature.getInstance(
                "SHA3-256withECDSAinP1363Format", provider);
            Assert.assertNotNull(sigSha3_256);
            Assert.assertEquals(PROVIDER, sigSha3_256.getProvider().getName());
        }

        /* Test SHA3-384withECDSAinP1363Format availability */
        if (availableAlgorithms.contains("SHA3-384withECDSAinP1363Format")) {
            Signature sigSha3_384 = Signature.getInstance(
                "SHA3-384withECDSAinP1363Format", provider);
            Assert.assertNotNull(sigSha3_384);
            Assert.assertEquals(PROVIDER, sigSha3_384.getProvider().getName());
        }

        /* Test SHA3-512withECDSAinP1363Format availability */
        if (availableAlgorithms.contains("SHA3-512withECDSAinP1363Format")) {
            Signature sigSha3_512 = Signature.getInstance(
                "SHA3-512withECDSAinP1363Format", provider);
            Assert.assertNotNull(sigSha3_512);
            Assert.assertEquals(PROVIDER, sigSha3_512.getProvider().getName());
        }

        /* Test SHA512withECDSAinP1363Format availability */
        if (availableAlgorithms.contains("SHA512withECDSAinP1363Format")) {
            Signature sig512 = Signature.getInstance(
                "SHA512withECDSAinP1363Format", provider);
            Assert.assertNotNull(sig512);
            Assert.assertEquals(PROVIDER, sig512.getProvider().getName());
        }
    }

    @Test
    public void testP1363SignatureLength() throws Exception {

        /* Skip test if no ECC curves are available */
        if (enabledCurves.size() == 0) {
            return;
        }

        /* Test enabled curves with their expected P1363 signature lengths */
        for (int i = 0; i < enabledCurves.size(); i++) {
            String curve = enabledCurves.get(i);
            int expectedLen = getExpectedP1363Length(curve);

            /* Use pre-generated key pair for this curve */
            KeyPair keyPair = curveKeyPairs.get(curve);
            Assert.assertNotNull("Key pair should not be null for " + curve,
                keyPair);

            /* Test message */
            byte[] message = ("P1363 test message for " + curve).getBytes();

            /* Test SHA256withECDSAinP1363Format */
            Signature sig = Signature.getInstance(
                "SHA256withECDSAinP1363Format", provider);
            sig.initSign(keyPair.getPrivate());
            sig.update(message);
            byte[] signature = sig.sign();

            Assert.assertEquals("P1363 signature length for " + curve,
                expectedLen, signature.length);

            /* Verify signature */
            sig.initVerify(keyPair.getPublic());
            sig.update(message);
            Assert.assertTrue("P1363 signature verification for " + curve,
                sig.verify(signature));
        }
    }

    @Test
    public void testP1363vsDERFormat() throws Exception {

        /* Skip test if secp256r1 not available */
        if (!enabledCurves.contains("secp256r1")) {
            return;
        }

        /* Use pre-generated key pair for secp256r1 */
        KeyPair keyPair = curveKeyPairs.get("secp256r1");
        Assert.assertNotNull("Key pair should not be null for secp256r1",
            keyPair);

        byte[] message = "P1363 vs DER format test".getBytes();

        /* Create DER format signature */
        Signature sigDer = Signature.getInstance("SHA256withECDSA", provider);
        sigDer.initSign(keyPair.getPrivate());
        sigDer.update(message);
        byte[] derSignature = sigDer.sign();

        /* Create P1363 format signature */
        Signature sigP1363 = Signature.getInstance(
            "SHA256withECDSAinP1363Format", provider);
        sigP1363.initSign(keyPair.getPrivate());
        sigP1363.update(message);
        byte[] p1363Signature = sigP1363.sign();

        /* P1363 signature should be exactly 64 bytes for secp256r1 */
        Assert.assertEquals("P1363 signature should be 64 bytes",
            64, p1363Signature.length);

        /* DER signature length varies, but should be different from P1363 */
        Assert.assertNotEquals(
            "DER and P1363 signatures should have different lengths",
            derSignature.length, p1363Signature.length);

        /* Verify P1363 signature */
        sigP1363.initVerify(keyPair.getPublic());
        sigP1363.update(message);
        Assert.assertTrue("P1363 signature should verify",
            sigP1363.verify(p1363Signature));

        /* Verify DER signature */
        sigDer.initVerify(keyPair.getPublic());
        sigDer.update(message);
        Assert.assertTrue("DER signature should verify",
            sigDer.verify(derSignature));
    }

    @Test
    public void testP1363SHA384() throws Exception {

        /* Skip test if secp384r1 not available */
        if (!enabledCurves.contains("secp384r1")) {
            return;
        }

        /* Use pre-generated key pair for secp384r1 */
        KeyPair keyPair = curveKeyPairs.get("secp384r1");
        Assert.assertNotNull("Key pair should not be null for secp384r1",
            keyPair);

        byte[] message = "SHA384 P1363 test message".getBytes();

        /* Test SHA384withECDSAinP1363Format */
        Signature sig = Signature.getInstance(
            "SHA384withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        /* P1363 signature should be exactly 96 bytes for secp384r1 */
        Assert.assertEquals("P1363 SHA384 signature should be 96 bytes",
            96, signature.length);

        /* Verify signature */
        sig.initVerify(keyPair.getPublic());
        sig.update(message);
        Assert.assertTrue("P1363 SHA384 signature should verify",
            sig.verify(signature));
    }

    @Test
    public void testP1363SHA3_256() throws Exception {

        /* Skip test if secp256r1 not available */
        if (!enabledCurves.contains("secp256r1")) {
            return;
        }

        /* Skip test if SHA3-256 algorithm not available */
        if (!availableAlgorithms.contains("SHA3-256withECDSAinP1363Format")) {
            return;
        }

        /* Use pre-generated key pair for secp256r1 */
        KeyPair keyPair = curveKeyPairs.get("secp256r1");
        Assert.assertNotNull("Key pair should not be null for secp256r1",
            keyPair);

        byte[] message = "SHA3-256 P1363 test message".getBytes();

        /* Test SHA3-256withECDSAinP1363Format */
        Signature sig = Signature.getInstance(
            "SHA3-256withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        /* P1363 signature should be exactly 64 bytes for secp256r1 */
        Assert.assertEquals("P1363 SHA3-256 signature should be 64 bytes",
            64, signature.length);

        /* Verify signature */
        sig.initVerify(keyPair.getPublic());
        sig.update(message);
        Assert.assertTrue("P1363 SHA3-256 signature should verify",
            sig.verify(signature));
    }

    @Test
    public void testP1363SHA3_384() throws Exception {

        /* Skip test if secp384r1 not available */
        if (!enabledCurves.contains("secp384r1")) {
            return;
        }

        /* Skip test if SHA3-384 algorithm not available */
        if (!availableAlgorithms.contains("SHA3-384withECDSAinP1363Format")) {
            return;
        }

        /* Use pre-generated key pair for secp384r1 */
        KeyPair keyPair = curveKeyPairs.get("secp384r1");
        Assert.assertNotNull("Key pair should not be null for secp384r1",
            keyPair);

        byte[] message = "SHA3-384 P1363 test message".getBytes();

        /* Test SHA3-384withECDSAinP1363Format */
        Signature sig = Signature.getInstance(
            "SHA3-384withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        /* P1363 signature should be exactly 96 bytes for secp384r1 */
        Assert.assertEquals("P1363 SHA3-384 signature should be 96 bytes",
            96, signature.length);

        /* Verify signature */
        sig.initVerify(keyPair.getPublic());
        sig.update(message);
        Assert.assertTrue("P1363 SHA3-384 signature should verify",
            sig.verify(signature));
    }

    @Test
    public void testP1363SHA3_512() throws Exception {

        /* Skip test if secp521r1 not available */
        if (!enabledCurves.contains("secp521r1")) {
            return;
        }

        /* Skip test if SHA3-512 algorithm not available */
        if (!availableAlgorithms.contains("SHA3-512withECDSAinP1363Format")) {
            return;
        }

        /* Use pre-generated key pair for secp521r1 */
        KeyPair keyPair = curveKeyPairs.get("secp521r1");
        Assert.assertNotNull("Key pair should not be null for secp521r1",
            keyPair);

        byte[] message = "SHA3-512 P1363 test message".getBytes();

        /* Test SHA3-512withECDSAinP1363Format */
        Signature sig = Signature.getInstance(
            "SHA3-512withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        /* P1363 signature should be exactly 132 bytes for secp521r1 */
        Assert.assertEquals("P1363 SHA3-512 signature should be 132 bytes",
            132, signature.length);

        /* Verify signature */
        sig.initVerify(keyPair.getPublic());
        sig.update(message);
        Assert.assertTrue("P1363 SHA3-512 signature should verify",
            sig.verify(signature));
    }

    @Test
    public void testP1363SHA512() throws Exception {

        /* Skip test if secp521r1 not available */
        if (!enabledCurves.contains("secp521r1")) {
            return;
        }

        /* Use pre-generated key pair for secp521r1 */
        KeyPair keyPair = curveKeyPairs.get("secp521r1");
        Assert.assertNotNull("Key pair should not be null for secp521r1",
            keyPair);

        byte[] message = "SHA512 P1363 test message".getBytes();

        /* Test SHA512withECDSAinP1363Format */
        Signature sig = Signature.getInstance(
            "SHA512withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        /* P1363 signature should be exactly 132 bytes for secp521r1 */
        Assert.assertEquals("P1363 SHA512 signature should be 132 bytes",
            132, signature.length);

        /* Verify signature */
        sig.initVerify(keyPair.getPublic());
        sig.update(message);
        Assert.assertTrue("P1363 SHA512 signature should verify",
            sig.verify(signature));
    }

    @Test
    public void testP1363MultipleUpdates() throws Exception {

        /* Skip test if no ECC curves are available */
        if (enabledCurves.size() == 0) {
            return;
        }

        /* Use pre-generated key pair for first available curve */
        String curve = enabledCurves.get(0);
        KeyPair keyPair = curveKeyPairs.get(curve);
        Assert.assertNotNull("Key pair should not be null for " + curve,
            keyPair);

        byte[] message1 = "First part of ".getBytes();
        byte[] message2 = "multi-update message".getBytes();

        /* Test with multiple updates */
        Signature sig = Signature.getInstance(
            "SHA256withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(message1);
        sig.update(message2);
        byte[] signature = sig.sign();

        int expectedLen = getExpectedP1363Length(enabledCurves.get(0));
        Assert.assertEquals("P1363 signature should be " + expectedLen +
            " bytes", expectedLen, signature.length);

        /* Verify with same multiple updates */
        sig.initVerify(keyPair.getPublic());
        sig.update(message1);
        sig.update(message2);
        Assert.assertTrue("Multi-update P1363 signature should verify",
            sig.verify(signature));

        /* Verify with single update should fail */
        byte[] fullMessage = new byte[message1.length + message2.length];
        System.arraycopy(message1, 0, fullMessage, 0, message1.length);
        System.arraycopy(message2, 0, fullMessage, message1.length,
            message2.length);

        sig.initVerify(keyPair.getPublic());
        sig.update(fullMessage);
        Assert.assertTrue(
            "Single update should also verify (content is the same)",
            sig.verify(signature));
    }

    @Test
    public void testP1363InvalidSignature() throws Exception {

        /* Skip test if no ECC curves are available */
        if (enabledCurves.size() == 0) {
            return;
        }

        /* Use two different key pairs to verify that signatures don't
         * cross-verify with wrong keys. We reuse the pre-generated key
         * pair for keyPair1, but must generate keyPair2 fresh since this
         * negative test requires different keys and we only have one
         * pre-generated key pair per curve. */
        String curve = enabledCurves.get(0);
        KeyPair keyPair1 = curveKeyPairs.get(curve);
        Assert.assertNotNull("Key pair 1 should not be null", keyPair1);

        /* Generate a second key pair on the same curve for negative
         * test verification */
        KeyPairGenerator keyGen =
            KeyPairGenerator.getInstance("EC", provider);
        keyGen.initialize(new ECGenParameterSpec(curve));
        KeyPair keyPair2 = keyGen.generateKeyPair();

        byte[] message = "Invalid signature test".getBytes();

        /* Create signature with first key */
        Signature sig = Signature.getInstance(
            "SHA256withECDSAinP1363Format", provider);
        sig.initSign(keyPair1.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        /* Try to verify with second key - should fail */
        sig.initVerify(keyPair2.getPublic());
        sig.update(message);
        Assert.assertFalse("Signature should not verify with wrong key",
            sig.verify(signature));

        /* Try to verify with correct key but wrong message - should fail */
        sig.initVerify(keyPair1.getPublic());
        sig.update("Wrong message".getBytes());
        Assert.assertFalse("Signature should not verify with wrong message",
            sig.verify(signature));
    }

    @Test
    public void testP1363LargeMessage() throws Exception {

        /* Skip test if no ECC curves are available */
        if (enabledCurves.size() == 0) {
            return;
        }

        /* Use pre-generated key pair for first available curve */
        String curve = enabledCurves.get(0);
        KeyPair keyPair = curveKeyPairs.get(curve);
        Assert.assertNotNull("Key pair should not be null for " + curve,
            keyPair);

        /* Create large message */
        byte[] largeMessage = new byte[10000];
        new SecureRandom().nextBytes(largeMessage);

        /* Test P1363 signature with large message */
        Signature sig = Signature.getInstance(
            "SHA256withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(largeMessage);
        byte[] signature = sig.sign();

        int expectedLen = getExpectedP1363Length(enabledCurves.get(0));
        Assert.assertEquals("P1363 signature should be " + expectedLen +
            " bytes", expectedLen, signature.length);

        /* Verify signature */
        sig.initVerify(keyPair.getPublic());
        sig.update(largeMessage);
        Assert.assertTrue("Large message P1363 signature should verify",
            sig.verify(signature));
    }

    @Test
    public void testP1363EmptyMessage() throws Exception {

        /* Skip test if no ECC curves are available */
        if (enabledCurves.size() == 0) {
            return;
        }

        /* Use pre-generated key pair for first available curve */
        String curve = enabledCurves.get(0);
        KeyPair keyPair = curveKeyPairs.get(curve);
        Assert.assertNotNull("Key pair should not be null for " + curve,
            keyPair);

        byte[] emptyMessage = new byte[0];

        /* Test P1363 signature with empty message */
        Signature sig = Signature.getInstance(
            "SHA256withECDSAinP1363Format", provider);
        sig.initSign(keyPair.getPrivate());
        sig.update(emptyMessage);
        byte[] signature = sig.sign();

        int expectedLen = getExpectedP1363Length(enabledCurves.get(0));
        Assert.assertEquals("P1363 signature should be " + expectedLen +
            " bytes", expectedLen, signature.length);

        /* Verify signature */
        sig.initVerify(keyPair.getPublic());
        sig.update(emptyMessage);
        Assert.assertTrue("Empty message P1363 signature should verify",
            sig.verify(signature));
    }
}

