/* WolfCryptX25519KeyFactoryTest.java
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
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Assume;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit4 tests for WolfCryptX25519KeyFactory (X25519 / XDH).
 */
public class WolfCryptX25519KeyFactoryTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallation() {
        Security.insertProviderAt(new WolfCryptProvider(), 1);
        System.out.println("JCE WolfCryptX25519KeyFactory Class");
    }

    /** Generate a fresh X25519 key pair via wolfJCE. */
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "wolfJCE");
        return kpg.generateKeyPair();
    }

    /** Get the X25519 KeyFactory from wolfJCE. */
    private static KeyFactory keyFactory() throws Exception {
        return KeyFactory.getInstance("X25519", "wolfJCE");
    }

    /**
     * Private key PKCS#8 round-trip: generate → getEncoded() → reconstruct
     * → encodings match.
     */
    @Test
    public void testPrivateKeyPKCS8RoundTrip() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPair kp = generateKeyPair();
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        assertNotNull("Private key encoding must not be null", pkcs8);
        assertEquals("X25519 PKCS#8 must be 48 bytes", 48, pkcs8.length);

        KeyFactory kf = keyFactory();
        PrivateKey reconstructed = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        assertNotNull("Reconstructed private key must not be null", reconstructed);
        assertArrayEquals("PKCS#8 round-trip encoding mismatch",
            pkcs8, reconstructed.getEncoded());
    }

    /**
     * Public key SPKI round-trip: generate → getEncoded() → reconstruct
     * → encodings match.
     */
    @Test
    public void testPublicKeySpkiRoundTrip() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPair kp = generateKeyPair();
        byte[] spki = kp.getPublic().getEncoded();
        assertNotNull("Public key encoding must not be null", spki);
        assertEquals("X25519 SPKI must be 44 bytes", 44, spki.length);

        KeyFactory kf = keyFactory();
        PublicKey reconstructed = kf.generatePublic(new X509EncodedKeySpec(spki));
        assertNotNull("Reconstructed public key must not be null", reconstructed);
        assertArrayEquals("SPKI round-trip encoding mismatch",
            spki, reconstructed.getEncoded());
    }

    /**
     * Private key XECPrivateKeySpec round-trip: generate → getKeySpec →
     * generatePrivate → encodings match.
     */
    @Test
    public void testPrivateKeyXECSpecRoundTrip() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPair kp = generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        byte[] originalEncoded = priv.getEncoded();

        KeyFactory kf = keyFactory();
        XECPrivateKeySpec spec = kf.getKeySpec(priv, XECPrivateKeySpec.class);
        assertNotNull("XECPrivateKeySpec must not be null", spec);
        assertEquals("Spec params must be X25519",
            "X25519", ((NamedParameterSpec) spec.getParams()).getName());

        PrivateKey reconstructed = kf.generatePrivate(spec);
        assertNotNull("Reconstructed private key must not be null", reconstructed);
        assertArrayEquals("XECPrivateKeySpec round-trip encoding mismatch",
            originalEncoded, reconstructed.getEncoded());
    }

    /**
     * Public key XECPublicKeySpec round-trip: generate → getKeySpec →
     * generatePublic → encodings match.
     */
    @Test
    public void testPublicKeyXECSpecRoundTrip() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPair kp = generateKeyPair();
        PublicKey pub = kp.getPublic();
        byte[] originalEncoded = pub.getEncoded();

        KeyFactory kf = keyFactory();
        XECPublicKeySpec spec = kf.getKeySpec(pub, XECPublicKeySpec.class);
        assertNotNull("XECPublicKeySpec must not be null", spec);
        assertEquals("Spec params must be X25519",
            "X25519", ((NamedParameterSpec) spec.getParams()).getName());

        PublicKey reconstructed = kf.generatePublic(spec);
        assertNotNull("Reconstructed public key must not be null", reconstructed);
        assertArrayEquals("XECPublicKeySpec round-trip encoding mismatch",
            originalEncoded, reconstructed.getEncoded());
    }

    /**
     * getKeySpec with PKCS8EncodedKeySpec class returns the DER encoding.
     */
    @Test
    public void testGetKeySpecPKCS8() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPair kp = generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        byte[] expected = priv.getEncoded();

        KeyFactory kf = keyFactory();
        PKCS8EncodedKeySpec spec = kf.getKeySpec(priv, PKCS8EncodedKeySpec.class);
        assertNotNull("PKCS8EncodedKeySpec must not be null", spec);
        assertArrayEquals("getKeySpec(PKCS8) encoding mismatch",
            expected, spec.getEncoded());
    }

    /**
     * getKeySpec with X509EncodedKeySpec class returns the DER encoding.
     */
    @Test
    public void testGetKeySpecX509() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPair kp = generateKeyPair();
        PublicKey pub = kp.getPublic();
        byte[] expected = pub.getEncoded();

        KeyFactory kf = keyFactory();
        X509EncodedKeySpec spec = kf.getKeySpec(pub, X509EncodedKeySpec.class);
        assertNotNull("X509EncodedKeySpec must not be null", spec);
        assertArrayEquals("getKeySpec(X509) encoding mismatch",
            expected, spec.getEncoded());
    }

    /**
     * translateKey returns the same object for native wolfJCE key types.
     */
    @Test
    public void testTranslateKeyPassThrough() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPair kp = generateKeyPair();
        KeyFactory kf = keyFactory();

        Key translatedPriv = kf.translateKey(kp.getPrivate());
        assertSame("translateKey must return same object for native private key",
            kp.getPrivate(), translatedPriv);

        Key translatedPub = kf.translateKey(kp.getPublic());
        assertSame("translateKey must return same object for native public key",
            kp.getPublic(), translatedPub);
    }

    /**
     * generatePrivate with an unsupported KeySpec throws InvalidKeySpecException.
     */
    @Test(expected = InvalidKeySpecException.class)
    public void testUnsupportedPrivateKeySpec() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyFactory kf = keyFactory();
        kf.generatePrivate(new java.security.spec.DSAPrivateKeySpec(
            java.math.BigInteger.ONE,
            java.math.BigInteger.ONE,
            java.math.BigInteger.ONE,
            java.math.BigInteger.ONE));
    }

    /**
     * generatePublic with an unsupported KeySpec throws InvalidKeySpecException.
     */
    @Test(expected = InvalidKeySpecException.class)
    public void testUnsupportedPublicKeySpec() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyFactory kf = keyFactory();
        kf.generatePublic(new java.security.spec.DSAPublicKeySpec(
            java.math.BigInteger.ONE,
            java.math.BigInteger.ONE,
            java.math.BigInteger.ONE,
            java.math.BigInteger.ONE));
    }

    /**
     * XDH alias for the KeyFactory resolves to the same implementation.
     */
    @Test
    public void testXDHKeyFactoryAlias() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();
        byte[] spki = kp.getPublic().getEncoded();

        KeyFactory kf = KeyFactory.getInstance("XDH", "wolfJCE");
        PublicKey reconstructed = kf.generatePublic(new X509EncodedKeySpec(spki));
        assertArrayEquals("XDH alias KeyFactory SPKI mismatch",
            spki, reconstructed.getEncoded());
    }
}
