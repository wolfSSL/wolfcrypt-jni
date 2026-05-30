/* WolfCryptX25519KeyAgreementTest.java
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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;

import javax.crypto.KeyAgreement;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit4 tests for WolfCryptKeyAgreement X25519 (XDH).
 *
 * RFC 7748 Section 6.1 test vector used for correctness verification.
 */
public class WolfCryptX25519KeyAgreementTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallation() {
        Security.insertProviderAt(new WolfCryptProvider(), 1);
        System.out.println("JCE WolfCryptX25519KeyAgreement Class");
    }

    /** Decode lowercase hex string to byte array. */
    private static byte[] hex(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i + 1), 16));
        }
        return out;
    }

    /**
     * Build X25519 SPKI DER (44 bytes) from a 32-byte little-endian
     * u-coordinate.
     *
     * Structure:
     *   30 2a              SEQUENCE (42 bytes)
     *     30 05            SEQUENCE (AlgorithmIdentifier)
     *       06 03 2b 65 6e  OID 1.3.101.110 (id-X25519)
     *     03 21            BIT STRING (33 bytes)
     *       00              0 unused bits
     *         <32-byte public key>
     */
    private static byte[] buildX25519Spki(byte[] pub) {
        byte[] prefix = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x03, 0x21, 0x00
        };
        byte[] out = new byte[44];
        System.arraycopy(prefix, 0, out, 0, 12);
        System.arraycopy(pub, 0, out, 12, 32);
        return out;
    }

    /*
     * RFC 7748 Section 6.1 — X25519 Diffie-Hellman test vector.
     * All values are 32-byte little-endian (raw X25519 wire format).
     */
    private static final byte[] RFC_ALICE_PRIV = hex(
        "77076d0a7318a57d3c16c17251b26645" +
        "df91ef6f5eacc0aee9eefb22e65fc54e");
    private static final byte[] RFC_ALICE_PUB = hex(
        "8520f0098930a754748b7ddcb43ef75a" +
        "0dbf3a0d26381af4eba4a98eaa9b4e6a");
    private static final byte[] RFC_BOB_PRIV = hex(
        "5dab087e624a8a4b79e17f8b83800ee6" +
        "6f3bb1292618b6fd1c268f061c90d7fd");
    private static final byte[] RFC_BOB_PUB = hex(
        "de9edb7d7b7dc1b4d35b61c2ece43527" +
        "3cf1cfa7673a7ee35f19c7ddc4d7b1bf");
    private static final byte[] RFC_SHARED = hex(
        "4a5d9d5ba4ce2de1728e3bf480350f25" +
        "e07e21c947d19e3376f09b3c1e161742");

    /**
     * RFC 7748 §6.1: Alice computes shared secret using her private key and
     * Bob's public key; result must equal the known shared secret.
     */
    @Test
    public void testRfc7748VectorAliceSide() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyFactory kf = KeyFactory.getInstance("X25519", "wolfJCE");
        PrivateKey alicePriv = kf.generatePrivate(
            new XECPrivateKeySpec(NamedParameterSpec.X25519, RFC_ALICE_PRIV));
        PublicKey bobPub = kf.generatePublic(
            new X509EncodedKeySpec(buildX25519Spki(RFC_BOB_PUB)));

        KeyAgreement ka = KeyAgreement.getInstance("XDH", "wolfJCE");
        ka.init(alicePriv);
        ka.doPhase(bobPub, true);
        byte[] shared = ka.generateSecret();

        assertArrayEquals("RFC 7748 §6.1 Alice-side shared secret mismatch",
            RFC_SHARED, shared);
    }

    /**
     * RFC 7748 §6.1: Bob computes shared secret using his private key and
     * Alice's public key; result must equal the known shared secret.
     */
    @Test
    public void testRfc7748VectorBobSide() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyFactory kf = KeyFactory.getInstance("X25519", "wolfJCE");
        PrivateKey bobPriv = kf.generatePrivate(
            new XECPrivateKeySpec(NamedParameterSpec.X25519, RFC_BOB_PRIV));
        PublicKey alicePub = kf.generatePublic(
            new X509EncodedKeySpec(buildX25519Spki(RFC_ALICE_PUB)));

        KeyAgreement ka = KeyAgreement.getInstance("XDH", "wolfJCE");
        ka.init(bobPriv);
        ka.doPhase(alicePub, true);
        byte[] shared = ka.generateSecret();

        assertArrayEquals("RFC 7748 §6.1 Bob-side shared secret mismatch",
            RFC_SHARED, shared);
    }

    /**
     * Round-trip with generated key pairs: both sides produce the same
     * shared secret.
     */
    @Test
    public void testRoundTripSymmetry() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "wolfJCE");
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("XDH", "wolfJCE");

        ka.init(alice.getPrivate());
        ka.doPhase(bob.getPublic(), true);
        byte[] aliceShared = ka.generateSecret();

        ka.init(bob.getPrivate());
        ka.doPhase(alice.getPublic(), true);
        byte[] bobShared = ka.generateSecret();

        assertEquals("X25519 shared secret must be 32 bytes", 32, aliceShared.length);
        assertArrayEquals("Alice and Bob must derive the same shared secret",
            aliceShared, bobShared);
    }

    /**
     * X25519 alias for KeyAgreement resolves to the same implementation.
     */
    @Test
    public void testX25519AlgorithmAlias() throws Exception {
        Assume.assumeTrue(FeatureDetect.Curve25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "wolfJCE");
        KeyPair alice = kpg.generateKeyPair();
        KeyPair bob = kpg.generateKeyPair();

        KeyAgreement kaXdh = KeyAgreement.getInstance("XDH", "wolfJCE");
        kaXdh.init(alice.getPrivate());
        kaXdh.doPhase(bob.getPublic(), true);
        byte[] sharedXdh = kaXdh.generateSecret();

        KeyAgreement kaX25519 = KeyAgreement.getInstance("X25519", "wolfJCE");
        kaX25519.init(alice.getPrivate());
        kaX25519.doPhase(bob.getPublic(), true);
        byte[] sharedX25519 = kaX25519.generateSecret();

        assertArrayEquals("XDH and X25519 aliases must produce the same secret",
            sharedXdh, sharedX25519);
    }
}
