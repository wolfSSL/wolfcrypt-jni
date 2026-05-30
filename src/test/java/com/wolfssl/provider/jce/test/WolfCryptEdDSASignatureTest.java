/* WolfCryptEdDSASignatureTest.java
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

import java.util.Arrays;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit4 tests for WolfCryptEdDSASignature (Ed25519).
 *
 * Test vectors from RFC 8032 Section 6.
 */
public class WolfCryptEdDSASignatureTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void testProviderInstallation() {
        Security.insertProviderAt(new WolfCryptProvider(), 1);
        System.out.println("JCE WolfCryptEdDSASignature Class");
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
     * Build Ed25519 PKCS#8 v1 DER (48 bytes) from a 32-byte seed.
     *
     * Structure:
     *   30 2e              SEQUENCE (46 bytes)
     *     02 01 00          INTEGER 0 (version)
     *     30 05            SEQUENCE (AlgorithmIdentifier)
     *       06 03 2b 65 70  OID 1.3.101.112 (id-Ed25519)
     *     04 22            OCTET STRING (34 bytes, privateKey)
     *       04 20          OCTET STRING (32 bytes, seed)
     *         <32-byte seed>
     */
    private static byte[] buildEd25519Pkcs8(byte[] seed) {
        byte[] prefix = {
            0x30, 0x2e, 0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x04, 0x22, 0x04, 0x20
        };
        byte[] out = new byte[48];
        System.arraycopy(prefix, 0, out, 0, 16);
        System.arraycopy(seed, 0, out, 16, 32);
        return out;
    }

    /**
     * Build Ed25519 SPKI DER (44 bytes) from a 32-byte public key.
     *
     * Structure:
     *   30 2a              SEQUENCE (42 bytes)
     *     30 05            SEQUENCE (AlgorithmIdentifier)
     *       06 03 2b 65 70  OID 1.3.101.112 (id-Ed25519)
     *     03 21            BIT STRING (33 bytes)
     *       00              0 unused bits
     *         <32-byte public key>
     */
    private static byte[] buildEd25519Spki(byte[] pub) {
        byte[] prefix = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
            0x03, 0x21, 0x00
        };
        byte[] out = new byte[44];
        System.arraycopy(prefix, 0, out, 0, 12);
        System.arraycopy(pub, 0, out, 12, 32);
        return out;
    }

    /*
     * draft-josefsson-eddsa-ed25519-02 §6 — Test Vector 1 (empty message)
     * (also cited as RFC 8032 §6; vectors from IETF draft)
     */
    private static final byte[] TV1_SEED = hex(
        "9d61b19deffd5a60ba844af492ec2cc4" +
        "4449c5697b326919703bac031cae7f60");
    private static final byte[] TV1_PUB = hex(
        "d75a980182b10ab7d54bfed3c964073a" +
        "0ee172f3daa62325af021a68f707511a");
    private static final byte[] TV1_MSG = new byte[0];
    private static final byte[] TV1_SIG = hex(
        "e5564300c360ac729086e2cc806e828a" +
        "84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b" +
        "d25bf5f0595bbe24655141438e7a100b");

    /*
     * RFC 8032 Section 6 — Test Vector 3 (message = 0xaf82)
     */
    private static final byte[] TV3_SEED = hex(
        "c5aa8df43f9f837bedb7442f31dcb7b1" +
        "66d38535076f094b85ce3a2e0b4458f7");
    private static final byte[] TV3_PUB = hex(
        "fc51cd8e6218a1a38da47ed00230f058" +
        "0816ed13ba3303ac5deb911548908025");
    private static final byte[] TV3_MSG = hex("af82");
    private static final byte[] TV3_SIG = hex(
        "6291d657deec24024827e69c3abe01a3" +
        "0ce548a284743a445e3680d7db5ac3ac" +
        "18ff9b538d16f290ae67f760984dc659" +
        "4a7c15e9716ed28dc027beceea1ec40a");

    /**
     * RFC 8032 vector 1: sign empty message, verify signature bytes match,
     * then verify the known good signature passes.
     */
    @Test
    public void testVector1SignAndVerify() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyFactory kf = KeyFactory.getInstance("Ed25519", "wolfJCE");
        PrivateKey priv = kf.generatePrivate(
            new PKCS8EncodedKeySpec(buildEd25519Pkcs8(TV1_SEED)));
        PublicKey pub = kf.generatePublic(
            new X509EncodedKeySpec(buildEd25519Spki(TV1_PUB)));

        Signature sig = Signature.getInstance("Ed25519", "wolfJCE");

        sig.initSign(priv);
        sig.update(TV1_MSG);
        byte[] produced = sig.sign();
        assertArrayEquals("RFC 8032 vector 1 signature mismatch", TV1_SIG, produced);

        sig.initVerify(pub);
        sig.update(TV1_MSG);
        assertTrue("RFC 8032 vector 1 verify failed", sig.verify(TV1_SIG));
    }

    /**
     * RFC 8032 vector 3: sign 2-byte message, verify signature bytes match,
     * then verify the known good signature passes.
     */
    @Test
    public void testVector3SignAndVerify() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyFactory kf = KeyFactory.getInstance("Ed25519", "wolfJCE");
        PrivateKey priv = kf.generatePrivate(
            new PKCS8EncodedKeySpec(buildEd25519Pkcs8(TV3_SEED)));
        PublicKey pub = kf.generatePublic(
            new X509EncodedKeySpec(buildEd25519Spki(TV3_PUB)));

        Signature sig = Signature.getInstance("Ed25519", "wolfJCE");

        sig.initSign(priv);
        sig.update(TV3_MSG);
        byte[] produced = sig.sign();
        assertArrayEquals("RFC 8032 vector 3 signature mismatch", TV3_SIG, produced);

        sig.initVerify(pub);
        sig.update(TV3_MSG);
        assertTrue("RFC 8032 vector 3 verify failed", sig.verify(TV3_SIG));
    }

    /**
     * Generated key pair: sign and verify round-trip.
     */
    @Test
    public void testRoundTrip() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = "Hello, wolfJCE Ed25519!".getBytes("UTF-8");

        Signature sig = Signature.getInstance("Ed25519", "wolfJCE");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        assertEquals("Ed25519 signature must be 64 bytes", 64, signature.length);

        sig.initVerify(kp.getPublic());
        sig.update(message);
        assertTrue("Ed25519 round-trip verify failed", sig.verify(signature));
    }

    /**
     * Multiple update() calls produce the same signature as a single update()
     * (Ed25519 is deterministic and buffers the full message).
     */
    @Test
    public void testMultipleUpdatesMatchSingleUpdate() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();

        byte[] part1 = "Hello, ".getBytes("UTF-8");
        byte[] part2 = "wolfJCE ".getBytes("UTF-8");
        byte[] part3 = "Ed25519!".getBytes("UTF-8");
        byte[] full = "Hello, wolfJCE Ed25519!".getBytes("UTF-8");

        Signature sig = Signature.getInstance("Ed25519", "wolfJCE");
        sig.initSign(kp.getPrivate());
        sig.update(part1);
        sig.update(part2);
        sig.update(part3);
        byte[] sigChunked = sig.sign();

        sig.initSign(kp.getPrivate());
        sig.update(full);
        byte[] sigFull = sig.sign();

        assertArrayEquals("Chunked updates must produce same sig as single update",
            sigFull, sigChunked);
    }

    /**
     * Tampered message must cause verify() to return false.
     */
    @Test
    public void testTamperedMessageFails() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = "tamper test".getBytes("UTF-8");

        Signature sig = Signature.getInstance("Ed25519", "wolfJCE");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        byte[] tampered = Arrays.copyOf(message, message.length);
        tampered[0] ^= 0x01;

        sig.initVerify(kp.getPublic());
        sig.update(tampered);
        assertFalse("Tampered message must fail verification", sig.verify(signature));
    }

    /**
     * Tampered signature must cause verify() to return false.
     */
    @Test
    public void testTamperedSignatureFails() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = "tamper sig test".getBytes("UTF-8");

        Signature sig = Signature.getInstance("Ed25519", "wolfJCE");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        byte[] tampered = Arrays.copyOf(signature, signature.length);
        tampered[0] ^= 0x01;

        sig.initVerify(kp.getPublic());
        sig.update(message);
        assertFalse("Tampered signature must fail verification", sig.verify(tampered));
    }

    /**
     * Verifying with a different key pair's public key must return false.
     */
    @Test
    public void testWrongKeyFails() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "wolfJCE");
        KeyPair kp1 = kpg.generateKeyPair();
        KeyPair kp2 = kpg.generateKeyPair();
        byte[] message = "wrong key test".getBytes("UTF-8");

        Signature sig = Signature.getInstance("Ed25519", "wolfJCE");
        sig.initSign(kp1.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        sig.initVerify(kp2.getPublic());
        sig.update(message);
        assertFalse("Verify with wrong public key must fail", sig.verify(signature));
    }

    /**
     * "EdDSA" alias resolves to the Ed25519 implementation.
     */
    @Test
    public void testEdDSAAlias() throws Exception {
        Assume.assumeTrue(FeatureDetect.Ed25519Enabled());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "wolfJCE");
        KeyPair kp = kpg.generateKeyPair();
        byte[] message = "EdDSA alias test".getBytes("UTF-8");

        Signature sig = Signature.getInstance("EdDSA", "wolfJCE");
        sig.initSign(kp.getPrivate());
        sig.update(message);
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(message);
        assertTrue("EdDSA alias verify failed", sig.verify(signature));
    }
}
