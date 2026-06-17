/* WolfCryptMlKemKeyFactoryTest.java
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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.security.Security;
import java.security.Provider;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.InvalidKeyException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptMlKemPublicKey;
import com.wolfssl.provider.jce.WolfCryptMlKemPrivateKey;
import com.wolfssl.wolfcrypt.MlKem;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit tests for the wolfJCE ML-KEM KeyFactory support, including parsing
 * of all RFC 9935 PKCS#8 CHOICE forms (seed, expandedKey, both).
 */
public class WolfCryptMlKemKeyFactoryTest {

    private static boolean mlKemEnabled = false;

    /* ML-KEM OID content bytes per level (arc 2.16.840.1.101.3.4.4.x) */
    private static final byte[] OID_512 = {
        0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01 };
    private static final byte[] OID_768 = {
        0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02 };
    private static final byte[] OID_1024 = {
        0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03 };

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptMlKemKeyFactoryTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        if (p != null && p.getService("KeyFactory", "ML-KEM") != null) {
            mlKemEnabled = true;
        }
        else {
            System.out.println("ML-KEM KeyFactory test skipped");
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("ML-KEM not compiled in", mlKemEnabled);
    }

    /** Minimal DER helpers for hand-crafting PKCS#8 CHOICE forms. */
    private static byte[] derLen(int len) {

        if (len < 128) {
            return new byte[] { (byte)len };
        }
        else if (len < 256) {
            return new byte[] { (byte)0x81, (byte)len };
        }

        return new byte[] { (byte)0x82, (byte)(len >> 8), (byte)(len & 0xFF) };
    }

    private static byte[] tlv(int tag, byte[] value) throws Exception {

        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(tag);
        o.write(derLen(value.length));
        o.write(value);

        return o.toByteArray();
    }

    private static byte[] cat(byte[]... parts) throws Exception {

        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            o.write(part);
        }

        return o.toByteArray();
    }

    private static byte[] oidFor(int level) {

        switch (level) {
            case MlKem.ML_KEM_512:  return OID_512;
            case MlKem.ML_KEM_768:  return OID_768;
            default:                return OID_1024;
        }
    }

    private static byte[] algId(int level) throws Exception {
        return tlv(0x30, tlv(0x06, oidFor(level)));
    }

    private static final byte[] VERSION_0 = { 0x02, 0x01, 0x00 };

    /* PKCS#8 with the given inner ML-KEM-PrivateKey CHOICE encoding. */
    private static byte[] pkcs8(int level, byte[] choice) throws Exception {
        return tlv(0x30, cat(VERSION_0, algId(level), tlv(0x04, choice)));
    }

    private static byte[] seedForm(int level, byte[] seed) throws Exception {
        /* seed [0] IMPLICIT OCTET STRING -> context primitive tag 0x80 */
        return pkcs8(level, tlv(0x80, seed));
    }

    private static byte[] expandedForm(int level, byte[] expanded)
        throws Exception {
        /* expandedKey is a universal OCTET STRING */
        return pkcs8(level, tlv(0x04, expanded));
    }

    private static byte[] bothForm(int level, byte[] seed, byte[] expanded)
        throws Exception {
        return pkcs8(level, tlv(0x30, cat(tlv(0x04, seed),
            tlv(0x04, expanded))));
    }

    @Test
    public void testX509Pkcs8RoundTrip() throws Exception {
        assumeEnabled();

        String[] names = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

        for (String name : names) {
            KeyPair kp = KeyPairGenerator.getInstance(name, "wolfJCE")
                .generateKeyPair();
            byte[] spki = kp.getPublic().getEncoded();
            byte[] p8 = kp.getPrivate().getEncoded();

            KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spki));
            PrivateKey priv =
                kf.generatePrivate(new PKCS8EncodedKeySpec(p8));

            assertArrayEquals(spki, pub.getEncoded());
            assertArrayEquals(p8, priv.getEncoded());
        }
    }

    @Test
    public void testGetKeySpec() throws Exception {
        assumeEnabled();

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");

        X509EncodedKeySpec pubSpec =
            kf.getKeySpec(kp.getPublic(), X509EncodedKeySpec.class);
        PKCS8EncodedKeySpec privSpec =
            kf.getKeySpec(kp.getPrivate(), PKCS8EncodedKeySpec.class);

        assertArrayEquals(kp.getPublic().getEncoded(), pubSpec.getEncoded());
        assertArrayEquals(kp.getPrivate().getEncoded(), privSpec.getEncoded());
    }

    @Test
    public void testLevelSpecificFactoryRejectsMismatch() throws Exception {
        assumeEnabled();

        KeyPair kp512 = KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
            .generateKeyPair();
        byte[] p8 = kp512.getPrivate().getEncoded();

        /* ML-KEM-768 factory must reject a 512 key */
        KeyFactory kf768 = KeyFactory.getInstance("ML-KEM-768", "wolfJCE");
        try {
            kf768.generatePrivate(new PKCS8EncodedKeySpec(p8));
            fail("Expected InvalidKeySpecException for level mismatch");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void testParseSeedFormMatchesExpandedForm() throws Exception {
        assumeEnabled();

        int[] levels = {
            MlKem.ML_KEM_512, MlKem.ML_KEM_768, MlKem.ML_KEM_1024 };

        for (int level : levels) {
            /* Deterministically derive a key from a fixed seed. */
            byte[] seed = new byte[MlKem.ML_KEM_SEED_SIZE];
            for (int i = 0; i < seed.length; i++) {
                seed[i] = (byte)(i + level);
            }

            MlKem k = new MlKem(level);
            k.makeKeyFromSeed(seed);
            byte[] expanded = k.exportPrivate();
            k.releaseNativeStruct();

            KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");

            /* seed form and expandedKey form must produce the same key, both
             * normalized to the expandedKey PKCS#8 output form. */
            PrivateKey fromSeed = kf.generatePrivate(
                new PKCS8EncodedKeySpec(seedForm(level, seed)));
            PrivateKey fromExpanded = kf.generatePrivate(
                new PKCS8EncodedKeySpec(expandedForm(level, expanded)));

            assertArrayEquals(fromExpanded.getEncoded(),
                fromSeed.getEncoded());
        }
    }

    @Test
    public void testParseBothForm() throws Exception {
        assumeEnabled();

        int level = MlKem.ML_KEM_768;
        byte[] seed = new byte[MlKem.ML_KEM_SEED_SIZE];
        Arrays.fill(seed, (byte)0x5A);

        MlKem k = new MlKem(level);
        k.makeKeyFromSeed(seed);
        byte[] expanded = k.exportPrivate();
        k.releaseNativeStruct();

        KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");
        PrivateKey fromBoth = kf.generatePrivate(
            new PKCS8EncodedKeySpec(bothForm(level, seed, expanded)));
        PrivateKey fromExpanded = kf.generatePrivate(
            new PKCS8EncodedKeySpec(expandedForm(level, expanded)));

        assertArrayEquals(fromExpanded.getEncoded(), fromBoth.getEncoded());
    }

    @Test
    public void testSeedFormKeyDecapsulates() throws Exception {
        assumeEnabled();

        int level = MlKem.ML_KEM_512;
        byte[] seed = new byte[MlKem.ML_KEM_SEED_SIZE];
        Arrays.fill(seed, (byte)0x11);

        /* Derive public key and a ciphertext/secret directly from native. */
        Rng rng = new Rng();
        rng.init();
        MlKem owner = new MlKem(level);
        owner.makeKeyFromSeed(seed);
        byte[][] enc = owner.encapsulate(rng);
        byte[] ciphertext = enc[0];
        byte[] secretEnc = enc[1];
        owner.releaseNativeStruct();
        rng.releaseNativeStruct();

        /* Build a seed-form PKCS#8 private key and decapsulate via native
         * after the KeyFactory expands it. Force the expandedKey output form
         * (set before generatePrivate, which sets encoding into the key)
         * so the trailing-bytes extraction below is valid regardless of any
         * jdk.mlkem.pkcs8.encoding override in the environment. */
        String prop = "jdk.mlkem.pkcs8.encoding";
        String saved = System.getProperty(prop);
        System.setProperty(prop, "expandedKey");

        byte[] expanded;
        try {
            KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");
            PrivateKey priv = kf.generatePrivate(
                new PKCS8EncodedKeySpec(seedForm(level, seed)));

            /* In expandedKey form the PKCS#8 ends with the expanded key
             * OCTET STRING bytes. */
            byte[] p8 = priv.getEncoded();
            int expSz = MlKem.ML_KEM_512_PRIVATE_KEY_SIZE;
            expanded = Arrays.copyOfRange(p8, p8.length - expSz, p8.length);

        } finally {
            if (saved == null) {
                System.clearProperty(prop);
            }
            else {
                System.setProperty(prop, saved);
            }
        }

        MlKem dec = new MlKem(level);
        dec.importPrivate(expanded);
        byte[] secretDec = dec.decapsulate(ciphertext);
        dec.releaseNativeStruct();

        assertArrayEquals(secretEnc, secretDec);
    }

    /* Parse a DER length at idx, returning {length, contentStart}. */
    private static int[] derLenAt(byte[] d, int idx) {
        int b = d[idx] & 0xFF;
        if ((b & 0x80) == 0) {
            return new int[] { b, idx + 1 };
        }
        int n = b & 0x7F;
        int len = 0;
        for (int i = 0; i < n; i++) {
            len = (len << 8) | (d[idx + 1 + i] & 0xFF);
        }
        return new int[] { len, idx + 1 + n };
    }

    /* Move cursor past one full TLV starting at off[0]. */
    private static void skipTlv(byte[] d, int[] off) {
        int[] li = derLenAt(d, off[0] + 1);
        off[0] = li[1] + li[0];
    }

    /* Move cursor into a constructed TLV's content at off[0]. */
    private static void enterSeq(byte[] d, int[] off) {
        int[] li = derLenAt(d, off[0] + 1);
        off[0] = li[1];
    }

    /* Return the first byte of the ML-KEM-PrivateKey CHOICE inside a PKCS#8
     * encoding: 0x80 seed, 0x04 expandedKey, 0x30 both. */
    private static int firstChoiceTag(byte[] p8) {
        int[] off = { 0 };
        enterSeq(p8, off);   /* into PrivateKeyInfo SEQUENCE */
        skipTlv(p8, off);    /* version INTEGER */
        skipTlv(p8, off);    /* privateKeyAlgorithm SEQUENCE */
        /* privateKey OCTET STRING; its content's first byte is the CHOICE */
        int[] li = derLenAt(p8, off[0] + 1);
        return p8[li[1]] & 0xFF;
    }

    @Test
    public void testPkcs8EncodingProperty() throws Exception {
        assumeEnabled();

        String prop = "jdk.mlkem.pkcs8.encoding";
        String saved = System.getProperty(prop);

        try {
            /* expandedKey form: inner CHOICE is a universal OCTET STRING */
            System.setProperty(prop, "expandedKey");
            byte[] exp = KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
                .generateKeyPair().getPrivate().getEncoded();
            assertEquals(0x04, firstChoiceTag(exp));

            /* seed form: inner CHOICE is the [0] context tag, much smaller */
            System.setProperty(prop, "seed");
            byte[] seed = KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
                .generateKeyPair().getPrivate().getEncoded();
            assertEquals(0x80, firstChoiceTag(seed));
            assertTrue(seed.length < exp.length);

            /* both form: inner CHOICE is a SEQUENCE, larger than expandedKey */
            System.setProperty(prop, "both");
            byte[] both = KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
                .generateKeyPair().getPrivate().getEncoded();
            assertEquals(0x30, firstChoiceTag(both));
            assertTrue(both.length > exp.length);

            /* A seed-form key re-imports and re-encodes identically while the
             * seed property is in effect. */
            System.setProperty(prop, "seed");
            KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");
            PrivateKey reimp =
                kf.generatePrivate(new PKCS8EncodedKeySpec(seed));
            assertArrayEquals(seed, reimp.getEncoded());

        } finally {
            if (saved == null) {
                System.clearProperty(prop);
            }
            else {
                System.setProperty(prop, saved);
            }
        }
    }

    /* X.509 SubjectPublicKeyInfo with the given raw public key. */
    private static byte[] spki(int level, byte[] rawPub) throws Exception {
        byte[] bitStr = tlv(0x03, cat(new byte[] { 0x00 }, rawPub));
        return tlv(0x30, cat(algId(level), bitStr));
    }

    private void assertPrivRejected(KeyFactory kf, byte[] der) {
        try {
            kf.generatePrivate(new PKCS8EncodedKeySpec(der));
            fail("Expected InvalidKeySpecException for malformed private key");
        } catch (InvalidKeySpecException e) {
            /* expected: parse errors surface as InvalidKeySpecException,
             * never an uncaught runtime exception */
        }
    }

    private void assertPubRejected(KeyFactory kf, byte[] der) {
        try {
            kf.generatePublic(new X509EncodedKeySpec(der));
            fail("Expected InvalidKeySpecException for malformed public key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void testMalformedKeysRejectedCleanly() throws Exception {
        assumeEnabled();

        KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");

        /* empty privateKey OCTET STRING -> must not throw a raw AIOOBE */
        assertPrivRejected(kf, pkcs8(MlKem.ML_KEM_512, new byte[0]));
        /* wrong-length seed */
        assertPrivRejected(kf, seedForm(MlKem.ML_KEM_512, new byte[32]));
        /* wrong-length expandedKey */
        assertPrivRejected(kf, expandedForm(MlKem.ML_KEM_512, new byte[100]));
        /* wrong-length public key */
        assertPubRejected(kf, spki(MlKem.ML_KEM_512, new byte[100]));

        /* negative long-form DER length (sign bit set) in privateKey */
        byte[] negLen = cat(VERSION_0, algId(MlKem.ML_KEM_512),
            new byte[] { 0x04, (byte)0x84, (byte)0x80, 0x00, 0x00, 0x00 });
        assertPrivRejected(kf, tlv(0x30, negLen));

        /* unsupported CHOICE tag (0x05 NULL) inside privateKey OCTET STRING */
        assertPrivRejected(kf,
            pkcs8(MlKem.ML_KEM_512, new byte[] { 0x05, 0x00 }));

        /* unrecognized algorithm OID (RSA OID) in a SPKI */
        byte[] rsaOid = tlv(0x06, new byte[] {
            (byte)0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7,
            0x0D, 0x01, 0x01, 0x01 });
        assertPubRejected(kf, tlv(0x30, cat(tlv(0x30, rsaOid),
            tlv(0x03, cat(new byte[] { 0x00 }, new byte[800])))));

        /* non-zero BIT STRING unused-bits byte */
        assertPubRejected(kf, tlv(0x30, cat(algId(MlKem.ML_KEM_512),
            tlv(0x03, cat(new byte[] { 0x07 }, new byte[800])))));

        /* both form with a seed and expandedKey from different keys must be
         * rejected as inconsistent (not silently accepted). */
        byte[] seedA = new byte[MlKem.ML_KEM_SEED_SIZE];
        Arrays.fill(seedA, (byte)0x11);
        byte[] seedB = new byte[MlKem.ML_KEM_SEED_SIZE];
        Arrays.fill(seedB, (byte)0x22);
        MlKem b = new MlKem(MlKem.ML_KEM_512);
        b.makeKeyFromSeed(seedB);
        byte[] expandedB = b.exportPrivate();
        b.releaseNativeStruct();
        assertPrivRejected(kf,
            bothForm(MlKem.ML_KEM_512, seedA, expandedB));

        /* Trailing data after the inner CHOICE (or inside the both SEQUENCE)
         * is non-canonical and must be rejected. Build from a valid,
         * consistent (seed, expandedKey) pair so only the trailing byte
         * differs. */
        MlKem g = new MlKem(MlKem.ML_KEM_512);
        byte[] seedG = new byte[MlKem.ML_KEM_SEED_SIZE];
        Arrays.fill(seedG, (byte)0x33);
        g.makeKeyFromSeed(seedG);
        byte[] expG = g.exportPrivate();
        g.releaseNativeStruct();

        /* trailing byte after the expandedKey OCTET STRING */
        assertPrivRejected(kf, pkcs8(MlKem.ML_KEM_512,
            cat(tlv(0x04, expG), new byte[] { 0x00 })));
        /* trailing byte inside the both SEQUENCE, after the OCTET STRINGs */
        assertPrivRejected(kf, pkcs8(MlKem.ML_KEM_512,
            tlv(0x30, cat(tlv(0x04, seedG), tlv(0x04, expG),
                new byte[] { 0x00 }))));

        /* trailing data after the PrivateKeyInfo SEQUENCE, and a trailing
         * element inside it after the privateKey OCTET STRING, must be
         * rejected (the optional v2 fields are not parsed). */
        assertPrivRejected(kf,
            cat(expandedForm(MlKem.ML_KEM_512, expG), new byte[] { 0x00 }));
        assertPrivRejected(kf, tlv(0x30, cat(VERSION_0,
            algId(MlKem.ML_KEM_512), tlv(0x04, tlv(0x04, expG)),
            new byte[] { 0x05, 0x00 })));

        /* SubjectPublicKeyInfo has no optional fields: reject trailing data
         * after the outer SEQUENCE, and a trailing element inside it after
         * the BIT STRING. Use a length-valid raw public key so only the
         * trailing data differs. */
        byte[] pub = new byte[MlKem.ML_KEM_512_PUBLIC_KEY_SIZE];
        assertPubRejected(kf,
            cat(spki(MlKem.ML_KEM_512, pub), new byte[] { 0x00 }));
        assertPubRejected(kf, tlv(0x30, cat(algId(MlKem.ML_KEM_512),
            tlv(0x03, cat(new byte[] { 0x00 }, pub)),
            new byte[] { 0x05, 0x00 })));

        /* AlgorithmIdentifier must contain only the OID (no parameters,
         * RFC 9935): reject an alg SEQUENCE with a trailing NULL parameter,
         * for both PKCS#8 and X.509. */
        byte[] algParams = tlv(0x30, cat(tlv(0x06, oidFor(MlKem.ML_KEM_512)),
            new byte[] { 0x05, 0x00 }));
        assertPrivRejected(kf, tlv(0x30, cat(VERSION_0, algParams,
            tlv(0x04, tlv(0x04, expG)))));
        assertPubRejected(kf, tlv(0x30, cat(algParams,
            tlv(0x03, cat(new byte[] { 0x00 }, pub)))));

        /* PrivateKeyInfo version must be 0; reject version 1. */
        byte[] version1 = { 0x02, 0x01, 0x01 };
        assertPrivRejected(kf, tlv(0x30, cat(version1,
            algId(MlKem.ML_KEM_512), tlv(0x04, tlv(0x04, expG)))));
    }

    @Test
    public void testPrivateKeyEqualsIndependentOfEncodingForm()
        throws Exception {
        assumeEnabled();

        /* Generate a real key to obtain a consistent (seed, expanded) pair. */
        int level = MlKem.ML_KEM_512;
        byte[] seed = new byte[MlKem.ML_KEM_SEED_SIZE];
        Arrays.fill(seed, (byte)0x44);
        MlKem k = new MlKem(level);
        k.makeKeyFromSeed(seed);
        byte[] expanded = k.exportPrivate();
        k.releaseNativeStruct();

        /* Force the seed output form so the two keys below encode
         * differently (seed form vs expandedKey fallback). */
        String prop = "jdk.mlkem.pkcs8.encoding";
        String saved = System.getProperty(prop);
        System.setProperty(prop, "seed");
        try {
            WolfCryptMlKemPrivateKey withSeed =
                new WolfCryptMlKemPrivateKey(level, expanded, seed);
            WolfCryptMlKemPrivateKey noSeed =
                new WolfCryptMlKemPrivateKey(level, expanded);

            /* getEncoded() differs (seed form vs expandedKey form)... */
            assertFalse(Arrays.equals(withSeed.getEncoded(),
                noSeed.getEncoded()));
            /* ...but they are the same logical key. */
            assertEquals(withSeed, noSeed);
            assertEquals(noSeed, withSeed);
            assertEquals(withSeed.hashCode(), noSeed.hashCode());
        } finally {
            if (saved == null) {
                System.clearProperty(prop);
            }
            else {
                System.setProperty(prop, saved);
            }
        }
    }

    @Test
    public void testRawConstructorValidatesLength() throws Exception {
        assumeEnabled();

        /* wrong public key length for the level */
        try {
            new WolfCryptMlKemPublicKey(MlKem.ML_KEM_512, new byte[100]);
            fail("Expected IllegalArgumentException for bad public length");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* unsupported parameter set level */
        try {
            new WolfCryptMlKemPublicKey(999,
                new byte[MlKem.ML_KEM_512_PUBLIC_KEY_SIZE]);
            fail("Expected IllegalArgumentException for bad level");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* wrong expanded private key length for the level */
        try {
            new WolfCryptMlKemPrivateKey(MlKem.ML_KEM_512, new byte[100]);
            fail("Expected IllegalArgumentException for bad private length");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* wrong seed length in the (level, expanded, seed) constructor */
        try {
            new WolfCryptMlKemPrivateKey(MlKem.ML_KEM_512,
                new byte[MlKem.ML_KEM_512_PRIVATE_KEY_SIZE], new byte[32]);
            fail("Expected IllegalArgumentException for bad seed length");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        /* correct lengths are accepted */
        new WolfCryptMlKemPublicKey(MlKem.ML_KEM_512,
            new byte[MlKem.ML_KEM_512_PUBLIC_KEY_SIZE]);
        new WolfCryptMlKemPrivateKey(MlKem.ML_KEM_512,
            new byte[MlKem.ML_KEM_512_PRIVATE_KEY_SIZE]);
    }

    @Test
    public void testGetKeySpecUnsupportedTypeRejected() throws Exception {
        assumeEnabled();

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");

        /* PKCS#8 spec for a public key is unsupported */
        try {
            kf.getKeySpec(kp.getPublic(), PKCS8EncodedKeySpec.class);
            fail("Expected InvalidKeySpecException");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        /* X.509 spec for a private key is unsupported */
        try {
            kf.getKeySpec(kp.getPrivate(), X509EncodedKeySpec.class);
            fail("Expected InvalidKeySpecException");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void testTranslateKey() throws Exception {
        assumeEnabled();

        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768", "wolfJCE")
            .generateKeyPair();
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", "wolfJCE");

        Key tPriv = kf.translateKey(kp.getPrivate());
        Key tPub = kf.translateKey(kp.getPublic());
        assertArrayEquals(kp.getPrivate().getEncoded(), tPriv.getEncoded());
        assertArrayEquals(kp.getPublic().getEncoded(), tPub.getEncoded());

        /* a non-ML-KEM key must be rejected */
        PrivateKey notMlKem = new PrivateKey() {
            public String getAlgorithm() { return "RSA"; }
            public String getFormat() { return "PKCS#8"; }
            public byte[] getEncoded() { return new byte[0]; }
        };
        try {
            kf.translateKey(notMlKem);
            fail("Expected InvalidKeyException");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void testPkcs8EncodingDefaultAndPrecedence() throws Exception {
        assumeEnabled();

        String prop = "jdk.mlkem.pkcs8.encoding";
        String savedSys = System.getProperty(prop);
        String savedSec = java.security.Security.getProperty(prop);

        try {
            /* unrecognized value falls back to the expandedKey default */
            System.setProperty(prop, "bogus");
            byte[] enc =
                KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
                    .generateKeyPair().getPrivate().getEncoded();
            assertEquals(0x04, firstChoiceTag(enc));
            System.clearProperty(prop);

            /* system property overrides the Security property */
            java.security.Security.setProperty(prop, "seed");
            System.setProperty(prop, "expandedKey");
            byte[] enc2 =
                KeyPairGenerator.getInstance("ML-KEM-512", "wolfJCE")
                    .generateKeyPair().getPrivate().getEncoded();
            assertEquals(0x04, firstChoiceTag(enc2));

        } finally {
            if (savedSys == null) {
                System.clearProperty(prop);
            }
            else {
                System.setProperty(prop, savedSys);
            }
            /* Security properties cannot be removed; restore prior value or
             * neutralize to empty (treated as the default). */
            java.security.Security.setProperty(prop,
                savedSec == null ? "" : savedSec);
        }
    }
}
