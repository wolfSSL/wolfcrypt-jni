/* WolfCryptEdDSAKeyTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import com.wolfssl.provider.jce.WolfCryptEdDSAParameterSpec;
import com.wolfssl.provider.jce.WolfCryptEdDSAPrivateKey;
import com.wolfssl.provider.jce.WolfCryptEdDSAPublicKey;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.Ed448;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.Ed25519TestVectors;
import com.wolfssl.wolfcrypt.test.Ed448TestVectors;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * Tests for wolfJCE EdDSA key classes and WolfCryptEdDSAParameterSpec,
 * including JDK 15+ multi-release overlay operation (using reflection so the
 * test compiles and runs on Java 8 floor).
 */
public class WolfCryptEdDSAKeyTest {

    private static boolean ed25519Enabled = false;
    private static boolean ed448Enabled = false;

    /* JDK 15+ EdEC key interfaces, null when absent */
    private static Class<?> edecPubIface = null;
    private static Class<?> edecPrivIface = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /** One curve's parameters */
    private static final class Curve {
        final String name;
        final int keySize;
        final int spkiLen;
        final int pkcs8Len;
        Curve(String name, int keySize, int spkiLen, int pkcs8Len) {
            this.name = name;
            this.keySize = keySize;
            this.spkiLen = spkiLen;
            this.pkcs8Len = pkcs8Len;
        }
    }

    private static final Curve ED25519 = new Curve("Ed25519",
        Ed25519.ED25519_PUB_KEY_SIZE, 44, 48);
    private static final Curve ED448 = new Curve("Ed448",
        Ed448.ED448_PUB_KEY_SIZE, 69, 73);

    @BeforeClass
    public static void setUp() {

        System.out.println("JCE WolfCryptEdDSAKeyTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        assertNotNull(Security.getProvider("wolfJCE"));

        ed25519Enabled = FeatureDetect.Ed25519KeyGenEnabled();
        ed448Enabled = FeatureDetect.Ed448KeyGenEnabled();

        try {
            edecPubIface =
                Class.forName("java.security.interfaces.EdECPublicKey");
            edecPrivIface =
                Class.forName("java.security.interfaces.EdECPrivateKey");
        } catch (ClassNotFoundException e) {
            edecPubIface = null;
            edecPrivIface = null;
        }
    }

    private static List<Curve> curves() {
        List<Curve> l = new ArrayList<Curve>();
        if (ed25519Enabled) {
            l.add(ED25519);
        }
        if (ed448Enabled) {
            l.add(ED448);
        }
        return l;
    }

    private void assumeAnyEnabled() {
        Assume.assumeTrue("No EdDSA curve compiled in",
            ed25519Enabled || ed448Enabled);
    }

    private static KeyPair generate(Curve c) throws Exception {
        return KeyPairGenerator.getInstance(c.name, "wolfJCE")
            .generateKeyPair();
    }

    private static byte[] serialize(Object o) throws Exception {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(o);
        oos.close();

        return bos.toByteArray();
    }

    private static Object deserialize(byte[] b) throws Exception {

        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(b));

        return ois.readObject();
    }

    /* NamedParameterSpec.getName() via reflection, null on JDK 8-10 */
    private static String paramsName(AlgorithmParameterSpec spec)
        throws Exception {

        if (spec == null) {
            return null;
        }

        Method m = spec.getClass().getMethod("getName");
        return (String) m.invoke(spec);
    }

    @Test
    public void publicKeyAccessors() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            KeyPair kp = generate(c);
            assertTrue(kp.getPublic() instanceof WolfCryptEdDSAPublicKey);
            WolfCryptEdDSAPublicKey pub =
                (WolfCryptEdDSAPublicKey) kp.getPublic();

            assertEquals("EdDSA", pub.getAlgorithm());
            assertEquals("X.509", pub.getFormat());
            assertEquals(c.name, pub.getCurveName());
            assertEquals(c.spkiLen, pub.getEncoded().length);
            assertEquals(c.keySize, pub.getRawPublicKey().length);
            assertFalse(pub.isDestroyed());
            assertTrue(pub.toString().contains(c.name));

            /* NamedParameterSpec on JDK 11+, null on JDK 8-10 */
            AlgorithmParameterSpec params = pub.getParams();
            try {
                Class.forName("java.security.spec.NamedParameterSpec");
                assertNotNull(params);
                assertEquals(c.name, paramsName(params));
            } catch (ClassNotFoundException e) {
                assertNull(params);
            }

            /* the SPKI is the raw key behind the fixed prefix */
            byte[] spki = pub.getEncoded();
            byte[] raw = pub.getRawPublicKey();
            assertArrayEquals(raw, Arrays.copyOfRange(spki,
                spki.length - raw.length, spki.length));
        }
    }

    @Test
    public void publicKeyEncodedMatchesNativeDer() throws Exception {

        assumeAnyEnabled();

        if (ed25519Enabled) {
            WolfCryptEdDSAPublicKey pub = new WolfCryptEdDSAPublicKey(
                "Ed25519", Ed25519TestVectors.PKEY1);
            Ed25519 k = new Ed25519();
            try {
                k.importPublic(Ed25519TestVectors.PKEY1);
                assertArrayEquals(k.exportPublicKeyDer(true), pub.getEncoded());
            }
            finally {
                k.releaseNativeStruct();
            }
            /* pin the RFC 8410 prefix independently of native */
            assertArrayEquals(Util.h2b("302a300506032b6570032100"),
                Arrays.copyOf(pub.getEncoded(), 12));
        }

        if (ed448Enabled) {
            WolfCryptEdDSAPublicKey pub448 = new WolfCryptEdDSAPublicKey(
                "Ed448", Ed448TestVectors.PKEY1);
            Ed448 k448 = new Ed448();
            try {
                k448.importPublic(Ed448TestVectors.PKEY1);
                assertArrayEquals(k448.exportPublicKeyDer(true),
                    pub448.getEncoded());
            }
            finally {
                k448.releaseNativeStruct();
            }
            assertArrayEquals(Util.h2b("3043300506032b6571033a00"),
                Arrays.copyOf(pub448.getEncoded(), 12));
        }
    }

    @Test
    public void publicKeyFromCurveNameAndRaw() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            KeyPair kp = generate(c);
            WolfCryptEdDSAPublicKey orig =
                (WolfCryptEdDSAPublicKey) kp.getPublic();

            WolfCryptEdDSAPublicKey copy = new WolfCryptEdDSAPublicKey(
                c.name, orig.getRawPublicKey());
            assertEquals(orig, copy);
            assertEquals(orig.hashCode(), copy.hashCode());

            /* case-insensitive name and OID forms */
            assertEquals(orig, new WolfCryptEdDSAPublicKey(
                c.name.toUpperCase(), orig.getRawPublicKey()));

            try {
                new WolfCryptEdDSAPublicKey("Ed12345", orig.getRawPublicKey());
                fail("unknown curve should be rejected");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                new WolfCryptEdDSAPublicKey(c.name, new byte[c.keySize - 1]);
                fail("wrong raw length should be rejected");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                new WolfCryptEdDSAPublicKey(c.name, null);
                fail("null raw key should be rejected");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* not a valid point: y = 2 is not on either curve, and all
             * 0xff bytes encode a y above the field prime */
            byte[] badY = new byte[c.keySize];
            badY[0] = 0x02;
            byte[] badFf = new byte[c.keySize];
            Arrays.fill(badFf, (byte)0xff);
            for (byte[] bad : new byte[][] { badY, badFf }) {
                try {
                    new WolfCryptEdDSAPublicKey(c.name, bad);
                    fail("invalid point should be rejected");
                } catch (IllegalArgumentException e) {
                    /* expected */
                }
            }
        }
    }

    @Test
    public void publicKeyAcceptsNullAlgIdParams() throws Exception {

        Assume.assumeTrue(ed25519Enabled || ed448Enabled);

        /* JDK can re-encode an absent AlgorithmIdentifier params field as an
         * explicit NULL, native rejects that form so wolfJCE strips it before
         * decoding */
        for (String curve : new String[] { "Ed25519", "Ed448" }) {
            if (!(curve.equals("Ed25519") ? ed25519Enabled : ed448Enabled)) {
                continue;
            }
            byte[] raw = curve.equals("Ed25519") ?
                Ed25519TestVectors.PKEY1 : Ed448TestVectors.PKEY1;
            byte[] spki = new WolfCryptEdDSAPublicKey(curve, raw).getEncoded();

            /* SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING } */
            byte[] withNull = new byte[spki.length + 2];
            System.arraycopy(spki, 0, withNull, 0, 9);
            withNull[1] += 2;
            withNull[3] += 2;
            withNull[9] = Util.TAG_NULL;
            withNull[10] = 0x00;
            System.arraycopy(spki, 9, withNull, 11, spki.length - 9);

            WolfCryptEdDSAPublicKey pub = new WolfCryptEdDSAPublicKey(withNull);
            assertArrayEquals(raw, pub.getRawPublicKey());
            assertArrayEquals(spki, pub.getEncoded());

            KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
            PublicKey viaKf =
                kf.generatePublic(new X509EncodedKeySpec(withNull));
            assertArrayEquals(spki, viaKf.getEncoded());
        }
    }

    @Test
    public void publicKeyEncodedReturnsClone() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            PublicKey pub = generate(c).getPublic();
            byte[] a = pub.getEncoded();
            byte[] b = pub.getEncoded();
            assertNotSame(a, b);
            assertArrayEquals(a, b);
            a[a.length - 1] ^= 1;
            assertFalse(Arrays.equals(a, pub.getEncoded()));

            byte[] r = ((WolfCryptEdDSAPublicKey) pub).getRawPublicKey();
            r[0] ^= 1;
            assertFalse(Arrays.equals(r,
                ((WolfCryptEdDSAPublicKey) pub).getRawPublicKey()));
        }
    }

    @Test
    public void publicKeyEqualsAndHashCode() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            PublicKey a = generate(c).getPublic();
            PublicKey b = generate(c).getPublic();
            PublicKey a2 = new WolfCryptEdDSAPublicKey(a.getEncoded());

            assertEquals(a, a2);
            assertEquals(a2, a);
            assertEquals(a.hashCode(), a2.hashCode());
            assertNotEquals(a, b);
            assertNotEquals(a, null);
            assertNotEquals(a, "not a key");

            /* any PublicKey with the same X.509 encoding is equal */
            final byte[] enc = a.getEncoded();
            PublicKey foreign = new PublicKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "Ed25519"; }
                public String getFormat() { return "X.509"; }
                public byte[] getEncoded() { return enc.clone(); }
            };
            assertEquals(a, foreign);
        }

        if (ed25519Enabled && ed448Enabled) {
            assertNotEquals(generate(ED25519).getPublic(),
                generate(ED448).getPublic());
        }
    }

    @Test
    public void publicKeyDestroy() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            WolfCryptEdDSAPublicKey pub =
                (WolfCryptEdDSAPublicKey) generate(c).getPublic();
            byte[] enc = pub.getEncoded();

            pub.destroy();
            assertTrue(pub.isDestroyed());
            if (edecPubIface != null && edecPubIface.isInstance(pub)) {
                /* EdECPoint has no empty form, the overlay throws */
                try {
                    edecPubIface.getMethod("getPoint").invoke(pub);
                    fail("getPoint() on a destroyed key should throw");
                } catch (InvocationTargetException e) {
                    assertTrue(e.getCause() instanceof IllegalStateException);
                }
            }
            assertNull(pub.getEncoded());
            assertNull(pub.getRawPublicKey());
            assertEquals(0, pub.hashCode());
            assertNotEquals(pub, new WolfCryptEdDSAPublicKey(enc));
            assertNotEquals(new WolfCryptEdDSAPublicKey(enc), pub);
            assertTrue(pub.toString().contains("DESTROYED"));

            /* idempotent */
            pub.destroy();
            assertTrue(pub.isDestroyed());

            try {
                Signature s = Signature.getInstance(c.name, "wolfJCE");
                s.initVerify(pub);
                fail("initVerify with destroyed key should fail");
            } catch (InvalidKeyException e) {
                /* expected */
            }
        }
    }

    @Test
    public void publicKeyCtorRejectsBadDer() throws Exception {

        assumeAnyEnabled();

        Curve c = curves().get(0);
        byte[] good = generate(c).getPublic().getEncoded();

        byte[][] bad = {
            null, new byte[0], new byte[] { Util.TAG_SEQUENCE },
            Arrays.copyOf(good, good.length - 1),
            "definitely not a SubjectPublicKeyInfo at all".getBytes(),
            generate(c).getPrivate().getEncoded()
        };

        for (byte[] der : bad) {
            try {
                new WolfCryptEdDSAPublicKey(der);
                fail("bad DER accepted");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }

        /* Ed448 OID on an Ed25519 sized key, and vice versa */
        byte[] swapped = good.clone();
        swapped[8] ^= 0x01;
        try {
            new WolfCryptEdDSAPublicKey(swapped);
            fail("mismatched OID/key size accepted");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
    }

    @Test
    public void publicKeySerialization() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            WolfCryptEdDSAPublicKey pub =
                (WolfCryptEdDSAPublicKey) generate(c).getPublic();

            Object back = deserialize(serialize(pub));
            assertTrue(back instanceof WolfCryptEdDSAPublicKey);
            assertEquals(pub, back);
            assertEquals(pub.hashCode(), back.hashCode());
            assertEquals(pub.getCurveName(),
                ((WolfCryptEdDSAPublicKey) back).getCurveName());

            /* a destroyed key stays destroyed */
            pub.destroy();
            WolfCryptEdDSAPublicKey backDestroyed =
                (WolfCryptEdDSAPublicKey) deserialize(serialize(pub));
            assertTrue(backDestroyed.isDestroyed());
            assertEquals(pub.getClass(), backDestroyed.getClass());
            assertNull(backDestroyed.getEncoded());
        }
    }

    @Test
    public void privateKeyAccessors() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            KeyPair kp = generate(c);
            assertTrue(kp.getPrivate() instanceof WolfCryptEdDSAPrivateKey);
            WolfCryptEdDSAPrivateKey priv =
                (WolfCryptEdDSAPrivateKey) kp.getPrivate();

            assertEquals("EdDSA", priv.getAlgorithm());
            assertEquals("PKCS#8", priv.getFormat());
            assertEquals(c.name, priv.getCurveName());
            assertEquals(c.pkcs8Len, priv.getEncoded().length);
            assertEquals(c.keySize, priv.getRawPrivateKey().length);
            assertEquals(c.keySize, priv.getRawPublicKey().length);
            assertFalse(priv.isDestroyed());
            assertTrue(priv.toString().contains(c.name));
            assertFalse(priv.toString().contains(
                new BigInteger(1, priv.getRawPrivateKey()).toString(16)));

            /* PKCS#8 v1: version 0 */
            assertEquals(0x00, priv.getEncoded()[4]);

            /* getBytes() has the EdECPrivateKey shape */
            Optional<byte[]> bytes = priv.getBytes();
            assertTrue(bytes.isPresent());
            assertArrayEquals(priv.getRawPrivateKey(), bytes.get());

            /* the public half matches the generated public key */
            assertArrayEquals(((WolfCryptEdDSAPublicKey) kp.getPublic())
                .getRawPublicKey(), priv.getRawPublicKey());

            AlgorithmParameterSpec params = priv.getParams();
            try {
                Class.forName("java.security.spec.NamedParameterSpec");
                assertEquals(c.name, paramsName(params));
            } catch (ClassNotFoundException e) {
                assertNull(params);
            }
        }
    }

    @Test
    public void privateKeyEncodedMatchesNativeDer() throws Exception {

        assumeAnyEnabled();

        if (ed25519Enabled) {
            WolfCryptEdDSAPrivateKey priv = new WolfCryptEdDSAPrivateKey(
                "Ed25519", Ed25519TestVectors.SKEY1);
            assertArrayEquals(Ed25519TestVectors.PKEY1, priv.getRawPublicKey());
            Ed25519 k = new Ed25519();
            try {
                k.importPrivate(Ed25519TestVectors.SKEY1,
                    Ed25519TestVectors.PKEY1);
                assertArrayEquals(k.exportPrivateKeyDer(), priv.getEncoded());
                /* the v2 (with public key) form decodes to the same key */
                WolfCryptEdDSAPrivateKey fromV2 = new WolfCryptEdDSAPrivateKey(
                    k.exportPrivateKeyDer(true));
                assertEquals(priv, fromV2);
                assertArrayEquals(priv.getEncoded(), fromV2.getEncoded());
            }
            finally {
                k.releaseNativeStruct();
            }
            /* pin the RFC 8410 prefix independently of native */
            assertArrayEquals(Util.h2b("302e020100300506032b657004220420"),
                Arrays.copyOf(priv.getEncoded(), 16));
        }

        if (ed448Enabled) {
            WolfCryptEdDSAPrivateKey p448 = new WolfCryptEdDSAPrivateKey(
                "Ed448", Ed448TestVectors.SKEY1);
            assertArrayEquals(Ed448TestVectors.PKEY1, p448.getRawPublicKey());
            Ed448 k448 = new Ed448();
            try {
                k448.importPrivate(Ed448TestVectors.SKEY1,
                    Ed448TestVectors.PKEY1);
                assertArrayEquals(k448.exportPrivateKeyDer(),
                    p448.getEncoded());
                assertEquals(p448, new WolfCryptEdDSAPrivateKey(
                    k448.exportPrivateKeyDer(true)));
            }
            finally {
                k448.releaseNativeStruct();
            }
            assertArrayEquals(Util.h2b("3047020100300506032b6571043b0439"),
                Arrays.copyOf(p448.getEncoded(), 16));
        }
    }

    @Test
    public void privateKeyFromCurveNameAndRaw() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            WolfCryptEdDSAPrivateKey orig =
                (WolfCryptEdDSAPrivateKey) generate(c).getPrivate();
            WolfCryptEdDSAPrivateKey copy = new WolfCryptEdDSAPrivateKey(
                c.name, orig.getRawPrivateKey());
            assertEquals(orig, copy);
            assertArrayEquals(orig.getRawPublicKey(), copy.getRawPublicKey());

            try {
                new WolfCryptEdDSAPrivateKey(c.name, new byte[c.keySize + 1]);
                fail("wrong raw length should be rejected");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                new WolfCryptEdDSAPrivateKey("nope", orig.getRawPrivateKey());
                fail("unknown curve should be rejected");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
    }

    @Test
    public void privateKeyEqualsAndHashCode() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            PrivateKey a = generate(c).getPrivate();
            PrivateKey b = generate(c).getPrivate();
            PrivateKey a2 = new WolfCryptEdDSAPrivateKey(a.getEncoded());

            assertEquals(a, a2);
            assertEquals(a.hashCode(), a2.hashCode());
            assertNotEquals(a, b);
            assertNotEquals(a, null);

            final byte[] enc = a.getEncoded();
            PrivateKey foreign = new PrivateKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "EdDSA"; }
                public String getFormat() { return "PKCS#8"; }
                public byte[] getEncoded() { return enc.clone(); }
            };
            assertEquals(a, foreign);
        }
    }

    @Test
    public void privateKeyDestroy() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            WolfCryptEdDSAPrivateKey priv =
                (WolfCryptEdDSAPrivateKey) generate(c).getPrivate();

            priv.destroy();
            assertTrue(priv.isDestroyed());
            assertNull(priv.getEncoded());
            assertNull(priv.getRawPrivateKey());
            assertNull(priv.getRawPublicKey());
            assertFalse(priv.getBytes().isPresent());
            assertEquals(0, priv.hashCode());
            assertTrue(priv.toString().contains("DESTROYED"));

            try {
                Signature s = Signature.getInstance(c.name, "wolfJCE");
                s.initSign(priv);
                fail("initSign with destroyed key should fail");
            } catch (InvalidKeyException e) {
                /* expected */
            }
        }
    }

    @Test
    public void privateKeyCtorRejectsBadDer() throws Exception {

        assumeAnyEnabled();

        Curve c = curves().get(0);
        KeyPair kp = generate(c);
        byte[] good = kp.getPrivate().getEncoded();

        byte[][] bad = {
            null, new byte[0], Arrays.copyOf(good, good.length - 2),
            "definitely not a PrivateKeyInfo at all, really".getBytes(),
            kp.getPublic().getEncoded()
        };
        for (byte[] der : bad) {
            try {
                new WolfCryptEdDSAPrivateKey(der);
                fail("bad DER accepted");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
    }

    private static int indexOf(byte[] hay, byte[] needle) {
        for (int i = 0; i + needle.length <= hay.length; i++) {
            if (Arrays.equals(Arrays.copyOfRange(hay, i, i + needle.length),
                    needle)) {
                return i;
            }
        }
        return -1;
    }

    @Test
    public void privateKeyDeserializationRejectsTamperedPublicKey()
        throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            WolfCryptEdDSAPrivateKey priv =
                (WolfCryptEdDSAPrivateKey) generate(c).getPrivate();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(priv);
            oos.close();

            /* flip a bit of the serialized public key so it no longer
             * matches the private key, readObject() must reject it */
            byte[] stream = bos.toByteArray();
            int at = indexOf(stream, priv.getRawPublicKey());
            assertTrue(at >= 0);
            stream[at] ^= 0x01;
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(stream));
            try {
                ois.readObject();
                fail("tampered stream accepted");
            } catch (InvalidObjectException e) {
                /* expected */
            }
        }
    }

    @Test
    public void privateKeySerialization() throws Exception {

        assumeAnyEnabled();

        for (Curve c : curves()) {
            WolfCryptEdDSAPrivateKey priv =
                (WolfCryptEdDSAPrivateKey) generate(c).getPrivate();

            byte[] stream = serialize(priv);
            assertFalse(new String(stream, "ISO-8859-1").contains("Key15"));
            Object back = deserialize(stream);
            assertTrue(back instanceof WolfCryptEdDSAPrivateKey);
            assertEquals(priv, back);
            assertArrayEquals(priv.getRawPublicKey(),
                ((WolfCryptEdDSAPrivateKey) back).getRawPublicKey());

            /* still signs identically after the round trip */
            byte[] msg = "serialized".getBytes();
            Signature s = Signature.getInstance(c.name, "wolfJCE");
            s.initSign(priv);
            s.update(msg);
            byte[] sig1 = s.sign();
            s.initSign((PrivateKey) back);
            s.update(msg);
            assertArrayEquals(sig1, s.sign());

            priv.destroy();
            WolfCryptEdDSAPrivateKey backDestroyed =
                (WolfCryptEdDSAPrivateKey) deserialize(serialize(priv));
            assertTrue(backDestroyed.isDestroyed());
            assertEquals(priv.getClass(), backDestroyed.getClass());
        }
    }

    @Test
    public void overlayKeysImplementEdECInterfacesOnJdk15() throws Exception {

        assumeAnyEnabled();
        Assume.assumeTrue("JDK 15+ EdEC interfaces not present",
            edecPubIface != null && edecPrivIface != null);
        Assume.assumeTrue("JDK 15 overlay not shipped in the loaded JAR",
            Util.multiReleaseEntryActive(WolfCryptProvider.class,
                "META-INF/versions/15/com/wolfssl/provider/jce/" +
                "WolfCryptEdDSAKeys.class"));

        for (Curve c : curves()) {
            KeyPair kp = generate(c);
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            assertTrue("public key must implement EdECPublicKey on JDK 15+",
                edecPubIface.isInstance(pub));
            assertTrue("private key must implement EdECPrivateKey on " +
                "JDK 15+", edecPrivIface.isInstance(priv));

            /* getParams() is the NamedParameterSpec constant */
            Object pubParams = edecPubIface.getMethod("getParams").invoke(pub);
            Object privParams = edecPrivIface.getMethod("getParams")
                .invoke(priv);
            assertEquals(c.name, paramsName(
                (AlgorithmParameterSpec) pubParams));
            assertEquals(c.name, paramsName(
                (AlgorithmParameterSpec) privParams));

            /* getPoint() reflects the raw encoding: x parity is the top
             * bit of the last byte, y the little-endian remainder */
            byte[] raw = ((WolfCryptEdDSAPublicKey) pub).getRawPublicKey();
            Object point = edecPubIface.getMethod("getPoint").invoke(pub);
            boolean xOdd = (Boolean) point.getClass().getMethod("isXOdd")
                .invoke(point);
            BigInteger y = (BigInteger) point.getClass().getMethod("getY")
                .invoke(point);
            assertEquals((raw[raw.length - 1] & 0x80) != 0, xOdd);
            byte[] le = raw.clone();
            le[le.length - 1] &= 0x7f;
            byte[] be = new byte[le.length];
            for (int i = 0; i < le.length; i++) {
                be[i] = le[le.length - 1 - i];
            }
            assertEquals(new BigInteger(1, be), y);

            /* getBytes() is the raw private key */
            @SuppressWarnings("unchecked")
            Optional<byte[]> bytes = (Optional<byte[]>) edecPrivIface
                .getMethod("getBytes").invoke(priv);
            assertArrayEquals(((WolfCryptEdDSAPrivateKey) priv)
                .getRawPrivateKey(), bytes.get());

            /* the stream carries only the base class, so JDK 8-14 can read
             * it, and readResolve() restores the overlay class here */
            byte[] stream = serialize(pub);
            assertFalse(new String(stream, "ISO-8859-1").contains("Key15"));
            Object back = deserialize(stream);
            assertTrue(edecPubIface.isInstance(back));
            assertEquals(pub, back);
        }
    }

    @Test
    public void baseKeysDoNotImplementEdECInterfacesBeforeJdk15()
        throws Exception {

        assumeAnyEnabled();
        Assume.assumeTrue("JDK 15+ EdEC interfaces present",
            edecPubIface == null);

        for (Curve c : curves()) {
            KeyPair kp = generate(c);
            /* only the base classes exist, nothing more to implement */
            assertEquals(WolfCryptEdDSAPublicKey.class,
                kp.getPublic().getClass());
            assertEquals(WolfCryptEdDSAPrivateKey.class,
                kp.getPrivate().getClass());
        }
    }

    @Test
    public void parameterSpec() {

        WolfCryptEdDSAParameterSpec pure = new WolfCryptEdDSAParameterSpec(
            false);
        assertFalse(pure.isPrehash());
        assertFalse(pure.hasContext());
        assertNull(pure.getContext());

        WolfCryptEdDSAParameterSpec ph = new WolfCryptEdDSAParameterSpec(true);
        assertTrue(ph.isPrehash());
        assertFalse(ph.hasContext());

        byte[] ctx = "foo".getBytes();
        WolfCryptEdDSAParameterSpec withCtx =
            new WolfCryptEdDSAParameterSpec(false, ctx);
        assertTrue(withCtx.hasContext());
        assertArrayEquals(ctx, withCtx.getContext());
        assertNotSame(ctx, withCtx.getContext());
        ctx[0] = 'x';
        assertEquals('f', withCtx.getContext()[0]);

        /* empty context is present but empty, null context is absent */
        assertTrue(new WolfCryptEdDSAParameterSpec(false, new byte[0])
            .hasContext());
        assertFalse(new WolfCryptEdDSAParameterSpec(false, null).hasContext());
        assertEquals(pure, new WolfCryptEdDSAParameterSpec(false, null));

        /* 255 ok, 256 rejected */
        new WolfCryptEdDSAParameterSpec(true,
            new byte[WolfCryptEdDSAParameterSpec.MAX_CONTEXT_LEN]);
        try {
            new WolfCryptEdDSAParameterSpec(true, new byte[256]);
            fail("256 byte context should be rejected");
        } catch (IllegalArgumentException e) {
            /* expected */
        }

        assertEquals(withCtx, new WolfCryptEdDSAParameterSpec(false,
            "foo".getBytes()));
        assertEquals(withCtx.hashCode(), new WolfCryptEdDSAParameterSpec(
            false, "foo".getBytes()).hashCode());
        assertNotEquals(withCtx, new WolfCryptEdDSAParameterSpec(true,
            "foo".getBytes()));
        assertNotEquals(withCtx, pure);
        assertNotEquals(withCtx, "foo");
        assertTrue(withCtx.toString().contains("3 bytes"));
        assertTrue(pure.toString().contains("absent"));
    }
}
