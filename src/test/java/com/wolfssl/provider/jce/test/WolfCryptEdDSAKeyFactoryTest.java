/* WolfCryptEdDSAKeyFactoryTest.java
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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.wolfssl.provider.jce.WolfCryptEdDSAPrivateKey;
import com.wolfssl.provider.jce.WolfCryptEdDSAPublicKey;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.Ed448;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * Tests for wolfJCE EdDSA KeyFactory services, including JDK 15+
 * EdECPublicKeySpec / EdECPrivateKeySpec paths (using reflection so the
 * test compiles on Java 8 lower bound).
 */
public class WolfCryptEdDSAKeyFactoryTest {

    private static boolean ed25519Enabled = false;
    private static boolean ed448Enabled = false;

    /* JDK 15+ EdEC spec classes, null when absent */
    private static Class<?> pubSpecCls = null;
    private static Class<?> privSpecCls = null;
    private static Class<?> pointCls = null;
    private static Class<?> npsCls = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {

        System.out.println("JCE WolfCryptEdDSAKeyFactoryTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        assertNotNull(Security.getProvider("wolfJCE"));

        ed25519Enabled = FeatureDetect.Ed25519KeyGenEnabled();
        ed448Enabled = FeatureDetect.Ed448KeyGenEnabled();

        /* JDK 11+, resolved on its own so the JDK 11-14 fallback branch of
         * resolveNamedParameterSpec() is covered */
        try {
            npsCls = Class.forName("java.security.spec.NamedParameterSpec");
        } catch (ClassNotFoundException e) {
            npsCls = null;
        }

        /* JDK 15+ */
        try {
            pubSpecCls = Class.forName("java.security.spec.EdECPublicKeySpec");
            privSpecCls =
                Class.forName("java.security.spec.EdECPrivateKeySpec");
            pointCls = Class.forName("java.security.spec.EdECPoint");
        } catch (ClassNotFoundException e) {
            pubSpecCls = null;
            privSpecCls = null;
            pointCls = null;
        }
    }

    private static List<String> curves() {

        List<String> l = new ArrayList<String>();
        if (ed25519Enabled) {
            l.add("Ed25519");
        }
        if (ed448Enabled) {
            l.add("Ed448");
        }
        return l;
    }

    private void assumeAnyEnabled() {
        Assume.assumeTrue("No EdDSA curve compiled in",
            ed25519Enabled || ed448Enabled);
    }

    private static KeyPair generate(String curve) throws Exception {
        return KeyPairGenerator.getInstance(curve, "wolfJCE")
            .generateKeyPair();
    }

    private static void assertSigns(String curve, PrivateKey priv,
        PublicKey pub) throws Exception {

        byte[] msg = "keyfactory".getBytes();

        Signature s = Signature.getInstance(curve, "wolfJCE");
        s.initSign(priv);
        s.update(msg);
        byte[] sig = s.sign();

        s.initVerify(pub);
        s.update(msg);

        assertTrue(s.verify(sig));
    }

    /* ----- JDK 15 reflection helpers ----- */

    private static Object namedSpec(String name) throws Exception {
        return npsCls.getConstructor(String.class).newInstance(name);
    }

    private static Object edecPoint(boolean xOdd, BigInteger y)
        throws Exception {

        Constructor<?> c = pointCls.getConstructor(boolean.class,
            BigInteger.class);

        return c.newInstance(xOdd, y);
    }

    private static KeySpec edecPublicKeySpec(String curve, byte[] raw)
        throws Exception {

        boolean xOdd = (raw[raw.length - 1] & 0x80) != 0;
        byte[] be = new byte[raw.length];

        for (int i = 0; i < raw.length; i++) {
            be[i] = raw[raw.length - 1 - i];
        }
        be[0] &= 0x7f;

        Constructor<?> c = pubSpecCls.getConstructor(npsCls, pointCls);
        return (KeySpec) c.newInstance(namedSpec(curve),
            edecPoint(xOdd, new BigInteger(1, be)));
    }

    private static KeySpec edecPrivateKeySpec(String curve, byte[] raw)
        throws Exception {

        Constructor<?> c = privSpecCls.getConstructor(npsCls, byte[].class);
        return (KeySpec) c.newInstance(namedSpec(curve), raw);
    }

    private static Object call(Object target, String method)
        throws Exception {

        Method m = target.getClass().getMethod(method);
        return m.invoke(target);
    }

    @Test
    public void getInstanceForAllAliases() throws Exception {

        assumeAnyEnabled();

        List<String> names = new ArrayList<String>();
        names.add("EdDSA");
        names.add("EDDSA");
        if (ed25519Enabled) {
            names.addAll(Arrays.asList("Ed25519", "ED25519", "1.3.101.112",
                "OID.1.3.101.112"));
        }
        if (ed448Enabled) {
            names.addAll(Arrays.asList("Ed448", "ED448", "1.3.101.113",
                "OID.1.3.101.113"));
        }
        for (String n : names) {
            assertEquals("wolfJCE",
                KeyFactory.getInstance(n, "wolfJCE").getProvider().getName());
        }
    }

    @Test
    public void encodedSpecRoundTrips() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);

            for (String alg : new String[] { curve, "EdDSA" }) {
                KeyFactory kf = KeyFactory.getInstance(alg, "wolfJCE");

                PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(
                    kp.getPublic().getEncoded()));
                PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(
                    kp.getPrivate().getEncoded()));

                assertEquals(kp.getPublic(), pub);
                assertEquals(kp.getPrivate(), priv);
                assertEquals("EdDSA", pub.getAlgorithm());
                assertEquals("EdDSA", priv.getAlgorithm());
                assertSigns(curve, priv, pub);

                X509EncodedKeySpec xs = kf.getKeySpec(pub,
                    X509EncodedKeySpec.class);
                PKCS8EncodedKeySpec ps = kf.getKeySpec(priv,
                    PKCS8EncodedKeySpec.class);
                assertArrayEquals(kp.getPublic().getEncoded(),
                    xs.getEncoded());
                assertArrayEquals(kp.getPrivate().getEncoded(),
                    ps.getEncoded());

                /* getKeySpec works for the parent EncodedKeySpec too */
                assertNotNull(kf.getKeySpec(pub,
                    java.security.spec.EncodedKeySpec.class));
                assertArrayEquals(kp.getPrivate().getEncoded(),
                    kf.getKeySpec(priv,
                        java.security.spec.EncodedKeySpec.class).getEncoded());
            }
        }
    }

    @Test
    public void pkcs8V2WithPublicKeyIsAccepted() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            byte[] rawPriv = ((WolfCryptEdDSAPrivateKey) kp.getPrivate())
                .getRawPrivateKey();
            byte[] v2;

            if (curve.equals("Ed25519")) {
                Ed25519 k = new Ed25519();
                k.importPrivateOnly(rawPriv);
                v2 = k.exportPrivateKeyDer(true);
                k.releaseNativeStruct();
            }
            else {
                Ed448 k = new Ed448();
                k.importPrivateOnly(rawPriv);
                v2 = k.exportPrivateKeyDer(true);
                k.releaseNativeStruct();
            }
            /* the v2 form ends with publicKey [1] */
            int pubSize = curve.equals("Ed25519") ?
                Ed25519.ED25519_PUB_KEY_SIZE : Ed448.ED448_PUB_KEY_SIZE;
            assertEquals((byte)Util.TAG_PUBLIC_KEY,
                v2[v2.length - pubSize - 2]);

            KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(v2));
            assertEquals(kp.getPrivate(), priv);
            /* re-encoded canonically as v1 */
            assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded());
            assertEquals(0x00, priv.getEncoded()[4]);
            assertSigns(curve, priv, kp.getPublic());
        }
    }

    /* RFC 8410 section 10.3 example: OneAsymmetricKey v2 with attributes
     * and publicKey [1] carrying the BIT STRING unused-bits octet. */
    private static final String RFC8410_V2_EXAMPLE =
        "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" +
        "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" +
        "Z9w7lshQhqowtrbLDFw4rXAxZuE=";

    /* RFC 8410 section 10.1 example public key, the same key as above */
    private static final String RFC8410_SPKI_EXAMPLE =
        "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

    /* private key octets from the RFC 8410 section 10.3 example */
    private static final String RFC8410_PRIV_HEX =
        "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";

    /* Build an RFC 8410 conformant OneAsymmetricKey v2:
     * SEQUENCE { INTEGER 1, AlgorithmIdentifier, OCTET STRING { OCTET STRING
     * priv }, [1] { 0x00, pub } } */
    private static byte[] rfc8410V2(String curve, byte[] priv, byte[] pub) {

        byte oidLast = curve.equals("Ed25519") ? (byte)0x70 : (byte)0x71;
        byte[] body = new byte[17 + priv.length + pub.length];
        int i = 0;

        /* version INTEGER 1 */
        body[i++] = 0x02;
        body[i++] = 0x01;
        body[i++] = 0x01;
        /* AlgorithmIdentifier SEQUENCE { OID 1.3.101.x } */
        body[i++] = Util.TAG_SEQUENCE;
        body[i++] = 0x05;
        body[i++] = 0x06;
        body[i++] = 0x03;
        body[i++] = 0x2b;
        body[i++] = 0x65;
        body[i++] = oidLast;
        /* CurvePrivateKey */
        body[i++] = Util.TAG_OCTET_STRING;
        body[i++] = (byte)(priv.length + 2);
        body[i++] = Util.TAG_OCTET_STRING;
        body[i++] = (byte)priv.length;
        System.arraycopy(priv, 0, body, i, priv.length);
        i += priv.length;
        /* publicKey [1], 0x00 unused bits then the raw key */
        body[i++] = (byte)Util.TAG_PUBLIC_KEY;
        body[i++] = (byte)(pub.length + 1);
        body[i++] = 0x00;
        System.arraycopy(pub, 0, body, i, pub.length);

        byte[] der;
        if (body.length < 0x80) {
            der = new byte[2 + body.length];
            der[0] = Util.TAG_SEQUENCE;
            der[1] = (byte)body.length;
            System.arraycopy(body, 0, der, 2, body.length);
        }
        else {
            der = new byte[3 + body.length];
            der[0] = Util.TAG_SEQUENCE;
            der[1] = (byte)0x81;
            der[2] = (byte)body.length;
            System.arraycopy(body, 0, der, 3, body.length);
        }

        return der;
    }

    @Test
    public void publicKeyFromSpkiWithoutKeyGen() throws Exception {

        /* decode paths need the curve only, not key generation */
        Assume.assumeTrue("Ed25519 not compiled in",
            FeatureDetect.Ed25519Enabled());

        byte[] spki = Base64.getDecoder().decode(RFC8410_SPKI_EXAMPLE);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "wolfJCE");
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spki));
        assertArrayEquals(spki, pub.getEncoded());
        assertArrayEquals(spki,
            kf.getKeySpec(pub, X509EncodedKeySpec.class).getEncoded());
        assertEquals(pub, kf.translateKey(pub));
    }

    @Test
    public void rfc8410V2ExampleWithUnusedBitsOctetIsAccepted()
        throws Exception {

        Assume.assumeTrue("Ed25519 not compiled in", ed25519Enabled);

        byte[] v2 = Base64.getDecoder().decode(RFC8410_V2_EXAMPLE);
        byte[] spki = Base64.getDecoder().decode(RFC8410_SPKI_EXAMPLE);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "wolfJCE");

        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(v2));
        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(spki));
        WolfCryptEdDSAPrivateKey wpriv = (WolfCryptEdDSAPrivateKey) priv;

        assertArrayEquals(Util.h2b(RFC8410_PRIV_HEX),
            wpriv.getRawPrivateKey());
        assertArrayEquals(((WolfCryptEdDSAPublicKey) pub).getRawPublicKey(),
            wpriv.getRawPublicKey());

        /* re-encoded canonically as v1 */
        assertEquals(48, priv.getEncoded().length);
        assertEquals(0x00, priv.getEncoded()[4]);
        assertArrayEquals(Util.h2b(RFC8410_PRIV_HEX),
            Arrays.copyOfRange(priv.getEncoded(), 16, 48));
        assertSigns("Ed25519", priv, pub);

        /* same envelope with a public key that does not match the
         * private key must be rejected */
        byte[] bad = v2.clone();
        bad[bad.length - 1] ^= 0x01;
        try {
            kf.generatePrivate(new PKCS8EncodedKeySpec(bad));
            fail("mismatched v2 public key accepted");
        }
        catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void pkcs8V2WithUnusedBitsOctetIsAccepted() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            WolfCryptEdDSAPrivateKey wpriv =
                (WolfCryptEdDSAPrivateKey) kp.getPrivate();
            byte[] v2 = rfc8410V2(curve, wpriv.getRawPrivateKey(),
                wpriv.getRawPublicKey());

            KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(v2));
            assertEquals(kp.getPrivate(), priv);
            assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded());
            assertEquals(0x00, priv.getEncoded()[4]);
            assertSigns(curve, priv, kp.getPublic());

            /* the umbrella factory also identifies the curve */
            PrivateKey priv2 = KeyFactory.getInstance("EdDSA", "wolfJCE")
                .generatePrivate(new PKCS8EncodedKeySpec(v2));
            assertEquals(priv, priv2);
        }
    }

    @Test
    public void malformedV2Rejected() throws Exception {

        Assume.assumeTrue("Ed25519 not compiled in", ed25519Enabled);

        byte[] v2 = Base64.getDecoder().decode(RFC8410_V2_EXAMPLE);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "wolfJCE");

        /* every truncation from inside the AlgorithmIdentifier onwards is
         * rejected cleanly, nothing but InvalidKeySpecException escapes */
        for (int n = 8; n < v2.length; n++) {
            try {
                kf.generatePrivate(new PKCS8EncodedKeySpec(
                    Arrays.copyOf(v2, n)));
                fail("truncated v2 of " + n + " bytes accepted");
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }

        /* the same body relabeled with the X25519 OID (1.3.101.110) */
        byte[] relabeled = v2.clone();
        relabeled[11] = 0x6e;
        for (String alg : new String[] { "Ed25519", "EdDSA" }) {
            try {
                KeyFactory.getInstance(alg, "wolfJCE").generatePrivate(
                    new PKCS8EncodedKeySpec(relabeled));
                fail("X25519-labeled v2 accepted by " + alg);
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }
    }

    @Test
    public void edecPointOutOfRangeRejected() throws Exception {

        assumeAnyEnabled();
        Assume.assumeTrue("JDK 15+ EdEC specs not present", pointCls != null);

        for (String curve : curves()) {
            int bits = curve.equals("Ed25519") ? 255 : 448;
            KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
            Constructor<?> c = pubSpecCls.getConstructor(npsCls, pointCls);

            BigInteger p;
            if (curve.equals("Ed25519")) {
                p = BigInteger.ONE.shiftLeft(255)
                    .subtract(BigInteger.valueOf(19));
            } else {
                p = BigInteger.ONE.shiftLeft(448)
                    .subtract(BigInteger.ONE.shiftLeft(224))
                    .subtract(BigInteger.ONE);
            }

            /* y with one bit more than the curve allows, the largest y
             * below 2^bits and the field prime itself (smallest
             * non-canonical y), all rejected by the Java range check */
            BigInteger[] rejected = {
                BigInteger.ONE.shiftLeft(bits),
                BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE),
                p
            };
            for (BigInteger y : rejected) {
                KeySpec spec = (KeySpec) c.newInstance(namedSpec(curve),
                    edecPoint(false, y));
                try {
                    kf.generatePublic(spec);
                    fail("y = " + y + " accepted for " + curve);
                } catch (InvalidKeySpecException e) {
                    /* expected */
                }
            }

            /* y = 0 and y = 1 decode to small order points. wolfSSL 5.9.2
             * rejects them, earlier releases accept some or all, so only
             * require the spec path to agree with a raw import */
            int pubSize = curve.equals("Ed25519") ?
                Ed25519.ED25519_PUB_KEY_SIZE : Ed448.ED448_PUB_KEY_SIZE;
            for (BigInteger y : new BigInteger[] {
                    BigInteger.ZERO, BigInteger.ONE }) {
                byte[] raw = new byte[pubSize];
                raw[0] = y.byteValue();
                boolean rawRejected;
                try {
                    new WolfCryptEdDSAPublicKey(curve, raw);
                    rawRejected = false;
                } catch (IllegalArgumentException e) {
                    rawRejected = true;
                }
                KeySpec spec = (KeySpec) c.newInstance(namedSpec(curve),
                    edecPoint(false, y));
                try {
                    kf.generatePublic(spec);
                    assertFalse("y = " + y + " accepted for " + curve +
                        " but a raw import rejects it", rawRejected);
                } catch (InvalidKeySpecException e) {
                    assertTrue("y = " + y + " rejected for " + curve +
                        " but a raw import accepts it", rawRejected);
                }
            }

            /* negative y, when the JDK point class accepts one */
            KeySpec neg;
            try {
                neg = (KeySpec) c.newInstance(namedSpec(curve),
                    edecPoint(false, BigInteger.valueOf(-1)));
            } catch (InvocationTargetException e) {
                continue;
            }
            try {
                kf.generatePublic(neg);
                fail("negative y accepted for " + curve);
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }
    }

    @Test
    public void edecPointSmallYRoundTrip() throws Exception {

        assumeAnyEnabled();
        Assume.assumeTrue("JDK 15+ EdEC specs not present", pointCls != null);

        for (String curve : curves()) {
            KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
            Constructor<?> c = pubSpecCls.getConstructor(npsCls, pointCls);
            boolean found = false;

            /* the smallest y that decompresses to a curve point is fixed
             * for each curve and takes the one-byte toByteArray() form,
             * about every second y is a valid point */
            for (int y = 2; y < 64 && !found; y++) {
                KeySpec spec = (KeySpec) c.newInstance(namedSpec(curve),
                    edecPoint(false, BigInteger.valueOf(y)));
                WolfCryptEdDSAPublicKey pub;
                try {
                    pub = (WolfCryptEdDSAPublicKey) kf.generatePublic(spec);
                } catch (InvalidKeySpecException e) {
                    continue;
                }
                byte[] raw = pub.getRawPublicKey();
                assertEquals(y, raw[0]);
                for (int i = 1; i < raw.length; i++) {
                    assertEquals(0, raw[i]);
                }
                Object back = kf.getKeySpec(pub,
                    pubSpecCls.asSubclass(KeySpec.class));
                Object point = call(back, "getPoint");
                assertEquals(BigInteger.valueOf(y), call(point, "getY"));
                assertFalse((Boolean) call(point, "isXOdd"));
                found = true;
            }
            assertTrue("no small y point found for " + curve, found);
        }
    }

    @Test
    public void rfc8410V2FieldsParsesTheRfcExample() throws Exception {

        Assume.assumeTrue("Ed25519 not compiled in", ed25519Enabled);

        /* Fallback parser is only reached when native rejects the DER, drive
         * it directly to keep it covered either way */
        Class<?> curveCls = Class.forName(
            "com.wolfssl.provider.jce.WolfCryptEdDSACurve");
        /* the enum class is package-private, reflection needs access */
        Method valueOf = curveCls.getMethod("valueOf", String.class);
        valueOf.setAccessible(true);
        Object ed25519 = valueOf.invoke(null, "ED25519");
        Method m = curveCls.getDeclaredMethod("rfc8410V2Fields",
            byte[].class);
        m.setAccessible(true);

        byte[] v2 = Base64.getDecoder().decode(RFC8410_V2_EXAMPLE);
        byte[][] fields = (byte[][]) m.invoke(ed25519, v2);
        assertNotNull(fields);
        assertArrayEquals(Util.h2b(RFC8410_PRIV_HEX), fields[0]);
        assertArrayEquals(Arrays.copyOfRange(v2, v2.length - 32, v2.length),
            fields[1]);

        /* anything that is not exactly the RFC form yields null */
        byte[][] bad = {
            Arrays.copyOf(v2, v2.length - 1),
            Arrays.copyOf(v2, 48),
            new byte[0]
        };
        for (byte[] b : bad) {
            assertNull(m.invoke(ed25519, b));
        }
        byte[] wrongOid = v2.clone();
        wrongOid[11] = 0x71;
        assertNull(m.invoke(ed25519, wrongOid));
        byte[] noPad = v2.clone();
        noPad[v2.length - 33] = 0x01;
        assertNull(m.invoke(ed25519, noPad));

        /* Envelope is checked as a whole: a byte after the outer SEQUENCE,
         * version v1 with a public key present, a NULL between the private key
         * and publicKey [1], attributes [0] overrunning publicKey [1] */
        assertNull(m.invoke(ed25519, Arrays.copyOf(v2, v2.length + 1)));
        byte[] v1 = v2.clone();
        v1[4] = 0x00;
        assertNull(m.invoke(ed25519, v1));
        int split = v2.length - 35;
        byte[] extra = new byte[v2.length + 2];
        System.arraycopy(v2, 0, extra, 0, split);
        extra[split] = Util.TAG_NULL;
        extra[split + 1] = 0x00;
        System.arraycopy(v2, split, extra, split + 2, 35);
        extra[1] += 2;
        assertNull(m.invoke(ed25519, extra));
        byte[] longAttrs = v2.clone();
        assertEquals((byte)Util.TAG_ATTRIBUTES, longAttrs[48]);
        longAttrs[49] += 1;
        assertNull(m.invoke(ed25519, longAttrs));

        /* Attributes [0] are skipped, not required: the example without them
         * still yields the same keys */
        byte[] noAttrs = new byte[v2.length - 33];
        System.arraycopy(v2, 0, noAttrs, 0, 48);
        System.arraycopy(v2, 81, noAttrs, 48, 35);
        noAttrs[1] -= 33;
        byte[][] plain = (byte[][]) m.invoke(ed25519, noAttrs);
        assertNotNull(plain);
        assertArrayEquals(fields[0], plain[0]);
        assertArrayEquals(fields[1], plain[1]);
    }

    @Test
    public void unsupportedSpecsRejected() throws Exception {

        assumeAnyEnabled();

        String curve = curves().get(0);
        KeyPair kp = generate(curve);
        KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");

        try {
            kf.generatePublic(new RSAPublicKeySpec(BigInteger.TEN,
                BigInteger.TEN));
            fail("RSAPublicKeySpec accepted");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf.generatePublic(new PKCS8EncodedKeySpec(
                kp.getPrivate().getEncoded()));
            fail("PKCS8EncodedKeySpec accepted for public key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf.generatePrivate(new X509EncodedKeySpec(
                kp.getPublic().getEncoded()));
            fail("X509EncodedKeySpec accepted for private key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf.generatePublic(null);
            fail("null spec accepted");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
            fail("RSAPublicKeySpec requested from EdDSA key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf.getKeySpec(kp.getPrivate(), X509EncodedKeySpec.class);
            fail("X509EncodedKeySpec requested from private key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
    }

    @Test
    public void malformedDerRejected() throws Exception {

        assumeAnyEnabled();

        String curve = curves().get(0);
        KeyPair kp = generate(curve);
        KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
        byte[] spki = kp.getPublic().getEncoded();
        byte[] pkcs8 = kp.getPrivate().getEncoded();

        byte[][] bad = { new byte[0], new byte[] { Util.TAG_SEQUENCE, 0x00 },
            Arrays.copyOf(spki, spki.length - 1), "garbage!!".getBytes() };
        for (byte[] b : bad) {
            try {
                kf.generatePublic(new X509EncodedKeySpec(b));
                fail("bad SPKI accepted");
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
            try {
                kf.generatePrivate(new PKCS8EncodedKeySpec(b));
                fail("bad PKCS#8 accepted");
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }
        /* RSA encodings */
        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        try {
            kf.generatePublic(new X509EncodedKeySpec(
                rsa.getPublic().getEncoded()));
            fail("RSA SPKI accepted");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf.generatePrivate(new PKCS8EncodedKeySpec(
                rsa.getPrivate().getEncoded()));
            fail("RSA PKCS#8 accepted");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        /* truncated and corrupted forms of the real PKCS#8 */
        byte[] truncated = Arrays.copyOf(pkcs8, pkcs8.length - 1);
        byte[] corrupted = pkcs8.clone();
        corrupted[1] ^= 0x7f;
        for (byte[] b : new byte[][] { truncated, corrupted }) {
            try {
                kf.generatePrivate(new PKCS8EncodedKeySpec(b));
                fail("bad PKCS#8 accepted");
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }
    }

    @Test
    public void perCurveFactoryRejectsOtherCurve() throws Exception {

        Assume.assumeTrue(ed25519Enabled && ed448Enabled);

        KeyPair kp25519 = generate("Ed25519");
        KeyPair kp448 = generate("Ed448");
        KeyFactory kf25519 = KeyFactory.getInstance("Ed25519", "wolfJCE");
        KeyFactory kf448 = KeyFactory.getInstance("Ed448", "wolfJCE");
        KeyFactory kfAny = KeyFactory.getInstance("EdDSA", "wolfJCE");

        try {
            kf25519.generatePublic(new X509EncodedKeySpec(
                kp448.getPublic().getEncoded()));
            fail("Ed25519 factory accepted Ed448 key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf448.generatePrivate(new PKCS8EncodedKeySpec(
                kp25519.getPrivate().getEncoded()));
            fail("Ed448 factory accepted Ed25519 key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }
        try {
            kf25519.translateKey(kp448.getPublic());
            fail("Ed25519 factory translated Ed448 key");
        } catch (InvalidKeyException e) {
            /* expected */
        }
        try {
            kf448.getKeySpec(kp25519.getPublic(), X509EncodedKeySpec.class);
            fail("Ed448 factory produced spec for Ed25519 key");
        } catch (InvalidKeySpecException e) {
            /* expected */
        }

        assertEquals(kp448.getPublic(), kfAny.generatePublic(
            new X509EncodedKeySpec(kp448.getPublic().getEncoded())));
        assertEquals(kp25519.getPrivate(), kfAny.generatePrivate(
            new PKCS8EncodedKeySpec(kp25519.getPrivate().getEncoded())));
    }

    @Test
    public void translateKey() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");

            /* wolfJCE keys pass through untouched */
            assertSame(kp.getPublic(), kf.translateKey(kp.getPublic()));
            assertSame(kp.getPrivate(), kf.translateKey(kp.getPrivate()));

            /* foreign keys are wrapped from their encoding */
            final byte[] spki = kp.getPublic().getEncoded();
            final byte[] pkcs8 = kp.getPrivate().getEncoded();
            PublicKey fpub = new PublicKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "Ed25519"; }
                public String getFormat() { return "X.509"; }
                public byte[] getEncoded() { return spki.clone(); }
            };
            PrivateKey fpriv = new PrivateKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "EdDSA"; }
                public String getFormat() { return "PKCS#8"; }
                public byte[] getEncoded() { return pkcs8.clone(); }
            };
            Key tpub = kf.translateKey(fpub);
            Key tpriv = kf.translateKey(fpriv);
            assertTrue(tpub instanceof WolfCryptEdDSAPublicKey);
            assertTrue(tpriv instanceof WolfCryptEdDSAPrivateKey);
            assertEquals(kp.getPublic(), tpub);
            assertEquals(kp.getPrivate(), tpriv);

            /* a key that hands out its own array must keep it intact */
            final byte[] owned = pkcs8.clone();
            PrivateKey fown = new PrivateKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "EdDSA"; }
                public String getFormat() { return "PKCS#8"; }
                public byte[] getEncoded() { return owned; }
            };
            assertEquals(kp.getPrivate(), kf.translateKey(fown));
            assertArrayEquals(pkcs8, owned);

            /* wrong format */
            PublicKey raw = new PublicKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "EdDSA"; }
                public String getFormat() { return "RAW"; }
                public byte[] getEncoded() { return spki.clone(); }
            };
            try {
                kf.translateKey(raw);
                fail("RAW format key translated");
            } catch (InvalidKeyException e) {
                /* expected */
            }

            /* not an EdDSA key */
            KeyPair rsa = KeyPairGenerator.getInstance("RSA")
                .generateKeyPair();
            try {
                kf.translateKey(rsa.getPublic());
                fail("RSA key translated");
            } catch (InvalidKeyException e) {
                /* expected */
            }
            try {
                kf.translateKey(null);
                fail("null key translated");
            } catch (InvalidKeyException e) {
                /* expected */
            }

            /* destroyed keys are rejected */
            WolfCryptEdDSAPrivateKey dead = (WolfCryptEdDSAPrivateKey)
                kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            dead.destroy();
            try {
                kf.translateKey(dead);
                fail("destroyed key translated");
            } catch (InvalidKeyException e) {
                /* expected */
            }
            try {
                kf.getKeySpec(dead, PKCS8EncodedKeySpec.class);
                fail("spec produced from destroyed key");
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }
    }

    @Test
    public void jdk15EdECKeySpecs() throws Exception {

        assumeAnyEnabled();
        Assume.assumeTrue("JDK 15+ EdEC specs not available",
            pubSpecCls != null && privSpecCls != null && pointCls != null);

        for (String curve : curves()) {
            KeyFactory kf = KeyFactory.getInstance(curve, "wolfJCE");
            boolean sawOdd = false;
            boolean sawEven = false;

            /* generate until both x parities have been exercised */
            for (int i = 0; i < 40 && !(sawOdd && sawEven); i++) {
                KeyPair kp = generate(curve);
                WolfCryptEdDSAPublicKey pub =
                    (WolfCryptEdDSAPublicKey) kp.getPublic();
                WolfCryptEdDSAPrivateKey priv =
                    (WolfCryptEdDSAPrivateKey) kp.getPrivate();
                byte[] rawPub = pub.getRawPublicKey();
                boolean xOdd = (rawPub[rawPub.length - 1] & 0x80) != 0;
                if (xOdd) {
                    sawOdd = true;
                }
                else {
                    sawEven = true;
                }

                /* generatePublic / generatePrivate from EdEC specs */
                PublicKey fromSpec = kf.generatePublic(
                    edecPublicKeySpec(curve, rawPub));
                assertEquals(pub, fromSpec);
                PrivateKey privFromSpec = kf.generatePrivate(
                    edecPrivateKeySpec(curve, priv.getRawPrivateKey()));
                assertEquals(priv, privFromSpec);
                assertSigns(curve, privFromSpec, fromSpec);

                /* getKeySpec back to EdEC specs, compare components */
                Object pubSpec = kf.getKeySpec(pub, pubSpecCls.asSubclass(
                    KeySpec.class));
                Object point = call(pubSpec, "getPoint");
                assertEquals(xOdd, call(point, "isXOdd"));
                byte[] be = new byte[rawPub.length];
                for (int j = 0; j < rawPub.length; j++) {
                    be[j] = rawPub[rawPub.length - 1 - j];
                }
                be[0] &= 0x7f;
                assertEquals(new BigInteger(1, be), call(point, "getY"));
                assertEquals(curve, call(call(pubSpec, "getParams"),
                    "getName"));

                Object privSpec = kf.getKeySpec(priv, privSpecCls.asSubclass(
                    KeySpec.class));
                assertArrayEquals(priv.getRawPrivateKey(),
                    (byte[]) call(privSpec, "getBytes"));
                assertEquals(curve, call(call(privSpec, "getParams"),
                    "getName"));
            }
            assertTrue("did not see both x parities", sawOdd && sawEven);

            /* wrong curve name in the spec */
            String other = curve.equals("Ed25519") ? "Ed448" : "Ed25519";
            KeyPair kp = generate(curve);
            byte[] rawPub = ((WolfCryptEdDSAPublicKey) kp.getPublic())
                .getRawPublicKey();
            try {
                kf.generatePublic(edecPublicKeySpec(other, Arrays.copyOf(
                    rawPub, other.equals("Ed448") ?
                        Ed448.ED448_PUB_KEY_SIZE :
                        Ed25519.ED25519_PUB_KEY_SIZE)));
                fail("spec for the other curve accepted");
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
            /* X25519 is not an EdDSA curve */
            try {
                Constructor<?> c = privSpecCls.getConstructor(npsCls,
                    byte[].class);
                kf.generatePrivate((KeySpec) c.newInstance(
                    namedSpec("X25519"), new byte[32]));
                fail("X25519 spec accepted");
            } catch (InvalidKeySpecException e) {
                /* expected */
            }
        }
    }

    @Test
    public void namedParameterSpecOnKeys() throws Exception {

        assumeAnyEnabled();
        Assume.assumeTrue("NamedParameterSpec not available", npsCls != null);

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            AlgorithmParameterSpec p = ((WolfCryptEdDSAPublicKey)
                kp.getPublic()).getParams();
            assertTrue(npsCls.isInstance(p));
            assertEquals(curve, call(p, "getName"));
            assertEquals(curve, call(((WolfCryptEdDSAPrivateKey)
                kp.getPrivate()).getParams(), "getName"));
        }
    }
}
