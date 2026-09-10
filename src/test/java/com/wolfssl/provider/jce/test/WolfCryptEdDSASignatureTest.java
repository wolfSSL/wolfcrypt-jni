/* WolfCryptEdDSASignatureTest.java
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.wolfssl.provider.jce.WolfCryptContextParameterSpec;
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

/**
 * Tests for wolfJCE EdDSA Signature services: aliases, sign/verify round
 * trips, RFC 8032 vectors through the JCA API, pre-hash and context
 * parameters, and error cases.
 */
public class WolfCryptEdDSASignatureTest {

    private static boolean ed25519Enabled = false;
    private static boolean ed448Enabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptEdDSASignatureTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        assertNotNull(Security.getProvider("wolfJCE"));

        ed25519Enabled = FeatureDetect.Ed25519KeyGenEnabled();
        ed448Enabled = FeatureDetect.Ed448KeyGenEnabled();
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

    private static byte[] sign(String alg, PrivateKey key, byte[] msg,
        AlgorithmParameterSpec spec) throws Exception {

        Signature s = Signature.getInstance(alg, "wolfJCE");
        if (spec != null) {
            s.setParameter(spec);
        }
        s.initSign(key);
        s.update(msg);

        return s.sign();
    }

    private static boolean verify(String alg, PublicKey key, byte[] msg,
        byte[] sig, AlgorithmParameterSpec spec) throws Exception {

        Signature s = Signature.getInstance(alg, "wolfJCE");
        if (spec != null) {
            s.setParameter(spec);
        }
        s.initVerify(key);
        s.update(msg);

        return s.verify(sig);
    }

    /* Build a JDK 15+ EdDSAParameterSpec via reflection, null when the
     * class is absent (pre JDK 15) */
    private static AlgorithmParameterSpec jdkSpec(boolean prehash,
        byte[] ctx) throws Exception {

        Class<?> cls;
        try {
            cls = Class.forName("java.security.spec.EdDSAParameterSpec");
        } catch (ClassNotFoundException e) {
            return null;
        }

        if (ctx == null) {
            Constructor<?> c = cls.getConstructor(boolean.class);
            return (AlgorithmParameterSpec) c.newInstance(prehash);
        }

        Constructor<?> c = cls.getConstructor(boolean.class, byte[].class);
        return (AlgorithmParameterSpec) c.newInstance(prehash, ctx);
    }

    @Test
    public void getInstanceForAllAliases() throws Exception {

        assumeAnyEnabled();

        List<String> names = new ArrayList<String>();
        names.add("EdDSA");
        names.add("EDDSA");

        if (FeatureDetect.Ed25519Enabled()) {
            names.addAll(Arrays.asList("Ed25519", "ED25519", "ed25519",
                "1.3.101.112", "OID.1.3.101.112"));
        }

        if (FeatureDetect.Ed448Enabled()) {
            names.addAll(Arrays.asList("Ed448", "ED448", "1.3.101.113",
                "OID.1.3.101.113"));
        }

        for (String n : names) {
            Signature s = Signature.getInstance(n, "wolfJCE");
            assertEquals("wolfJCE", s.getProvider().getName());
        }

        if (!FeatureDetect.Ed448Enabled()) {
            try {
                Signature.getInstance("Ed448", "wolfJCE");
                fail("Ed448 should not be registered");
            } catch (java.security.NoSuchAlgorithmException e) {
                /* expected */
            }
        }
        if (!FeatureDetect.Ed25519Enabled()) {
            try {
                Signature.getInstance("Ed25519", "wolfJCE");
                fail("Ed25519 should not be registered");
            } catch (java.security.NoSuchAlgorithmException e) {
                /* expected */
            }
        }
    }

    @Test
    public void signVerifyRoundTrip() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            byte[] msg = "wolfJCE EdDSA round trip".getBytes();

            for (String alg : new String[] { curve, "EdDSA" }) {
                byte[] sig = sign(alg, kp.getPrivate(), msg, null);
                assertEquals(curve.equals("Ed25519") ?
                    Ed25519.ED25519_SIG_SIZE : Ed448.ED448_SIG_SIZE,
                    sig.length);
                assertTrue(verify(alg, kp.getPublic(), msg, sig, null));

                /* EdDSA is deterministic */
                assertArrayEquals(sig, sign(alg, kp.getPrivate(), msg, null));

                /* aliases interoperate */
                assertTrue(verify(curve, kp.getPublic(), msg,
                    sign("EdDSA", kp.getPrivate(), msg, null), null));
            }
        }
    }

    @Test
    public void multipleUpdatesAndEmptyMessage() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            byte[] msg = "abcdefghijklmnopqrstuvwxyz".getBytes();

            Signature s = Signature.getInstance(curve, "wolfJCE");
            s.initSign(kp.getPrivate());
            s.update(msg[0]);
            s.update(msg, 1, 10);
            s.update(msg, 11, msg.length - 11);
            byte[] sig = s.sign();
            assertArrayEquals(sig, sign(curve, kp.getPrivate(), msg, null));

            s.initVerify(kp.getPublic());
            s.update(msg, 0, 13);
            s.update(msg, 13, msg.length - 13);
            assertTrue(s.verify(sig));

            /* empty message */
            byte[] esig = sign(curve, kp.getPrivate(), new byte[0], null);
            assertTrue(verify(curve, kp.getPublic(), new byte[0], esig, null));
            assertFalse(verify(curve, kp.getPublic(), new byte[1], esig, null));

            /* sign/verify reset the buffer, so a second use is clean */
            s.initSign(kp.getPrivate());
            s.update("junk".getBytes());
            s.sign();
            s.update(msg);
            assertArrayEquals(sig, s.sign());
        }
    }

    @Test
    public void largeMessage() throws Exception {

        assumeAnyEnabled();

        String curve = curves().get(0);
        KeyPair kp = generate(curve);
        byte[] big = new byte[5 * 1024 * 1024];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) i;
        }

        Signature s = Signature.getInstance(curve, "wolfJCE");
        s.initSign(kp.getPrivate());
        for (int off = 0; off < big.length; off += 65536) {
            s.update(big, off, Math.min(65536, big.length - off));
        }
        byte[] sig = s.sign();

        s.initVerify(kp.getPublic());
        s.update(big);
        assertTrue(s.verify(sig));

        /* the object keeps working after the buffer high-water mark */
        byte[] small = "small".getBytes();
        s.initSign(kp.getPrivate());
        s.update(small);
        assertTrue(verify(curve, kp.getPublic(), small, s.sign(), null));
    }

    @Test
    public void umbrellaAcceptsBothCurvesPerCurveRejectsOther()
        throws Exception {

        Assume.assumeTrue(ed25519Enabled && ed448Enabled);

        KeyPair kp25519 = generate("Ed25519");
        KeyPair kp448 = generate("Ed448");
        byte[] msg = "curve lock".getBytes();

        assertTrue(verify("EdDSA", kp25519.getPublic(), msg,
            sign("EdDSA", kp25519.getPrivate(), msg, null), null));
        assertTrue(verify("EdDSA", kp448.getPublic(), msg,
            sign("EdDSA", kp448.getPrivate(), msg, null), null));

        try {
            sign("Ed25519", kp448.getPrivate(), msg, null);
            fail("Ed25519 Signature accepted Ed448 key");
        } catch (InvalidKeyException e) {
            /* expected */
        }
        try {
            verify("Ed448", kp25519.getPublic(), msg,
                new byte[Ed448.ED448_SIG_SIZE], null);
            fail("Ed448 Signature accepted Ed25519 key");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void tamperedInputsFail() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            byte[] msg = "tamper".getBytes();
            byte[] sig = sign(curve, kp.getPrivate(), msg, null);

            byte[] badMsg = msg.clone();
            badMsg[0] ^= 1;
            assertFalse(verify(curve, kp.getPublic(), badMsg, sig, null));

            byte[] badSig = sig.clone();
            badSig[3] ^= 1;
            assertFalse(verify(curve, kp.getPublic(), msg, badSig, null));

            assertFalse(verify(curve, kp.getPublic(), msg,
                Arrays.copyOf(sig, sig.length - 1), null));
            assertFalse(verify(curve, kp.getPublic(), msg,
                Arrays.copyOf(sig, sig.length + 1), null));
            assertFalse(verify(curve, kp.getPublic(), msg, new byte[0], null));

            /* wrong public key */
            assertFalse(verify(curve, generate(curve).getPublic(), msg, sig,
                null));
        }
    }

    @Test
    public void rfc8032Ed25519VectorsThroughJce() throws Exception {

        Assume.assumeTrue(ed25519Enabled);

        for (int i = 0; i < Ed25519TestVectors.SKEY.length; i++) {
            if (i == 3 || i == 4) {
                /* non-canonical public key encodings, JNI-level only */
                continue;
            }
            PrivateKey priv = new WolfCryptEdDSAPrivateKey("Ed25519",
                Ed25519TestVectors.SKEY[i]);
            PublicKey pub = new WolfCryptEdDSAPublicKey("Ed25519",
                Ed25519TestVectors.PKEY[i]);
            byte[] msg = Ed25519TestVectors.MSG[i];

            assertArrayEquals("vector " + i, Ed25519TestVectors.SIG[i],
                sign("Ed25519", priv, msg, null));
            assertTrue(verify("Ed25519", pub, msg,
                Ed25519TestVectors.SIG[i], null));
        }

        /* Ed25519ctx (RFC 8032 7.2) */
        PrivateKey ctxPriv = new WolfCryptEdDSAPrivateKey("Ed25519",
            Ed25519TestVectors.CTX_SKEY);
        PublicKey ctxPub = new WolfCryptEdDSAPublicKey("Ed25519",
            Ed25519TestVectors.CTX_PKEY);
        byte[] cmsg = Ed25519TestVectors.CTX_MSG;
        byte[] foo = Ed25519TestVectors.CTX_CONTEXT;

        assertArrayEquals(Ed25519TestVectors.CTX_SIG_FOO, sign("Ed25519",
            ctxPriv, cmsg, new WolfCryptEdDSAParameterSpec(false, foo)));
        assertArrayEquals(Ed25519TestVectors.CTX_SIG_FOO, sign("Ed25519",
            ctxPriv, cmsg, new WolfCryptContextParameterSpec(foo)));
        assertTrue(verify("Ed25519", ctxPub, cmsg,
            Ed25519TestVectors.CTX_SIG_FOO,
            new WolfCryptEdDSAParameterSpec(false, foo)));
        assertTrue(verify("EdDSA", ctxPub, cmsg,
            Ed25519TestVectors.CTX_SIG_FOO,
            new WolfCryptContextParameterSpec(foo)));

        /* present-but-empty context is Ed25519ctx, not pure */
        assertArrayEquals(Ed25519TestVectors.CTX_SIG_EMPTY, sign("Ed25519",
            ctxPriv, cmsg, new WolfCryptEdDSAParameterSpec(false,
            new byte[0])));
        assertFalse(Arrays.equals(Ed25519TestVectors.CTX_SIG_EMPTY,
            sign("Ed25519", ctxPriv, cmsg, null)));
        assertFalse(Arrays.equals(Ed25519TestVectors.CTX_SIG_EMPTY,
            sign("Ed25519", ctxPriv, cmsg,
            new WolfCryptEdDSAParameterSpec(false))));

        /* wrong or missing context fails */
        assertFalse(verify("Ed25519", ctxPub, cmsg,
            Ed25519TestVectors.CTX_SIG_FOO,
            new WolfCryptEdDSAParameterSpec(false, "bar".getBytes())));
        assertFalse(verify("Ed25519", ctxPub, cmsg,
            Ed25519TestVectors.CTX_SIG_FOO, null));

        /* Ed25519ph (RFC 8032 7.3) */
        PrivateKey phPriv = new WolfCryptEdDSAPrivateKey("Ed25519",
            Ed25519TestVectors.PH_SKEY);
        PublicKey phPub = new WolfCryptEdDSAPublicKey("Ed25519",
            Ed25519TestVectors.PH_PKEY);
        byte[] pmsg = Ed25519TestVectors.PH_MSG;
        byte[] pfoo = Ed25519TestVectors.PH_CONTEXT;

        assertArrayEquals(Ed25519TestVectors.PH_SIG, sign("Ed25519", phPriv,
            pmsg, new WolfCryptEdDSAParameterSpec(true)));
        assertArrayEquals(Ed25519TestVectors.PH_SIG_FOO, sign("Ed25519",
            phPriv, pmsg, new WolfCryptEdDSAParameterSpec(true, pfoo)));
        assertTrue(verify("Ed25519", phPub, pmsg, Ed25519TestVectors.PH_SIG,
            new WolfCryptEdDSAParameterSpec(true)));
        assertTrue(verify("Ed25519", phPub, pmsg,
            Ed25519TestVectors.PH_SIG_FOO,
            new WolfCryptEdDSAParameterSpec(true, pfoo)));
        assertFalse(verify("Ed25519", phPub, pmsg,
            Ed25519TestVectors.PH_SIG, null));
    }

    @Test
    public void rfc8032Ed448VectorsThroughJce() throws Exception {

        Assume.assumeTrue(ed448Enabled);

        for (int i = 0; i < Ed448TestVectors.SKEY.length; i++) {
            if (i == 4) {
                /* 0x40-prefixed public key encoding, JNI-level only */
                continue;
            }
            PrivateKey priv = new WolfCryptEdDSAPrivateKey("Ed448",
                Ed448TestVectors.SKEY[i]);
            PublicKey pub = new WolfCryptEdDSAPublicKey("Ed448",
                Ed448TestVectors.PKEY[i]);
            byte[] msg = Ed448TestVectors.MSG[i];

            assertArrayEquals("vector " + i, Ed448TestVectors.SIG[i],
                sign("Ed448", priv, msg, null));
            assertArrayEquals("vector " + i, Ed448TestVectors.SIG[i],
                sign("EdDSA", priv, msg,
                new WolfCryptEdDSAParameterSpec(false, new byte[0])));
            assertTrue(verify("Ed448", pub, msg, Ed448TestVectors.SIG[i],
                null));
        }

        /* Ed448 with context "foo" (RFC 8032 7.4) */
        PrivateKey ctxPriv = new WolfCryptEdDSAPrivateKey("Ed448",
            Ed448TestVectors.CTX_SKEY);
        PublicKey ctxPub = new WolfCryptEdDSAPublicKey("Ed448",
            Ed448TestVectors.CTX_PKEY);
        byte[] foo = Ed448TestVectors.CTX_CONTEXT;
        assertArrayEquals(Ed448TestVectors.CTX_SIG_FOO, sign("Ed448", ctxPriv,
            Ed448TestVectors.CTX_MSG,
            new WolfCryptEdDSAParameterSpec(false, foo)));
        assertArrayEquals(Ed448TestVectors.CTX_SIG_FOO, sign("Ed448", ctxPriv,
            Ed448TestVectors.CTX_MSG, new WolfCryptContextParameterSpec(foo)));
        assertTrue(verify("Ed448", ctxPub, Ed448TestVectors.CTX_MSG,
            Ed448TestVectors.CTX_SIG_FOO,
            new WolfCryptEdDSAParameterSpec(false, foo)));
        assertFalse(verify("Ed448", ctxPub, Ed448TestVectors.CTX_MSG,
            Ed448TestVectors.CTX_SIG_FOO, null));

        /* Ed448ph (RFC 8032 7.5) */
        PrivateKey phPriv = new WolfCryptEdDSAPrivateKey("Ed448",
            Ed448TestVectors.PH_SKEY);
        PublicKey phPub = new WolfCryptEdDSAPublicKey("Ed448",
            Ed448TestVectors.PH_PKEY);
        byte[] pmsg = Ed448TestVectors.PH_MSG;
        byte[] pfoo = Ed448TestVectors.PH_CONTEXT;
        assertArrayEquals(Ed448TestVectors.PH_SIG, sign("Ed448", phPriv,
            pmsg, new WolfCryptEdDSAParameterSpec(true)));
        assertArrayEquals(Ed448TestVectors.PH_SIG_FOO, sign("Ed448", phPriv,
            pmsg, new WolfCryptEdDSAParameterSpec(true, pfoo)));
        assertTrue(verify("Ed448", phPub, pmsg, Ed448TestVectors.PH_SIG,
            new WolfCryptEdDSAParameterSpec(true)));
        assertTrue(verify("Ed448", phPub, pmsg, Ed448TestVectors.PH_SIG_FOO,
            new WolfCryptEdDSAParameterSpec(true, pfoo)));
        assertFalse(verify("Ed448", phPub, pmsg, Ed448TestVectors.PH_SIG,
            null));
    }

    @Test
    public void jdkEdDSAParameterSpecAccepted() throws Exception {

        Assume.assumeTrue(ed25519Enabled);
        Assume.assumeTrue("JDK EdDSAParameterSpec not available",
            jdkSpec(false, null) != null);

        PrivateKey ctxPriv = new WolfCryptEdDSAPrivateKey("Ed25519",
            Ed25519TestVectors.CTX_SKEY);
        PrivateKey phPriv = new WolfCryptEdDSAPrivateKey("Ed25519",
            Ed25519TestVectors.PH_SKEY);

        assertArrayEquals(Ed25519TestVectors.CTX_SIG_FOO, sign("Ed25519",
            ctxPriv, Ed25519TestVectors.CTX_MSG,
            jdkSpec(false, Ed25519TestVectors.CTX_CONTEXT)));
        assertArrayEquals(Ed25519TestVectors.CTX_SIG_EMPTY, sign("Ed25519",
            ctxPriv, Ed25519TestVectors.CTX_MSG, jdkSpec(false, new byte[0])));
        assertArrayEquals(Ed25519TestVectors.PH_SIG, sign("Ed25519", phPriv,
            Ed25519TestVectors.PH_MSG, jdkSpec(true, null)));
        assertArrayEquals(Ed25519TestVectors.PH_SIG_FOO, sign("Ed25519",
            phPriv, Ed25519TestVectors.PH_MSG,
            jdkSpec(true, Ed25519TestVectors.PH_CONTEXT)));

        /* absent context with prehash false is pure */
        assertArrayEquals(sign("Ed25519", ctxPriv,
            Ed25519TestVectors.CTX_MSG, null), sign("Ed25519", ctxPriv,
            Ed25519TestVectors.CTX_MSG, jdkSpec(false, null)));
    }

    @Test
    public void contextSpecKeepsPrehash() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            byte[] msg = "prehash then context".getBytes();
            byte[] ctx = "ctx".getBytes();

            Signature a = Signature.getInstance(curve, "wolfJCE");
            a.setParameter(new WolfCryptEdDSAParameterSpec(true, ctx));
            a.initSign(kp.getPrivate());
            a.update(msg);
            byte[] expected = a.sign();

            /* the context spec sets a context only */
            Signature b = Signature.getInstance(curve, "wolfJCE");
            b.setParameter(new WolfCryptEdDSAParameterSpec(true));
            b.setParameter(new WolfCryptContextParameterSpec(ctx));
            b.initSign(kp.getPrivate());
            b.update(msg);
            assertArrayEquals(expected, b.sign());
        }
    }

    @Test
    public void verifyRfc8032VectorsWithoutKeyGen() throws Exception {

        /* the JCE verify path needs the curve only, not key generation */
        Assume.assumeTrue("no EdDSA curve compiled in",
            FeatureDetect.Ed25519Enabled() || FeatureDetect.Ed448Enabled());

        if (FeatureDetect.Ed25519Enabled()) {
            PublicKey pub = new WolfCryptEdDSAPublicKey("Ed25519",
                Ed25519TestVectors.PKEY1);
            assertTrue(verify("Ed25519", pub, Ed25519TestVectors.MSG1,
                Ed25519TestVectors.SIG1, null));
            assertFalse(verify("Ed25519", pub, "x".getBytes(),
                Ed25519TestVectors.SIG1, null));
        }
        if (FeatureDetect.Ed448Enabled()) {
            PublicKey pub = new WolfCryptEdDSAPublicKey("Ed448",
                Ed448TestVectors.PKEY1);
            assertTrue(verify("Ed448", pub, Ed448TestVectors.MSG1,
                Ed448TestVectors.SIG1, null));
            assertFalse(verify("Ed448", pub, "x".getBytes(),
                Ed448TestVectors.SIG1, null));
        }
    }

    @SuppressWarnings("deprecation")
    @Test
    public void parameterErrors() throws Exception {

        assumeAnyEnabled();

        String curve = curves().get(0);
        KeyPair kp = generate(curve);
        Signature s = Signature.getInstance(curve, "wolfJCE");

        try {
            s.setParameter(new ECGenParameterSpec("secp256r1"));
            fail("unsupported spec type should be rejected");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
        try {
            s.setParameter((AlgorithmParameterSpec) null);
            fail("null spec should be rejected");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
        try {
            s.setParameter(new WolfCryptContextParameterSpec(
                new byte[WolfCryptContextParameterSpec.MAX_CONTEXT_LEN]));
            s.setParameter(new WolfCryptEdDSAParameterSpec(true,
                new byte[WolfCryptEdDSAParameterSpec.MAX_CONTEXT_LEN]));
        } catch (InvalidAlgorithmParameterException e) {
            fail("255 byte context should be accepted");
        }

        /* even a zero-length update starts the message */
        Signature z = Signature.getInstance(curve, "wolfJCE");
        z.initSign(kp.getPrivate());
        z.update(new byte[0]);
        try {
            z.setParameter(new WolfCryptEdDSAParameterSpec(true));
            fail("setParameter after empty update should be rejected");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }

        /* cannot change parameters once data is buffered */
        s.initSign(kp.getPrivate());
        s.update("data".getBytes());
        try {
            s.setParameter(new WolfCryptEdDSAParameterSpec(true));
            fail("setParameter after update should be rejected");
        } catch (InvalidAlgorithmParameterException e) {
            /* expected */
        }
        s.sign();

        /* parameters persist across init calls */
        Signature p = Signature.getInstance(curve, "wolfJCE");
        p.setParameter(new WolfCryptEdDSAParameterSpec(true));
        byte[] msg = "persist".getBytes();
        p.initSign(kp.getPrivate());
        p.update(msg);
        byte[] phSig = p.sign();
        p.initVerify(kp.getPublic());
        p.update(msg);
        assertTrue(p.verify(phSig));
        assertFalse(verify(curve, kp.getPublic(), msg, phSig, null));

        /* wolfJCE registers no EdDSA AlgorithmParameters service, so null is
         * the only legal return even after setParameter() */
        assertNull(s.getParameters());
        try {
            s.setParameter("prehash", Boolean.TRUE);
            fail("String parameters should be rejected");
        } catch (InvalidParameterException e) {
            /* expected */
        }
        try {
            s.getParameter("prehash");
            fail("String parameters should be rejected");
        } catch (InvalidParameterException e) {
            /* expected */
        }
    }

    @Test
    public void stateErrors() throws Exception {

        assumeAnyEnabled();

        String curve = curves().get(0);
        KeyPair kp = generate(curve);
        Signature s = Signature.getInstance(curve, "wolfJCE");
        /* never inspected, the state check rejects the call first */
        byte[] anySig = new byte[1];

        try {
            s.update((byte) 1);
            fail("update before init should fail");
        } catch (SignatureException e) {
            /* expected */
        }
        try {
            s.sign();
            fail("sign before init should fail");
        } catch (SignatureException e) {
            /* expected */
        }
        try {
            s.verify(anySig);
            fail("verify before init should fail");
        } catch (SignatureException e) {
            /* expected */
        }

        s.initVerify(kp.getPublic());
        try {
            s.sign();
            fail("sign after initVerify should fail");
        } catch (SignatureException e) {
            /* expected */
        }
        try {
            s.verify(null);
            fail("null signature should fail");
        } catch (SignatureException e) {
            /* expected */
        }

        s.initSign(kp.getPrivate());
        try {
            s.verify(anySig);
            fail("verify after initSign should fail");
        } catch (SignatureException e) {
            /* expected */
        }

        try {
            s.initSign((PrivateKey) null);
            fail("null key should fail");
        } catch (InvalidKeyException e) {
            /* expected */
        }
        try {
            s.initVerify((PublicKey) null);
            fail("null key should fail");
        } catch (InvalidKeyException e) {
            /* expected */
        }

        /* the object recovers after the rejected calls */
        byte[] msg = "recover".getBytes();
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();
        s.initVerify(kp.getPublic());
        s.update(msg);
        assertTrue(s.verify(sig));
    }

    @Test
    public void foreignKeysResolvedByEncoding() throws Exception {

        assumeAnyEnabled();

        for (String curve : curves()) {
            KeyPair kp = generate(curve);
            byte[] msg = "foreign".getBytes();
            byte[] sig = sign(curve, kp.getPrivate(), msg, null);

            final byte[] spki = kp.getPublic().getEncoded();
            final byte[] pkcs8 = kp.getPrivate().getEncoded();

            /* algorithm name is not consulted, only format + encoding */
            PublicKey fpub = new PublicKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "1.3.101.112"; }
                public String getFormat() { return "X.509"; }
                public byte[] getEncoded() { return spki.clone(); }
            };
            PrivateKey fpriv = new PrivateKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "Ed448"; }
                public String getFormat() { return "PKCS#8"; }
                public byte[] getEncoded() { return pkcs8.clone(); }
            };
            assertTrue(verify(curve, fpub, msg, sig, null));
            assertArrayEquals(sig, sign(curve, fpriv, msg, null));

            /* unknown format is rejected */
            PublicKey raw = new PublicKey() {
                private static final long serialVersionUID = 1L;
                public String getAlgorithm() { return "EdDSA"; }
                public String getFormat() { return "RAW"; }
                public byte[] getEncoded() { return spki.clone(); }
            };
            try {
                verify(curve, raw, msg, sig, null);
                fail("RAW format key should be rejected");
            } catch (InvalidKeyException e) {
                /* expected */
            }

            /* a non-EdDSA key is rejected */
            KeyPair rsa = KeyPairGenerator.getInstance("RSA")
                .generateKeyPair();
            try {
                verify(curve, rsa.getPublic(), msg, sig, null);
                fail("RSA key should be rejected");
            } catch (InvalidKeyException e) {
                /* expected */
            }
            try {
                sign(curve, rsa.getPrivate(), msg, null);
                fail("RSA key should be rejected");
            } catch (InvalidKeyException e) {
                /* expected */
            }
        }
    }

    @Test
    public void reinitReleasesPreviousKey() throws Exception {

        assumeAnyEnabled();

        String curve = curves().get(0);
        KeyPair a = generate(curve);
        KeyPair b = generate(curve);
        byte[] msg = "reinit".getBytes();

        Signature s = Signature.getInstance(curve, "wolfJCE");
        s.initSign(a.getPrivate());
        s.update("stale".getBytes());
        s.initSign(b.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        assertTrue(verify(curve, b.getPublic(), msg, sig, null));
        assertFalse(verify(curve, a.getPublic(), msg, sig, null));

        /* many re-inits, leak detection is the sanitizer jobs */
        for (int i = 0; i < 500; i++) {
            s.initSign(a.getPrivate());
            s.initVerify(b.getPublic());
        }
    }

    @Test
    public void failedReinitLeavesNoKey() throws Exception {

        assumeAnyEnabled();

        String curve = curves().get(0);
        KeyPair kp = generate(curve);
        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        byte[] msg = "reinit".getBytes();
        Signature s = Signature.getInstance(curve, "wolfJCE");

        s.initVerify(kp.getPublic());
        try {
            s.initVerify(rsa.getPublic());
            fail("RSA key should be rejected");
        } catch (InvalidKeyException e) {
            /* expected */
        }
        /* the earlier key must not survive the failed init */
        try {
            s.update(msg);
            fail("update after a failed init should fail");
        } catch (SignatureException e) {
            /* expected */
        }

        s.initSign(kp.getPrivate());
        try {
            s.initSign(rsa.getPrivate());
            fail("RSA key should be rejected");
        } catch (InvalidKeyException e) {
            /* expected */
        }
        try {
            s.update(msg);
            fail("update after a failed init should fail");
        } catch (SignatureException e) {
            /* expected */
        }

        /* a good init works again */
        s.initSign(kp.getPrivate());
        s.update(msg);
        assertTrue(verify(curve, kp.getPublic(), msg, s.sign(), null));
    }

    @Test
    public void threadedSignVerify() throws Exception {

        assumeAnyEnabled();

        for (final String curve : curves()) {
            final KeyPair kp = generate(curve);
            final byte[] shared = "shared".getBytes();
            final byte[] sharedSig = sign(curve, kp.getPrivate(), shared, null);
            final int numThreads = 8;
            final int iterations = 20;
            final ExecutorService service =
                Executors.newFixedThreadPool(numThreads);
            final CountDownLatch latch = new CountDownLatch(numThreads);
            final AtomicInteger failures = new AtomicInteger(0);
            final AtomicReference<Throwable> firstError =
                new AtomicReference<Throwable>();

            for (int t = 0; t < numThreads; t++) {
                final int id = t;
                service.execute(new Runnable() {
                    public void run() {
                        try {
                            for (int i = 0; i < iterations; i++) {
                                byte[] msg = ("t" + id + " " + i).getBytes();
                                byte[] sig = sign(curve, kp.getPrivate(),
                                    msg, null);
                                if (!verify(curve, kp.getPublic(), msg, sig,
                                        null) ||
                                    !verify(curve, kp.getPublic(), shared,
                                        sharedSig, null)) {
                                    failures.incrementAndGet();
                                }
                            }
                        } catch (Throwable e) {
                            firstError.compareAndSet(null, e);
                            failures.incrementAndGet();
                        } finally {
                            latch.countDown();
                        }
                    }
                });
            }

            try {
                assertTrue("threads timed out",
                    latch.await(60, TimeUnit.SECONDS));
                assertEquals(curve + " first error: " + firstError.get(), 0,
                    failures.get());
            }
            finally {
                service.shutdownNow();
            }
        }
    }
}
