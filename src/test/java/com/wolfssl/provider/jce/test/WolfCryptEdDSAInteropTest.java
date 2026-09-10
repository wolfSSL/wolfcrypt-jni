/* WolfCryptEdDSAInteropTest.java
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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.wolfssl.provider.jce.WolfCryptEdDSAParameterSpec;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.wolfcrypt.test.Util;

/**
 * EdDSA interop tests between wolfJCE and SunEC (JDK 15+) or Conscrypt /
 * AndroidOpenSSL (Ed25519 only). Peers are optional, tests skip when one
 * is absent.
 *
 * Keys cross over two ways: through the peer's KeyFactory from the X.509 /
 * PKCS#8 encoding (every peer), and as the other provider's key object
 * directly (SunEC, needs the JDK 15+ overlay). The Conscrypt case runs only
 * where that provider is installed, CI has none.
 */
public class WolfCryptEdDSAInteropTest {

    private static boolean ed25519Enabled = false;
    private static boolean ed448Enabled = false;

    private static boolean sunAvailable = false;
    private static String conscryptName = null;

    /* JDK 15+ EdEC key interface, null when absent */
    private static Class<?> edecPubIface = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptEdDSAInteropTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        assertNotNull(Security.getProvider("wolfJCE"));

        ed25519Enabled = FeatureDetect.Ed25519KeyGenEnabled();
        ed448Enabled = FeatureDetect.Ed448KeyGenEnabled();

        try {
            Signature.getInstance("Ed25519", "SunEC");
            KeyPairGenerator.getInstance("Ed448", "SunEC");
            KeyFactory.getInstance("EdDSA", "SunEC");
            sunAvailable = true;
        } catch (NoSuchAlgorithmException e) {
            /* SunEC without EdDSA (pre JDK 15) */
        } catch (java.security.NoSuchProviderException e) {
            /* no SunEC at all */
        }

        for (String n : new String[] { "Conscrypt", "AndroidOpenSSL" }) {
            if (Security.getProvider(n) != null) {
                try {
                    Signature.getInstance("Ed25519", n);
                    conscryptName = n;
                    break;
                } catch (Exception e) {
                    /* provider without Ed25519 */
                }
            }
        }

        try {
            edecPubIface =
                Class.forName("java.security.interfaces.EdECPublicKey");
        } catch (ClassNotFoundException e) {
            edecPubIface = null;
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

    private static byte[] sign(String alg, String prov, PrivateKey key,
        byte[] msg, AlgorithmParameterSpec spec) throws Exception {

        Signature s = Signature.getInstance(alg, prov);
        if (spec != null) {
            s.setParameter(spec);
        }
        s.initSign(key);
        s.update(msg);

        return s.sign();
    }

    private static boolean verify(String alg, String prov, PublicKey key,
        byte[] msg, byte[] sig, AlgorithmParameterSpec spec)
        throws Exception {

        Signature s = Signature.getInstance(alg, prov);
        if (spec != null) {
            s.setParameter(spec);
        }
        s.initVerify(key);
        s.update(msg);

        return s.verify(sig);
    }

    private static PublicKey toPeerPublic(String alg, String prov,
        PublicKey k) throws Exception {

        return KeyFactory.getInstance(alg, prov).generatePublic(
            new X509EncodedKeySpec(k.getEncoded()));
    }

    private static PrivateKey toPeerPrivate(String alg, String prov,
        PrivateKey k) throws Exception {

        return KeyFactory.getInstance(alg, prov).generatePrivate(
            new PKCS8EncodedKeySpec(k.getEncoded()));
    }

    /* Build a JDK 15+ EdDSAParameterSpec via reflection (Java 8 compile) */
    private static AlgorithmParameterSpec jdkSpec(boolean prehash,
        byte[] ctx) throws Exception {

        Class<?> cls = Class.forName("java.security.spec.EdDSAParameterSpec");
        if (ctx == null) {
            Constructor<?> c = cls.getConstructor(boolean.class);
            return (AlgorithmParameterSpec) c.newInstance(prehash);
        }
        Constructor<?> c = cls.getConstructor(boolean.class, byte[].class);
        return (AlgorithmParameterSpec) c.newInstance(prehash, ctx);
    }

    /**
     * Sign, verify and encoding checks in both directions against one
     * peer, using the encoded-key path every peer supports.
     */
    private void encodedInterop(String peer, String curve) throws Exception {

        byte[] msg = ("wolfJCE <-> " + peer + " " + curve).getBytes();

        /* 1. wolf keygen, wolf sign, peer verify */
        KeyPair wkp = KeyPairGenerator.getInstance(curve, "wolfJCE")
            .generateKeyPair();
        byte[] wsig = sign(curve, "wolfJCE", wkp.getPrivate(), msg, null);
        PublicKey peerPub = toPeerPublic(curve, peer, wkp.getPublic());
        assertTrue(peer + " must verify wolfJCE " + curve + " signature",
            verify(curve, peer, peerPub, msg, wsig, null));
        byte[] bad = msg.clone();
        bad[0] ^= 1;
        assertFalse(verify(curve, peer, peerPub, bad, wsig, null));

        /* 2. peer keygen, peer sign, wolf verify (peer key object, and via
         * wolf KeyFactory) */
        KeyPair pkp = KeyPairGenerator.getInstance(curve, peer)
            .generateKeyPair();
        byte[] psig = sign(curve, peer, pkp.getPrivate(), msg, null);
        assertTrue("wolfJCE must verify " + peer + " " + curve +
            " signature (direct key)",
            verify(curve, "wolfJCE", pkp.getPublic(), msg, psig, null));
        PublicKey wpub = toPeerPublic(curve, "wolfJCE", pkp.getPublic());
        assertTrue(verify(curve, "wolfJCE", wpub, msg, psig, null));
        assertTrue(verify("EdDSA", "wolfJCE", wpub, msg, psig, null));

        /* 3. wolf signs with the peer's private key (public key derived from
         * its PKCS#8), peer verifies. EdDSA is deterministic so the signatures
         * match byte for byte */
        byte[] wsig2 = sign(curve, "wolfJCE", pkp.getPrivate(), msg, null);
        assertArrayEquals(psig, wsig2);
        assertTrue(verify(curve, peer, pkp.getPublic(), msg, wsig2, null));
        PrivateKey wpriv = toPeerPrivate(curve, "wolfJCE", pkp.getPrivate());
        assertArrayEquals(psig, sign(curve, "wolfJCE", wpriv, msg, null));

        /* 4. SPKI encodings match; wolf re-encodes the peer's PKCS#8 as v1,
         * which the peer must decode again */
        assertArrayEquals(pkp.getPublic().getEncoded(), wpub.getEncoded());
        assertArrayEquals(wkp.getPublic().getEncoded(),
            peerPub.getEncoded());
        PrivateKey back = toPeerPrivate(curve, peer, wpriv);
        assertArrayEquals(psig, sign(curve, peer, back, msg, null));
    }

    private void assumeSun() {
        Assume.assumeTrue("No EdDSA curve compiled in",
            ed25519Enabled || ed448Enabled);
        Assume.assumeTrue("SunEC EdDSA not available (need JDK 15+)",
            sunAvailable);
    }

    @Test
    public void sunEncodedInterop() throws Exception {

        assumeSun();

        for (String curve : curves()) {
            encodedInterop("SunEC", curve);
        }
    }

    @Test
    public void sunPkcs8AndSpkiAreByteIdentical() throws Exception {

        assumeSun();

        for (String curve : curves()) {
            KeyPair skp = KeyPairGenerator.getInstance(curve, "SunEC")
                .generateKeyPair();
            PrivateKey wpriv = toPeerPrivate(curve, "wolfJCE",
                skp.getPrivate());
            PublicKey wpub = toPeerPublic(curve, "wolfJCE", skp.getPublic());
            assertArrayEquals(skp.getPrivate().getEncoded(),
                wpriv.getEncoded());
            assertArrayEquals(skp.getPublic().getEncoded(), wpub.getEncoded());

            KeyPair wkp = KeyPairGenerator.getInstance(curve, "wolfJCE")
                .generateKeyPair();
            assertArrayEquals(wkp.getPrivate().getEncoded(),
                toPeerPrivate(curve, "SunEC", wkp.getPrivate()).getEncoded());
            assertArrayEquals(wkp.getPublic().getEncoded(),
                toPeerPublic(curve, "SunEC", wkp.getPublic()).getEncoded());
        }
    }

    @Test
    public void sunParameterParity() throws Exception {

        assumeSun();

        byte[] msg = "EdDSAParameterSpec parity".getBytes();
        byte[] foo = "foo".getBytes();
        byte[] max = new byte[WolfCryptEdDSAParameterSpec.MAX_CONTEXT_LEN];
        Arrays.fill(max, (byte) 0x5a);

        Object[][] combos = {
            { Boolean.FALSE, null },
            { Boolean.TRUE, null },
            { Boolean.FALSE, foo },
            { Boolean.TRUE, foo },
            { Boolean.FALSE, new byte[0] },
            { Boolean.TRUE, new byte[0] },
            { Boolean.FALSE, max },
            { Boolean.TRUE, max }
        };

        for (String curve : curves()) {
            KeyPair skp = KeyPairGenerator.getInstance(curve, "SunEC")
                .generateKeyPair();
            PrivateKey wpriv = toPeerPrivate(curve, "wolfJCE",
                skp.getPrivate());
            PublicKey wpub = toPeerPublic(curve, "wolfJCE", skp.getPublic());

            for (Object[] combo : combos) {
                boolean prehash = (Boolean) combo[0];
                byte[] ctx = (byte[]) combo[1];
                AlgorithmParameterSpec jdk = jdkSpec(prehash, ctx);
                AlgorithmParameterSpec wolf =
                    new WolfCryptEdDSAParameterSpec(prehash, ctx);
                String label = curve + " prehash=" + prehash + " ctx=" +
                    (ctx == null ? "absent" : ctx.length);

                byte[] ssig = sign(curve, "SunEC", skp.getPrivate(), msg,
                    jdk);
                /* wolfJCE matches SunEC with either spec object */
                assertArrayEquals(label, ssig,
                    sign(curve, "wolfJCE", wpriv, msg, jdk));
                assertArrayEquals(label, ssig,
                    sign(curve, "wolfJCE", wpriv, msg, wolf));
                assertArrayEquals(label, ssig,
                    sign(curve, "wolfJCE", skp.getPrivate(), msg, wolf));
                /* each side verifies the other */
                assertTrue(label, verify(curve, "wolfJCE", wpub, msg, ssig,
                    wolf));
                assertTrue(label, verify(curve, "wolfJCE",
                    skp.getPublic(), msg, ssig, jdk));
                assertTrue(label, verify(curve, "SunEC", skp.getPublic(),
                    msg, sign(curve, "wolfJCE", wpriv, msg, wolf), jdk));
            }
        }

        /* a 256 byte context is rejected by both spec classes */
        try {
            new WolfCryptEdDSAParameterSpec(false, new byte[256]);
            fail("wolfJCE spec accepted a 256 byte context");
        } catch (IllegalArgumentException e) {
            /* expected */
        }
        try {
            jdkSpec(false, new byte[256]);
            fail("JDK spec accepted a 256 byte context");
        } catch (InvocationTargetException e) {
            assertTrue(e.getCause() instanceof IllegalArgumentException);
        }
    }

    @Test
    public void sunKeyFactoryTranslateAndEdECSpecs() throws Exception {

        assumeSun();

        for (String curve : curves()) {
            KeyFactory skf = KeyFactory.getInstance(curve, "SunEC");
            KeyFactory wkf = KeyFactory.getInstance(curve, "wolfJCE");
            KeyPair wkp = KeyPairGenerator.getInstance(curve, "wolfJCE")
                .generateKeyPair();
            KeyPair skp = KeyPairGenerator.getInstance(curve, "SunEC")
                .generateKeyPair();

            /* SunEC re-encodes wolfJCE keys through translateKey */
            Key tpub = skf.translateKey(wkp.getPublic());
            Key tpriv = skf.translateKey(wkp.getPrivate());
            assertArrayEquals(wkp.getPublic().getEncoded(), tpub.getEncoded());
            assertArrayEquals(wkp.getPrivate().getEncoded(),
                tpriv.getEncoded());

            /* wolfJCE translates SunEC keys */
            assertEquals(wkp.getPublic().getClass(),
                wkf.translateKey(skp.getPublic()).getClass());
            assertArrayEquals(skp.getPublic().getEncoded(),
                wkf.translateKey(skp.getPublic()).getEncoded());

            /* EdEC key specs work across both factories */
            Class<?> pubSpecCls = Class.forName(
                "java.security.spec.EdECPublicKeySpec");
            Class<?> privSpecCls = Class.forName(
                "java.security.spec.EdECPrivateKeySpec");
            KeySpec sunPubSpec = skf.getKeySpec(skp.getPublic(),
                pubSpecCls.asSubclass(KeySpec.class));
            KeySpec sunPrivSpec = skf.getKeySpec(skp.getPrivate(),
                privSpecCls.asSubclass(KeySpec.class));
            assertArrayEquals(skp.getPublic().getEncoded(),
                wkf.generatePublic(sunPubSpec).getEncoded());
            assertArrayEquals(skp.getPrivate().getEncoded(),
                wkf.generatePrivate(sunPrivSpec).getEncoded());

            KeySpec wolfPubSpec = wkf.getKeySpec(wkp.getPublic(),
                pubSpecCls.asSubclass(KeySpec.class));
            KeySpec wolfPrivSpec = wkf.getKeySpec(wkp.getPrivate(),
                privSpecCls.asSubclass(KeySpec.class));
            assertArrayEquals(wkp.getPublic().getEncoded(),
                skf.generatePublic(wolfPubSpec).getEncoded());
            assertArrayEquals(wkp.getPrivate().getEncoded(),
                skf.generatePrivate(wolfPrivSpec).getEncoded());
        }
    }

    @Test
    public void sunDirectKeyObjectsWithOverlay() throws Exception {

        assumeSun();
        Assume.assumeTrue("JDK 15+ EdEC interfaces not present",
            edecPubIface != null);
        Assume.assumeTrue("JDK 15 overlay not shipped in the loaded JAR",
            Util.multiReleaseEntryActive(WolfCryptProvider.class,
                "META-INF/versions/15/com/wolfssl/provider/jce/" +
                "WolfCryptEdDSAKeys.class"));

        byte[] msg = "direct key object".getBytes();

        for (String curve : curves()) {
            KeyPair wkp = KeyPairGenerator.getInstance(curve, "wolfJCE")
                .generateKeyPair();
            assertTrue("overlay must make wolfJCE keys EdECPublicKey",
                edecPubIface.isInstance(wkp.getPublic()));

            /* SunEC accepts the wolfJCE key objects directly */
            byte[] wsig = sign(curve, "wolfJCE", wkp.getPrivate(), msg, null);
            assertTrue(verify(curve, "SunEC", wkp.getPublic(), msg, wsig,
                null));
            byte[] ssig = sign(curve, "SunEC", wkp.getPrivate(), msg, null);
            assertArrayEquals(wsig, ssig);
            assertTrue(verify("EdDSA", "SunEC", wkp.getPublic(), msg, ssig,
                null));

            /* SunEC getKeySpec also accepts wolfJCE keys */
            KeyFactory skf = KeyFactory.getInstance(curve, "SunEC");
            assertArrayEquals(wkp.getPublic().getEncoded(),
                skf.getKeySpec(wkp.getPublic(), X509EncodedKeySpec.class)
                    .getEncoded());
        }
    }

    @Test
    public void unpinnedLookupFallsBackToWolfJce() throws Exception {

        assumeSun();

        final boolean overlay = Util.multiReleaseEntryActive(
            WolfCryptProvider.class,
            "META-INF/versions/15/com/wolfssl/provider/jce/" +
            "WolfCryptEdDSAKeys.class");

        for (String curve : curves()) {
            KeyPair wkp = KeyPairGenerator.getInstance(curve, "wolfJCE")
                .generateKeyPair();
            byte[] msg = "unpinned".getBytes();

            /* wolfJCE is at position 1, so it is chosen directly */
            Signature s = Signature.getInstance(curve);
            s.initSign(wkp.getPrivate());
            assertEquals("wolfJCE", s.getProvider().getName());
            s.update(msg);
            byte[] sig = s.sign();

            /* with wolfJCE last, the JCA picks the first provider that accepts
             * the key: SunEC with the overlay, otherwise wolfJCE */
            Provider wolf = Security.getProvider("wolfJCE");
            try {
                Security.removeProvider("wolfJCE");
                Security.addProvider(wolf);
                Signature v = Signature.getInstance(curve);
                v.initVerify(wkp.getPublic());
                assertEquals(overlay ? "SunEC" : "wolfJCE",
                    v.getProvider().getName());
                v.update(msg);
                assertTrue(v.verify(sig));
            }
            finally {
                Security.removeProvider("wolfJCE");
                Security.insertProviderAt(wolf, 1);
            }
            assertEquals("wolfJCE", Security.getProviders()[0].getName());
        }
    }

    @Test
    public void sunKeyPairGeneratorParity() throws Exception {

        assumeSun();

        for (String curve : curves()) {
            int bits = curve.equals("Ed25519") ? 255 : 448;
            /* the umbrella EdDSA generator is registered only with Ed25519 */
            KeyPairGenerator wg = KeyPairGenerator.getInstance(
                ed25519Enabled ? "EdDSA" : curve, "wolfJCE");
            KeyPairGenerator sg = KeyPairGenerator.getInstance("EdDSA",
                "SunEC");
            wg.initialize(bits);
            sg.initialize(bits);
            KeyPair wkp = wg.generateKeyPair();
            KeyPair skp = sg.generateKeyPair();
            byte[] msg = "kpg parity".getBytes();

            assertEquals(skp.getPublic().getEncoded().length,
                wkp.getPublic().getEncoded().length);
            assertTrue(verify(curve, "SunEC",
                toPeerPublic(curve, "SunEC", wkp.getPublic()), msg,
                sign(curve, "wolfJCE", wkp.getPrivate(), msg, null), null));
            assertTrue(verify(curve, "wolfJCE", skp.getPublic(), msg,
                sign(curve, "SunEC", skp.getPrivate(), msg, null), null));
        }
    }

    @Test
    public void conscryptEncodedInterop() throws Exception {

        Assume.assumeTrue("Ed25519 not compiled in", ed25519Enabled);
        Assume.assumeTrue("Conscrypt provider with Ed25519 not available",
            conscryptName != null);

        /* Conscrypt registers "EdDSA" with "Ed25519" as an alias and accepts
         * foreign keys through their encoding */
        encodedInterop(conscryptName, "Ed25519");

        KeyPair ckp = KeyPairGenerator.getInstance("Ed25519", conscryptName)
            .generateKeyPair();
        byte[] msg = "conscrypt".getBytes();
        byte[] csig = sign("EdDSA", conscryptName, ckp.getPrivate(), msg,
            null);
        assertTrue(verify("Ed25519", "wolfJCE", ckp.getPublic(), msg, csig,
            null));
        KeyPair wkp = KeyPairGenerator.getInstance("Ed25519", "wolfJCE")
            .generateKeyPair();
        try {
            assertTrue(verify("EdDSA", conscryptName, wkp.getPublic(), msg,
                sign("Ed25519", "wolfJCE", wkp.getPrivate(), msg, null),
                null));
        } catch (InvalidKeyException e) {
            fail("Conscrypt should accept wolfJCE keys via getEncoded()");
        }
    }
}
