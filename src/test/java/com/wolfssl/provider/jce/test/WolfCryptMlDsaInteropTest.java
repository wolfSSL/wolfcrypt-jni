/* WolfCryptMlDsaInteropTest.java
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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Cross-provider interop tests between wolfJCE and SunJCE for ML-DSA.
 *
 * <p>SunJCE shipped ML-DSA in JDK 24 (JEP 497) under provider name
 * {@code "SUN"}. These tests skip cleanly via {@code Assume} on JDKs
 * that don't have it.</p>
 */
public class WolfCryptMlDsaInteropTest {

    private static final String SUN_PROVIDER = "SUN";
    private static final String[] LEVEL_NAMES = {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    };

    private static boolean mlDsaEnabled = false;
    private static boolean sunMlDsaAvailable = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptMlDsaInteropTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        try {
            new MlDsa(MlDsa.ML_DSA_44);
            mlDsaEnabled = true;
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("ML-DSA test skipped: NOT_COMPILED_IN");
                return;
            }
            throw e;
        }

        /* Probe one alias to decide whether to run interop tests. ML-DSA
         * was added to SunJCE in JDK 24 (JEP 497). Reason for skip is
         * surfaced via Assume in assumeEnabled(). */
        try {
            Signature.getInstance("ML-DSA-65", SUN_PROVIDER);
            KeyPairGenerator.getInstance("ML-DSA-65", SUN_PROVIDER);
            KeyFactory.getInstance("ML-DSA", SUN_PROVIDER);
            sunMlDsaAvailable = true;
        } catch (NoSuchAlgorithmException e) {
            /* Sun ML-DSA not available (pre-JDK 24), skip tests */
        } catch (NoSuchProviderException e) {
            /* "SUN" provider missing entirely, skip tests */
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("ML-DSA not compiled in", mlDsaEnabled);
        Assume.assumeTrue("SunJCE ML-DSA not available (need JDK 24+)",
            sunMlDsaAvailable);
    }

    /* wolf KPG, wolfJCE sign, Sun verify */
    @Test
    public void wolfKeyGen_wolfSign_sunVerify() throws Exception {

        assumeEnabled();

        byte[] msg = "wolf-keygen wolf-sign sun-verify".getBytes();

        for (String name : LEVEL_NAMES) {
            KeyPair kp = KeyPairGenerator.getInstance(name, "wolfJCE")
                .generateKeyPair();

            Signature ws = Signature.getInstance(name, "wolfJCE");
            ws.initSign(kp.getPrivate());
            ws.update(msg);
            byte[] sig = ws.sign();

            /* Sun KeyFactory imports our SPKI, then Sun Signature verifies */
            KeyFactory sunKf = KeyFactory.getInstance("ML-DSA", SUN_PROVIDER);
            PublicKey sunPub = sunKf.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));

            Signature sv = Signature.getInstance(name, SUN_PROVIDER);
            sv.initVerify(sunPub);
            sv.update(msg);
            assertTrue("wolf->sun verify, " + name, sv.verify(sig));
        }
    }

    /* Sun KPG, Sun sign, wolfJCE verify */
    @Test
    public void sunKeyGen_sunSign_wolfVerify() throws Exception {

        assumeEnabled();

        byte[] msg = "sun-keygen sun-sign wolf-verify".getBytes();

        for (String name : LEVEL_NAMES) {
            KeyPair kp = KeyPairGenerator.getInstance(name, SUN_PROVIDER)
                .generateKeyPair();

            Signature ss = Signature.getInstance(name, SUN_PROVIDER);
            ss.initSign(kp.getPrivate());
            ss.update(msg);
            byte[] sig = ss.sign();

            /* wolfJCE KeyFactory imports Sun SPKI, wolfJCE Signature verify */
            KeyFactory wkf = KeyFactory.getInstance("ML-DSA", "wolfJCE");
            PublicKey wPub = wkf.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));

            Signature wv = Signature.getInstance(name, "wolfJCE");
            wv.initVerify(wPub);
            wv.update(msg);
            assertTrue("sun->wolf verify, " + name, wv.verify(sig));
        }
    }

    /* Sun PKCS#8, wolfJCE import + sign, Sun verify */
    @Test
    public void sunPkcs8_wolfSign_sunVerify() throws Exception {

        assumeEnabled();

        byte[] msg = "sun-pkcs8 wolf-sign sun-verify".getBytes();

        for (String name : LEVEL_NAMES) {
            KeyPair sunKp = KeyPairGenerator.getInstance(name, SUN_PROVIDER)
                .generateKeyPair();

            KeyFactory wkf = KeyFactory.getInstance("ML-DSA", "wolfJCE");
            PrivateKey wPriv = wkf.generatePrivate(
                new PKCS8EncodedKeySpec(sunKp.getPrivate().getEncoded()));

            Signature ws = Signature.getInstance(name, "wolfJCE");
            ws.initSign(wPriv);
            ws.update(msg);
            byte[] sig = ws.sign();

            Signature sv = Signature.getInstance(name, SUN_PROVIDER);
            sv.initVerify(sunKp.getPublic());
            sv.update(msg);
            assertTrue("sun-pkcs8->wolf-sign->sun-verify, " + name,
                sv.verify(sig));
        }
    }

    /**
     * Skip the current test only when the exception chain matches the known
     * native wolfSSL PKCS#8 bug: version=0 with bundled publicKey field,
     * which Sun's parser rejects with "publicKey seen in v1" (RFC 5958
     * requires version=1 when publicKey is present).
     *
     * Any other Sun rejection of wolfJCE's encoding propagates as a real test
     * failure so future encoding regressions (wrong OID, bad nesting, etc)
     * are not silently masked. Once fixed native wolfSSL is used, the
     * known-bug message no longer occurs and these tests run fully.
     */
    private static void assumeKnownPkcs8V1Bug(String context, Exception e)
        throws Exception {

        for (Throwable t = e; t != null; t = t.getCause()) {
            String m = t.getMessage();
            if (m != null && m.contains("publicKey seen in v1")) {
                Assume.assumeNoException(context, e);
                return;
            }
        }
        throw e;
    }

    /* wolfJCE PKCS#8, Sun import + sign, wolfJCE verify
     *
     * Older native wolfSSL versions create PKCS#8 with version=0 but bundle
     * the publicKey field, which Sun's parser rejects with "publicKey seen in
     * v1" (RFC 5958 requires version=1 when publicKey is present). Native
     * wolfSSL was fixed to set version=1 on the bundled form output. The
     * assumeKnownPkcs8V1Bug() below keeps `ant test` passing against older
     * native wolfSSL versions that still have the bug. On fixed native wolfSSL
     * this test runs and must pass. */
    @Test
    public void wolfPkcs8_sunSign_wolfVerify() throws Exception {

        assumeEnabled();

        byte[] msg = "wolf-pkcs8 sun-sign wolf-verify".getBytes();

        for (String name : LEVEL_NAMES) {
            KeyPair wKp = KeyPairGenerator.getInstance(name, "wolfJCE")
                .generateKeyPair();

            KeyFactory skf = KeyFactory.getInstance("ML-DSA", SUN_PROVIDER);
            PrivateKey sPriv;
            try {
                sPriv = skf.generatePrivate(
                    new PKCS8EncodedKeySpec(wKp.getPrivate().getEncoded()));
            }
            catch (java.security.spec.InvalidKeySpecException e) {
                assumeKnownPkcs8V1Bug(
                    "wolfJCE PKCS#8 v1+publicKey not yet accepted by Sun", e);
                return;
            }

            Signature ss = Signature.getInstance(name, SUN_PROVIDER);
            ss.initSign(sPriv);
            ss.update(msg);
            byte[] sig = ss.sign();

            Signature wv = Signature.getInstance(name, "wolfJCE");
            wv.initVerify(wKp.getPublic());
            wv.update(msg);
            assertTrue("wolf-pkcs8->sun-sign->wolf-verify, " + name,
                wv.verify(sig));
        }
    }

    /* wolfJCE generated PublicKey passed directly to Sun Signature */
    @Test
    public void wolfPubKey_directlyUsableInSunSignature() throws Exception {

        assumeEnabled();

        byte[] msg = "direct wolf->sun pub".getBytes();

        KeyPair wKp = KeyPairGenerator.getInstance("ML-DSA-65", "wolfJCE")
            .generateKeyPair();

        Signature ws = Signature.getInstance("ML-DSA-65", "wolfJCE");
        ws.initSign(wKp.getPrivate());
        ws.update(msg);
        byte[] sig = ws.sign();

        try {
            Signature sv = Signature.getInstance("ML-DSA-65", SUN_PROVIDER);
            sv.initVerify(wKp.getPublic());
            sv.update(msg);
            assertTrue(sv.verify(sig));

        } catch (java.security.InvalidKeyException e) {
            Assume.assumeNoException(
                "Sun does not accept foreign PublicKey directly", e);
        }
    }

    /* Cross-provider encoded-form interop:
     *  - SPKI is canonical, byte-identical between wolfJCE and Sun.
     *  - PKCS#8 is not required to be byte-identical: wolfJCE creates the
     *    OneAsymmetricKey (RFC 5958, v2) form with the bundled publicKey
     *    field, while Sun re-encodes to a shorter seed-only form. Both are
     *    valid PKCS#8 encodings of the same key. We verify functional
     *    equivalence by signing with the round-tripped key and verifying
     *    under the original public.
     *
     *  PKCS#8 leg falls back to Assume.assumeNoException on older native
     *  wolfSSL builds that create v1+publicKey (rejected by Sun's parser). */
    @Test
    public void encodedFormsAgreeRoundTrip() throws Exception {

        assumeEnabled();

        for (String name : LEVEL_NAMES) {
            KeyPair wKp = KeyPairGenerator.getInstance(name, "wolfJCE")
                .generateKeyPair();
            byte[] wSpki  = wKp.getPublic().getEncoded();
            byte[] wPkcs8 = wKp.getPrivate().getEncoded();

            KeyFactory skf = KeyFactory.getInstance("ML-DSA", SUN_PROVIDER);

            /* SPKI leg: byte-identical. */
            PublicKey sPub = skf.generatePublic(new X509EncodedKeySpec(wSpki));
            assertArrayEquals("SPKI preserved through Sun, " + name,
                wSpki, sPub.getEncoded());

            /* PKCS#8 leg: functional equivalence (not byte-identical). */
            PrivateKey sPriv;
            try {
                sPriv = skf.generatePrivate(new PKCS8EncodedKeySpec(wPkcs8));
            }
            catch (java.security.spec.InvalidKeySpecException e) {
                assumeKnownPkcs8V1Bug(
                    "wolfJCE PKCS#8 v1+publicKey not yet accepted by Sun, " +
                    "older native wolfSSL detected", e);
                return;
            }

            byte[] msg = ("functional eq " + name).getBytes();
            Signature ss = Signature.getInstance(name, SUN_PROVIDER);
            ss.initSign(sPriv);
            ss.update(msg);
            byte[] sig = ss.sign();

            Signature wv = Signature.getInstance(name, "wolfJCE");
            wv.initVerify(wKp.getPublic());
            wv.update(msg);
            assertTrue("PKCS#8 round-tripped key signs validly, " + name,
                wv.verify(sig));
        }
    }
}
