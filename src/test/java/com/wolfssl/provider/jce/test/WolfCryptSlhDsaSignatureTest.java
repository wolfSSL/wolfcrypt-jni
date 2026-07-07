/* WolfCryptSlhDsaSignatureTest.java
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
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.util.Arrays;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.InvalidKeyException;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptContextParameterSpec;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * wolfJCE tests for the SLH-DSA Signature service.
 */
public class WolfCryptSlhDsaSignatureTest {

    private static final String[] PARAM_NAMES = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    };

    /* Fast-signing sets for end-to-end round trips. */
    private static final String[] FAST_NAMES = {
        "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f"
    };

    /* HashSLH-DSA per-set service names, in the same order as their
     * FIPS 205 OID aliases 2.16.840.1.101.3.4.3.35 - .46. */
    private static final String[] PREHASH_NAMES = {
        "SLH-DSA-SHA2-128s-WITH-SHA256",
        "SLH-DSA-SHA2-128f-WITH-SHA256",
        "SLH-DSA-SHA2-192s-WITH-SHA512",
        "SLH-DSA-SHA2-192f-WITH-SHA512",
        "SLH-DSA-SHA2-256s-WITH-SHA512",
        "SLH-DSA-SHA2-256f-WITH-SHA512",
        "SLH-DSA-SHAKE-128s-WITH-SHAKE128",
        "SLH-DSA-SHAKE-128f-WITH-SHAKE128",
        "SLH-DSA-SHAKE-192s-WITH-SHAKE256",
        "SLH-DSA-SHAKE-192f-WITH-SHAKE256",
        "SLH-DSA-SHAKE-256s-WITH-SHAKE256",
        "SLH-DSA-SHAKE-256f-WITH-SHAKE256"
    };

    private static final byte[] MSG = "SLH-DSA JCE message".getBytes();

    private static boolean slhDsaEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() {
        System.out.println("JCE WolfCryptSlhDsaSignatureTest Class");

        Security.insertProviderAt(new WolfCryptProvider(), 1);
        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        slhDsaEnabled = FeatureDetect.SlhDsaEnabled();
        if (!slhDsaEnabled) {
            System.out.println("SLH-DSA test skipped: NOT_COMPILED_IN");
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("SLH-DSA not compiled in", slhDsaEnabled);
    }

    private static boolean available(String name) {
        try {
            KeyPairGenerator.getInstance(name, "wolfJCE").generateKeyPair();
            return true;

        } catch (Exception e) {
            return false;
        }
    }

    private static KeyPair genKey(String name) throws Exception {
        return KeyPairGenerator.getInstance(name, "wolfJCE").generateKeyPair();
    }

    @Test
    public void getInstanceForAllNames() throws Exception {
        assumeEnabled();

        Signature.getInstance("SLH-DSA", "wolfJCE");

        for (String n : PARAM_NAMES) {
            Signature.getInstance(n, "wolfJCE");
        }

        for (int i = 0; i < 12; i++) {
            Signature.getInstance(
                "2.16.840.1.101.3.4.3." + (20 + i), "wolfJCE");
        }
    }

    @Test
    public void signVerifyUmbrella() throws Exception {
        assumeEnabled();

        for (String n : FAST_NAMES) {
            if (!available(n)) {
                continue;
            }

            KeyPair kp = genKey(n);

            /* Umbrella "SLH-DSA" Signature works with any parameter-set key. */
            Signature signer = Signature.getInstance("SLH-DSA", "wolfJCE");
            signer.initSign(kp.getPrivate());
            signer.update(MSG);
            byte[] sig = signer.sign();
            assertNotNull(sig);

            Signature verifier = Signature.getInstance("SLH-DSA", "wolfJCE");
            verifier.initVerify(kp.getPublic());
            verifier.update(MSG);
            assertTrue("verify, " + n, verifier.verify(sig));

            /* Tampered message must fail. */
            Signature v2 = Signature.getInstance("SLH-DSA", "wolfJCE");
            v2.initVerify(kp.getPublic());
            byte[] bad = MSG.clone();
            bad[0] ^= 0x01;
            v2.update(bad);
            assertFalse("tampered, " + n, v2.verify(sig));
        }
    }

    @Test
    public void signVerifyPerSetName() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHAKE-128f"));

        KeyPair kp = genKey("SLH-DSA-SHAKE-128f");

        Signature signer =
            Signature.getInstance("SLH-DSA-SHAKE-128f", "wolfJCE");
        signer.initSign(kp.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        Signature verifier =
            Signature.getInstance("SLH-DSA-SHAKE-128f", "wolfJCE");
        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);
        assertTrue(verifier.verify(sig));
    }

    @Test
    public void perSetSignatureRejectsMismatchedKey() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHAKE-128f"));
        Assume.assumeTrue(available("SLH-DSA-SHA2-128f"));

        KeyPair shake = genKey("SLH-DSA-SHAKE-128f");

        /* A SHA2-128f-named Signature must reject a SHAKE-128f key. */
        Signature signer =
            Signature.getInstance("SLH-DSA-SHA2-128f", "wolfJCE");

        try {
            signer.initSign(shake.getPrivate());
            fail("expected InvalidKeyException for parameter-set mismatch");
        } catch (InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void perSetPreHashSignatureRejectsMismatchedKey()
        throws Exception {

        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHAKE-128f"));
        Assume.assumeTrue(available("SLH-DSA-SHA2-128f"));

        KeyPair shake = genKey("SLH-DSA-SHAKE-128f");

        /* A SHA2-128f pre-hash-named Signature must reject a SHAKE-128f */
        Signature signer = Signature.getInstance(
            "SLH-DSA-SHA2-128f-WITH-SHA256", "wolfJCE");

        try {
            signer.initSign(shake.getPrivate());
            fail("expected InvalidKeyException for parameter-set mismatch");
        } catch (java.security.InvalidKeyException e) {
            /* expected */
        }
    }

    @Test
    public void contextStringRoundTrip() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHA2-128f"));

        KeyPair kp = genKey("SLH-DSA-SHA2-128f");
        byte[] ctx = "application-context".getBytes();

        Signature signer = Signature.getInstance("SLH-DSA", "wolfJCE");
        signer.setParameter(new WolfCryptContextParameterSpec(ctx));
        signer.initSign(kp.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        /* Verify with the same context succeeds. */
        Signature verifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        verifier.setParameter(new WolfCryptContextParameterSpec(ctx));
        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);
        assertTrue("same ctx verifies", verifier.verify(sig));

        /* Verify with empty context (default) must fail. */
        Signature v2 = Signature.getInstance("SLH-DSA", "wolfJCE");
        v2.initVerify(kp.getPublic());
        v2.update(MSG);
        assertFalse("empty ctx must not verify", v2.verify(sig));

        /* Verify with a different context must fail. */
        Signature v3 = Signature.getInstance("SLH-DSA", "wolfJCE");
        v3.setParameter(new WolfCryptContextParameterSpec("other".getBytes()));
        v3.initVerify(kp.getPublic());
        v3.update(MSG);
        assertFalse("different ctx must not verify", v3.verify(sig));
    }

    @Test
    public void contextPersistsAcrossInit() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHA2-128f"));

        KeyPair kp = genKey("SLH-DSA-SHA2-128f");
        byte[] ctx = "persistent-context".getBytes();

        /* Documented behavior: a context set via setParameter() persists
         * across init calls until replaced, matching how JCA providers
         * treat setParameter() state (for example PSS parameters in
         * SunRsaSign). */
        Signature signer = Signature.getInstance("SLH-DSA", "wolfJCE");
        signer.setParameter(new WolfCryptContextParameterSpec(ctx));
        signer.initSign(kp.getPrivate());
        signer.update(MSG);
        byte[] sig1 = signer.sign();

        /* Re-init the same instance, the context still applies. */
        signer.initSign(kp.getPrivate());
        signer.update(MSG);
        byte[] sig2 = signer.sign();

        Signature verifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        verifier.setParameter(new WolfCryptContextParameterSpec(ctx));
        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);
        assertTrue("first sig verifies with ctx", verifier.verify(sig1));
        verifier.update(MSG);
        assertTrue("sig after re-init verifies with ctx",
            verifier.verify(sig2));

        /* And must not verify against the empty-context default. */
        Signature v2 = Signature.getInstance("SLH-DSA", "wolfJCE");
        v2.initVerify(kp.getPublic());
        v2.update(MSG);
        assertFalse("sig after re-init must not verify with empty ctx",
            v2.verify(sig2));
    }

    @Test
    public void contextSpecRejectsTooLong() {
        assumeEnabled();

        byte[] tooLong = new byte[256];
        try {
            new WolfCryptContextParameterSpec(tooLong);
            fail("expected IllegalArgumentException for ctx > 255");

        } catch (IllegalArgumentException e) {
            /* expected */
        }
    }

    @Test
    public void crossKeyVerificationFails() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHA2-128f"));

        KeyPair kpA = genKey("SLH-DSA-SHA2-128f");
        KeyPair kpB = genKey("SLH-DSA-SHA2-128f");

        Signature signer = Signature.getInstance("SLH-DSA", "wolfJCE");
        signer.initSign(kpA.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("SLH-DSA", "wolfJCE");
        verifier.initVerify(kpB.getPublic());
        verifier.update(MSG);
        assertFalse("other key must not verify", verifier.verify(sig));
    }

    @Test
    public void hashSlhDsaGetInstance() throws Exception {
        assumeEnabled();

        Signature.getInstance("HASH-SLH-DSA", "wolfJCE");

        for (String n : PREHASH_NAMES) {
            Signature.getInstance(n, "wolfJCE");
        }

        /* OID aliases .35 - .46, same order as PREHASH_NAMES */
        for (int i = 0; i < PREHASH_NAMES.length; i++) {
            Signature.getInstance(
                "2.16.840.1.101.3.4.3." + (35 + i), "wolfJCE");
        }
    }

    @Test
    public void hashSlhDsaSignVerify() throws Exception {
        assumeEnabled();

        for (String n : new String[] { "SLH-DSA-SHA2-128f",
                                       "SLH-DSA-SHAKE-128f" }) {
            if (!available(n)) {
                continue;
            }
            KeyPair kp = genKey(n);

            /* Umbrella HASH-SLH-DSA works with any SLH-DSA key. */
            Signature signer = Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
            signer.initSign(kp.getPrivate());
            signer.update(MSG);
            byte[] sig = signer.sign();

            Signature verifier =
                Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
            verifier.initVerify(kp.getPublic());
            verifier.update(MSG);
            assertTrue("HASH-SLH-DSA verify, " + n, verifier.verify(sig));

            /* Tampered message must fail. */
            Signature v2 = Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
            v2.initVerify(kp.getPublic());
            byte[] bad = MSG.clone();
            bad[0] ^= 0x01;
            v2.update(bad);
            assertFalse("HASH-SLH-DSA tampered, " + n, v2.verify(sig));

            /* Pure SLH-DSA and HashSLH-DSA use different domain separation
             * (M' prefix 0x00 vs 0x01), so a pure signature must NOT verify
             * as pre-hash. */
            Signature pureSigner =
                Signature.getInstance("SLH-DSA", "wolfJCE");
            pureSigner.initSign(kp.getPrivate());
            pureSigner.update(MSG);
            byte[] pureSig = pureSigner.sign();
            Signature hv = Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
            hv.initVerify(kp.getPublic());
            hv.update(MSG);
            assertFalse("pure sig must not verify as pre-hash, " + n,
                hv.verify(pureSig));
        }
    }

    @Test
    public void hashSlhDsaPerSetSignVerify() throws Exception {
        assumeEnabled();

        /* Per-parameter-set pre-hash services, paired with the plain name
         * used to generate a key of that set. The fast 128f sets keep test
         * time bounded. */
        String[][] pairs = new String[][] {
            { "SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-128f-WITH-SHA256"    },
            { "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f-WITH-SHAKE128" }
        };

        for (String[] pair : pairs) {
            String keyName = pair[0];
            String sigName = pair[1];

            if (!available(keyName)) {
                continue;
            }
            KeyPair kp = genKey(keyName);

            Signature signer = Signature.getInstance(sigName, "wolfJCE");
            signer.initSign(kp.getPrivate());
            signer.update(MSG);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(sigName, "wolfJCE");
            verifier.initVerify(kp.getPublic());
            verifier.update(MSG);
            assertTrue(sigName + " verify", verifier.verify(sig));

            /* Tampered message must fail. */
            Signature v2 = Signature.getInstance(sigName, "wolfJCE");
            v2.initVerify(kp.getPublic());
            byte[] bad = MSG.clone();
            bad[0] ^= 0x01;
            v2.update(bad);
            assertFalse(sigName + " tampered", v2.verify(sig));

            /* The per-set service and the umbrella HASH-SLH-DSA use the
             * same FIPS 205 Section 10.2.2 pre-hash for a given key, so
             * signatures must interop between the two. */
            Signature hv = Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
            hv.initVerify(kp.getPublic());
            hv.update(MSG);
            assertTrue("umbrella verifies per-set sig, " + sigName,
                hv.verify(sig));
        }
    }

    @Test
    public void hashSlhDsaContextRoundTrip() throws Exception {
        assumeEnabled();
        Assume.assumeTrue(available("SLH-DSA-SHA2-128f"));

        KeyPair kp = genKey("SLH-DSA-SHA2-128f");
        byte[] ctx = "prehash-context".getBytes();

        /* Sign pre-hash with a non-empty FIPS 205 context. */
        Signature signer = Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
        signer.setParameter(new WolfCryptContextParameterSpec(ctx));
        signer.initSign(kp.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        /* Verify with the same context succeeds. */
        Signature verifier = Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
        verifier.setParameter(new WolfCryptContextParameterSpec(ctx));
        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);
        assertTrue("same ctx verifies pre-hash", verifier.verify(sig));

        /* Verify with the default empty context must fail. */
        Signature v2 = Signature.getInstance("HASH-SLH-DSA", "wolfJCE");
        v2.initVerify(kp.getPublic());
        v2.update(MSG);
        assertFalse("empty ctx must not verify pre-hash", v2.verify(sig));
    }

    @Test
    public void contextParameterSpecBehavior() {

        /* null context normalizes to an empty context */
        WolfCryptContextParameterSpec empty =
            new WolfCryptContextParameterSpec(null);
        assertNotNull(empty.getContext());
        assertEquals(0, empty.getContext().length);

        /* Constructor copies its input, later caller mutation of the
         * source array must not change the spec */
        byte[] src = "spec-context".getBytes();
        WolfCryptContextParameterSpec spec =
            new WolfCryptContextParameterSpec(src);
        src[0] ^= (byte)0xFF;
        assertFalse("ctor must copy input",
            Arrays.equals(src, spec.getContext()));

        /* getContext() returns a copy, mutating it must not change the
         * spec */
        byte[] out = spec.getContext();
        out[0] ^= (byte)0xFF;
        assertArrayEquals("getContext must return a copy",
            "spec-context".getBytes(), spec.getContext());

        /* equals/hashCode compare by content */
        WolfCryptContextParameterSpec same =
            new WolfCryptContextParameterSpec("spec-context".getBytes());
        WolfCryptContextParameterSpec other =
            new WolfCryptContextParameterSpec("different".getBytes());
        assertEquals(spec, same);
        assertEquals(spec.hashCode(), same.hashCode());
        assertFalse("different contexts must not be equal",
            spec.equals(other));
    }
}
