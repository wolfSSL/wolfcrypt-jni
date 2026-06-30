/* SlhDsaTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class SlhDsaTest {

    /* All 12 FIPS 205 parameter sets, matching native enum SlhDsaParam. */
    private static final int[] ALL_PARAMS = {
        SlhDsa.SLH_DSA_SHAKE_128S, SlhDsa.SLH_DSA_SHAKE_128F,
        SlhDsa.SLH_DSA_SHAKE_192S, SlhDsa.SLH_DSA_SHAKE_192F,
        SlhDsa.SLH_DSA_SHAKE_256S, SlhDsa.SLH_DSA_SHAKE_256F,
        SlhDsa.SLH_DSA_SHA2_128S,  SlhDsa.SLH_DSA_SHA2_128F,
        SlhDsa.SLH_DSA_SHA2_192S,  SlhDsa.SLH_DSA_SHA2_192F,
        SlhDsa.SLH_DSA_SHA2_256S,  SlhDsa.SLH_DSA_SHA2_256F
    };

    /* FIPS 205 Table 2 sizes, indexed by parameter set 0-11. */
    private static final int[] EXPECTED_PUB_SIZE = {
        32, 32, 48, 48, 64, 64, 32, 32, 48, 48, 64, 64
    };
    private static final int[] EXPECTED_PRIV_SIZE = {
        64, 64, 96, 96, 128, 128, 64, 64, 96, 96, 128, 128
    };
    private static final int[] EXPECTED_SIG_SIZE = {
        7856, 17088, 16224, 35664, 29792, 49856,
        7856, 17088, 16224, 35664, 29792, 49856
    };

    /* Cheap-to-run parameter sets used for the sign/verify round trips, kept
     * to the 128-bit category to bound test time. The larger and 's' sets are
     * exercised by the size checks and the NIST KAT vectors. */
    private static final int[] CORE_PARAMS = {
        SlhDsa.SLH_DSA_SHAKE_128S, SlhDsa.SLH_DSA_SHAKE_128F,
        SlhDsa.SLH_DSA_SHA2_128S,  SlhDsa.SLH_DSA_SHA2_128F
    };

    private static Rng rng = new Rng();
    private static final Object rngLock = new Object();
    private static boolean slhDsaEnabled = false;

    /* Parameter sets actually compiled into this native wolfSSL build. */
    private static final ArrayList<Integer> availableParams =
        new ArrayList<Integer>();

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUpRng() {
        synchronized (rngLock) {
            rng.init();
        }
    }

    @BeforeClass
    public static void checkAvailability() {
        slhDsaEnabled = FeatureDetect.SlhDsaEnabled();
        if (!slhDsaEnabled) {
            System.out.println("SLH-DSA test skipped: NOT_COMPILED_IN");
            return;
        }
        System.out.println("JNI SlhDsa Class");

        /* Probe each parameter set. publicKeySize() forces a native Init,
         * which fails for parameter sets not compiled into this build. */
        for (int p : ALL_PARAMS) {
            try {
                SlhDsa k = new SlhDsa(p);
                try {
                    k.publicKeySize();
                    availableParams.add(p);
                }
                finally {
                    k.releaseNativeStruct();
                }
            }
            catch (WolfCryptException e) {
                /* parameter set not compiled in */
            }
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("SLH-DSA not compiled in", slhDsaEnabled);
    }

    private static boolean isAvailable(int param) {
        return availableParams.contains(param);
    }

    /**
     * Skip test if WolfCryptException is NOT_COMPILED_IN, otherwise rethrow.
     * Key generation and signing throw NOT_COMPILED_IN on a native
     * WOLFSSL_SLHDSA_VERIFY_ONLY build.
     */
    private static void skipIfNotCompiledIn(WolfCryptException e) {

        if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
            Assume.assumeNoException(e);
        }
        throw e;
    }

    private SlhDsa makeKey(int param) {
        SlhDsa key = new SlhDsa(param);
        try {
            synchronized (rngLock) {
                key.makeKey(rng);
            }
        }
        catch (WolfCryptException e) {
            key.releaseNativeStruct();
            skipIfNotCompiledIn(e);
        }
        return key;
    }

    @Test
    public void constructorRejectsBadParam() {
        assumeEnabled();

        try {
            new SlhDsa(-1);
            fail("expected WolfCryptException for invalid parameter set");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
        }

        try {
            new SlhDsa(12);
            fail("expected WolfCryptException for invalid parameter set");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
        }
    }

    @Test
    public void getParamReturnsConstructorParam() {
        assumeEnabled();

        for (int p : availableParams) {
            SlhDsa key = new SlhDsa(p);
            try {
                assertEquals(p, key.getParam());
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void paramToNMatchesExpected() {
        assumeEnabled();

        assertEquals(16, SlhDsa.paramToN(SlhDsa.SLH_DSA_SHAKE_128S));
        assertEquals(16, SlhDsa.paramToN(SlhDsa.SLH_DSA_SHAKE_128F));
        assertEquals(24, SlhDsa.paramToN(SlhDsa.SLH_DSA_SHAKE_192S));
        assertEquals(32, SlhDsa.paramToN(SlhDsa.SLH_DSA_SHAKE_256F));
        assertEquals(16, SlhDsa.paramToN(SlhDsa.SLH_DSA_SHA2_128S));
        assertEquals(24, SlhDsa.paramToN(SlhDsa.SLH_DSA_SHA2_192F));
        assertEquals(32, SlhDsa.paramToN(SlhDsa.SLH_DSA_SHA2_256S));
    }

    @Test
    public void sizesMatchExpected() {
        assumeEnabled();

        for (int p : availableParams) {
            SlhDsa key = new SlhDsa(p);
            try {
                assertEquals("pub size, param " + p,
                    EXPECTED_PUB_SIZE[p], key.publicKeySize());
                try {
                    assertEquals("priv size, param " + p,
                        EXPECTED_PRIV_SIZE[p], key.privateKeySize());
                }
                catch (WolfCryptException e) {
                    /* No private key support on a verify-only native build,
                     * still check public and signature sizes */
                    if (e.getError() != WolfCryptError.NOT_COMPILED_IN) {
                        throw e;
                    }
                }
                assertEquals("sig size, param " + p,
                    EXPECTED_SIG_SIZE[p], key.signatureSize());
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void deferredObjectRejectsSizeQueries() {
        assumeEnabled();

        /* A no-arg (deferred parameter set) object has no meaningful sizes
         * before a DER import detects the parameter set. */
        SlhDsa key = new SlhDsa();
        try {
            try {
                key.publicKeySize();
                fail("expected BAD_FUNC_ARG for deferred publicKeySize()");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
            }

            try {
                key.privateKeySize();
                fail("expected BAD_FUNC_ARG for deferred privateKeySize()");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
            }

            try {
                key.signatureSize();
                fail("expected BAD_FUNC_ARG for deferred signatureSize()");
            } catch (WolfCryptException e) {
                assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signVerifyRoundTrip() {
        assumeEnabled();

        byte[] msg = "SLH-DSA round trip message".getBytes();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa key = makeKey(p);
            try {
                byte[] sig;
                synchronized (rngLock) {
                    sig = key.sign(msg, rng);
                }
                assertEquals(EXPECTED_SIG_SIZE[p], sig.length);
                assertTrue("verify, param " + p, key.verify(sig, msg));

                /* Tampered message must fail. */
                byte[] bad = msg.clone();
                bad[0] ^= 0x01;
                assertFalse("tampered msg, param " + p, key.verify(sig, bad));

                /* Tampered signature must fail. */
                byte[] badSig = sig.clone();
                badSig[0] ^= 0x01;
                assertFalse("tampered sig, param " + p,
                    key.verify(badSig, msg));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void verifyWrongLengthSignatureReturnsFalse() {
        assumeEnabled();

        byte[] msg = "wrong length sig".getBytes();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa key = makeKey(p);
            try {
                /* A too-short and a too-long signature are verification
                 * failures, not errors: verify() must return false rather
                 * than throw (native returns BAD_LENGTH_E, not SIG_VERIFY_E,
                 * for a sigSz != params->sigLen mismatch). */
                byte[] tooShort = new byte[100];
                assertFalse("short sig, param " + p, key.verify(tooShort, msg));

                byte[] tooLong = new byte[EXPECTED_SIG_SIZE[p] + 16];
                assertFalse("long sig, param " + p, key.verify(tooLong, msg));

                byte[] empty = new byte[0];
                assertFalse("empty sig, param " + p, key.verify(empty, msg));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void signVerifyWithContext() {
        assumeEnabled();

        byte[] msg = "context test".getBytes();
        byte[] ctx = "my-context".getBytes();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa key = makeKey(p);
            try {
                byte[] sig;
                synchronized (rngLock) {
                    sig = key.sign(msg, ctx, rng);
                }
                assertTrue("verify ctx, param " + p, key.verify(sig, msg, ctx));

                /* Empty context must not verify a non-empty-context sig. */
                assertFalse("empty ctx mismatch, param " + p,
                    key.verify(sig, msg));

                /* Different context must not verify. */
                byte[] otherCtx = "other-context".getBytes();
                assertFalse("ctx mismatch, param " + p,
                    key.verify(sig, msg, otherCtx));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void contextTooLongRejected() {
        assumeEnabled();
        Assume.assumeTrue(isAvailable(SlhDsa.SLH_DSA_SHAKE_128F));

        byte[] msg = "msg".getBytes();
        byte[] longCtx = new byte[256];

        SlhDsa key = makeKey(SlhDsa.SLH_DSA_SHAKE_128F);
        try {
            synchronized (rngLock) {
                key.sign(msg, longCtx, rng);
            }
            fail("expected IllegalArgumentException for ctx > 255");
        } catch (IllegalArgumentException e) {
            /* expected */
        } finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void deterministicSignIsRepeatable() {
        assumeEnabled();

        byte[] msg = "deterministic".getBytes();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa key = makeKey(p);
            try {
                byte[] sig1 = key.signDeterministic(msg, null);
                byte[] sig2 = key.signDeterministic(msg, null);
                assertArrayEquals("deterministic, param " + p, sig1, sig2);
                assertTrue("det verify, param " + p, key.verify(sig1, msg));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void makeKeyWithSeedsDeterministic() {
        assumeEnabled();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            int n = SlhDsa.paramToN(p);
            byte[] skSeed = new byte[n];
            byte[] skPrf = new byte[n];
            byte[] pkSeed = new byte[n];
            for (int i = 0; i < n; i++) {
                skSeed[i] = (byte)(i + 1);
                skPrf[i] = (byte)(i + 100);
                pkSeed[i] = (byte)(i + 200);
            }

            SlhDsa k1 = new SlhDsa(p);
            SlhDsa k2 = new SlhDsa(p);
            try {
                k1.makeKeyWithSeeds(skSeed, skPrf, pkSeed);
                k2.makeKeyWithSeeds(skSeed, skPrf, pkSeed);
                assertArrayEquals("pub determinism, param " + p,
                    k1.exportPublicKey(), k2.exportPublicKey());
                assertArrayEquals("priv determinism, param " + p,
                    k1.exportPrivateKey(), k2.exportPrivateKey());
            }
            catch (WolfCryptException e) {
                skipIfNotCompiledIn(e);
            }
            finally {
                k1.releaseNativeStruct();
                k2.releaseNativeStruct();
            }
        }
    }

    @Test
    public void rawExportImportRoundTrip() {
        assumeEnabled();

        byte[] msg = "raw import".getBytes();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa signer = makeKey(p);
            try {
                byte[] pub = signer.exportPublicKey();
                byte[] priv = signer.exportPrivateKey();
                assertEquals(EXPECTED_PUB_SIZE[p], pub.length);
                assertEquals(EXPECTED_PRIV_SIZE[p], priv.length);

                byte[] sig;
                synchronized (rngLock) {
                    sig = signer.sign(msg, rng);
                }

                /* Import raw public into a fresh object and verify. */
                SlhDsa verifier = new SlhDsa(p);
                try {
                    verifier.importPublicKey(pub);
                    assertTrue("raw pub verify, param " + p,
                        verifier.verify(sig, msg));
                }
                finally {
                    verifier.releaseNativeStruct();
                }

                /* Import raw private into a fresh object and sign. */
                SlhDsa signer2 = new SlhDsa(p);
                try {
                    signer2.importPrivateKey(priv);
                    byte[] sig2;
                    synchronized (rngLock) {
                        sig2 = signer2.sign(msg, rng);
                    }
                    assertTrue("raw priv sign+verify, param " + p,
                        signer.verify(sig2, msg));
                }
                finally {
                    signer2.releaseNativeStruct();
                }
            }
            finally {
                signer.releaseNativeStruct();
            }
        }
    }

    @Test
    public void checkKeyAcceptsValidPairRejectsMismatched() {
        assumeEnabled();

        for (int p : CORE_PARAMS) {

            if (!isAvailable(p)) {
                continue;
            }

            SlhDsa keyA = makeKey(p);
            SlhDsa keyB = makeKey(p);
            SlhDsa mismatched = null;

            try {
                keyA.checkKey();

                /* A raw private key is SK.seed || SK.prf || PK.seed ||
                 * PK.root (4n bytes). Splice key B's public half (last 2n
                 * bytes) onto key A's private half to build a mismatched
                 * pair. */
                byte[] spliced = keyA.exportPrivateKey();
                byte[] pubB = keyB.exportPublicKey();
                System.arraycopy(pubB, 0, spliced,
                    spliced.length - pubB.length, pubB.length);

                mismatched = new SlhDsa(p);
                try {
                    mismatched.importPrivateKey(spliced);
                    mismatched.checkKey();
                    fail("expected WolfCryptException for mismatched key " +
                        "pair, param " + p);
                } catch (WolfCryptException e) {
                    /* expected, mismatch detected at import or check */
                }
            }
            finally {
                keyA.releaseNativeStruct();
                keyB.releaseNativeStruct();
                if (mismatched != null) {
                    mismatched.releaseNativeStruct();
                }
            }
        }
    }

    @Test
    public void publicKeyDerRawFormMatchesRawExport() {
        assumeEnabled();

        for (int p : CORE_PARAMS) {

            if (!isAvailable(p)) {
                continue;
            }

            SlhDsa key = makeKey(p);

            try {
                /* withAlg=false is the raw public key without the
                 * SubjectPublicKeyInfo wrapper, byte-identical to
                 * exportPublicKey(). */
                byte[] raw = key.exportPublicKeyDer(false);
                assertEquals("raw form size, param " + p,
                    EXPECTED_PUB_SIZE[p], raw.length);
                assertArrayEquals("raw form, param " + p,
                    key.exportPublicKey(), raw);

                /* The SPKI form embeds the same raw key at its tail. */
                byte[] spki = key.exportPublicKeyDer(true);
                assertTrue(spki.length > raw.length);
                assertArrayEquals("SPKI tail, param " + p, raw,
                    Arrays.copyOfRange(spki, spki.length - raw.length,
                        spki.length));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void publicKeyDerRoundTrip() {
        assumeEnabled();

        byte[] msg = "spki".getBytes();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa signer = makeKey(p);
            try {
                byte[] spki = signer.exportPublicKeyDer(true);
                assertNotNull(spki);
                assertTrue(spki.length > EXPECTED_PUB_SIZE[p]);

                byte[] sig;
                synchronized (rngLock) {
                    sig = signer.sign(msg, rng);
                }

                /* Decode SPKI with the no-arg auto-detect constructor. */
                SlhDsa verifier = new SlhDsa();
                try {
                    verifier.importPublicKeyDer(spki);
                    assertEquals("auto-detect param, set " + p,
                        p, verifier.getParam());
                    assertTrue("SPKI verify, param " + p,
                        verifier.verify(sig, msg));
                }
                finally {
                    verifier.releaseNativeStruct();
                }
            }
            finally {
                signer.releaseNativeStruct();
            }
        }
    }

    @Test
    public void privateKeyDerRoundTrip() {
        assumeEnabled();

        byte[] msg = "pkcs8".getBytes();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa signer = makeKey(p);
            try {
                byte[] pkcs8 = signer.exportPrivateKeyDer();
                assertNotNull(pkcs8);

                SlhDsa signer2 = new SlhDsa();
                try {
                    signer2.importPrivateKeyDer(pkcs8);
                    assertEquals("auto-detect param, set " + p,
                        p, signer2.getParam());
                    byte[] sig;
                    synchronized (rngLock) {
                        sig = signer2.sign(msg, rng);
                    }
                    assertTrue("PKCS8 sign+verify, param " + p,
                        signer.verify(sig, msg));
                }
                finally {
                    signer2.releaseNativeStruct();
                }
            }
            finally {
                signer.releaseNativeStruct();
            }
        }
    }

    @Test
    public void parseAndValidateDer() {
        assumeEnabled();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa signer = makeKey(p);
            try {
                byte[] spki = signer.exportPublicKeyDer(true);
                byte[] pkcs8 = signer.exportPrivateKeyDer();

                assertEquals("public parse, param " + p, p,
                    SlhDsa.parseAndValidateSlhDsaPublicKeyDer(spki));
                assertEquals("private parse, param " + p, p,
                    SlhDsa.parseAndValidateSlhDsaPrivateKeyDer(pkcs8));
            }
            finally {
                signer.releaseNativeStruct();
            }
        }
    }

    @Test
    public void preHashSignVerifySha2() {
        assumeEnabled();

        byte[] msg = "pre-hash message".getBytes();

        /* SHA2-128 uses SHA-256, SHA2-192/256 use SHA-512. Exercise the SHA2
         * sets only here, the SHAKE sets need the SHAKE hash-type constants
         * added alongside the JCE pre-hash support. */
        runPreHash(SlhDsa.SLH_DSA_SHA2_128S, WolfCrypt.WC_HASH_TYPE_SHA256,
            sha256(msg), msg);
        runPreHash(SlhDsa.SLH_DSA_SHA2_128F, WolfCrypt.WC_HASH_TYPE_SHA256,
            sha256(msg), msg);
    }

    @Test
    public void signPreHashRoundTripAllAvailable() {
        assumeEnabled();

        byte[] msg = "HashSLH-DSA message".getBytes();

        /* Message-based HashSLH-DSA: native picks the FIPS 205 pre-hash
         * function from the parameter set (SHA-256/512 for SHA2 sets,
         * SHAKE128/256 for SHAKE sets). */
        for (int p : availableParams) {
            SlhDsa key = makeKey(p);
            try {
                byte[] sig;
                synchronized (rngLock) {
                    sig = key.signPreHash(msg, rng);
                }
                assertTrue("pre-hash verify, param " + p,
                    key.verifyPreHash(sig, msg));

                byte[] bad = msg.clone();
                bad[0] ^= 0x01;
                assertFalse("pre-hash tampered, param " + p,
                    key.verifyPreHash(sig, bad));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void preHashContextRoundTrip() {
        assumeEnabled();

        byte[] msg = "ph ctx".getBytes();
        byte[] ctx = "ph-context".getBytes();

        /* Bound to the fast 128f sets across both families. */
        for (int p : new int[] { SlhDsa.SLH_DSA_SHA2_128F,
                                 SlhDsa.SLH_DSA_SHAKE_128F }) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa key = makeKey(p);
            try {
                byte[] sig;
                synchronized (rngLock) {
                    sig = key.signPreHash(msg, ctx, rng);
                }
                assertTrue("same ctx, param " + p,
                    key.verifyPreHash(sig, msg, ctx));
                assertFalse("empty ctx mismatch, param " + p,
                    key.verifyPreHash(sig, msg));
                assertFalse("diff ctx mismatch, param " + p,
                    key.verifyPreHash(sig, msg, "other".getBytes()));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void preHashPairingMatchesSha2() {
        assumeEnabled();

        byte[] msg = "pre-hash pairing check".getBytes();

        /* Independently validate the FIPS 205 Section 10.2.2 pre-hash pairing
         * for the SHA2 sets. signPreHash() chooses the hash in native C. Here
         * we reconstruct the expected digest and hashType in Java and confirm
         * the signature verifies through the explicit-digest verifyHash()
         * path, then that the other SHA-2 hash does NOT verify. Sign and verify
         * do not share the digest helper, so a wrong-but-consistent pairing is
         * caught (128-bit sets use SHA-256, 192/256-bit sets use SHA-512). The
         * SHAKE sets cannot be cross-checked here (no Java SHAKE digest). */
        checkSha2Pairing(SlhDsa.SLH_DSA_SHA2_128F, msg,
            sha256(msg), WolfCrypt.WC_HASH_TYPE_SHA256,
            sha512(msg), WolfCrypt.WC_HASH_TYPE_SHA512);
        checkSha2Pairing(SlhDsa.SLH_DSA_SHA2_192F, msg,
            sha512(msg), WolfCrypt.WC_HASH_TYPE_SHA512,
            sha256(msg), WolfCrypt.WC_HASH_TYPE_SHA256);
    }

    @Test
    public void preHashRejectsUnsupportedHashAlg() {
        assumeEnabled();

        for (int p : CORE_PARAMS) {
            if (!isAvailable(p)) {
                continue;
            }
            SlhDsa key = makeKey(p);
            try {
                byte[] hash = new byte[32];

                /* MD5 is not a permitted FIPS 205 pre-hash function. */
                try {
                    synchronized (rngLock) {
                        key.signHash(hash, WolfCrypt.WC_HASH_TYPE_MD5, rng);
                    }
                    fail("expected WolfCryptException for MD5 pre-hash");
                } catch (WolfCryptException e) {
                    /* expected */
                }

                /* Out-of-range hash type value. */
                try {
                    synchronized (rngLock) {
                        key.signHash(hash, 0x7fffffff, rng);
                    }
                    fail("expected WolfCryptException for bad hashAlg");
                } catch (WolfCryptException e) {
                    /* expected */
                }

                /* verifyHash with an unsupported hash type is an error
                 * (throws), not a false return. Signature is sized
                 * correctly so the failure is the hash type itself. */
                byte[] sig = new byte[key.signatureSize()];
                try {
                    key.verifyHash(sig, hash, WolfCrypt.WC_HASH_TYPE_MD5);
                    fail("expected WolfCryptException for MD5 pre-hash " +
                        "verify");
                } catch (WolfCryptException e) {
                    /* expected */
                }
            }
            finally {
                key.releaseNativeStruct();
            }

            /* Error mapping is parameter-set independent, one set is
             * enough. */
            break;
        }
    }

    private void checkSha2Pairing(int param, byte[] msg,
        byte[] expectDigest, int expectHashAlg,
        byte[] wrongDigest, int wrongHashAlg) {

        if (!isAvailable(param)) {
            return;
        }
        SlhDsa key = makeKey(param);
        try {
            byte[] sig;
            synchronized (rngLock) {
                sig = key.signPreHash(msg, rng);
            }
            assertTrue("expected pairing, param " + param,
                key.verifyHash(sig, expectDigest, expectHashAlg));
            assertFalse("wrong pairing, param " + param,
                key.verifyHash(sig, wrongDigest, wrongHashAlg));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    private void runPreHash(int param, int hashAlg, byte[] hash, byte[] msg) {
        if (!isAvailable(param)) {
            return;
        }
        SlhDsa key = makeKey(param);
        try {
            byte[] sig;
            synchronized (rngLock) {
                sig = key.signHash(hash, hashAlg, rng);
            }
            assertTrue("pre-hash verify, param " + param,
                key.verifyHash(sig, hash, hashAlg));

            byte[] badHash = hash.clone();
            badHash[0] ^= 0x01;
            assertFalse("pre-hash tampered, param " + param,
                key.verifyHash(sig, badHash, hashAlg));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    private static byte[] sha256(byte[] in) {
        Sha256 sha = new Sha256();
        sha.update(in);
        return sha.digest();
    }

    private static byte[] sha512(byte[] in) {
        Sha512 sha = new Sha512();
        sha.update(in);
        return sha.digest();
    }

    /* NIST CAVP/ACVP SLH-DSA keyGen known-answer vectors, ported
     * from wolfSSL wolfcrypt/test/test.c slhdsa_keygen_kat(). Each
     * set is { param, name, sk_seed, sk_prf, pk_seed, expected_sk,
     * expected_pk } as hex. (SHAKE-128s has no published vector.) */
    private static final class KatVector {
        final int param;
        final String name;
        final byte[] skSeed;
        final byte[] skPrf;
        final byte[] pkSeed;
        final byte[] expectedSk;
        final byte[] expectedPk;
        KatVector(int param, String name, String skSeed,
            String skPrf, String pkSeed, String expectedSk,
            String expectedPk) {
            this.param = param;
            this.name = name;
            this.skSeed = hexToBytes(skSeed);
            this.skPrf = hexToBytes(skPrf);
            this.pkSeed = hexToBytes(pkSeed);
            this.expectedSk = hexToBytes(expectedSk);
            this.expectedPk = hexToBytes(expectedPk);
        }
    }

    private static final KatVector[] KAT_VECTORS = {
        new KatVector(SlhDsa.SLH_DSA_SHA2_128S,
            "SLH-DSA-SHA2-128s",
            /* sk_seed */
            "173d04c938c1c36bf289c3c022d04b14",
            /* sk_prf */
            "63ae23c41aa546da589774ac20b745c4",
            /* pk_seed */
            "0d794777914c99766827f0f09ca972be",
            /* expected_sk */
            "173d04c938c1c36bf289c3c022d04b1463ae23c41aa546da589774ac20b7" +
            "45c40d794777914c99766827f0f09ca972be0162c10219d422adba1359e6" +
            "aa65299c",
            /* expected_pk */
            "0d794777914c99766827f0f09ca972be0162c10219d422adba1359e6aa65" +
            "299c"),
        new KatVector(SlhDsa.SLH_DSA_SHA2_128F,
            "SLH-DSA-SHA2-128f",
            /* sk_seed */
            "c42bcb3b5a6f331f5cce899253c6d9e2",
            /* sk_prf */
            "9ff2b7ead7a04bab1794db8cc659c3b4",
            /* pk_seed */
            "a868f1bd5debc12d4c9fad66aabd0a94",
            /* expected_sk */
            "c42bcb3b5a6f331f5cce899253c6d9e29ff2b7ead7a04bab1794db8cc659" +
            "c3b4a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cd" +
            "fcfabd39",
            /* expected_pk */
            "a868f1bd5debc12d4c9fad66aabd0a94b546df247be4c457f3d467cdfcfa" +
            "bd39"),
        new KatVector(SlhDsa.SLH_DSA_SHA2_192S,
            "SLH-DSA-SHA2-192s",
            /* sk_seed */
            "040266529c1864088925506c20a624a2b6d50cd77c1c6f0d",
            /* sk_prf */
            "2841150ae8157512ef34a343ffea77ff7d9e814b45a8b414",
            /* pk_seed */
            "64462665f4202886206a8f632267186ca6a1cad08a2b9a86",
            /* expected_sk */
            "040266529c1864088925506c20a624a2b6d50cd77c1c6f0d2841150ae815" +
            "7512ef34a343ffea77ff7d9e814b45a8b41464462665f4202886206a8f63" +
            "2267186ca6a1cad08a2b9a862c6a7bc4ac4aaa84accef60d529f0311274f" +
            "205e8da642c9",
            /* expected_pk */
            "64462665f4202886206a8f632267186ca6a1cad08a2b9a862c6a7bc4ac4a" +
            "aa84accef60d529f0311274f205e8da642c9"),
        new KatVector(SlhDsa.SLH_DSA_SHA2_192F,
            "SLH-DSA-SHA2-192f",
            /* sk_seed */
            "a021b4b9d6dee168722bc10225e50a946642af630c3c7c7d",
            /* sk_prf */
            "69e3a40ba09df2ac165b792a07f064ac5fc28d8c99a580f4",
            /* pk_seed */
            "ee4823d09e79854706daa80ae3179b5bc8c2e9409d6328a3",
            /* expected_sk */
            "a021b4b9d6dee168722bc10225e50a946642af630c3c7c7d69e3a40ba09d" +
            "f2ac165b792a07f064ac5fc28d8c99a580f4ee4823d09e79854706daa80a" +
            "e3179b5bc8c2e9409d6328a33577fd584bc0784c559cdb2437a46f7f753c" +
            "336369419acf",
            /* expected_pk */
            "ee4823d09e79854706daa80ae3179b5bc8c2e9409d6328a33577fd584bc0" +
            "784c559cdb2437a46f7f753c336369419acf"),
        new KatVector(SlhDsa.SLH_DSA_SHA2_256S,
            "SLH-DSA-SHA2-256s",
            /* sk_seed */
            "fcbf36a9807b30697be063a5105e091b412a391dd39e1326eba23cbd4096" +
            "ca77",
            /* sk_prf */
            "ef4121c08dd71be913572f1f91e57d0acbcd5cec28539ac275832bbaa6c1" +
            "1081",
            /* pk_seed */
            "a0b4f5549ebcadb951dc2e512c76b0620d8fb8100b4ee886ef8784780d52" +
            "a254",
            /* expected_sk */
            "fcbf36a9807b30697be063a5105e091b412a391dd39e1326eba23cbd4096" +
            "ca77ef4121c08dd71be913572f1f91e57d0acbcd5cec28539ac275832bba" +
            "a6c11081a0b4f5549ebcadb951dc2e512c76b0620d8fb8100b4ee886ef87" +
            "84780d52a2543e57ab494d47068ffee4b8244aad6f19cdf94a2172bd134a" +
            "15a6b5f298d5a80e",
            /* expected_pk */
            "a0b4f5549ebcadb951dc2e512c76b0620d8fb8100b4ee886ef8784780d52" +
            "a2543e57ab494d47068ffee4b8244aad6f19cdf94a2172bd134a15a6b5f2" +
            "98d5a80e"),
        new KatVector(SlhDsa.SLH_DSA_SHA2_256F,
            "SLH-DSA-SHA2-256f",
            /* sk_seed */
            "18523702a0fe2c9e488948b127185bab93d3f02c3d7c23a1b379f762de05" +
            "09e5",
            /* sk_prf */
            "6ab0d9f93540bd809d1d2e8a050440aa81e853750470e2b00c959dbd3be4" +
            "0e2b",
            /* pk_seed */
            "d7125f5d00ba47f1fc8d4c32c2f57c444bd384d7ce770bc50dd5980c1d12" +
            "64d0",
            /* expected_sk */
            "18523702a0fe2c9e488948b127185bab93d3f02c3d7c23a1b379f762de05" +
            "09e56ab0d9f93540bd809d1d2e8a050440aa81e853750470e2b00c959dbd" +
            "3be40e2bd7125f5d00ba47f1fc8d4c32c2f57c444bd384d7ce770bc50dd5" +
            "980c1d1264d00ad5197ffcbaafe11b1e413f26adb1504ce1c3f5c40c1dcd" +
            "a14e99fd126d5b81",
            /* expected_pk */
            "d7125f5d00ba47f1fc8d4c32c2f57c444bd384d7ce770bc50dd5980c1d12" +
            "64d00ad5197ffcbaafe11b1e413f26adb1504ce1c3f5c40c1dcda14e99fd" +
            "126d5b81"),
        new KatVector(SlhDsa.SLH_DSA_SHAKE_128F,
            "SLH-DSA-SHAKE-128f",
            /* sk_seed */
            "3956ab391b4d22fc907af0740326d061",
            /* sk_prf */
            "ab0eb206436f2b86ebe086d77739b3e4",
            /* pk_seed */
            "56505c229f4e7fa6b201714c7dcc9da3",
            /* expected_sk */
            "3956ab391b4d22fc907af0740326d061ab0eb206436f2b86ebe086d77739" +
            "b3e456505c229f4e7fa6b201714c7dcc9da366578f1f24c3fe371c97c14c" +
            "e0e79cdc",
            /* expected_pk */
            "56505c229f4e7fa6b201714c7dcc9da366578f1f24c3fe371c97c14ce0e7" +
            "9cdc"),
        new KatVector(SlhDsa.SLH_DSA_SHAKE_192S,
            "SLH-DSA-SHAKE-192s",
            /* sk_seed */
            "8732621860e9a6e1887be55f7af692b98eb4c10b2599f94a",
            /* sk_prf */
            "d5cc9d6470d8b21136158e8b1710f1fbe03eced37ed4ac68",
            /* pk_seed */
            "53fc64d46d7e1653ebbb36ed5fbc12c6e7cef3cb756482c8",
            /* expected_sk */
            "8732621860e9a6e1887be55f7af692b98eb4c10b2599f94ad5cc9d6470d8" +
            "b21136158e8b1710f1fbe03eced37ed4ac6853fc64d46d7e1653ebbb36ed" +
            "5fbc12c6e7cef3cb756482c8c620452e864e8497e1b38a7b04449219acd9" +
            "e4393f9c88ef",
            /* expected_pk */
            "53fc64d46d7e1653ebbb36ed5fbc12c6e7cef3cb756482c8c620452e864e" +
            "8497e1b38a7b04449219acd9e4393f9c88ef"),
        new KatVector(SlhDsa.SLH_DSA_SHAKE_192F,
            "SLH-DSA-SHAKE-192f",
            /* sk_seed */
            "fb7a2c2c75ce6c96b5f4328e0ab300476fc6f864cb5b0b99",
            /* sk_prf */
            "990ecb726ca822a4e3652dd92ec0aab7637ea41c0482ae28",
            /* pk_seed */
            "68dcc671e3534f81a352c275b6a25f906d2ed0ff62b8b4e3",
            /* expected_sk */
            "fb7a2c2c75ce6c96b5f4328e0ab300476fc6f864cb5b0b99990ecb726ca8" +
            "22a4e3652dd92ec0aab7637ea41c0482ae2868dcc671e3534f81a352c275" +
            "b6a25f906d2ed0ff62b8b4e398f1a9876cb082a48e9ae2c862b289486a39" +
            "25cefc6ff4be",
            /* expected_pk */
            "68dcc671e3534f81a352c275b6a25f906d2ed0ff62b8b4e398f1a9876cb0" +
            "82a48e9ae2c862b289486a3925cefc6ff4be"),
        new KatVector(SlhDsa.SLH_DSA_SHAKE_256S,
            "SLH-DSA-SHAKE-256s",
            /* sk_seed */
            "e440e39644a11a6a58e850c09c8f03c273e465237f3bef7c58de62281e67" +
            "6cea",
            /* sk_prf */
            "99c199c00db30f8499a61b5b9dc8a361725f6ae80e97037176f408c30b38" +
            "844d",
            /* pk_seed */
            "d7b5e755b4879fde3288a21af3e32fbb006fd9b8bc2b180eb9b0d82c9f31" +
            "57af",
            /* expected_sk */
            "e440e39644a11a6a58e850c09c8f03c273e465237f3bef7c58de62281e67" +
            "6cea99c199c00db30f8499a61b5b9dc8a361725f6ae80e97037176f408c3" +
            "0b38844dd7b5e755b4879fde3288a21af3e32fbb006fd9b8bc2b180eb9b0" +
            "d82c9f3157af02acd6b3198ee1c9fe9afe61fd86d1e0877ad9061980b57b" +
            "178ce27191d8eb1b",
            /* expected_pk */
            "d7b5e755b4879fde3288a21af3e32fbb006fd9b8bc2b180eb9b0d82c9f31" +
            "57af02acd6b3198ee1c9fe9afe61fd86d1e0877ad9061980b57b178ce271" +
            "91d8eb1b"),
        new KatVector(SlhDsa.SLH_DSA_SHAKE_256F,
            "SLH-DSA-SHAKE-256f",
            /* sk_seed */
            "2ac9403858d186b172edd8df9c78a11449893681487d3af0dad0ec341e8a" +
            "ca48",
            /* sk_prf */
            "afa2771bae6c17dd6f77b4e3808b05f56f31b8f4128df2ccb677f0283cfb" +
            "18da",
            /* pk_seed */
            "559bc883105e8ba0264648b532626155f87edb4bedcfc12a24204d3b696d" +
            "5370",
            /* expected_sk */
            "2ac9403858d186b172edd8df9c78a11449893681487d3af0dad0ec341e8a" +
            "ca48afa2771bae6c17dd6f77b4e3808b05f56f31b8f4128df2ccb677f028" +
            "3cfb18da559bc883105e8ba0264648b532626155f87edb4bedcfc12a2420" +
            "4d3b696d53707a158ff5d30e3428183a3b3a96a0e4a341a2a16e5a6226af" +
            "374d1efb39a35df6",
            /* expected_pk */
            "559bc883105e8ba0264648b532626155f87edb4bedcfc12a24204d3b696d" +
            "53707a158ff5d30e3428183a3b3a96a0e4a341a2a16e5a6226af374d1efb" +
            "39a35df6"),
    };

    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(
                s.substring(i, i + 2), 16);
        }
        return out;
    }

    @Test
    public void keyGenKat() {
        assumeEnabled();

        for (KatVector v : KAT_VECTORS) {
            if (!isAvailable(v.param)) {
                continue;
            }
            SlhDsa key = new SlhDsa(v.param);
            try {
                key.makeKeyWithSeeds(v.skSeed, v.skPrf, v.pkSeed);
                assertArrayEquals("priv KAT, " + v.name,
                    v.expectedSk, key.exportPrivateKey());
                assertArrayEquals("pub KAT, " + v.name,
                    v.expectedPk, key.exportPublicKey());
            }
            catch (WolfCryptException e) {
                skipIfNotCompiledIn(e);
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    /* ACVP SLH-DSA sigGen (FIPS 205) known-answer vectors: deterministic,
     * external-interface, pure-sign cases from the NIST ACVP-Server
     * reference vectors (SLH-DSA-sigGen-FIPS205 internalProjection.json).
     * One vector per hash family independently validates the sign/verify */
    private static final class SigKatVector {
        final int param;
        final String name;
        final byte[] sk;
        final byte[] pk;
        final byte[] ctx;
        final byte[] msg;
        final byte[] expectedSig;
        SigKatVector(int param, String name, String sk, String pk,
            String ctx, String msg, String expectedSig) {
            this.param = param;
            this.name = name;
            this.sk = hexToBytes(sk);
            this.pk = hexToBytes(pk);
            this.ctx = hexToBytes(ctx);
            this.msg = hexToBytes(msg);
            this.expectedSig = hexToBytes(expectedSig);
        }
    }

    private static final SigKatVector[] SIG_KAT_VECTORS = {
        /* SLH-DSA-SHA2-128s, ACVP tgId 19 tcId 161 */
        new SigKatVector(SlhDsa.SLH_DSA_SHA2_128S, "SLH-DSA-SHA2-128s",
            /* sk */
            "9AE2F36B1EB8295ACDAA5589D996788F06977D16AC51524D770152E02DE29C8A"
            + "DB30F66D17E197683997000BC98342AF"
            + "9B0862379CA9F32EDB1A2EF3A9262207",
            /* pk */
            "DB30F66D17E197683997000BC98342AF9B0862379CA9F32EDB1A2EF3A9262207",
            /* context */
            "0610D63CCA608F79C617F1C311FB4CF35D63982536A41B2C305A21D56641AD21"
            + "3B9B0253E8518F46642033680F25F91D936C184F78F6170864BE8E59A6F399FA"
            + "7F01E80B19DF5F76B3111C4EAC7FEBBEB4C7C9FF3B2C2324A61B3348C8425781"
            + "6EE0E8FBE3AEE55C6C547C9B1ABE239707569CFD7408DA68FDCCB9FE3BCBCA2F"
            + "AC370CCF17F31551C53E07169520F0601A6E14937204B87BB0FFEFF8FFAB9A73"
            + "6A12BC0B1E3D051CE90F022D848A68ECC5B8AAD63F354269422B0D1D0FFE60C8"
            + "6B8BA0FD0DB518C44454C8B46DFAA7BD1DFEF75F7305FF0B10CAC037024A70B1"
            + "C470282B4885EBBD181EDB3F4052330362106780B0243893B7E983F97230E3",
            /* message */
            "20",
            /* signature */
            "630DA8596A4D35420375671D16319B59664A38D8CEF78D7EAC30BB9BBC84B78C"
            + "98218A5D5AC691B242680DA056553DDF18571A55054BA00C09F901FBFEDC3DA3"
            + "F7A9282EF455426F86DA132D6EE885A1DBB7FE796F5DBF0AE979166B93948FC3"
            + "485814E9CB6A9C656569F8F7ECD165B7E774CCD20B7EF1D052A56D1476C5AD84"
            + "0280D82E43385541CD86C89DDDEDB955E89C31D696500287C73E70D5CF894021"
            + "31C25F9D07B68EF6934DB8D13324E35BC1B0E59A45FB33A87D71A8154B2F92CE"
            + "EBD7E095855BD38C11E3AD571F27FE60F3D37AEFF5E9F05A39AFB8FD0156C221"
            + "BC40B847FBF7635D94C33284D125A379DB186206AFBFB6C1DFBB8AAE060D05DE"
            + "9C9BBC2652A506DFF01AE980057AD5513A45FAEDD058C4509E9C3737D8EB9155"
            + "BFC460AEA87F36EAD99B9A6B3DA5362D1035FF87A0E421611B225AA07DD4D5BB"
            + "E90D8272258723F29867481276F01789A94C617B22A8C5EE7A86D526B6A9BA49"
            + "24E9BEC3C0BC993ABB44032B61F76A37DCC17B150E5FF474B499582068203817"
            + "8C8DDB563058DD15985D27A4FFC9BB179465443449E6CAA7A9E90E9AE061F3B1"
            + "1B9285951F9517B4F31F1AB05E7EAB67997DE3F03F3381536CA7420235316B9D"
            + "9C9BB634469231974A0FD690C490E3F8D00160195CC9757BC45A3ACB84DEB975"
            + "11EC7AACD7219AEC8183188C4167ACD9AC00B49B9843C406253F49B5A317FD77"
            + "1A6DD906873357C7E077FBCFBD7D3FC5FEC42D3476F94EB8B626B1F26AE13CB1"
            + "009C6A719A5FED0E1E9B4E15C532676C3A624C6CAA6036C9CA145D25286274C9"
            + "4FDD172590D82E4858D3FDD14B77AE1CD595DC3CBEE6AEAAF00E748E630178C7"
            + "A489F1B201199F221C3F2DDFD77C46F08FCBA979F0E4AD6916E92D1BDE94C998"
            + "CDB71CB0233C7FDC264DA44E2839DF1863819C772CDE146724716935CF1044F0"
            + "A2DD234E7A73FB7EE0456C085B6495B441783715F27BEC7149B2B865404B8128"
            + "93A22BACD975F0DE66F9821CFE3E066364F5A22BE584EE923199043396955F2A"
            + "83443E01EED644F87F10AA9EA1808B7BE488355883A7B7A6C0A9F505D7475277"
            + "43E22337170015F65FF78705AD752DA841530D7DF480605C2B3792AB5ECDA2F3"
            + "49E9A62130972D650BA84DB47554780B5D4C68ABD7098546BBAE74DB22152AD4"
            + "8E4B68D174CDE9729AB05AD114B885FC02FD1D7EB3988C275FFF666352FFD193"
            + "4FFD39A40182B7A0939D7333BE7C06311E060F557C12B77E20B81D38E78E105F"
            + "A58A11F600B8B6DFA15850BEDF499466BDF36CC4BA76D9F7946FC2F066F538C7"
            + "4DCD4AEDDE1E45D6F19B9863B1E3A693B5C82AA72705EFE500DE8C58032B7D96"
            + "4E2740C788D4CADBA2E1804A02C12CB048DCC7A057B26AD3645345B2F98CE171"
            + "0AD8678F99B84790D531DC154D8EF8F67EAFDD3822D2EC79D57EC916FFD76650"
            + "509597CC4524FEEEA91A14DEF32D144E5E53CF8DC204ECE0FB36E29B056151F6"
            + "1B4348EE4C1C62F95B0243EF6409EC4736DBDC310A7B9B27231715D2AFCFE541"
            + "8519D46B7E1F80D863269216E8E19A2716886495A9009634BC371BFD4F853D14"
            + "5020CB6DEDC1FDB151AA3FDE7C6A214BEF76E0C68DA9C904FA0D741080ED2F88"
            + "612F6D2A3D64D379F3CADC0BA9EB6E2381E9FD96BD0299BC202C6721A7ABC6C4"
            + "A4B9F4ED9C7D6F9A2E8E9D8C6E53FAB5AFDE9FE829861A34C234E627133D0556"
            + "F6CF5C14C2F6852C58FBE930CFC5CC002AE65F891CF46CA5B77030C7915B546F"
            + "0283106F4816AA1CC5EC56CAC04F55D1A67FB4C241AF72DE6A93EB45FC5B615B"
            + "A1DACDF6654C1FFC83A887E64ADC78E05D2EA08F8F0718135742FF2E014EA303"
            + "ABECE2D4E5514FB3E60FA32C779AF35915EB9B67C9491AD4970194636907DB36"
            + "93BA597780D4F32068D44CA2A2E4667EA0F8E7C02AED87BBE75A43F8E00D6429"
            + "3A9FD631B11FA427C2FE030393617C9956209D59EAD9D39F259F606D67AE011C"
            + "3E6B7FDB7E003EA41A4EA65C634F9B1C9551EB807D4D9715F17B6FA5AF825638"
            + "2DD1E0BB562E3DAB96A956C66C6D13341D735F8FF46871FB8B257D04A57E0848"
            + "E7C31E421815CD1E43CD9AC195BE17DB0DC6D83DA9C3D905F79C37F39409F43A"
            + "1489205F8FCD16CDE3A08EC7A3ECE4F9976A8A6C42480C4006D57C5574F9D886"
            + "638D9CCC95941F120885BE84E02FB7F205C5233A8F1B0F0D015E43BA7CC4BF92"
            + "02C063988199C1F23B3029826F84E3006E42003673F1D649E4369A5A665CCAFF"
            + "96AF3EA2752B901B58142C5F072AF21A632EB34865326FC950154E85E2433CC7"
            + "A159F350D84E7129D33D531A044048EFC7FA0359551F4999A46F9330F328F01C"
            + "8B65225600C4AEF8816250F4A3A50B9C408A00C738C4B590B30F2A6CB5591906"
            + "EE7D600FC9397E2506C00B405F0B904E719838FEB4D0B667B3D7C0E4A412321E"
            + "D5F45CA970C1E2A57C951AD19DEE6E546A6F3320F383AA22CAC9C5DA3C84CC35"
            + "DA69190D1942A2403048FC10D169D77928031DEF4E3D5AF774847B712AA7A7D6"
            + "61A98DD9B818B26AE555D4592047C4B7FC206E67D8995E00EC3D1B3249C61EF4"
            + "A68F92D757BC343834EAE0AC0D29F79D5EA62BBE637C249930C013766C3B1B64"
            + "CCC7BCA32483C6D01477F6C84D9021EB8EFB84FDD6C1293C9B031D3B58042D16"
            + "F215F01CDD8A987878FF9D7C148274826896B3A887058750D2D69797FDDDE7B6"
            + "6B710132CB731D9F5CE0F9280E0212E5F80E2B3C774A23C02BAF92F920A5F3A5"
            + "2407C11DB710BB3B56CBE3E788E0C089A414E82F4C01C5816E17A595318240E7"
            + "88760E7264A849BA9DA2151DCE811EF269F2415D4FE5B53274096D7434117B97"
            + "8F0EB32CF379135DC0AF7B5972D2CA88D1DA887C62DA577BEC4675284FFFB510"
            + "083D6DA8996BFCF0859DC039EBAFE72D173B1BAA5CB93FD094DEB1A1F97BB0C9"
            + "AA31CDEAD4FE7286DD126FE67E5F696137CAF3B33B7F66DFB1544C048D943759"
            + "B019DF309DCFEF7725F704FB0DF370799679A60FCDA9BBC47C8D55EC20B0D653"
            + "FC5C11ED1AA65211D5F7C80C9C9AD7468A58261DA31D6EE2E6407515D74F099B"
            + "DCC3D63A76E3B5B008DF13C4FC0CC7753283393C5252327FB9AA2027FF85B3F4"
            + "3E94F94538F9ABE360FB38A58C060B19B1D60A9D98396614E980EBB957044DAB"
            + "D0400E4D11A4C31E41B8B8BABFC9247BCF12DE04A4F18F6F89AEC46A39CEF38A"
            + "69D0BA305A1D75F72312BA22D8A1B1C99D6EDB37E1EF9EFFB188138352272110"
            + "9D25A6B16A420CA08B0A7FF45A07484698A440FE425DE405D4F46B0F2326DDA7"
            + "3BF98DD5EC40E824172078ECF4B6DA0C77CE4BD485258CBD47A9FEF9DB7A6F0E"
            + "963EE331721E816A5F9EDA8D8ED81EEB32B62A429877253B92360EB67DDE3AEC"
            + "11196E81A0FC691B58326BBF9143B8FA9BEFBC110F7B6118E334DB6E5D26BA64"
            + "E83E2ED57C49CD4070A0F37C5F38F857F6D78396CD3E1441FCCDC33D25BCA9FF"
            + "29AC919DF1D2878968366A13F53878757B830A63A0C95EF1C6FB492B84134B34"
            + "99E08C0867B877FF4D19741EAB55DE59E26C355ACED8030AA70C7652E4BA2458"
            + "520089390EB17F2B322C30A6D130CDC5299F80EBF321B7D7F466E556116DED3B"
            + "A6A68532118475B3626D6C07F9E6F2CC458038F81AD0A5406CAD82840B319B7C"
            + "1ADD82E8C0BE84F84B6128981557535D2CBB2FE6C314924FC49AAF4AFFED6A26"
            + "DADD14F1DE33F4F32AC145010739E063B32E4E24A62DBAFE33C5D07CDCA45F10"
            + "4056140FDDC21987A7796515B786E61E9D0FB7CD75C79F2EFD607CCEA6C739ED"
            + "04741ED08932F58208506A4B7A6066AD939EE4B900C161E4D5D1A25ED3FF9225"
            + "0A33FF97E540CAF765F0E09035B665705DF1C5A2C57BF8A15AF1DF266C6511A8"
            + "345A9C0BD84638EDF94DF1E3720F5C6615D9C7A6CF4B0B100D81F67727CAF552"
            + "28A506BBA564B56259B0C3AACC04E1D2B71BF78A20468C35340F646B6423F7F3"
            + "39FCCC245F229EE57E02CDE3CA78C29B5DB9FD937BD3F3E80BE45CF2A9518362"
            + "7A5A09B83176AC7BF43A88CCEDD83289EE5734AA8738816B2EE7292296ACDED3"
            + "CD5CE0E82495AD7C9AB9D75C17204F37EE6716F446DEB81D5720EC783D521CE3"
            + "6D64E5ADEB161D4861F97F4993DE2A663A6EC46C1911286CA3411E4EDDD69228"
            + "AF73984264AE65A78F1C3BCA1DEE7D86D4E65273973A9F988EDB2B267D6CF669"
            + "264F5352579909DB3873F09C978A22B7452C4695B3C5D459C2E46309952C48A0"
            + "97BD08EDC69BB20BD0DBA931C783A16AA501E21F65C5E52BDAB0FD2CCB21C824"
            + "29D939A335EA43B17925A171FD101F5DBE397747304EB135441222B02EE5A712"
            + "0F88655A96F68546DC6216499DF4FB61A2BB197FC25B3F615C6FACF9F87BC82A"
            + "DA37EE09FBA6918C89808125C25362BD5B6CA6772FBE51568941F1E060D6229F"
            + "E3EA1027A31B3A107050E8BC25A000035C1556A249761006DBB6C5D748386151"
            + "E3995AB389171045D92AC9E747F69121B1930385D69D9CA0E78317AD58C1F2C3"
            + "2C569488658AEFBC53175E1EC2FD349916F66F0C170549CF5A9F8E5531DD75A1"
            + "4CCF096DAF2D7BE5424900B339580322B3C325A700BDA181725E9DBEF6CA53BE"
            + "EC7C7A3EAB04FA99F1E1ABE930CA935BAAB07A146F4284C7E3808613E724E5ED"
            + "7B23CEFC93B77848D7737B762FA662BA940E20B6533B9275E7250FD58ED6A898"
            + "4F1949C8B4D9AD4D6EF144B6FF33D1ADB66F8F991DAE9FACB5F6690F61EEC081"
            + "C6EAADF7208D3B80A1A72D411A955FE67528D70282E298908D00C116C653876C"
            + "A18333AA8C8A68DF936DEC59D5B549F5690FCEAA0AA67B5D4F5E4ADAC1639412"
            + "42784846476AAA1F3562C029383F87682CE78E10FF526861386E62E057744B2B"
            + "5ADF349DA0E3D214EC038189D57649A68DBBED360AE31A2CCA9243E4D828568A"
            + "7436FAD2536437662BBD4B2D5834D6EAF2437A02F5DAD641A6C9509A24D0E7B2"
            + "4647159F6A1273DB0C6DBA847E6F4A6A6C99CD8E2160C2D1D23D6F95839908D8"
            + "0DE30D2FCAD15EAD1B09A7DB183FC6F1E29730059B9FCB8727D8E7525DBE50F9"
            + "AC6096074E1F640187F23B65CF29687F10D83D7104FA751E3D3DD96325CFF4DE"
            + "5C27982265A0ABFAF550C7A0487C43A9B0B0DD8FCAFD72647AF912F56A5006BC"
            + "09AF79DB6D75D920FB9DE0CA9F1193277E773F3013E6F1555B31F14E5D9FC215"
            + "E4E058F0700D841F5FCD54E50D2D8AD0A0CE12C2F84161747F7C9DE084DE1B34"
            + "EB1CD8CCCAAEE0D341A2E4BFF01FE36BF5D694D4C13CE80491C19C6A569B2588"
            + "9BEFCEF12C368C98A4CCBAD04524845C24F09420A00AD72A5BE1C7D2F29B53E4"
            + "4322461BB181B4A9E3965D37C3B287FB9786F9F479100EF7866AD7A1FF151318"
            + "15583E98B985CDAC94565C7DF96C1685D35F4EF8A9CBF91B6FDA161FE6FB85B5"
            + "E8978286C5CE496ED70B971EC43378973AD3C5BC8AFC676BC9E14E649E9B5B9F"
            + "C36F1AA1C0345C93292B8DE236CEEA0A6AF20154F4F1648EC13E529E745B2D67"
            + "DA8346B0875E2CA7C97EFB5195227E61F58AA8CC1F50AC766AA407C7E4567C65"
            + "B8DA6456A9F62331A7F585A2BE52EBF92B4C5CB5DDDB5C65696E1CC0979ACD40"
            + "6A69E63ECA476BACB413D91D39393704B6265194A279DE32D104FD32591B7CB8"
            + "4FDA2668861282AC4BF10B0447C021D852B71431359D076E093B0244E608FCD4"
            + "52F11A9E1378B57C0A567B4ECF6617769005440E02AD85ED1D28891C05729D8F"
            + "AD8153A0E9540125CDD9B267DB0D6E754C3DE632C247F2204A53E9B8B969D04D"
            + "0A02C9D83067A48000E5552E4645C897DCFE2422988A1A9ABEA8648B1BFD8AF6"
            + "AB6DB484868CAEFA95498A1EEBA601578ACE45577693DBDE1B15431DAA1C052B"
            + "F37F27EB966C3210DD80A75C0F99F132E6F56FF19ADED0EFB68604FFBF1B7596"
            + "2C787020D4A479D801EE6BE2EAD8E1840080D3A20168AFDADD0CCF9EC2EAD44F"
            + "84CA8BD0E5FCAB9A8C0AB80723D94C012C0CFA6DFA6ED13F6B956A142585CD09"
            + "6B736B6765B1A39131A68F22B75503022DB74F6F3DE7C093787E7B327DEC202D"
            + "BC5BBC05640032D6410B8CA4015B744B0EE22A1499181D43BF9195C7A5451CEB"
            + "44FDAC2BBF0C7C05937C78ED8EC57BFB86DBA1A6D6EB1F30E6486DBAAD6C9BF9"
            + "04D7D157B88CFC88563720C7B7521653566E7E0CF410F2C9C52BF5214684E94F"
            + "0598393D67AA48747AB874D69D031E8BF33AF9CE8B4CE0A8D79BA16D6E83F1C6"
            + "4B8D000BDCB1B003BB1B617026FE850E55549BB1A678990A5D5CF4300DCAF410"
            + "3DA02ADA0959198F97030656D65F6C8759B0686F213C2DD78BACF47DC5E112A5"
            + "7F68782ED118E2161EF28A1ACAB56ECFA396078BB652C8D0D279B11F50785A5F"
            + "56729B4BEC7E2E8C24D2949E99CDFF59BC6C9D54E91879EDE6CF991537D963D4"
            + "470B9D9B5C3496F8C7539D5575602B01C5A70788547760733E7E74B150875EFE"
            + "A6EC747051217A0350AF6FF3792203BAC4E065E043367520C1C8C14AD5C25921"
            + "E7D46AAC932F2137ED3C5DF51183C76D67B7F7689A11DBB1749DA843EC23939D"
            + "35BAD4422A53D32D9413AB5CF5D36918E421F72DBD224A9471D2A14AEF5822F4"
            + "0E4A6741D10960141332EFF7715F0962E8C21D70BBEAAE684A7B98F224581132"
            + "7018EB8A409C8B3F9614415AC9AE4A4314FB295CC926B8FC26D278946A807B32"
            + "619A44AE6CC8F875B3D747B6CEFD475C47750B5A2F1DEA3280084D128EADD126"
            + "338E0E9A4D2340EC6665947EAE1B8F48A7B3280DB152919809D13F1BBA248107"
            + "0C8FE619162F6202C8256DE6A0B68D8C6093C62279D4A4A23597B8D8846F54D8"
            + "72C1B56DF62F9FCAB211ECFF7652521030C12FF04B1A40D2BAD37B277D3ADF15"
            + "A993B483E6534C3CE8906274497AB2C83519F1DC77B6CC6E3219D25641BE9CFC"
            + "5E51392AEEABCBCE66B1BA1C5B3A1066F1D3F5761710C46D58D3906A47457D72"
            + "E1244FEDE14A3660840F6475901A1D391B9B4FBFAD925A1F620A94CE3B547B3C"
            + "F5F82CC9878ADCB8F8419E6A5C4A332DBEDDC9F4771D302174B3531156FCF217"
            + "1EE9F94CEE5BB8FEB3A333185F29C039D26620890ED3308C0D936F322EF54CE7"
            + "208C8E3D26DF4FCF9A654EE9A2898F87023D4B907A8D0ADE8D61CACBA8A3EC67"
            + "05FBE8B375F1168FB374EEF7ACC1F240017FF7EBDD68F44B664A2B3D4631D174"
            + "C5B8249A4124902D747C6B42760A6D6CE2D127EC16FBF20607BABD64C03CADC6"
            + "7ADC5C930B2A58F1FE678C8ABAC324546159B62446C07F1C958B4D9190935663"
            + "68D3CB54AB973EFD1847634766AC690412BA8899953C6523787E6BF1E87A48DA"
            + "C3D66CBA67D241B6953C6F29653E7E71B9AEE5E9C91BADA6EF95B5D52FD32ADD"
            + "45D707FEA4C854C5B610A087621C5F28A54D87D9A36F4EF91D01AB129FF895AC"
            + "370138A57DE6BA0FD1F7D659B062DBB58A744985190EBCE7B7BCF35EAE3FA587"
            + "FF9C437AEF81CC194967030D5D099A895B3726BABDF283E5F9231D1C4667510D"
            + "97D4A3C9E544EBED8EDC74CE0003077DD9E82267566D0907B614C32FC466BA5A"
            + "DE473020F675AE6F3F23CEF15D49C5CAB979CA9F51FA59AD642D3F7DF5166946"
            + "486B23680B26D1E756F8251D4A2CA8D3351B241C930DCA5833CCA9B16D6B214E"
            + "9CBACC97BBA87B6BAFC160D68CA75ED872FA14325F078BD54B723B3DAA8DDF26"
            + "D94DA0C18928BF2D9238047ECC1E83AD663889D4EB6D928321B499DB089A9D55"
            + "359FBB5F08BC65B5B1646615AE6BAA9F93A60C2DCE8333384172578596480F2E"
            + "5EF52DE483DFB647228FBB27297CB2FA1A8BBB44BFC912010374945388918C41"
            + "E194230E88149F23EE5542E8478B39B4C24A0B235223A741B2976A86695346EE"
            + "608C77EBD1287035E8DC0CED187BF1E8DD0FBE248665159800C8C23316B614A7"
            + "FFC1CC7E07C56428D45A768BCC6A45E01D66CCE9D6044B80B6E77D5B9DCEA037"
            + "1A1FDD63DA33194D28A777BDE4760D0BA21CE35590B76D7F2325DFD27B47614C"
            + "366473EC8795276CBADC4167E7BA58934D4868F83E3F31EB0E00A9E50F58057F"
            + "96E624FD25DBEC9899685ADC2B37232B139214E24A738E4D6CD92A8D8AD4B137"
            + "3E76994E8B5E2F79E210A6147959A9B20F8BC3F956D2ADFACD253E5D7FC471FA"
            + "DB5185160305F22C95C2AC6BAAEE4EBEF74F3FA8CFC505818377C311BEC78A57"
            + "52CB9382B412FF13B79979856E84BEC1711E594EBB87AF3C1B28A0CEF3BB1678"
            + "53E03A175E1AF9E5B21C868681F907CC282C86A4A2448A8B7EEB9F67E14F4078"
            + "39C0913B26A1C8510C877645FD2974D7D0672E340E5F05F2FE44B4B49BF40380"
            + "AE71FE54989AC378B41430FEDE46B00A94765D49ADC52A671F0921581ED7B116"
            + "3C1E213D33A65294DDA46E96877A4A06601BFA99EAD37C848AD3A605D36E1A46"
            + "80E194D850A3ED8B62DB9E5830FFD20405F440B8A35A98A114A3DF3EBDEFE952"
            + "644FC82A50F3383B726B32683432172182E2F5D59C411A111B96548EFE225288"
            + "5E7E694F8DB42E9F221223CE6EA52E7D2E078B09E4C3118A0C8FFDC46D92D1B8"
            + "1BAA3E80B9FDE5103A3438D05006EF3FC486DD24BE9E594EF55FD7454D397E46"
            + "8174B9D0BA12DB7E085B9485FAB5C16674499212863DD9D61AEC80E1A7DD4C5A"
            + "9A9F09AF6A219E18F53E5479D9F9D2B864B61339E6367DFD1C252E669DC3AA60"
            + "EE9A153A2BE13439E19A47CB67A35B1040C6E95333A021EE9CB2CEE20019DCE0"
            + "38395B458E2C53617F1ACD502A94FDBDACA93B1EEA54491F076566E63D5EF590"
            + "5FF9F2373B480D0F61052106F210D66674CF873E3C1491AF6CC6EA6AE22183E9"
            + "A551E716DA33569AC1DE8D635899502E65A28363253D3B207A56D6C9BAF00B3C"
            + "05AAB5E8CEA1D32F1D8A7FC42446647429F12ACE238B6965BA9AB4CE82DEE386"
            + "A69CC656ED4B4F7AD890433FF404D075100CCBF95E6A48846F5920C44D5DEA63"
            + "8AE0D78AE8C495DED6972560618259EB010F8C989A0F3AA3C2BD9987C5C332D4"
            + "40124A180E699D20E2FA51532E67146678AB3B9B8B30E230B94424AABD92FE16"
            + "8C8B8AFD2084C81AE4DCCDB8422C02CD1EE4CC71BDA137D0B48F660EF2E27398"
            + "6FB69149447D16151B88C4F7B5390A44A5622DC952CC1E5AE4508DEA41FD5853"
            + "C37DBA0D6CAF1322734D5D57024C112F01CA125B291898A84475E82B82C85767"
            + "9949EF36DA607EFB59B1E4D68740FBE704C6C7917C62B4F087165B3BE84580B3"
            + "FA687A15216A31553E997E3E5E9C00A8508B9F6C405C5C9918C801248FF8F067"
            + "02DC78902B0D2DC5FD75A59FFD4EDA16F4B615E4819A9F3193963DA746ECA3BD"
            + "22CD0F396D88D096A763D4A1538F6671E775DC80D41F81CA730510F35804F047"
            + "C4CC53FF754C5248BDFEA9CA6E8F2A5B04099E1258DE9C0A1324AEDFA71EC3CE"
            + "9CE7D728DE411C608A85DCF27BD51164AB5E84A2AFCA16621FBAE23EFF4C1190"
            + "E4876CE260D73C7BCCAF23FED560FC5D90CA8A4B8D26438EBA160AC2F49059D6"
            + "1FCD7870B204BF8A1E831C136C803631223E54B64C4EA1CCA3766447A16CC89D"
            + "5EFBCD1D364F4B7B7A8EC7F374C3E2B4D824F2231DB95E98A766E00269C37DD8"
            + "CD00A279F3B4CDA1C507FB2BE135AD70E9F889D515AB73FB9F5D85A98B5EE9A9"
            + "37B99FE42C19F3FC2A355A01AC2D88C4BDB66E286E7F0577B6AA51D655B83295"
            + "97E504BFFA12E822C3484932D72BC8E5B7BB6EE6835AD02ADD5E0D8CA238B5AC"
            + "97E1CFA0416DE82DEABFAE846070DB2791CF32BC6429724E08B0A74D15A4FBD1"
            + "54F212104E8E659B45074C06C8FB50EC4D036E78960CF62FC46B532EF68DA6AF"
            + "03D8E8D52301171C6CEDE9EB153B04B54B93BE887A966B25A385CD837B7E2EAE"
            + "C3B5EF7AC7AA06BD36E3C4A2DC3E4656D2E0AA8D4C132EF7CAC986BD11FEE0E1"
            + "CBE8D60CC8E4417D665A4DEA1B780E78410FC9EB6036D1B959D81ED5E42F3840"
            + "CBF76468E84CEFD53B26C016C8E2CB21D1A9B90171D32B6908C602F4D76B085F"
            + "36E92DA8CDF97DB8C2AC96FB74A46401D5507C431E95B3A68DB014B8CD1D8932"
            + "CD0002F0C0F4DB11D7FE499A7C71831F6D88253004B0B8A740205BAF10F3ABF5"
            + "4A8FB76D16BF594EBA33E019E9A8E9821EFE1D0EF9C5C357EAE3F9A45E06D31B"
            + "487BD00E5902D2CE3A6EE33F5FEA0B50E3F54DA53D8F6CF3351BE717F422CBCD"
            + "B1D85570C47560C0E9721D0AD0E5E7BD6C4281B6C7A62F8C5D47BC0548CA14E2"
            + "A8E5A5C537A115B0952806B80607A37ACD52CFDB94AFC71F7C132E9D8BE43E76"
            + "52F2BAD885D5CA244416815288880BDA65369E102DAD6B3FD423F81EB339B2AB"
            + "60D2015FD0D9FE9D027345FF2952EC6568E1B2578CFF7201ABB38F3E755AF173"
            + "5EF46B0754AC7FB4FCD5209890454813DF8E0C26A4E4BE03E7D9464AB36168BB"
            + "2A5CE5EF3C0A8450064200792BD15E969D97AAE987AC0B3F8BC5F23AD0C001DD"
            + "7A2FB1D395F2DD228C2DA695D9079BE3754DA7F97EEE713EEEA20D7894C13FAB"
            + "B6D9B914F7EB3BFFA096BC475996AE6C4D699362D7EEF5FCFE03ED90D6D6C5C0"
            + "5666F328D285917230A934FB1C55EA43CC92B809FE19F21AC6B0D20E6B3A60F7"
            + "132C68A39667087842A52AC84E9A3C2568F64F7C0F01E8D615199DAE1696C4F6"
            + "B00AE3675EA888E789FC0A8A9C57F6F4B5291DE7A99B6678A1A694278D253149"
            + "2A973FB388A125B02737650755AF045F3D74961FC6397D409C08322403D8219D"
            + "1D44ED18A2282C2C726275AF1BB383625CC898E21A765E6DF1491ED37C44BEC7"
            + "3DBED110D4E6E6A471E5C7727ECF078597F8323B2701A2332B33E503521BB789"
            + "0BDC3EE8C62F6C4F99C74C17796F2FA3EB97EFCBB8DA74ED9C96F026A62C79DF"
            + "6257C495589F646B925142529C963DD1B18C2AADE621D90A5247F08F43311385"
            + "EFAB86D1C72C2444502CD5C25050FFB86B392505D533DE67485EEC57DFBAE94C"
            + "96253E5C1EC2591D586E6C0633BBFCA80AB506210CD114C88BC89F86804FF965"
            + "49AE5482833AA78E52BEBEC9009B26A85551802D55007A26D834EC9E72139782"
            + "CDC1048CE222EE1D54B0D65AEC2CD62E3C27DA5C7967224FDA398B728270225C"
            + "96A24FA6314A63A90E5554A707B5EBE4"),
        /* SLH-DSA-SHAKE-128s, ACVP tgId 25 tcId 216 */
        new SigKatVector(SlhDsa.SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s",
            /* sk */
            "1CF0849EEF53F932A4DB4BC1FC236622EF5803E521B3EBE437827EF49961F888"
            + "2E3A575B3E6136284D5ED0B96F5C5469"
            + "3B0A6D8DC6E4ADAC66A546D3EEC7B9BC",
            /* pk */
            "2E3A575B3E6136284D5ED0B96F5C54693B0A6D8DC6E4ADAC66A546D3EEC7B9BC",
            /* context */
            "7E5DAB6CE1962B82363446D0297B41065B1E664E36D38ED69846F9C7EEF86360"
            + "50CA14131640C2F1B34A48D299CB8FF968C95B42A142769371C2ACA488DFCC7E"
            + "06E09CB874A9D0B7600791AC66FF9845EA81A6BB776940EC8289BDE6F723F945"
            + "F6AFD23210797B0E84D2ACE22EF81C2FA9A4C78124C32DD812AC31EFB8548A0C"
            + "E9C0A5832F41EAB103CB7FA4425298B478763B812FE3059C320174FA2B7EDA04"
            + "77EE34C7AC95A5E526F7642A5F5FD986A75D6E925901FB1E885118D42710A968"
            + "F5DF041CD94011E70995832B018EED4AD59B0BD4E7CFE37C0A0E08",
            /* message */
            "BD",
            /* signature */
            "0E6CFDA717823D6E2A571653EB7BBAAF125645D1FCA5F007611D463768C0E63E"
            + "01D052F0872125F08F7191C5550CB832CECDB175E434642F15EB9A31E89C5F83"
            + "1D25BB50630989E75798D2E35266E8630B4B65C163E4EE5253C6694E2047044C"
            + "0F5A399C64E4DBC59EECCCA63D7C01BABAD2436F0A3974130035A670808E90B9"
            + "625C979776B507E9038D5A2626BB2040C568461C3F768F5B25CAD213776E5140"
            + "469BEB15980D628A1F2B3CA067E3C6B7106CED53E1F85E2B5BEDDCC495FB5DA4"
            + "B18FA59B7D12567F5C118DC6BE526DE174E226C3D3A74B45F625CBBB28A609FB"
            + "B77EC6B4DAADF373D46D6569747147AE01CC55F33E3200CBAB1402EC31686947"
            + "33A3F6DDB37423DAD1FED017089DA8282577E24D25DD3FFBFD21351E6FB85D93"
            + "F526F5D73714F1889B12FEF71E723A068669523428000AC29115485B338709D1"
            + "579BA0B71BC8809410877F34894BAF5291B1ECEE49EDDB01D78D469346F9AFB3"
            + "5FF608F19FDD76E069AA026E50EE93CC2058A0B2A2AC9D42E95227C97E782CD1"
            + "AE57D6E0F4E30B4ACF7127814837922596AC9AFFDB4533E96BA51A97324662C8"
            + "DAAB4E24D416A4BC40AA9191600EF7892EC4CEBD8C73C9E12A5FFBD1282EA295"
            + "48D93EA519D2D1B83AFFB130DDC39AA8CF68A32B2DC8CC461E32C2795BA46025"
            + "451EF19268145B88F78F12DF5227F252663BC46B9100B228EEDFDDFF2BB2A1B2"
            + "3302C1D296B461464238461522666040ADD380BBC244DDD15FBA50EA26C90358"
            + "E262F67DEABBA2FC35306E39CE21EBB5CCC2EC88A4882226075EF0A2CE34F89D"
            + "37D1B79C1EC7C244D090417FC53AA134F63A50576888F1C4156C5C03936F7E28"
            + "F37DD00FCFFD93160E9551B2CA138F44EF496F21F8BAB036223419420073C376"
            + "5C2580452E167DCEA2A72428F11769EF8A814BCA1D1B5A47178B23DAB42E84B2"
            + "D820013ECC99C48FC0E6655EC659FB1DD5BB95133575836879C7BC30A7C064AB"
            + "82A929194722E54009BFD739E97DB8F65201B1E9FA80FFE9B2A8CF096DA9B545"
            + "952277CDB7F8F4097D5F54913576E1483DD75696DC01852342B978CF3B0C4661"
            + "6714DEEE9C46D45FC4779D5A94CF590D0A22A4CD6C027727F6FF21DB4E231737"
            + "14ABC54DE9DC1B07D87CDB96A27189C4FEFFD0320455F825A6E309EC1DC4232C"
            + "D36A2FD2EC59C3707B32A9E4AD5DA813CFFD41C97670752BFD0E6209244B9070"
            + "D353FAE44D156B5E7201A1446DE1A7568CE340E3DC517912A8BE174FC79D6FB6"
            + "9BC9957A607932377F569A167A1F002D071A6021B9200951B193451CF1A4559F"
            + "FDF95C8EE567DB50A4DA1E027F0047A3992BC6986A4E5AD8F093C16E13E98510"
            + "F876101AB1404B4450287E9AF605BA468C093C5199A1EB522B6CBFEDE084491C"
            + "D33C811E8DBA036AE357A5252450B74E4121083246A085CB7967A9C339B6AD57"
            + "32EA56D3B717F6113FDE127958FC3C926D5BED56A1E5B55B68F6174BB5031767"
            + "9FCD364A7E93BC84DB717FB5842F029466E677D39372D1884171CC1B012D4810"
            + "EAB84F15DE04D11AF28EBE587FD1140AC61510261A5A51C6AC0620D85710DFBA"
            + "EC4B9FB0436F8946FD486181243DB9324A0C1D2FDDB919FF09901E38FF83A982"
            + "5A8ACE0DA57E0A9D4D74BF4A0EDBBFE28EDAB8B335B5A362CC45D9664F0F3E01"
            + "851258B2BCF7148B696FAD6A0663901F4DAA5D499A1EEFEF2927433DECA33D59"
            + "C27CF651C963934F879341119CBB197A19A9B544C1C1549F5A53C6321208EBED"
            + "B591B8CC5E3936B513AD94D7F45A96C03ECDB97C8536ACCE3FDEE9A7B11C17AB"
            + "32DBD631DF1AD900A671E63E9A3516C4CEF59111E7D0CEC26DEB2D7B43A5DE31"
            + "FC63CAE603B6E2A25C235C3F243830D4F0B085D00D020C7822FC623736857F1C"
            + "1E94AB4A1B2CCAB7CF42FB6C495838EB00274872595E37FE95AA2C9183E9D634"
            + "6F4ECC5BED22B3B93768503DB4B8CB6EEC0935A7E3455CF009260F911B3E6BDB"
            + "FB2D450F62D03478DBD181F19720F0A90AE43D77F68C1C67E15D96D6FAD9299C"
            + "4B8ED4C4E7A17BD45A87759CBF6278748D2F2BEB1ACFC2A19FD423D9DF6A6344"
            + "52342CF148F9354DEE442CBD9FD9BAAA180DFB8A4D480FD94A0C8802DBA4057E"
            + "C994CDCA0C5753419D1233569B07CF2563701BE7CEA0363D52E4A10A3DD5EED0"
            + "0F59CDEB881D193AA153E2597C2C2EF038F0BB4F202D3634DF4AAD9143A5AFFC"
            + "CC2832F0FE44312D73B76659F20EDFBD30CB27563728711D8BA262595CCD6B44"
            + "887AD55239332FF500B0C1EACBBB71A8E194085F8CC5C2D3F13E039BDE34C60F"
            + "D3F91AFC46D881E5017BE6F0B8E3395974E86EC35C8F377CBBCB37823C89287D"
            + "574BD5B795D305771754008805668CD43AE32E1A7D280C38D311AE55ECCBAC37"
            + "0B526AE165354DDCF6DD5001756B3565371FC88E1890119A055B04BE96ACEDF7"
            + "CD61CB196DB51D71AB545CDFDFCFA24B8CCB70EE6B009CBD247EF7380B3ACFC5"
            + "A8372E16B8596BC594EA74F1754F55F496E94EDD5FD18B706CCAE30B067CA286"
            + "EE846C5E7F67C5F776D677E25997F8F1CE2937A55ED5F3A6E2FA04A414808531"
            + "568FCBD3305BEAE2C2593EE8FDE297402988F953BD81E789E2A76BBCF14F5EB7"
            + "6297AF788EC8250D37B47C7F41ABBD6237C1AB4B51F00D67E7FC53CED40B7FDC"
            + "E6CB68072FB691F1EA815F0EC74744E2D63B568923BA0A268D55C99C6EF31B84"
            + "756E80FEDEDD3FF0B063EB585F17615B3D6345F48653C0249D461EE22705DCBD"
            + "BD161509B1545DD0E322D6CF352D548C34C807E38C83D0D5843FF2F1FEF1A0F0"
            + "6E1F5B1FAE12B30B2539CD0B6B2EDFE8D7A8AA61633A2E94A3C0A1BA9902C6B4"
            + "6971CC89CEE027BAAF5E8AE2AEA70555D52DE69E44AB29D8AD28C8FA4FC19827"
            + "3791F718EBB64C2BE06DDEE8E0DA303FA9C89EEC021569C2EB2202274F5F3224"
            + "56BE18BB2A6515490574D0E6BF9C91F9F93D9EA793842CCA0D22D001065C0F5E"
            + "66FAF436DEA7584EF9D33B95776A6009F98D7AD183C17A7F116CB2F1C5FEEFE7"
            + "2670F828839B48CC4D6CD7EB13BB559B933F322C249536C98D5F96DFDBC9D09D"
            + "25C5950F55B1BF2682CFEC7546D64E534B9971C9D39B34C402DA9F61EF330BC6"
            + "ED52EDD6CA1C7F87AD231CBBAC71AF3F7B044616C4510DCC1AE3090C35D70C34"
            + "C908E19869EF289624C8B082CE200AC9B3EC9C28AFFC78A5D7357BC834241E60"
            + "59DE6DDC97C44C8BCE588C00818E0825C6A0884E6995C7FA5D3FA0399EDDCBA4"
            + "948223D9A7806C3A8CA536BDC5CB39371ABBA3785DCEEAAF63601D28EB5BE23A"
            + "75DCAD49EBEA969B9A008644EAFC02686FF6924D69816E25F197F4A5A40C0C2A"
            + "28DEF8AD65FB75B8B1723E05D3B8A4BE0C7A095F7A16D8903F06BD5B86EFDD72"
            + "E94882321147A5E5CB6E620108B5D493330E29F9B6A44D6079D84D37E5854115"
            + "F1061AE4102893B0FAD74F171F5EFD1FC97DFB0061DCE6E06C4EF06B64702B6F"
            + "D2B1B221515176C629CFEABA9B289C889BEEEA04206B7C67B3D3F9366B04E10C"
            + "BE42DF398F4D05C2A14804D71502681D83EC0B0C3265FC50ED61775F8077B904"
            + "0F82E65A1BB6CFE0EE45181A9E2BC2C60018F75BC659EBE18BFF3CC007888E62"
            + "14A5570D466CF883F6B81A7FD66891560B7CCB1FB6871E2E00C2B9D0402C62AB"
            + "96DC5543ED5572BB890EA3259FE4B0B1B004C956A23BF2504109CAF56C0D44CC"
            + "DCA9DD30EE8D2715B127355F69E733651508404F196073BB89804C8CF1295C35"
            + "F34DDD924550516246B612B3078657729BC62E031C09E1301E6F48C5B77704D3"
            + "1B6523CF15C906EABFC4750262DBEFDE07E5D5EE39AA5E4F217A57DB60F68025"
            + "5832C19DB9FD8EECE16CCEB29899657967F494EAFBA3F563C97CAEB302B4E547"
            + "5307368675A57B40258B4100BBE035D8ACFD9EDB75FCB2BBDB235E302994892D"
            + "D7D8DBA28E34941C4055ED76B47A195FF69E2721CCE66B68484EF169FD38D30F"
            + "F2896A64C04A6B9048922E59603B9F00D59FAE799B6C05B5A61EA805C6835481"
            + "C51D2CFF23D3011F7FE8E7D5074120DC5AA084473D74C873BC104111DB37C693"
            + "47684D977CB99C366677AD3EB43AE167A59ED32A85CF3391388A657F2B47252D"
            + "17E3DAE7853F53EA937FE399578E17A79C7457EA713F3B359EDE7A428EC12092"
            + "7DA9D36EDF3699C93148C343DA7876060BEAFA9448A389CBDDBA47C0BF0116A3"
            + "B67AFD546F375DFABD2C4E6DB50D8826D2642EC57EFF9D3024D7419AC917F5AB"
            + "F1785819FD816F3379BDA53A996F6A6716D61F045C4766C2427D174723B2AD0E"
            + "D4FC39E12068A3CCB423F7992046114F74A1B8ADC10579AABF9DDD9AE29CFDD6"
            + "60CDAC11AE86AD4531F09FD482E8DA59146FF3D979FB9C02CF1079C6AF76926A"
            + "2607AFF1B2DE8DADA580CF2B1C27386B2C9AAC7410CEC74BB7E61BC67B9F6918"
            + "3D26896559748D0A42013BC1E55901F5864EEAC6F6FF4225699D663D208866C7"
            + "267AF56E7A08A6867D15FBA1A10186B3867360EB036004A49BF5BF48587D4C94"
            + "7A53F7FCB6834C851B07E69EDE884530BA39BFDA8417F1B596F908ADA78B92ED"
            + "197C780B0D94DA850AE22C07467DB571F10756058A833CA66CEB5FA0CBA507E0"
            + "3375C6500A2D1CBAF4AD02D76A6078CCFB64A7EE59BE0C6FBCF0401CE1245AB3"
            + "7C53D73EE7FCA226976C14F83D8646B39F453B74048579AF327DF5E2DB3C110E"
            + "E85F870BB6A43C85834DDEA234CEC696737BDC28C30F6010E06B350E47B4E0C2"
            + "2E3294F386BF234C4AD80E5C590FB8CB4957F7C56E213982BC1FF17D62AC5332"
            + "EC12C6572165BEFC470D8BBF4E683FD8D1BAED922C1913A8FD7B2AD53F6CB50C"
            + "63ADEA6DF9590023B6AAF61F0548FDC0DCCB549EA98BCAD648052D90C83D5AD5"
            + "EB7F26934F7C18B0870BD8794BE38AFE0D7E676DEC23AEBDD9943D9D824E6438"
            + "755E8BD64C05B6D629944573A0BE2150710A466F241175B2B32638AC25F8062E"
            + "340EDA8785BBCFA986D2EE8B8048C865548A2401D213B21B1423018FD3AFD975"
            + "2479240D40BEDB2923F8E412E8256CB155AAAC5084DBEC0A340AA57F03CE0CC8"
            + "2CD6DC1A72D2A2EB290A062BB9A0C627B532333236C02561F4A2AC086BB6A41C"
            + "EAC0BE53083CF33C1F628FC8925224E2A46931ACB39387252B95DA7D59C9B138"
            + "73784FC9E406A6E33919124EDA7BFC160DFD72ECCA7226F8914062FF8BA508BF"
            + "48A6DC36E37D8F66F91300DD38BF895A624DAF0C518152B94998592FCFC1BA27"
            + "A66C10321A7024029D4A378FF8A98D781D67DA7600E944C1E7FDFB32DE11FF37"
            + "561B7686663AE96EC53816E738ACB4D3E2ECF63B3475694BB3042D8800BA22A9"
            + "AAAB4F29F5D2109D2BED1BBCC52814C7E81109356D6531531EF4E16855045184"
            + "805B35C55CFB812C1266F2ACA066E31AE3A01E93AED4315E6458D5EACDBE1CEA"
            + "B26CE460A94D5C324B21A9A13AE751786D57002510BCD6C9A2B4E053DC50286E"
            + "F7CE9B014A885FB7EBA7D294DCA7AB525124112FDE4AFBBB306ACB83B549FA54"
            + "41F51E958919F741A47F78E925F7FB62BBD1CA8999D482C6F4FACB4E3DC15945"
            + "F2B6F0E838B2F471679BE050623FD4677FB97C9FF38811FC321EE45063981F8F"
            + "060F6F52C959792EADE30EDFCF616D74C7F49C176675F7AAB63EB8208A95800E"
            + "8C040EC19F55F8631499D2829E6B478C3020012F7B5361CA58A54A2314600CDE"
            + "3984E18E83E7923152DF3E875578A90EC76F7F7E7B9390B11078790082F4D846"
            + "5102AA75CBE35AEC1A24DB00E6F4AF8F3CB3B74128373F9CB9FA68C797C5784D"
            + "778F350CA3923AE8DCF833DCA5F71B7B60722D0F0442ECC52D25B5FDA6CE8927"
            + "BAA08925ED95E7CFDF5A17C31661E8A26524B8A595D55BA095AD7EE51198CA07"
            + "7322F2AD24D42CC13C12D3C3BDC0402D8DA0A525A810E4190F2FBDD235C9093C"
            + "4C4D48E56CA9F6B84642F01CCD453BE3AF735757626A8542F10B1B16BE360493"
            + "BAD5CB0C0168E6CA313E0FD7534B2E59CC3A70BEF7F85D5D1FF026E724F951AC"
            + "0B9A661093405898813D9B638BCD5F03930724DF8228119F880962EA5B9A7F56"
            + "D38A5D4DD1169A28A89E9AFF8BE2A25A420B2EC448349EE73CACEC30DC1D08DD"
            + "8CA34BA9E010939617CB8C90B915BA76D652B278CE95F3D32A031B438A92D3B2"
            + "48773B10F01500E21F30CA46871493567C38171C25FF49C7D87344F48BB20E55"
            + "0B25BB026F16F46C432CF21E58B72F435A6F55EA66D0A0792186569041965E04"
            + "1F80EA30B831632F932D5216AF284804C8ABE6E8583B0BF56A72E4E01766C80B"
            + "3D321A9AAD3B500463D3334B6B9829138B8A6002E175FC950C00B93FC6583C1A"
            + "4450FA5EA86C7704A31E6A31FC75571A912495D157F75A7D18AABC193AD325D7"
            + "6A4BF668F4E3095FACC7EE6854AD68CB7513B4F75CC44B2DFB8F6B9B333AB646"
            + "3FA62B50C48A1B287D8574915FE5479AC47B8C334C604AB8948A9CE0A713C126"
            + "0D6FC38D74C68C46FB73E2B999FD4E1B58E1F2B25242A88C719D90492F14A13F"
            + "701CCC2DC08D34A9767AFDC6439B1DB04B10FF53567FE01BCB78D69AC004791A"
            + "4E8261713C9E0ADB2447A3B767DAE1F7C772A880A61D267A85280046ADC4D182"
            + "55194BFC2FD0B319816481C920EB1DB6C9AF488D553DB5760E2AEF22CA2547D5"
            + "FCD19453AE38C70A7B8BCC28846298D2B50DF8DB984075343BEB8C6A9FE1803F"
            + "2CA19D7EF9E8456BFC6D47509880F89FC9E421FFA2F210B70887C43100ACFA34"
            + "AABB4FFC75892C118619D3CD97A34247E13ADFCDAF77C93ABE29C38708DC8D53"
            + "4E3A9C986548ABE220F4DD1232F4C860B10E84C10A81B07B1004D15D35561C7F"
            + "84A76E19F0067C5607F5A89F232086B3A5CA2A0090CB69535F9B143B279E5805"
            + "B09149B8BFBA0A83EB461AD18CED18004B8C48104F3FC659FE4A0A2585870311"
            + "5127CF520DA137719675BF3FCD2A8C7CBAADAF70350D986FADB76A56D4ECF7C5"
            + "A7D004CB5A365B43E23106B915532B4FAAE23E59AC679350248A951342D7F724"
            + "7985D5FE64A76CA135E50B02BE790AFDCD6046C63F7785246BDAA1C38CE41713"
            + "374B1FD26805F1736013F4BBF62B42A91A6785B403E2279C3917EB2B12DCE31B"
            + "A6AB398AE38067A1C08E44CC63829759A2C8C452132626F45860D09C6C6F6848"
            + "461A8E8F8CEAAB7EAD50236519BA4978383DF9AE7853309E25A5F8A80A9B6F23"
            + "0A98D479B02D8BA49A00FA8C68D68ED9977D845223BD6F3F15FD95590B490027"
            + "10D976AD3B619154E40E6AF929AC1F83D9FE29FAEFC338B9D2068E78AF4E9FC2"
            + "F756602EEF967B14FF18D0AFB9A41A14741C333BCEB29BB9D8131A619D616D87"
            + "97BA9EC976897F3053D8725B515C947D031FE401647D935DE302222EE0E8D02F"
            + "7817A199989A82A7CE97BF898B01EEF0E267D21E20C590E0F5DFDC85E2E63FE4"
            + "F1CF19917B123988537706DDAC23985C8D33EAEEC15CA967CE4285C7D44B08E7"
            + "105AE0F40A2D1C349FB02BCA90A93DDD383733B65426813AB52E3F1A9F256245"
            + "6AC15620CFBF8B15E5B50ECC11D187D5EE9E51D68D54761059C0EAE7198A5F7A"
            + "1D5DA6224A3DAA6292606A1919F620CCBF6BC99A5C07823B3DB769448FFA5868"
            + "907413E3E10BEDAAFEA935BA220F0D92DD1A4902302155416D58CB251D96B227"
            + "472B081BE1AFAA95DB4CC12726CE5BBF58663973B7ED62D68F17543DC29F5598"
            + "2BC4E4F451E671D98710EFE7AD3EBAE9A78550A82DB70B04ED1C9D1358967541"
            + "ADA5F24CD4FDAA6A8C1D067CAEE0FA841050FDBA10A41D5C6ACC46E88979BFE1"
            + "420604BAB888F784B1A77DAE715E389A94915CA11B18A4476CFA44C4A7FC42E9"
            + "D38D4AB5B040D5ACB329CD40C244F22BABFAF24D121BF23530BDA82C0328B252"
            + "CA04902750DF076D558F7E9EE813F48ED3B9ECB5F817E957135A03820B7FBEA0"
            + "BE06A24187E72F91D5AEFE7DFF525195F7698A7CCC5744AC50841CDB6F011817"
            + "F5BFC743D67F1CF818F44E5D7BE9434050A8EBF0C250C000383AE5B6AD9A494A"
            + "30E4C6C6DE31DED41F92A56CC94128B9754328F697B73CDC50DC3D50507FAF4C"
            + "776B0B06A07BE33B15BBF4B5A6FBC9004D628D2AC60E483C7078E0B83F19BDE8"
            + "120A6E8B8CA3A28AB7CCF8B973926348716C407A358D709F7C66F49B1CA1F822"
            + "EFFFC2F4122355B28F3DC867F757EFC7A110A5ED567E48C26E64F4FEC248C8C2"
            + "F7A9902A863DF58813152623D529E2799D363FD84AD121C6BE0A523EC7BB206D"
            + "B9AD680663776516AB3EEBCE5F6E39D29DBFEC770DB2462FCBA82EB37D006128"
            + "38E3FF29AF740F1B32AB66FF8571821DE04D485B74B1E1415FA448355114CCB3"
            + "BCD52768251BBB00BABA8CA8B8E5B460231014F2A90FE167E600EC9119A1BD7A"
            + "CA8336E7F53896C8E1F6550D5B7E5DDBFE54D9DB790AE8F5F4B8C2C0174F44B1"
            + "4486C10E4BBF89A02817CBDD18DDC65AFF02C491834B9E0E502076DFB0EC96DF"
            + "B3A72D6C840CA542D9710E8574BBF8A0D9E27CC2C8CB769A73E0435570CD05C1"
            + "22E0BE360B9307DADD454981B629BB7DCA6AB3CD1873FB044000D9289DA790B4"
            + "EB4F534DF2A2CF52FBE5775CCDBB5FF883552D2A8ED2D1EEAFDBFBC5730E9222"
            + "F098A1EFE2DEA5AC6A2E37C71F0698156A679119BE8D0B8E4DAC078A06CF38B7"
            + "B03EB503345A728D44751F91B7AF9573477E65F2D688616E9A6CD83873CAB0E4"
            + "3E4979C916EA2092C4DEF3BDAD50BE50E2A388CD41EEE7E21D174A45E5A44274"
            + "6A9FEEF689EF77DF9DA00EE283197686227CA060ED2EC1FE5FF364816FEF0B53"
            + "0895C39DC5C58BA543AEC1FF0C4EE79049B2CB76B05546FA9125EFF612DC54BA"
            + "602D539135F7A6EB2538CEC6DDBDDABF7A22E8FAFF0DCEBB4AD8B9411CC30918"
            + "0B2BC641ABEE43B159BFEEF49A6C9904A042391821B84A1C852CD1868B4EF6F6"
            + "2EE5173B49AEEFDF885F95FC0CFB496D8D41EB86F695498CBADEFD5D2DA15432"
            + "B49F34E8375A7D357F73AE0984E022BEEFC2CBAA117B27DDB3E084D38260439F"
            + "5438896B90021C8BD623AC3384DAEF133E585A31B1A87207FC27081685549600"
            + "0C5C98A625AF1B1A3EA83649963AD8590663F6C73345F19F145C589D9D53010A"
            + "669707D380660D28EC0E6BD06AA6DCE608B6305FA4FAC9A693FD4AD8B58D66D3"
            + "3FC639FD95800F7495FD0963BB41D9C7F2EAD322478E77033189227A5C6DFAC3"
            + "729CAA8583261E02B977C1A227BE8C6D5B4C010AC2FE1BF2843AD344FC439017"
            + "138658B1E169C560750034D8BC30CB29CAE528391F6DDD043EC18D2440407D39"
            + "80D113491C3E39DFB1AB2082CADF3067E0C5D32A800BAAEC704334BB88225A67"
            + "2A170CD58583B38A3C8F9F9B6F6B66AFF971A88C0A143A465D31C9162916F996"
            + "DDA19B54251BECA336ADA65E7AE9D40F8DA49B7F80FE5F1F0138314114FC0493"
            + "DBDD63EF43546404CD355ECBBBA3F1169C6480BDAEEE8467259A54BE474E7527"
            + "4A692F63EAAA564BD5F85867A850D7B71ADDF4ED05FA2CECC32235115EA26310"
            + "4AABBAD196714543EDA4F7A63D1B37C691DB1C24A82E27FFB532EAA8C1F14EC1"
            + "4D679F0E2AFBB2B730D9F8941E2DB9BB6C0F60E9C98C6CD7CDE94A44C76E9146"
            + "2BB6067C6A2FFED7A87A84A2ABF3575760E0C2BFB4CDE6D498B326358ABBE0B1"
            + "235A1924229444CB0C6B817B7A9A0F5546FE03595385B517418E47879FE1CBB1"
            + "5E29C97D8E30E6E8B8AE6396FF8C7871661B63F6536CD5D7F40B99948A6A7C32"
            + "9EEB98B2E69CFDE6E7335DDED89B3AE39C4FD8BC58895744F65E2BEA882949D3"
            + "794D87521F6C1C8CC5951120D2A20CF7FE72DD80193E0A3A595BCDC6D0DE4DF9"
            + "8AC35146F78E5FEA7E1F2A72B02FA35921954E2EB84DDA9CBC463C932427DC8D"
            + "026679E40FF747468936BF5D4999B766A08B4E49ACAB01E195C6537AB2051A01"
            + "DE59F2F4A4000F98FFE3184A2E196DC652F7C1050C74745FF148386AC44A9BD9"
            + "4BED7E1C2E844373FDA98C49045B7010642FAF1BC94FFF57D8B97725CB113769"
            + "F546A48C311B521210D666DB143E571EF50D8479C4CCFC6FF2805BB88F4D3C86"
            + "9DAB564DB3F3BC9EE47ECFEB10F51CEE5B2ED5358B883A2A43F25B2B9037AD02"
            + "3C5EBB6C79CC4F08F53EA8B82BBA3A85ACA0D2FFDCDD668DE441618A4F60EC04"
            + "841125F776CBBF995234DE622F23688A70C34735C74A109AEA2F62916CECD535"
            + "B48A865C91B57D148D0B1FE7DEDECFDC8732BC20908402873EEF3F3AC9150823"
            + "BB12013D9C8ECFB49B965419710B7F575BC3ECFAB67268F69005DBC4B9658FDD"
            + "0851359AD79A007F068B47B6AD62AB66DF4DC78D3059E29FACEEA7EB47E076E9"
            + "7C7E27EFB9D7A8F65357A2E10BF7C27E823AD3071FFF7D5E76D93E784786A0A8"
            + "11F70ED89072F9E801FF0AC711DF9904820382A8AE96CEDE7099714268A12287"
            + "91F77F93A97E444A8E96D185CA8B102BA2417FB0E054D3A13CA03093D86B5D7E"
            + "B699F4126CA53B8DEF2182E3C1E46C9C0D0DF6C6A033C36283BB7F46D18285B7"
            + "8A12AC1B05DD2398E428188949C5B1994E2A1659184A3CDE28CB39F5021B3A16"
            + "8AD6E65CC95A042C83F312940BD46FFCA84574AFEFE494F0A1E8E68B8AA5771A"
            + "AF66DB233A9673430EC5738CAFA2009E2E48FC75F3CDF9D9F9CFBB74C78A61B7"
            + "709849E16F7162914E76E96A2EDFEEB57671032AF9C19B6DFF2DC80DD12994E1"
            + "FB5F52ADECC864C13672029AD20FFB8D28C5A3E2A7895A2C0AA74DBBDE9AC8B6"
            + "50E38F76A3CFA519195F4C8D552ACBA502FF49C0D69A6067E3829488F18B8AE3"
            + "AE45BD954D667657D70E632923D29FA0CE43A20FECC86CAF72EE201268F259F7"
            + "3397BAB2A249EFFBBB7CDDD5FB3D0762C18B5DC00AECA5D37E3BD34F28B3C2A3"
            + "C5EDE116D378DCBC30ADB53DA25FDC0D2D433ACF8A83AB00B114B1E49013A6AA"
            + "C6F41EFB6C36B5CDCF7C5A877D9E9D6E8C1AFC3C32BB6DBBB603394B20DE41F5"
            + "D1BA85344C5DEE0304BC8182BE60621C15B44D8F83C8FEBD887499BAAB87E144"
            + "140558C3B6EB1B2420203C0513496A24AE6C4B3E4A563967D7EC85FFFC6D6825"
            + "465CE0D89CA4AAECE0E57C8B970C5DB55213E22FB18A3F46EE1556A2F0D3E45A"
            + "6144A0BDC0434772354C0E0A7586E95F"),
    };

    @Test
    public void sigGenKat() {
        assumeEnabled();

        for (SigKatVector v : SIG_KAT_VECTORS) {
            if (!isAvailable(v.param)) {
                continue;
            }
            SlhDsa signer = new SlhDsa(v.param);
            try {
                signer.importPrivateKey(v.sk);
                byte[] sig = signer.signDeterministic(v.msg, v.ctx);
                assertArrayEquals("sigGen KAT, " + v.name,
                    v.expectedSig, sig);
            }
            catch (WolfCryptException e) {
                /* verify-only builds cannot import private keys or sign */
                skipIfNotCompiledIn(e);
            }
            finally {
                signer.releaseNativeStruct();
            }
        }
    }

    @Test
    public void sigVerKat() {
        assumeEnabled();

        for (SigKatVector v : SIG_KAT_VECTORS) {
            if (!isAvailable(v.param)) {
                continue;
            }
            SlhDsa verifier = new SlhDsa(v.param);
            try {
                verifier.importPublicKey(v.pk);
                assertTrue("sigVer KAT, " + v.name,
                    verifier.verify(v.expectedSig, v.msg, v.ctx));

                /* Tampered signature must fail. */
                byte[] bad = v.expectedSig.clone();
                bad[0] ^= 0x01;
                assertFalse("sigVer KAT tampered, " + v.name,
                    verifier.verify(bad, v.msg, v.ctx));
            }
            finally {
                verifier.releaseNativeStruct();
            }
        }
    }
}
