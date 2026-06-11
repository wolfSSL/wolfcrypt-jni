/* MlDsaTest.java
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

import java.util.Arrays;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class MlDsaTest {

    private static final int[] LEVELS = {
        MlDsa.ML_DSA_44, MlDsa.ML_DSA_65, MlDsa.ML_DSA_87
    };

    /* FIPS 204 expected sizes (raw export private excludes pub). */
    private static final int[] EXPECTED_PUB_SIZE  = { 1312, 1952, 2592 };
    private static final int[] EXPECTED_SIG_SIZE  = { 2420, 3309, 4627 };

    private static Rng rng = new Rng();
    private static final Object rngLock = new Object();
    private static boolean mlDsaEnabled = false;

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
        try {
            new MlDsa(MlDsa.ML_DSA_44);
            mlDsaEnabled = true;
            System.out.println("JNI MlDsa Class");

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                System.out.println("ML-DSA test skipped: " + e.getError());
            }
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("ML-DSA not compiled in", mlDsaEnabled);
    }

    /**
     * Skip test if WolfCryptException is NOT_COMPILED_IN, otherwise rethrow.
     */
    private static void skipIfNotCompiledIn(WolfCryptException e) {

        if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
            Assume.assumeNoException(e);
        }
        throw e;
    }

    private static int idx(int level) {
        if (level == MlDsa.ML_DSA_44) return 0;
        if (level == MlDsa.ML_DSA_65) return 1;
        if (level == MlDsa.ML_DSA_87) return 2;
        throw new IllegalArgumentException("bad level: " + level);
    }

    private MlDsa makeKey(int level) {
        MlDsa key = new MlDsa(level);
        synchronized (rngLock) {
            key.makeKey(rng);
        }
        return key;
    }

    @Test
    public void constructorRejectsBadLevel() {
        assumeEnabled();

        try {
            new MlDsa(0);
            fail("expected WolfCryptException for invalid level");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
        }

        try {
            new MlDsa(99);
            fail("expected WolfCryptException for invalid level");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
        }
    }

    @Test
    public void getLevelReturnsConstructorLevel() {
        assumeEnabled();

        for (int level : LEVELS) {
            MlDsa key = new MlDsa(level);
            assertEquals(level, key.getLevel());
            key.releaseNativeStruct();
        }
    }

    @Test
    public void keyAndSignatureSizesMatchSpec() {
        assumeEnabled();

        for (int level : LEVELS) {
            MlDsa key = new MlDsa(level);
            try {
                int i = idx(level);
                assertEquals("pub size, level=" + level,
                    EXPECTED_PUB_SIZE[i], key.publicKeySize());
                assertEquals("sig size, level=" + level,
                    EXPECTED_SIG_SIZE[i], key.signatureSize());
                /* priv_size is impl-defined (pub+key); just sanity-check >0 */
                assertTrue(key.privateKeySize() > 0);
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void signVerifyRoundTripAllLevels() {
        assumeEnabled();

        byte[] msg = "Everyone gets Friday off.".getBytes();

        for (int level : LEVELS) {
            MlDsa key = makeKey(level);
            try {
                byte[] sig;
                synchronized (rngLock) {
                    sig = key.sign(msg, rng);
                }
                assertNotNull(sig);
                assertEquals("sig length, level=" + level,
                    EXPECTED_SIG_SIZE[idx(level)], sig.length);
                assertTrue("verify, level=" + level, key.verify(sig, msg));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void verifyTamperedMsgFails() {
        assumeEnabled();

        byte[] msg = "original message".getBytes();
        MlDsa key = makeKey(MlDsa.ML_DSA_65);

        try {
            byte[] sig;
            synchronized (rngLock) {
                sig = key.sign(msg, rng);
            }
            byte[] tampered = msg.clone();
            tampered[0] ^= (byte)0x01;

            assertFalse(key.verify(sig, tampered));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void verifyTamperedSignatureFails() {
        assumeEnabled();

        byte[] msg = "original message".getBytes();
        MlDsa key = makeKey(MlDsa.ML_DSA_65);

        try {
            byte[] sig;
            synchronized (rngLock) {
                sig = key.sign(msg, rng);
            }
            sig[0] ^= (byte)0xFF;

            boolean res;
            try {
                res = key.verify(sig, msg);
            } catch (WolfCryptException e) {
                /* Some corruptions may fail at decode rather than verify. */
                res = false;
            }
            assertFalse(res);
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signWithContextRequiresMatchingContext() {
        assumeEnabled();

        byte[] msg = "context test".getBytes();
        byte[] ctxA = "context-A".getBytes();
        byte[] ctxB = "context-B".getBytes();

        MlDsa key = makeKey(MlDsa.ML_DSA_65);
        try {
            byte[] sig;
            synchronized (rngLock) {
                sig = key.sign(msg, ctxA, rng);
            }
            assertTrue(key.verify(sig, msg, ctxA));
            assertFalse(key.verify(sig, msg, ctxB));
            /* Empty-context verify of a context-A signature must fail. */
            assertFalse(key.verify(sig, msg));
            /* And vice versa: empty-context sig with explicit ctx must fail. */
            byte[] sig2;
            synchronized (rngLock) {
                sig2 = key.sign(msg, rng);
            }
            assertTrue(key.verify(sig2, msg));
            assertFalse(key.verify(sig2, msg, ctxA));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signRejectsContextLongerThan255() {
        assumeEnabled();

        byte[] msg = "msg".getBytes();
        byte[] tooLong = new byte[MlDsa.ML_DSA_MAX_CTX_LEN + 1];

        MlDsa key = makeKey(MlDsa.ML_DSA_44);
        try {
            try {
                synchronized (rngLock) {
                    key.sign(msg, tooLong, rng);
                }
                fail("expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            /* boundary at 255 must be accepted */
            byte[] maxCtx = new byte[MlDsa.ML_DSA_MAX_CTX_LEN];
            byte[] sig;
            synchronized (rngLock) {
                sig = key.sign(msg, maxCtx, rng);
            }
            assertTrue(key.verify(sig, msg, maxCtx));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void rawExportImportPublicKeyVerifies() {
        assumeEnabled();

        byte[] msg = "raw pub key import".getBytes();

        for (int level : LEVELS) {
            MlDsa signer = makeKey(level);
            MlDsa verifier = null;
            try {
                byte[] sig;
                synchronized (rngLock) {
                    sig = signer.sign(msg, rng);
                }
                byte[] pub = signer.exportPublicKey();
                assertEquals("raw pub size, level=" + level,
                    EXPECTED_PUB_SIZE[idx(level)], pub.length);

                verifier = new MlDsa(level);
                verifier.importPublicKey(pub);
                assertTrue("verify with imported pub, level=" + level,
                    verifier.verify(sig, msg));
            }
            finally {
                signer.releaseNativeStruct();
                if (verifier != null) {
                    verifier.releaseNativeStruct();
                }
            }
        }
    }

    @Test
    public void rawExportImportPrivateKeySigns() {
        assumeEnabled();

        byte[] msg = "raw priv key import".getBytes();

        for (int level : LEVELS) {
            MlDsa orig = makeKey(level);
            MlDsa imported = null;
            try {
                byte[] priv = orig.exportPrivateKey();
                assertNotNull(priv);
                assertTrue(priv.length > 0);

                imported = new MlDsa(level);
                imported.importPrivateKey(priv);

                byte[] sig;
                synchronized (rngLock) {
                    sig = imported.sign(msg, rng);
                }
                /* Verify with original key (which still has the public part) */
                assertTrue("verify with orig pub, level=" + level,
                    orig.verify(sig, msg));
            }
            finally {
                orig.releaseNativeStruct();
                if (imported != null) {
                    imported.releaseNativeStruct();
                }
            }
        }
    }

    @Test
    public void derSpkiRoundTripVerifies() {
        assumeEnabled();

        byte[] msg = "SPKI round trip".getBytes();

        for (int level : LEVELS) {
            MlDsa signer = makeKey(level);
            MlDsa verifier = null;
            try {
                byte[] sig;
                synchronized (rngLock) {
                    sig = signer.sign(msg, rng);
                }
                byte[] spki;
                try {
                    spki = signer.exportPublicKeyDer(true);
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }
                assertNotNull(spki);
                assertTrue("SPKI larger than raw pub, level=" + level,
                    spki.length > EXPECTED_PUB_SIZE[idx(level)]);

                verifier = new MlDsa(level);
                try {
                    verifier.importPublicKeyDer(spki);
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }
                assertTrue("verify with SPKI-imported pub, level=" + level,
                    verifier.verify(sig, msg));
            }
            finally {
                signer.releaseNativeStruct();
                if (verifier != null) {
                    verifier.releaseNativeStruct();
                }
            }
        }
    }

    @Test
    public void derPkcs8RoundTripSignsAndVerifies() {
        assumeEnabled();

        byte[] msg = "PKCS#8 round trip".getBytes();

        for (int level : LEVELS) {
            MlDsa orig = makeKey(level);
            MlDsa imported = null;
            try {
                byte[] pkcs8;
                try {
                    pkcs8 = orig.exportPrivateKeyDer();
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }
                assertNotNull(pkcs8);
                assertTrue(pkcs8.length > 0);

                imported = new MlDsa(level);
                try {
                    imported.importPrivateKeyDer(pkcs8);
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }

                byte[] sig;
                synchronized (rngLock) {
                    sig = imported.sign(msg, rng);
                }
                assertTrue("orig.verify(import-sig), level=" + level,
                    orig.verify(sig, msg));
            }
            finally {
                orig.releaseNativeStruct();
                if (imported != null) {
                    imported.releaseNativeStruct();
                }
            }
        }
    }

    @Test
    public void operationsAfterReleaseFail() {
        assumeEnabled();

        MlDsa key = makeKey(MlDsa.ML_DSA_44);
        key.releaseNativeStruct();

        try {
            synchronized (rngLock) {
                key.sign("msg".getBytes(), rng);
            }
            fail("expected IllegalStateException");
        } catch (IllegalStateException e) {
            /* expected */
        }
    }

    @Test
    public void doubleReleaseIsSafe() {
        assumeEnabled();

        MlDsa key = makeKey(MlDsa.ML_DSA_44);
        key.releaseNativeStruct();
        key.releaseNativeStruct();
    }

    @Test
    public void signWithoutKeyFails() {
        assumeEnabled();

        MlDsa key = new MlDsa(MlDsa.ML_DSA_44);
        try {
            try {
                synchronized (rngLock) {
                    key.sign("msg".getBytes(), rng);
                }
                fail("expected IllegalStateException");
            } catch (IllegalStateException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void importIntoKeyWithExistingKeyFails() {
        assumeEnabled();

        MlDsa key = makeKey(MlDsa.ML_DSA_44);
        try {
            byte[] pub = key.exportPublicKey();
            try {
                key.importPublicKey(pub);
                fail("expected IllegalStateException");
            } catch (IllegalStateException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signWithPublicOnlyKeyFails() {
        assumeEnabled();

        MlDsa signer = makeKey(MlDsa.ML_DSA_65);
        MlDsa pubOnly = null;
        try {
            byte[] pub = signer.exportPublicKey();
            pubOnly = new MlDsa(MlDsa.ML_DSA_65);
            pubOnly.importPublicKey(pub);

            try {
                synchronized (rngLock) {
                    pubOnly.sign("msg".getBytes(), rng);
                }
                fail("expected sign() to fail with public-only key");
            } catch (WolfCryptException e) {
                /* expected -- signing requires private key material */
            }
        }
        finally {
            signer.releaseNativeStruct();
            if (pubOnly != null) {
                pubOnly.releaseNativeStruct();
            }
        }
    }

    @Test
    public void crossLevelRawKeyImportFails() {
        assumeEnabled();

        /* Level-44 raw pubkey (1312 bytes) into a level-87 MlDsa (2592)
         * must fail -- sizes differ and the parameter sets are distinct. */
        MlDsa src = makeKey(MlDsa.ML_DSA_44);
        MlDsa dst = null;
        try {
            byte[] pub44 = src.exportPublicKey();
            dst = new MlDsa(MlDsa.ML_DSA_87);
            try {
                dst.importPublicKey(pub44);
                fail("expected import to fail across parameter sets");
            } catch (WolfCryptException e) {
                /* expected */
            }
        }
        finally {
            src.releaseNativeStruct();
            if (dst != null) {
                dst.releaseNativeStruct();
            }
        }
    }

    @Test
    public void crossLevelSignatureVerifyFails() {
        assumeEnabled();

        byte[] msg = "cross-level".getBytes();

        MlDsa k44 = makeKey(MlDsa.ML_DSA_44);
        MlDsa k87 = makeKey(MlDsa.ML_DSA_87);
        try {
            byte[] sig44;
            synchronized (rngLock) {
                sig44 = k44.sign(msg, rng);
            }
            /* sig44 has length 2420; k87 expects 4627. Verify should
             * cleanly fail (or throw decode error) -- never crash. */
            boolean res;
            try {
                res = k87.verify(sig44, msg);
            } catch (WolfCryptException e) {
                res = false;
            }
            assertFalse("level-44 sig verified by level-87 key", res);
        }
        finally {
            k44.releaseNativeStruct();
            k87.releaseNativeStruct();
        }
    }

    @Test
    public void signVerifyEmptyMessage() {
        assumeEnabled();

        byte[] empty = new byte[0];
        MlDsa key = makeKey(MlDsa.ML_DSA_65);
        try {
            byte[] sig;
            synchronized (rngLock) {
                sig = key.sign(empty, rng);
            }
            assertNotNull(sig);
            assertEquals(EXPECTED_SIG_SIZE[idx(MlDsa.ML_DSA_65)], sig.length);
            assertTrue(key.verify(sig, empty));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signVerifyLargeMessage() {
        assumeEnabled();

        byte[] big = new byte[64 * 1024];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte)(i & 0xFF);
        }

        MlDsa key = makeKey(MlDsa.ML_DSA_65);
        try {
            byte[] sig;
            synchronized (rngLock) {
                sig = key.sign(big, rng);
            }
            assertTrue(key.verify(sig, big));

            /* flip one byte deep in the message; verify must fail */
            big[big.length / 2] ^= (byte)0x01;
            assertFalse(key.verify(sig, big));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void knownAnswerVectorsVerify() {
        assumeEnabled();

        byte[] msg = katMessage();

        /* Each triple: pre-computed (pubKey, sig) from native wolfSSL.
         * Empty context, level wired in via constructor. */
        int[] levels = LEVELS;
        byte[][] pubKeys = {
            ML_DSA_44_PUBKEY,
            ML_DSA_65_PUBKEY,
            ML_DSA_87_PUBKEY,
        };
        byte[][] sigs = {
            ML_DSA_44_SIG,
            ML_DSA_65_SIG,
            ML_DSA_87_SIG,
        };

        for (int i = 0; i < levels.length; i++) {
            int level = levels[i];
            assertEquals("KAT pubkey size, level=" + level,
                EXPECTED_PUB_SIZE[i], pubKeys[i].length);
            assertEquals("KAT sig size, level=" + level,
                EXPECTED_SIG_SIZE[i], sigs[i].length);

            MlDsa key = new MlDsa(level);
            try {
                key.importPublicKey(pubKeys[i]);
                assertTrue("KAT verify failed, level=" + level,
                    key.verify(sigs[i], msg));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void knownAnswerSignatureTamperedFails() {
        assumeEnabled();

        /* Defense-in-depth: same KAT triple, but flip one byte of the sig
         * and confirm verify returns false. */
        byte[] msg = katMessage();
        byte[] tampered = ML_DSA_65_SIG.clone();
        tampered[tampered.length / 2] ^= (byte)0x01;

        MlDsa key = new MlDsa(MlDsa.ML_DSA_65);
        try {
            key.importPublicKey(ML_DSA_65_PUBKEY);
            assertFalse(key.verify(tampered, msg));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void emptyContextEqualsNullContext() {
        assumeEnabled();

        byte[] msg = "ctx-equivalence".getBytes();
        byte[] emptyCtx = new byte[0];

        MlDsa key = makeKey(MlDsa.ML_DSA_65);
        try {
            /* Sign with null ctx, verify with empty-array ctx. */
            byte[] sigNull;
            synchronized (rngLock) {
                sigNull = key.sign(msg, null, rng);
            }
            assertTrue("null-sig verified with empty ctx",
                key.verify(sigNull, msg, emptyCtx));

            /* Sign with empty-array ctx, verify with null ctx. */
            byte[] sigEmpty;
            synchronized (rngLock) {
                sigEmpty = key.sign(msg, emptyCtx, rng);
            }
            assertTrue("empty-array-sig verified with null ctx",
                key.verify(sigEmpty, msg, null));
            assertTrue("empty-array-sig verified via empty-ctx overload",
                key.verify(sigEmpty, msg));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    /** Compute SHA-512 digest using wolfCrypt JNI Sha512. */
    private static byte[] sha512(byte[] data) {
        Sha512 sha = new Sha512();
        try {
            sha.update(data);
            return sha.digest();
        }
        finally {
            sha.releaseNativeStruct();
        }
    }

    @Test
    public void makeKeyFromSeedIsDeterministic() {
        assumeEnabled();

        byte[] seed = new byte[MlDsa.ML_DSA_SEED_LEN];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte)i;
        }

        for (int level : LEVELS) {
            MlDsa a = new MlDsa(level);
            MlDsa b = new MlDsa(level);
            try {
                try {
                    a.makeKeyFromSeed(seed);
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }
                b.makeKeyFromSeed(seed);

                assertArrayEquals("pub deterministic, level=" + level,
                    a.exportPublicKey(), b.exportPublicKey());
                assertArrayEquals("priv deterministic, level=" + level,
                    a.exportPrivateKey(), b.exportPrivateKey());

                byte[] msg = "seeded keygen".getBytes();
                byte[] sig;
                synchronized (rngLock) {
                    sig = a.sign(msg, rng);
                }
                assertTrue("verify, level=" + level, b.verify(sig, msg));
            }
            finally {
                a.releaseNativeStruct();
                b.releaseNativeStruct();
            }
        }
    }

    @Test
    public void makeKeyFromSeedRejectsBadSeedLength() {
        assumeEnabled();

        MlDsa key = new MlDsa(MlDsa.ML_DSA_44);
        try {
            try {
                key.makeKeyFromSeed(new byte[MlDsa.ML_DSA_SEED_LEN - 1]);
                fail("expected IllegalArgumentException for short seed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }

            try {
                key.makeKeyFromSeed(null);
                fail("expected IllegalArgumentException for null seed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signWithSeedIsDeterministic() {
        assumeEnabled();

        byte[] msg = "deterministic signing".getBytes();
        byte[] seed = new byte[MlDsa.ML_DSA_RND_LEN];
        for (int i = 0; i < seed.length; i++) {
            seed[i] = (byte)(0xA5 ^ i);
        }

        MlDsa key = makeKey(MlDsa.ML_DSA_65);
        try {
            byte[] sigA;
            try {
                sigA = key.signWithSeed(msg, null, seed);
            } catch (WolfCryptException e) {
                skipIfNotCompiledIn(e);
                return;
            }
            byte[] sigB = key.signWithSeed(msg, null, seed);

            assertArrayEquals("same seed gives same signature", sigA, sigB);
            assertTrue("seeded sig verifies", key.verify(sigA, msg));

            byte[] seed2 = seed.clone();
            seed2[0] ^= (byte)0x01;
            byte[] sigC = key.signWithSeed(msg, null, seed2);
            assertFalse("different seed gives different signature",
                Arrays.equals(sigA, sigC));
            assertTrue("other-seed sig verifies", key.verify(sigC, msg));

            try {
                key.signWithSeed(msg, null, new byte[16]);
                fail("expected IllegalArgumentException for short seed");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signHashVerifyHashRoundTripAllLevels() {
        assumeEnabled();

        byte[] hash;
        try {
            hash = sha512("HashML-DSA round trip".getBytes());
        } catch (WolfCryptException e) {
            skipIfNotCompiledIn(e);
            return;
        }

        for (int level : LEVELS) {
            MlDsa key = makeKey(level);
            try {
                byte[] sig;
                try {
                    synchronized (rngLock) {
                        sig = key.signHash(hash,
                            WolfCrypt.WC_HASH_TYPE_SHA512, rng);
                    }
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }
                assertNotNull(sig);
                assertEquals("sig length, level=" + level,
                    EXPECTED_SIG_SIZE[idx(level)], sig.length);
                assertTrue("verifyHash, level=" + level,
                    key.verifyHash(sig, hash,
                        WolfCrypt.WC_HASH_TYPE_SHA512));

                byte[] tampered = hash.clone();
                tampered[0] ^= (byte)0x01;
                assertFalse("tampered hash fails, level=" + level,
                    key.verifyHash(sig, tampered,
                        WolfCrypt.WC_HASH_TYPE_SHA512));

                /* HashML-DSA and pure ML-DSA are domain separated, a
                 * pre-hash signature must not verify as a pure signature
                 * over the digest. */
                assertFalse("pre-hash sig not valid as pure sig, level=" +
                    level, key.verify(sig, hash));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void signHashWithSeedIsDeterministic() {
        assumeEnabled();

        byte[] ctx = "hash-ctx".getBytes();
        byte[] seed = new byte[MlDsa.ML_DSA_RND_LEN];

        byte[] hash;
        try {
            hash = sha512("HashML-DSA deterministic".getBytes());
        } catch (WolfCryptException e) {
            skipIfNotCompiledIn(e);
            return;
        }

        MlDsa key = makeKey(MlDsa.ML_DSA_44);
        try {
            byte[] sigA;
            try {
                sigA = key.signHashWithSeed(hash,
                    WolfCrypt.WC_HASH_TYPE_SHA512, ctx, seed);
            } catch (WolfCryptException e) {
                skipIfNotCompiledIn(e);
                return;
            }
            byte[] sigB = key.signHashWithSeed(hash,
                WolfCrypt.WC_HASH_TYPE_SHA512, ctx, seed);

            assertArrayEquals("same seed gives same signature", sigA, sigB);
            assertTrue("seeded pre-hash sig verifies",
                key.verifyHash(sigA, hash, WolfCrypt.WC_HASH_TYPE_SHA512,
                    ctx));
            assertFalse("wrong ctx fails",
                key.verifyHash(sigA, hash, WolfCrypt.WC_HASH_TYPE_SHA512,
                    "other-ctx".getBytes()));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signMuVerifyMuRoundTrip() {
        assumeEnabled();

        byte[] mu = new byte[MlDsa.ML_DSA_MU_LEN];
        for (int i = 0; i < mu.length; i++) {
            mu[i] = (byte)(i * 3);
        }
        byte[] seed = new byte[MlDsa.ML_DSA_RND_LEN];

        for (int level : LEVELS) {
            MlDsa key = makeKey(level);
            try {
                byte[] sig;
                try {
                    sig = key.signMuWithSeed(mu, seed);
                } catch (WolfCryptException e) {
                    /* External mu requires the wc_MlDsaKey API in native
                     * wolfSSL, skip when not available. */
                    skipIfNotCompiledIn(e);
                    return;
                }
                assertNotNull(sig);
                assertEquals("sig length, level=" + level,
                    EXPECTED_SIG_SIZE[idx(level)], sig.length);
                assertTrue("verifyMu, level=" + level,
                    key.verifyMu(sig, mu));

                byte[] tampered = mu.clone();
                tampered[0] ^= (byte)0x01;
                assertFalse("tampered mu fails, level=" + level,
                    key.verifyMu(sig, tampered));
            }
            finally {
                key.releaseNativeStruct();
            }
        }
    }

    @Test
    public void signMuRejectsBadMuLength() {
        assumeEnabled();

        MlDsa key = makeKey(MlDsa.ML_DSA_44);
        try {
            try {
                key.signMuWithSeed(new byte[32],
                    new byte[MlDsa.ML_DSA_RND_LEN]);
                fail("expected IllegalArgumentException for short mu");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                key.verifyMu(new byte[EXPECTED_SIG_SIZE[0]], new byte[32]);
                fail("expected IllegalArgumentException for short mu");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void importKeyPairSignsAndVerifies() {
        assumeEnabled();

        byte[] msg = "key pair import".getBytes();

        for (int level : LEVELS) {
            MlDsa orig = makeKey(level);
            MlDsa imported = null;
            try {
                byte[] pub = orig.exportPublicKey();
                byte[] priv = orig.exportPrivateKey();

                imported = new MlDsa(level);
                try {
                    imported.importKeyPair(priv, pub);
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }

                byte[] sig;
                synchronized (rngLock) {
                    sig = imported.sign(msg, rng);
                }
                assertTrue("orig verifies imported-pair sig, level=" + level,
                    orig.verify(sig, msg));
            }
            finally {
                orig.releaseNativeStruct();
                if (imported != null) {
                    imported.releaseNativeStruct();
                }
            }
        }
    }

    @Test
    public void checkKeyAcceptsValidPairRejectsMismatched() {
        assumeEnabled();

        MlDsa keyA = makeKey(MlDsa.ML_DSA_44);
        MlDsa keyB = makeKey(MlDsa.ML_DSA_44);
        MlDsa mismatched = null;
        try {
            try {
                keyA.checkKey();
            } catch (WolfCryptException e) {
                /* CheckKey requires WOLFSSL_MLDSA_CHECK_KEY in native
                 * wolfSSL, skip when not available. */
                skipIfNotCompiledIn(e);
                return;
            }

            mismatched = new MlDsa(MlDsa.ML_DSA_44);
            try {
                mismatched.importKeyPair(keyA.exportPrivateKey(),
                    keyB.exportPublicKey());
                mismatched.checkKey();
                fail("expected WolfCryptException for mismatched key pair");
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

    @Test
    public void derPkcs8WithoutPublicKeyRoundTrip() {
        assumeEnabled();

        byte[] msg = "PKCS#8 without public".getBytes();

        for (int level : LEVELS) {
            MlDsa orig = makeKey(level);
            MlDsa imported = null;
            try {
                byte[] pkcs8NoPub;
                byte[] pkcs8WithPub;
                try {
                    pkcs8NoPub = orig.exportPrivateKeyDer(false);
                    pkcs8WithPub = orig.exportPrivateKeyDer(true);
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }
                assertNotNull(pkcs8NoPub);
                assertTrue(pkcs8NoPub.length > 0);
                assertTrue("encoding without pub smaller, level=" + level,
                    pkcs8NoPub.length < pkcs8WithPub.length);
                assertArrayEquals(
                    "withPublicKey=true matches exportPrivateKeyDer()",
                    orig.exportPrivateKeyDer(), pkcs8WithPub);

                imported = new MlDsa(level);
                try {
                    imported.importPrivateKeyDer(pkcs8NoPub);
                } catch (WolfCryptException e) {
                    skipIfNotCompiledIn(e);
                    return;
                }

                byte[] sig;
                synchronized (rngLock) {
                    sig = imported.sign(msg, rng);
                }
                assertTrue("orig verifies sig from priv-only import, " +
                    "level=" + level, orig.verify(sig, msg));
            }
            finally {
                orig.releaseNativeStruct();
                if (imported != null) {
                    imported.releaseNativeStruct();
                }
            }
        }
    }

    /* Known-answer tests for the deterministic ML-DSA APIs. Vectors are
     * the ML-DSA-44 deterministic KATs from native wolfSSL
     * tests/api/test_mldsa.c (FIPS 204 final, non-draft). */
    @Test
    public void makeKeyFromSeedMatchesKnownAnswer() {
        assumeEnabled();

        MlDsa key = new MlDsa(MlDsa.ML_DSA_44);
        try {
            try {
                key.makeKeyFromSeed(KAT_SEED_44);
            } catch (WolfCryptException e) {
                skipIfNotCompiledIn(e);
                return;
            }
            assertArrayEquals("seeded keygen public key KAT",
                KAT_PK_44, key.exportPublicKey());
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signWithSeedMatchesKnownAnswer() {
        assumeEnabled();

        MlDsa key = new MlDsa(MlDsa.ML_DSA_44);
        try {
            byte[] sig;
            try {
                key.importPrivateKey(KAT_SK_44);
                sig = key.signWithSeed(KAT_MSG_44, null, KAT_RND_44);
            } catch (WolfCryptException e) {
                skipIfNotCompiledIn(e);
                return;
            }
            assertArrayEquals("seeded sign KAT, empty ctx",
                KAT_SIG_44_CTX0, sig);

            sig = key.signWithSeed(KAT_MSG_44, KAT_CTX_44, KAT_RND_44);
            assertArrayEquals("seeded sign KAT, 33-byte ctx",
                KAT_SIG_44_CTX33, sig);
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void signMuVerifyMuMatchesKnownAnswer() {
        assumeEnabled();

        byte[] zeroSeed = new byte[MlDsa.ML_DSA_RND_LEN];

        MlDsa signer = new MlDsa(MlDsa.ML_DSA_44);
        MlDsa verifier = new MlDsa(MlDsa.ML_DSA_44);
        try {
            byte[] sig;
            try {
                signer.importPrivateKey(KAT_SK_44_MU);
                sig = signer.signMuWithSeed(KAT_MU_44, zeroSeed);
            } catch (WolfCryptException e) {
                /* External mu requires the wc_MlDsaKey API in native
                 * wolfSSL, skip when not available. */
                skipIfNotCompiledIn(e);
                return;
            }
            assertArrayEquals("external mu sign KAT", KAT_SIG_44_MU, sig);

            verifier.importPublicKey(KAT_PK_44_MU);
            assertTrue("external mu verify KAT",
                verifier.verifyMu(KAT_SIG_44_MU, KAT_MU_44));

            byte[] tampered = KAT_MU_44.clone();
            tampered[0] ^= (byte)0x01;
            assertFalse("tampered mu fails KAT verify",
                verifier.verifyMu(KAT_SIG_44_MU, tampered));
        }
        finally {
            signer.releaseNativeStruct();
            verifier.releaseNativeStruct();
        }
    }

    @Test
    public void signHashWithContextRoundTrip() {
        assumeEnabled();

        byte[] ctx = "pre-hash ctx".getBytes();

        byte[] hash;
        try {
            hash = sha512("HashML-DSA with context".getBytes());
        } catch (WolfCryptException e) {
            skipIfNotCompiledIn(e);
            return;
        }

        MlDsa key = makeKey(MlDsa.ML_DSA_65);
        try {
            byte[] sig;
            try {
                synchronized (rngLock) {
                    sig = key.signHash(hash, WolfCrypt.WC_HASH_TYPE_SHA512,
                        ctx, rng);
                }
            } catch (WolfCryptException e) {
                skipIfNotCompiledIn(e);
                return;
            }
            assertTrue("verifyHash with matching ctx",
                key.verifyHash(sig, hash, WolfCrypt.WC_HASH_TYPE_SHA512,
                    ctx));
            assertFalse("verifyHash with missing ctx fails",
                key.verifyHash(sig, hash, WolfCrypt.WC_HASH_TYPE_SHA512));
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void newSignVerifyApisRejectContextLongerThan255() {
        assumeEnabled();

        byte[] longCtx = new byte[MlDsa.ML_DSA_MAX_CTX_LEN + 1];
        byte[] msg = "ctx too long".getBytes();
        byte[] hash = new byte[64];
        byte[] seed = new byte[MlDsa.ML_DSA_RND_LEN];

        MlDsa key = new MlDsa(MlDsa.ML_DSA_44);
        try {
            try {
                key.signWithSeed(msg, longCtx, seed);
                fail("signWithSeed: expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                synchronized (rngLock) {
                    key.signHash(hash, WolfCrypt.WC_HASH_TYPE_SHA512,
                        longCtx, rng);
                }
                fail("signHash: expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                key.signHashWithSeed(hash, WolfCrypt.WC_HASH_TYPE_SHA512,
                    longCtx, seed);
                fail("signHashWithSeed: expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                key.verifyHash(new byte[0], hash,
                    WolfCrypt.WC_HASH_TYPE_SHA512, longCtx);
                fail("verifyHash: expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void seededApisRejectBadSeedLength() {
        assumeEnabled();

        byte[] hash = new byte[64];
        byte[] mu = new byte[MlDsa.ML_DSA_MU_LEN];
        byte[] shortSeed = new byte[MlDsa.ML_DSA_RND_LEN - 1];

        MlDsa key = new MlDsa(MlDsa.ML_DSA_44);
        try {
            try {
                key.signHashWithSeed(hash, WolfCrypt.WC_HASH_TYPE_SHA512,
                    null, shortSeed);
                fail("signHashWithSeed: expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
            try {
                key.signMuWithSeed(mu, shortSeed);
                fail("signMuWithSeed: expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void makeKeyFromSeedRequiresLevelSet() {
        assumeEnabled();

        /* No-arg constructor defers level, raw seeded keygen requires it
         * to be set up front. */
        MlDsa key = new MlDsa();
        try {
            key.makeKeyFromSeed(new byte[MlDsa.ML_DSA_SEED_LEN]);
            fail("expected WolfCryptException for unset level");
        } catch (WolfCryptException e) {
            assertEquals(WolfCryptError.BAD_FUNC_ARG, e.getError());
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    @Test
    public void importKeyPairIntoKeyWithExistingKeyFails() {
        assumeEnabled();

        MlDsa key = makeKey(MlDsa.ML_DSA_44);
        try {
            byte[] priv = key.exportPrivateKey();
            byte[] pub = key.exportPublicKey();
            try {
                key.importKeyPair(priv, pub);
                fail("expected IllegalStateException");
            } catch (IllegalStateException e) {
                /* expected */
            }
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    /* ML-DSA-44 deterministic KAT vectors, extracted from the native
     * wolfSSL KATs in tests/api/test_mldsa.c
     * (test_mldsa_make_key_from_seed, test_mldsa_sign_ctx_kats and
     * test_mldsa_sign_mu_kats). */

    private static final byte[] KAT_SEED_44 = hex(
        "93EF2E6EF1FB08999D142ABE0295482370D3F43BDB254A78E2B0D5168ECA065F");

    private static final byte[] KAT_PK_44 = hex(
        "BC5FF810EB089048B8AB3020A7BD3B16C0E0CA3D6B97E4646C2CCAE0BBF19EF7" +
        "230A19D75ADBDED52DB855E252A719FCBD147BA67B2FAD14ED0E68FDFE8C65BA" +
        "DEACB0911193ADFA8794D78F8E3D662A1C49DA819FD959E7F078F203C456F8B6" +
        "E7C9415898E541C73032DBD619EAF60F8D64F8683DA99ECA51220B0ACA284640" +
        "99F547C02777BD37D84A59BD37ED7A8A92633C75D07C793FE7252B584ABF6A15" +
        "EE14507E5E193F89864D09AC8727A6D0421F0C19F0E2FBFC213D3FBD70F4F976" +
        "2CECFF231E9C8A7628D3F8B0857B032D32DE62FF8ECBF4008289BF34403665F8" +
        "1A081AD5A85A282F99BAB9E5385AFBCCCF44B74C0196C7545527EC3026DA1280" +
        "C4EB37D09CFE3EC4B4910B62EB9815A425C6590FC4AD3FBB225752CC1FC5693F" +
        "187E7DEC4EEFBEB6B91BD91C5E2EA6A91D14D097BE203FBA0BF937C97507DC00" +
        "7C4CAA9B0785892966FF15900924E579D4FBA02BDA87555F073DAE00513E7080" +
        "9ABBC711FBA2E7649577C42AFDC24BF7413E51268AD6DB6113B7D9191AF9D061" +
        "DBDED5D630877650C124F11BC4BDC3FDC6A900F63126F921E838AD0C2275A338" +
        "9A39BD99A134504550101CD3E95E6D1496BE7DE6627DF4FD6C28BBF40B30EFA9" +
        "B5C3D5C85AB14A65C02D6D4781FF13D328608554B6D15ED91289A6D55AAC0C38" +
        "E37706F7355E9A4FDA615B875926BFE5A59D9EF273BF94A07CFA573178F0E004" +
        "B6E1EF0A8349E9BCC01981F2460F0A2743C28D1E138FFB765E7E3397B7913335" +
        "D402FE91806AA8FC819253AF32692FA651E867F5907EF46F00625A030EC904ED" +
        "AB21426D59119D2CAA43BD935DEC0A550C61EE4B279C1CA3A79C79A66E3F2D2F" +
        "ADB00F59A3A438AA44570106073017FA1C8757500109720D125BBA231A0C3635" +
        "0C78086DFDC8D613AECA88C4CCAEB4A44D13ADB3C717D65C82A351B9B6EABF6A" +
        "10F4B4E9623E3A95B4D40A12A818AC6B3822DB82FB05DC4202648B4454689AEB" +
        "69EA325F03E35DEFA54708481420C6D697BB912FCA0D3F192EF297DFE77FF36B" +
        "2103F1AD1AEECED1C814C2CD7EF16BCE476AD04F941AFC79E3295474A4106251" +
        "8C0037860934F0E5E652F72749A698632A0991F613F5CB96CA1178F974F2C4AA" +
        "0CE63DC24E364C92A643B90A5F85A62FD4D8D2B193D29B18BEDE2653FC5D3F24" +
        "F5B2C018DBBCB6EF00F305BF93666BD47FEA9193BC233DB39121442E938DA5DD" +
        "07EE6E879C5B9DFF41ECEE5E0589AE6175FF5EC6F6D2629F56B18B4DE66FCB13" +
        "DF0400A797C92270F69BDEBDDCB88C4248919B56CDA70B8AC4F9429C292DA94D" +
        "6478280764FE2386FC38CB0931458839EF4E7DE8F0689D99805988C7F9611185" +
        "2C8929E5A540D3B78D712DECC396FEF3EC34402184E4FD29F363EA80F6FC50BA" +
        "9A11351ACEEA8FE68D541E1AA5848D9F6E61DFB62B2F23BC5081E82F76226E03" +
        "284982EC48481209B1A7D4C8797E44BFA870B22004DB74BD7D478D5B3614D2B1" +
        "DA7502B398EB9DA80D06461E90E03060446AB4A8238432BFAF752F391791214F" +
        "1E6B63590D536060D1C245307BC5C1BAC4AAA099D36BB6DCBC973CF2E69F2734" +
        "D0F29AEEC4567B99A16BC17C6CDDACEFE49927FB14E7D98DD4263519469CCA3D" +
        "B4679A68CEEDA955592210FC49AA5FBE934CC73D84E4BA5478002D6890989068" +
        "EF8FC98C2532B83BF3CB9EF02893C2152426B9D1A94734DFB4F91135143C9EED" +
        "18FD51AE875D07A23775606A734FBA98C063B4A1622E7FF21AA7E652A3D6C19F" +
        "E0DC6761B7D35302BF214D3079F76051082A875929920DC3B3CB43211A23A43A" +
        "50332FAF1AC2191E717125F63E2586C4D86DCA6BCD3D038F9D3A7B66CBC7DF34");

    private static final byte[] KAT_MSG_44 = hex(
        "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556A" +
        "C8");

    private static final byte[] KAT_RND_44 = hex(
        "6255563BA961772146CA0867678D56787CAD77AB4FC8FCFE9E02DF839C99424D");

    private static final byte[] KAT_CTX_44 = hex(
        "8626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB8F" +
        "AB");

    private static final byte[] KAT_SIG_44_CTX0 = hex(
        "5E716FE13DF971D50BF014CAAA51A545CCADF809EFE0ECE23D4D634158FEDED4" +
        "961C04D23671827FD161A040B302302FE4C00C6173B3B24A578934BD1180D218" +
        "261B5301528A767679C9DCEFC5E6E8F6FE4BE817FC73DF5D12165B61B373C560" +
        "720CA4937575AB5EB64C02B3C951CF4BFA1EC295483AA0559447861A46ACD82B" +
        "93B69B8E00ED6C039CA8B61CBBBD2DC908D2E3CE8D39B0B10CB53FEE75C75DDD" +
        "C48F95049D316DC29E417D16D99736827CCBA54A735E339077996D51AEF03CD7" +
        "758EBFDABAF055D7509979A72792446AE15D209C17CF26766897EDC3EC777082" +
        "185443776B231EFF18E78B066FC4D02EF5C66C50EE86160E37A24484DDAFE63E" +
        "71DFD7CA354F694E191EFA000B8C9F5F80DAB7600A8C07BE1CB11414E6001752" +
        "948175D2B8CFFC811BB86C62893F606233321F4367D0BBB178E09D21767EE90F" +
        "CF482254D3C9C21CDD0FB5325CFCA730AD67D8CC54151C827B953E552940E212" +
        "8488D5F5066F1BCB486838E7DFA0A449257D72E68ADD8E82BAFFF8D8186E4C58" +
        "81B38416ACA3EA318ADC513EBD45A2C735BA0D62AA166C0CC4B938ED037692FD" +
        "A9CEFA168FF73623EF5E3E259C2D5BD7CE1ED4F2CD60795CCE879159F74FF546" +
        "0226F2941838F46F00EFD00A28D1F67E8E8DCFD21FB73EC66FAAC60CF8126876" +
        "EF4A611037C6DCC3AEC0F6C8791BB86C7C33C65289C401D188C5D81902DCD9DA" +
        "0B40A8ACE870AEF8609BCC363D65445474F64FB303BF073062CB7887112D1476" +
        "66410A29D265B196FFBA7E43588D8E8B04FD1ABE9EB5E8F28C566C0FDE2C7721" +
        "AB6AE5A0129A67436CE115F1B934BBC2E2583D60ABFFEF2A81A8DD1E5FEAFB0C" +
        "89E22A9A92D7D2AD4484F99A8BD805A3184A257690C28EC4B32F0551EA844E43" +
        "799CBA61A6217AB9407424A80203884A5AD85A37872701C2E813FBE40CB46971" +
        "FAE472403FC2E9B9D64C06BF8E5476FA490BCA579EBD1A587B65F104C8543A83" +
        "72614695DC257316E583CB95C37D4A4FF488F974B9095BD7A584D34C676FAC04" +
        "6E9B64A6D4A7067E37DB2B2C94DDFD38FC0F7245BBC10D2AFA27307507527333" +
        "C9E4894E51F494FF4112F06167E036EA249461F2816BBBE055C871771F14280E" +
        "87BD2C48D34E6DC115E6CFA491B0E6357867E19CC2C422555AA08AF1C32DD9EC" +
        "A17B5AF75F93062615CFC90B9FED6EA02E75091EAC0381841D4EFFC7301EE3BA" +
        "67B95D00ECB539550DB9209E22E7286CB9AB5F4DFEC9B0870701792C54BEA2F9" +
        "3E8EBD79266AD464D8090A8E684623C114CD9F70A5FB6DF63794F804F981B0B2" +
        "E1F69A5AF4A654D8680BD8720C374B46054585D0C698AFC25A75F13D226D790B" +
        "6958DB89F8299D6E11C0EE4914D34BF2B6436691507C15CD8A568BE4881A75E4" +
        "43911B06D856AA1C11734591076AAB3626CB1264ABAE6849B5CA8EA938C3EA12" +
        "7C4E38CF87DB9B0403FBC385A9E5AAD637B4AB753B3D5D04E92562FA350F24A1" +
        "1F85BE80E8FFFD2CE72ABA38542FE52A9A8BA2C217DD009647A95833D4F49DAC" +
        "CDD6A8CA63484EA17EFA8EA4923294503E9A5B1A1D9910535352E993F0CB0EFD" +
        "A157E16AC660F223ED2C711EC2937D198D69FEBB1FDC81B524340E85AD44BDCF" +
        "20989A2D5EAD92A7D0429ED979951F1E33D2F11E965AF19AC30CCCD1CD46C2F1" +
        "BD8B0641ABA76DA4439F08AA7F8477A7030F20959DA06EEC6A4D7554A270B0C2" +
        "6115A1F715E0E6BD512B44A23E85C352D3DE792791804112F21C9802709AB739" +
        "CD34A425A14C7E59594475871AEC485E17E7BCD806111A4163752816DEB1279C" +
        "C9452A223ED8BD3AB3B2BC30226A3258B7FAC633700862BA76EDF585EC1566AE" +
        "76D691911E959CDDAC1D0B51198DCA2ABDAD19962E591472C00B838413B67B35" +
        "CD543C49C068D71C78276D5333AF030D1BF68CE6DB16D42873CFE35D1C5FE3AC" +
        "9C38416743113A1CACF4160B239650097343DF99AB4DA9011C20083817E46CC9" +
        "41EAC89E58B540DE934F290886FF3A38DD9488847FE56436D407A8FD59775A5C" +
        "BB53CC7F2F9BACEAAF547E697EE920801E9B1FA6F390D7BAAA8B32C1656B61BD" +
        "F27B5C268AE2A2C0CCC10EC549571BB4EF6A1E7B572766904D10903C14B378E7" +
        "F8302BF24050A31883B4FC91B51A75BA788B9394894BA6F428A8C4CBC1776840" +
        "CDA5F86528ECD04795E98440D3592ACF70ECC15F681062650095632F69E8AF4F" +
        "F0EBB71862CD2A123220463FACCA732C66F5DD5F15E7F0FE43FA9C26F39C2496" +
        "680F847A9049B2D52A84B9C197832150C3BBC02BAD4C1807C9B6AA6715580FB5" +
        "45751F9A8D50F6D6788F7296B5D154E793C4C68884101E2F65AB52EDBC95E33F" +
        "87FD1CED922A34886F8E1EF23FF5A4561A0811C85A7DCFE043253EFC336A65E7" +
        "F9A99B7185677E1301D3CDE0576D84A0AE5E6A30DE69C51BC0EE4EE1971A9D6B" +
        "676544DF601E3543929E9B47EB4D6C3C0849615B0CF92E570AE6819324F6CB3D" +
        "F8EEA736F30DB056130FB6978FEF39B0BABF9F1601A006D0246C486FD5365FA9" +
        "25F0AB8BC973263BD134BA14DC0DEF5376F40E2E9833870E127597F242B426D7" +
        "EE53EA004519B6C4A553DC0B110AA8999816370A778A7A1177E8A761B9EB02D5" +
        "F95269B0E09A5DE744474437123FB337BA873C3023138D5612ADD005569CF88F" +
        "40860B1A10D0E5FCB587461AC315F232E0BE8BF76F3D4917E130599E7FCF5C08" +
        "99DD2D9EDCC6FC002F175485499128C2866469B87DD0EAB40ACD395F90469BD0" +
        "3228FC90C2A5F8306CFC3620F69B48217D27B78AA0C561A8F334B62C5BAF6F99" +
        "E2EAE52E8084DDD40D8E3FF06F195DFC9E15AAF1DB7E30F72987190DCF51DD9F" +
        "EA81E8A2A7067A7ED51D4AF32D8D39C9D2C61119EB8362F29A8F5A2A04A1CA52" +
        "AC2C2F72FE02BC34CE04BFC0B1141D68232D6390C1568A1FF9482117E38E040A" +
        "8974D28944FB10DB2F950C3683304E83B018BDEEF9383004DA053201B0ED7B1F" +
        "72D6BE956FD3980ABD00F09704DB002C7787362189F2C806E25A4E510154AE69" +
        "D2ECE22122D09FE27960FF841CF71FF8106DACCBFBC08B7B46006542E3008965" +
        "883B9754779A824D5B520120F8070BBDC6607C184DC3C83EA2062BFE9824A1B3" +
        "108B6021FDF3F7E65EA98D7CF11542339D282A60CEA5364A3390CB0DC063BB72" +
        "992946FA6BCD7087981805B0AFDFA84ACE5DFD6ACEC9BBE0AF77BB47D6AC2B28" +
        "E389E7A804CDFC566C10E363F97346384C8CF320B1C5C2C7B4EF771896B68F8C" +
        "22E7128E73F23B286CBFB6AB8E304A2543F6CA4FB9432684D069CAE9597F3263" +
        "0813162E406E878AA7B9CED2D8F0FB0B17282A2C484A6D777984ACB5BAD2DDEB" +
        "F0F8040E22242B385870767E849FB5BED4F820222C303947676B7C7F8082C0E7" +
        "000000000000000000000000000000000F223240");

    private static final byte[] KAT_SIG_44_CTX33 = hex(
        "CDA4A78CAB6CED4ECFA25627AECE5DCFBA40AB7F29BCCA35517B0EF81714BB1A" +
        "6B6225096523A63B1F41E258D1620881BB0BC90EF179B68387001DE351BFD8F1" +
        "42944FBB23CD16B4F56958E3179F35A17228C248636A96AC1D5FC9ECD11FD3EA" +
        "D2CCACAC24BD6AAA4571A80321BE96B25345B56810D65C87FA80E8B7F0EA1F7A" +
        "CCDEB171753D28725AB6D7C06656B8CED06F1CFD25963C14B857C1BEA064116F" +
        "2530202A9C3A3E8CA75DB407C6704282E950515ADBE201739ED58ACFCFABE7FE" +
        "9B2ACB62F49AACA5FD64AF27890B4763042A8E30B5B120677B349F693ADBBF64" +
        "2ECBB6C11ACAD9F7EAF5EA16D54B245D61091573D50421EAE34B98CCFBDCC6C3" +
        "6E82335FEC44B3761B98D982A7950DE49092AB058075FABDB24AAFB2CBABAD4F" +
        "505FE815021FD7B4BA7002FF09C9C931537EBDF06DA2FA09AF9C3C2BEB7EE913" +
        "B73D843CB7D4C98AA9008CC683233F795A9945BD6AE1C69970A699F822E89431" +
        "EC46C2B7145F170AFD843DF09D93B130CA4477D93BD974913CD6FB75D0C78FA7" +
        "1BD2EDC7DC027DEAFC11CE406C0BEE7D4CDC7795BBBD3F396D5A8C28DC42FE7E" +
        "41AFC9DD702308DC8277D17F5DEC88B34516B1A38C75CB40509DFE59AF0869A1" +
        "5A6E2BCFCCBF0B7045C0BF6DAB17A96949817732AC7A7C81F7B49ED39C95F572" +
        "9CB9A349EF1FD7B7BDE35C108345EBB2BEB36B6097A54C322DD3371500913BE0" +
        "4912746C7A2C400BD15F0B5AAFB23224100F0D1EE7300CF8E1BA86CB92BCC578" +
        "B4AC4E7FFD1E47C2908E09F49227330697BDC1A9463211526FF35A3FBB1E3D9C" +
        "8FCBA49B07EA0891C709C92266970F384D5ECFBBA21CC2C3263F6DEB826272E2" +
        "A39DE63E9F76B84696A77041EAC17988D92BD21DED53D1AD36318AC3AF5A71D7" +
        "8D122E087238C63013889C602953086D051636B9ABF8729B6A1076E382FF1C0B" +
        "327514D3A5B2359B2796E7EFB315D7D44473E20DA51CEDB2D7A958ED746E8D70" +
        "573043869D36FCD454A852EBDEB69947A2413E4BFFDFEA2232D0DDE94BEEF176" +
        "9D4DA88C824697D94F0B21ED536E9D2F284EAFA41BEA9B1923A1CA5A4DF1A2B2" +
        "44E61FADB48A427E4A80617F52CA05D431D91694C47E05BE5BA5362CCCFA0235" +
        "8E6A81C7EF0DD7824C129B2680814B692CB130A8DCED71CEDB24E3E94EE28BA7" +
        "3619676D1F2767C10574FA861E7E5079C6AD057506F6B735C4821CC0657B3951" +
        "D236A5FAC339925CC805D2688F6371210896522ACFCB846A4BEB77C2E6355C71" +
        "4306CCC4F2CF7114D2C57B26C236F141D52FC7234AA8E44D94D2AAADEEE716B2" +
        "CCC023ACD1CACBC7572FD4DAB1E70A340471683C2AD7AC10EDEF3E1FC659E6D8" +
        "30A8447CC3EFD00A16652B64CF644B068BC0D520A6F3F79BD5286D7C6F8CBF39" +
        "F30EF00C2151FA4959D899556E8899DED1E2B4D460EA72E53ED9B5A98B96DD77" +
        "EF3E6A5C968540128932E387F136506654A59BEEAAE649AA6F74EAC026926A3B" +
        "7B7C0E9EDC56A8A150BE1D2AB7F830594F2953C10F2B4C2669D471F4B22A5654" +
        "402C7D0332DFB8F5D159D49314C17EF60E426BEEEFF28164FBA15A04639BDDF1" +
        "433A3F4D8B871429097AA1917E791849E9E4AE84DAAC6A39319F92E4A70A63A7" +
        "DDC919A1F179209E5C5BD15B86BAC2CD393336AEB2F85F2E163BABA6C16629E1" +
        "E88D61B2906C8F5A971547B1990A1D58A04CF432A545E945FD638EB871A69F2C" +
        "754C371D60090DC2C79CD45ABD9885D0D138B544E3F0891CF601F7F1483FFD29" +
        "B9377E9A33BBA63CF715651E26AF1D0207943ED0428FF4B59F63B6B4DC9DEC62" +
        "A990CC913B91096BCE2F833EC625981EBEA1B397777C6B2A9E689861E76A23C2" +
        "81986235BCB800FB28E34CE3D81677BDEAA67EF3BF86E00993A8CFF23C1CF6AF" +
        "9348DB04AB1F49817310744B012414E3997EB3866E1DF6FCD1CA644DA0F20BEE" +
        "2587F97232CD62C5FE918176A0D142E680703900A8E1315D9FAD4374C9602C3B" +
        "5EACF8F4E299E33064C80B65E94ADC84382DD8D675EF538016A21D76761DAA48" +
        "877DB2B5C676E8F42C4253EA86C2ABED54166961638B908EFD26FF2076055996" +
        "4C423CA556C01C9D9FEBBC5583E488C1BB3B6E2B0EA45885D7BB362ABEF21AFE" +
        "8743233B397F90C7E35AE8F225FB09D03F29C664E330B9CD35F733A4314B236B" +
        "20F37BFE00FCE9CB119910804EBA636BF8777CF4ECA5E8F1F1439785B21D43CE" +
        "26C0363095153F316C1F9B97FEA3176B116E3CA6CE83A2A456D1C915F87379A0" +
        "3D68DCFFFE80B1CC600C020914ED582012B488775942A465CE7ACCF088F97A6F" +
        "E85F9BC82A246EA59E9955A8418DB50069186FB1BFFE062FE638353C4F5C4C53" +
        "28D957ADF353A86DDDD1EF332C537CB832FFE7731480AB134B0206BEEF4373A2" +
        "6551C401D54F623FB078D9626AD7872460F3AB10D3A278F2C5C84C7EFDB64F60" +
        "829A451102D74ECF807FEFFF5F83B2FF56F490B63CDAEEB951E66374E1B34DD2" +
        "18974DFCA934DB5B3994117435A53CC6AE318290F26E20338DEEA045A9F1872B" +
        "4CF9F25C5EB0FBE8411F5F8BE19A3724D4E2479D62A83F6FA341EA59067A68D7" +
        "E2972EFBC0776CB07954C246D3BADD1C6BFB0B94AE25A798C4147E59520D116C" +
        "2B9EE76A3F7231EF572ECD59380FD44F4A83193D8041EEFF5869FDB93E72AFF6" +
        "598FC18E7E084130E9F23961D41A994DE8D52963D101A1640301CE8AFA815379" +
        "6C6BCC214C6138890F8A3DCE2993C5AD3CDF7E4C20C520FE0CD05B24EEE01AE4" +
        "0EE32A811D005D1203FA22CA224CBC5DEEDFE2648DC350D20A0B3A6CDDBE8FA2" +
        "62BAC453E8F4335EBBAAC739197523377BA3B5E122371457BDD0A636FA5DEF7C" +
        "EDB1583347695D9C49641028AA5C29D5B197668B849C2576D00D231737C07D57" +
        "330057C8BA32684E04BEE4C2B6ADEAC3A147B7CD7685B94628828D23EF7E9672" +
        "710ED4B3B3A62E03E4EADEB99A877C89F5407006A68AA18CA9E05A49C6274B8B" +
        "D849EB0B369BA45DDA8CB16255E20796521ACAA176C6624A9FFA6D6BE6E57B7A" +
        "7FDE801DB6266B8E38E78D278FB427F5E4B37A1E4D82319F634068FB8CCCB275" +
        "1848A40E3CF77E1F4690A44686D4654F2289B34F3813861AA59D11937905EBEF" +
        "D25D4CA1961DFC17273F5F63DF2BA0D6B882F6DA9EE0AB2674802D0CA3D17CA3" +
        "E3D63E6B21E5C021DC3479BBBC6BC3461D5E7C132BA0B873C85F499796BD9DCA" +
        "3BA569B94C01AB6FDBAF7F31280782993260D681EADA05ED85CA69B7A964EAC8" +
        "D9F3450873710B3C36F144BA22C243E99E4C5C74FA2473832E673EAB80ADC198" +
        "141819304D5669A8B3BBCFD0D1070E141E26293139424358727D82838C9EA2B8" +
        "D3D70D23297B7CB4B5BED6FE0B194D5A6C8D92ACB8D4E4000000000000000000" +
        "000000000000000000000000000000000D222C37");

    private static final byte[] KAT_MU_44 = hex(
        "E78AE81FBFC8EF719AF1AECAC8EA9A9B19424D15F1418EAFD7A76F6AED007825" +
        "2A1FDB9E0C6F00523359F68A30E9C158F1674F1D3459B8C329F48FBF1A22CA91");

    private static final byte[] KAT_SIG_44_MU = hex(
        "A3F1E8D7F3389E080EE300A9F77103703E28C73CD4EC3D62BAF59C1B86D90CE0" +
        "DE85E085C17C1AE8427CB5372B88690CE7EE5AECEDCEC01A3588EE15A610834D" +
        "61C11A7DE8CBA3547A3C43BA26EF5462332D4A2F43076C1E2A6F769E6B742417" +
        "06A81F5D8A59309F97BD8C550CA6C2BF340A366FE5525525B3159E4CBA167250" +
        "F10A45B165B506141A2410EBE15BA33B01DCD018F7CD0215D58276521D601608" +
        "BF44510AB2D46899C69C97F5371CD127CFE8332F8114D5A69A9C61C0916A5A63" +
        "39119D353398F62C78BA4C6B7F3C71645B29F7DC3D2545ED30C1B53E1851A706" +
        "6D24C2435591AB4CDDBD54B0480E8775DB313C706192D8EDBE18E7D3C4BED55E" +
        "46F5F414C5BAB64F2397136E6A86766A203F4638A95D33F7146FC53F4F5BE4F2" +
        "78342388DFB9F1D93E1F3094FB9932B976DA9752BD73D833443FFC9B75E004A3" +
        "370CD4489F72C0D5BAE65F930D0782BB6C06EB9F6AE49F2925AC22C350533EA8" +
        "325E55DE8642637EC4401242B55AC42FE4A3E713BF1F3B9C3AABA9A834521FEE" +
        "B275E725AC8C4F348EB62943F43704E558DEF0D2721EB4C217E797A99D26FA68" +
        "213C8CEAA29E3A186E792B83242CF246071939454750965AA257622472BB9565" +
        "BB2233835110996C21A48241C92DA3A2D9EEC1032792334E2D6F5486767DD8C4" +
        "45DFE1A7B0EBA8565F8999A278B496E456D2EA562EF893049C5FF2706E8E5F17" +
        "D491756339DC67D77F304D2D4B87EAF978FF0AB3AB9DADB3529BEA8C7FA9E663" +
        "8CE570349FF20D90723289642C6514B144F74636D2D8D7844AAB08C49BB76B14" +
        "BE3759EC6F0F1699756E00BE8A7F31E3EC597132A40BDE969A36E28F60162C23" +
        "4737913E302D36979640A83798649FFC86826D6A8C2EF5351291CB5E5231113D" +
        "67239F4F530CF9D0BB8A3BB3F400127B731B960C5690803C6C4423C3D4AC5322" +
        "1070F044E9BB1AA3F21B0E3943EA2C05F7415D487DB14BFCCF768657CD42DFD1" +
        "CC89F1238EE8E491F694C69E516A4A6684CDFCA1B73B5CF9B24C00498DC279C2" +
        "F9E0CC1BD7D8A898A9C713149D8A9CC1D995525155FC3A1D718F236A4AC28B1E" +
        "AC4B2FAA22D3FECE30364BA0E63B3853ECD87641C824A4E6597AD16D34B46A40" +
        "DDA5D58645CC72CD82B59A38691BF453B0DB903EC70B66939352D380939FDE39" +
        "DB7BAEBB8EFDD9FC54F641C5380916BD1B21EDBE33C4B1BD77880506094C41DA" +
        "B71770F03E442FA30C5565C4C00D3482B154B4FF39E26867727BD8604E6148DC" +
        "6502F72882F2B8F5875E917CEAD4EFAFEE248DABFB8DAB59AA85FA526A96CF08" +
        "60472DE3DFAD6F75BD1599B09C75F391361ACF8478F5333A78514087478856C0" +
        "8C1FC29452E618D9E60A9BD4A53AEA3549AEFECBC17C999C2938833BBEC94D33" +
        "16CA9A72FA079F72BA11130638F3C30CD779EE3BCF9AE8BB26032275F978B04A" +
        "65A89F95D6D9B37BE059D17125CE60C1503E2ED5ABF7D327D3C79BC4D3578210" +
        "A4EF2020F58BA00C08ECF03902E4E6D9527E7673485D1586C428EE6E5C47D452" +
        "FDD0BA3CEC59930104A91FF573EB18F7485720CDA567CC9F9C18B7CFF255F208" +
        "8D403FAAB583F285338A0FD2251030DA5AD339B1C09C01EF8E814B0D002106D0" +
        "CF1B9AEA49AAAAA8087B013C9665E90B744436252608C7AC161538BBFEAC0C86" +
        "6ACE712CEAFABDDA5CD25171FEE213AE338DFAFA801C7BE8B279A74ABC6872DB" +
        "5A45337324B1A4E024291CB36A16A0F6045025DC2120ECF03D460C55537DFFDE" +
        "1F4DCB42D6EE1466B5F22F3E47D54645A5C8BA5B7EBD7AC6642EDB3F011E89E3" +
        "48DD44A27BEB1A5710D40208502DDFFD4B00BAED1CDC105AA375CEAEFFA8B375" +
        "5ABC132EEB2013FCE44DA801A16DEF73F28C7BD937B1E3287170EBFE4A4FAF6A" +
        "E13ADF05274D7A90B100168B5D593894FC881F00DC01F5023B1D8E34A6E98672" +
        "7B97016E75F0DDB02AED6822C70DDF521B81F98F741836EC7DE7687E8CC358DC" +
        "C904A05587C7AAAD2E63C9942B19304C35A263C58E80E992BECE2A129784C931" +
        "08973BECD31D9279144B252C6030E616607EFB1B9783D5BFCF881AF315DC5171" +
        "EDF8E0EDC445B496F9D025A7F8D9E441D4B904700260EB17A8104EE8DB6C207F" +
        "4163016DA8408230674C87546F19954AA646438EB3FD86F0C53E678CB66F8A15" +
        "0135F07B67650D6965B83F30CB10B302088EEF9C50904F8523B5FA75C2709B33" +
        "F9EB6933FBBE67875E9F79548BB427F1D777DD329AEA7B977E10B149F245EF47" +
        "A63F34DF0E6CED5D1F8071003E9C6F37602DD7B163B1F80FC6DF99FF5C1A370E" +
        "48BA33A82AAD04AE14B89D9B7DE61AD58A55FB2127C8D5C741B173A1E63F0868" +
        "35F5B285A83AEDE50E3A3D2C875D6EC7664ECF000415D97865770879B36B47EA" +
        "4567E59542DE07D66E41011837F9B5553CB06CDDFE335B53038842AEFDBE02F3" +
        "D532954C5C4BB89B54933F5099FC315ABC139C73653301E004B791F52A0BD4B2" +
        "BFF6552CA5D97E13888078FBDEB9923E0D58DF5EAF29F1603BB9CF487D87624E" +
        "494626383363C0315803F1A0D81CF2C21F1E913455EBBB13EA7E66AF12434C0F" +
        "795722D0848023F5323A536991898C849A8DC3D8F687899C5C1DD86326FA37BC" +
        "9E36755981CCBBA3A12D9D59E71C8CFF614465929FAE1E55FFB81FF9B3D48E03" +
        "23E9491D7471719859EEF87EF36E0C9C87D4A12EEEAC2411ACE1C45B0F4083B8" +
        "FD0B36FFF5FC38557151FD15866F2DE1F5FFCBDD270B9D74505C4F7A4D320D58" +
        "9F48C360FE86F04FFD98FD4FD2D0E5CB57ABAB54C8B52E4584A5A7694DFEA294" +
        "0EDFE63AA989E5AF118E72E0BB04DDE9393881D972C738663EE290B9692AE14B" +
        "934577728C981218EB0777E88B124ABDE30C0B3BE93A24E47A8294886DBF373A" +
        "62F81E13A708FD26BD0BB3EF042A568FA11CBCA57A140EF3E87E445490549CF8" +
        "E339CDA1452D6CFB2A5D1391B225F8E71C4E63B01BDFDDCB631C30A85035DD48" +
        "63ADD889BDF3F31D035F8BE1DFA50B0480704DAC2F88D37E457A4E19BDA9AA21" +
        "91C47D8E1ACF204D300C0782D10B013A6F91373EE643F5E31ECE753F1D3C65DB" +
        "3989A74B304E37D5CCF55AB14586446CEA2FDBFEE92E124C47150858599F6A05" +
        "24A84671D665D5791B6C3BF3596B6D6AA975E76B53BD6381457F59C3FB98C52F" +
        "E2170F0AADFEF4306E10F425904F50B3CAC91A47F275A286FFD9FCAE77AAA603" +
        "D20721654E2E0B00488B27D02896A40004CF6338C955D60D4903FB68DE43245F" +
        "4E40FA1EF21972A40032DB1CBCC366627E391F6D17EB326E4D2071D890415CC3" +
        "04141C3740495457676D71778587C4D9E4EE121E2242666D727AA4C6CFEDEF02" +
        "080F1467BBC2CAEB000124373F4F5F707376B9BBCCDEE2EBFA00000000000000" +
        "00000000000000000000000000000000121F2839");

    private static final byte[] KAT_PK_44_MU = hex(
        "81F55DBACC51EBDE5C5A258C14F554FB3A93E16C783A7E8C608E6EBDD2352F20" +
        "60631399DFE2D97CECFB23DB183E6729A61B6D07CC85D8297C04A05CAB45F2DB" +
        "C87F4AD59A2B4E8629954F11A9F434ED0AE851452CCEFF158C7E1CD7BA3ADDAF" +
        "7DF7EB10423887F9E2C7ABD73ED2F786BA6A509380C2CE482EBCDD630C02DB0B" +
        "7A24B3C4BFF1576DC162993A5F136B2F4FDD1B8241B612598B549C7884EBB736" +
        "5F9F96BCB1993CCAE2837AA9E243378E867B2ACA307B1933FC121722D335D9B1" +
        "5056254111DFFCC67717D377AA3670FCF8DCC5CCC7237C74EF3C409AD5365B4E" +
        "FA2526B79F505C246E144C982F7A676239D8F9D9B46C9031991EAC56D9837118" +
        "558F385B4E4CE94DCE82EE671A7DB63B62AD1BB9109ECFCD66F3CFDAD159BD1A" +
        "8B9D5A88CD263BA8D1F526D9FB341079C708DCFAD0483A061FA57EC0CEF44EB2" +
        "9FEDE3BE4B3F4267B0E31709DA38EC4DD66252E6C91E1E6E254F074E9501FBF2" +
        "5BBA2CEC03AD9B7444D8D04A8CA41B19CBF8213D3AB07562202137F496055418" +
        "167EA7EFD9048FD93E18F40A22EA3126F7798B42F77637E804A17F540EF3F413" +
        "195E48F050C6B714A264A8CF75A7F95D0C73D957340A6C2806588C8AFD638650" +
        "44BAFFF0C01DF43280EA9803B7147ECAC6976BEBC9C9EB3AFA3D73F87EB84E42" +
        "724776BC58D80EC76F9FC112A5025A18E45C79E7F574177201FB82A2D32767B7" +
        "B9C8FB8A6BF389AC825323BC1A11A8FBC8D282EC6868684E9C976BB32D87E9DB" +
        "B786BC2F71FAC030583404FC37665C715FEABD5E74A5BC3E95AB123F163B92EA" +
        "DB4C2C046ECDA58B2986A864A234F69CFB6A4F06809A54AC65C7D30BB3C36255" +
        "9E118B4546C170FC41A1369C4263DF5C6AEBDC4236D85A9767B332BE1F7E1545" +
        "AD3501A1396B86DDAC1BF2DA2F2A7A5AB84815E66873C0F155DB9A91C1F245CD" +
        "82C22420AE6C0A662D8368537FE919696C50FA90FDA30AA30EEA2129693BD1CC" +
        "312A4A6880BCEF57FA1EB15F12B213676D5A0F60447ABB65996A4A5680386B9F" +
        "E81423D39A07CF364869E83CBF8D6EBA2B0C8D6E6A2A0FAB07B561B25C2E08E9" +
        "1361E72064D60587252B00CBDBD8513D267F33916FE5F8A5CD2C55FE97E54B55" +
        "10AEA7F21B8B08C0B425DC3BF561087D1E0410F4249400E887AC54A5A3B622DF" +
        "3749D5D86C330A7DDA54129A238FCF69C21FAA8CEBFF81283D5E585BE2D3BAA9" +
        "C39AE1470ACDE707FB7071F13BE287E63A429C900111E639B5231EF1D6CE2E24" +
        "1D7B605BA729958633D153AF9068D27A4C6714302EE6BAE003143D7AE95103BC" +
        "EA9D87BAEEF9ECB554693A3295BA0DC5BD3187EE36F1BD368C8696084481861B" +
        "D320DCA5870443F15756D234E6CFD288E3645B1520F8AD8B3F1EA4495EC44D5B" +
        "F5FDBD2FDF4E37A970D3BC105CB8C21EF1B8B3E19AA6ADF751E5CC4DEA14D8AB" +
        "880F28CA8FAAC060A16C84DFA4D9B576C099373ED2781438F7440DD7B76A1630" +
        "469572E98CBB45B5C0CE0012F11B0A0999D4EADD6ED910665E8809924202287F" +
        "400F54002A370E21BFD555D5495DAAF23B0F44FF3E941B0D2B1F1AF3C13BC2E1" +
        "087D4093F937E887060CF3F0AFF703F9D74C013ACCB363FACE48D68E0042472A" +
        "C9C3B2A4C76346A6E0D3C2D62F8D5285CA92B2FE4D25625E70DE128ECADD3248" +
        "268404F86A4ED94A18C4643E9752175BF84F643E3B9862F9316BA9495106F995" +
        "E8F4A026F00EB7230F0F4AE23471E614631748DB41EA183D2F44E895C0B4CE70" +
        "ABCD53DA9D1B6147B7A26918DF2582EF2DAE3D59E73F164495E46851D5D5FBFC" +
        "480968E64F05462D89DE3533292669AAEB68AD66D9B175C64DFC62CE203FB4A3");

    private static final byte[] KAT_SK_44 = hex(
        "DC7BC9A2E0B6DC66823AE4FBDE971C0CFC46F9D96BBFBEEBB3470AE0A5A0139F" +
        "F037B84E75537E0A1CF02A517ACFE323FFFFE11DF72E4F38430E0E66A2654B2F" +
        "2EF757DA47649D9F63FA03F1BF6FE6BC7C62971A98A2BD9D36EB0EC43AD4E9D9" +
        "40DF3BB5874F5C92192AA31E0535D3CF70950BBA858D11A688EAF854F63ECFC5" +
        "20C50D624891434265D8B0680C03061040299A104082C0910C8508D1100D44A6" +
        "509408292211125B90508A2688E1302DC4021280028AC302611820851237808A" +
        "000AE2040421B4910BB80550A08051B2511C28428A3672A494504910201BB451" +
        "61424424A75001328181942D62A850023449CA94200B296213156408924C4812" +
        "2100B605030208E0060200A311E1802021116483A62898029291480801083041" +
        "066613200E5B360951400C53000AA08851944842E316704AB2089B9244002512" +
        "1B0309418209C2A0800B290A819851C4340DA4424500A0105B048E6034001389" +
        "28A4422648002C90202D194068E2146D19278A083746E4146914006422C660D3" +
        "A03013242844965014166DA0284DCC462E94367100232E1C114909A204013106" +
        "0A2172C2142ADA000C5A260D13228A62C444E3142D013445980224D33841C030" +
        "8121A621E348720B1984D2C89108B8690887714A2884D496451A9301CA2285DA" +
        "30859AC851DCC00820106060465262302AA224251044640B2842988011540692" +
        "144251D236719BB4900B082890188E41C469E1A469032160E01409D3020C20C8" +
        "8C1CB23164086218476920228CCB847008952802955053327001340588842454" +
        "1041D202881AA84CCAC88181008D0392899AB809D9900C9A1290614065C9322D" +
        "89860C123521CC4266C8360010062411028EA3B44D44023043A0285A002ED198" +
        "0C4882658922441C010212907084226E12134D011902519064113364C91806C2" +
        "C04589262908B63024308CDA022E0C27250B367058162C5116420B4946C12088" +
        "41246C99466A04434E18A86C821661922028639409C30211029520211782D438" +
        "68003460C84688E0160000A32DC0A82824B640831464C81022A2086503234AC8" +
        "122EA098418C2072CC308A62C665093408412682DA4290893285149670812260" +
        "01176D5948428AB88D592051D80892E2C0889044700AC0245A020904218A59C4" +
        "5094441094140820460209270C441020DCC8209212015038250C456E4A166622" +
        "3770DC808CA426412222441BA3618A343099844099C42952046D88146CCB242A" +
        "7CD129A8D333115C62D033B6A8357CF7CD10268AB12F16FCEB7975D0A28A6C48" +
        "22213C9A772DF084AD91A669E2040550FC5E8D0AEB10FAB2375FC9625EF9CD48" +
        "C19631997A1CB6455D2C6286C569C9637ADD0317CE990996B28E51C3F3F717FB" +
        "5907BBDD53961AD3497F2C3C473CCE170906AC4C624A89AA8FBE624D99385E9C" +
        "9548BF05E8CAFD47D2476E41B73001F813726499E88B2B3B6F596CA311657850" +
        "346598994C40E34747161E4E76264DEEF2A3019389D1594C942301AF47B7544C" +
        "23ECDA2DF2DECE81E487D8F3F58EA89CD811D7275807FF1B0369BA86470088C1" +
        "74A3099FDAFBE5FBB4D158801053B2B435D54059E26DEE76D10A7A372F06B0B8" +
        "8B985B32F52052387438BE8DC8BC6AE7369E2DA9AA5E2585F8DE403D091CCB7F" +
        "790D54DDB34C608B0876F2825E9113BE20A2B85867A01BDA53287AC780BCD8B6" +
        "06D2E6D7712C56CE0142D22FE6B786DE544963E134FECEDFAFB83D763061D799" +
        "096A59E30D4472E440AE1FAAABDF42640CE69740CEB9CAE1A9612C21931B74AF" +
        "3F780236123321B205B6EFD6CBB134F4C73D63C0C13E660B59D5920BC33197C3" +
        "55853D8D1CDDC7959F7BC500AC81D985016F5B89A0EEC79B0D9364EAD8E38577" +
        "C2A6549F2D067CB09438FDB21220AEC80F6E22A476F332A2A4A0B7ACBEB9E078" +
        "D2B5A92AE84C924F7CB19FC7DF377BEB6546AF97AA985C747CD111A127A674B4" +
        "C26D89C14485B82E3A498A12D05406FEBD6C4D4B8BC051AB2CB91224B0785383" +
        "74B794B7DD9DDF3AC2B4A671FB7B9CF5ACB78622AE2709EB2DB16943AA24A9C9" +
        "7A81077BC784D25C0EA5991D2DE883798A1F0E78F3361ED6A10DDED81B1D6836" +
        "58331534FD7C01BC0EB00DFC4C3C84F0693046FF806BB200DD7BD4C0E6ABCA3F" +
        "2934B4814FC0E1F8BE615A2DDA7C8A8D06CF9CE8566B40F4A6543B25BACDDC92" +
        "6863FC0FA2007D6D7BF6D18DC98DF696BD0865BF0BE4C492B8043A32DEF8E359" +
        "5BA7DA345252F38F95BE10FD7FB899B498FA01B09DE5D5608EABC44A721AA04C" +
        "4EF1DCB86102AC5F5F79C9708DCF5C5E896EDD8C2C7BDE3FA83E6FFCE22D6617" +
        "4E31657A0B6361585E669D3031952F08631AE1F16FF90B90D0AAD3C6D7E1DD0A" +
        "9C41AB00A6E1C4F96AF9AC5B79FCF821FFC016CB059245FB78DBE6C633D965AA" +
        "AB5333BE07195C4B74B18E4600CE783C0A914EF4281016E80A7C9AA92D0FD789" +
        "879C5E6751125ECB154432311E41CEBD4FAB3A31E4D2CE22D0F8C67737BF8A0D" +
        "D85FE1349D5079A4D5FEB3FEE9378CA47AE46CC58A3F02038CFD53C4CEE9CC42" +
        "70CEBC3D115A39C831E8ED41C4DBE4051B51D7872BA0C2BB163E0085201188EA" +
        "A624A6BEA9400A3A1FCC355A57F15704E61FDA55A5DBAEA8448FA5CB2D377A07" +
        "F58305AD107E844AB4806E5BF99C1F513EE1D0A2ACC04549F0801742169A7797" +
        "1D0ADBFBFE0DD2EE5D16BC461E35748D1F3F6F4598321E8C49E79E740F990359" +
        "858D2729DDE007FCB26FDDA9AA6E2EC4BD736F2836E7E4C83440191C849F6A53" +
        "C72A4F8F830D001EA3B18F3CB4A5BD3CF066032B4932CFD2E62A9B55723FA61C" +
        "688C935518AF6860CD649BFBF1BF5FDC1F36DCAEFAA157438D1CC8D56A150161" +
        "511DF82631F5E88E773E4CE263F276B7B3678D4C6FC75311D411C0D01BFDB595" +
        "BB70552838E1B86517C837D909E772B428599E1FE569F77CE61531FDE6FD31CD" +
        "CE1BDEE4BA467FCBFBB9FEEAAD99FEF67D4906E036C73662DDCE158D4E5D4635" +
        "E5D366F79F31A19D1B3DC4A591B0DF194BB06C18147F41D88D1A409BECDFB67E" +
        "B063D16312266FD51B521BA9115E2E5E2AEAE6EC511CEDE13ED4132FFBE0273F" +
        "6C7039B3874F058804A54809AF60557A21D9B4B831D04156A7C22DCBCDFE14F6" +
        "2437F449CB5EF12BF4251D485496CD835C0C2BC58BD845963DFA76ECD68519C4" +
        "BDAF110BE7AB052876DC3407591568C956EA3BF107C90FD5853A292F59A8D4B5" +
        "8B5D3FDDF29BDBEAC36852E3C69766FE460176A801831292B8E88A74A01ECBBE" +
        "09A7B4D74CFD7FD628841944D9D556DBD60C76F96F07DC53443805EE9AA09365" +
        "DE4FB8179252C6B099B5DD351FDEFC23DBD8090596C5D208FFD2C5661D8E5612" +
        "DD574FC69045C769A969E600D77CFE192F1D3AE911289355C585811491B0CCD7" +
        "3692AB158824AB9EDF8AC8193F0B33E6138B72C6DCD5D344F807B3DA92425037" +
        "DE5EA4EEAD1C795EFFAA145E2ECDD327606EB2609929B9474B2BB04653602555" +
        "C068385E92F06F29CA613CE5B4404F01AB1805DB0ACAA890330D291F40692DF3" +
        "82509302B6DC8668F2C8F2D3A44FD58DCA26E9802794F73D25B3149E6D576441");

    private static final byte[] KAT_SK_44_MU = hex(
        "81F55DBACC51EBDE5C5A258C14F554FB3A93E16C783A7E8C608E6EBDD2352F20" +
        "0C590071D23DDCB80A7EC0C0BC311691E3ECEF93FC4ED11EE2DAA6F7DC26C268" +
        "0CBDE1979A621E46E05F0E8843E4A72042AFEFD90575FE6D11737AA5D95C563C" +
        "FFFB1A4E973ED504DC259FF0DDB2C7F42932077EB763609365BDE7F87BF77548" +
        "1AA64C9988880C274ECB4448A444904C48311A428A1A8925A2184C4AB000C026" +
        "469CA285001600DC480E24A32C24340503075283B68810432A02C01010247144" +
        "92005446129936094C964059229209C78491C40101866959204221A284902640" +
        "E4266CD322665000126190854A102800B06DDAA269124405A248050BB60C0AA8" +
        "315A200DE4C60CA3B6418B386611A54D0A2328D9408C08B54C4128325B8048A3" +
        "427022820948364DDB908153A20D01916C8C802919C3511AA9501426814C2610" +
        "0C33601C45300C20529A3265DA1011122884CB960509A490C2482C60300A6020" +
        "6659166982008A219825093769D1B4648B980C19224C4A2828DAB82564924422" +
        "39808824912449509044209AC2641B270C1A27698B100082067291369084300D" +
        "C8866051C4419A0206614605C4C411A1842C51B441C23686C2302DD3A010E3B8" +
        "649298288B986DCAA644C8323108284DC9364CCA282101450164A609D1068C08" +
        "95709016500A13280CC60112A22D18B08D1B924C628225A394881A926513A388" +
        "0145721A858C08394459063190024D4344524148818904040B30402345891C97" +
        "4060945000871048A62D12B71119B98C20020C44C86162128244080441806551" +
        "C890D0B28809038118004D0C176911974C21A931CB3011C39445E44484C11450" +
        "88364A99006E5430250B8849600071D3148A0228486022304A30919334728480" +
        "20C8382CC9A2041C80881CC62DE0004650840D5BB20D21479223246A93482A44" +
        "40690B916C98A44D5CA2714900049B42120C492D9C18654C90094B24514AA668" +
        "00250890486AC180608B244A64405218384222248911978503A74DE2444C0836" +
        "68A32452A22205628401108104D940709102401B9009210322CB860951041289" +
        "B6245428841C384901231004358019220911A94C43120684482942B649082042" +
        "88B4504346691A012208056E52A48D4982681A39309994440BA92DDB9831A204" +
        "4804062EC0322DCA406110B004D0220A63180AD3A810544862A3942090208242" +
        "38452139861BB948220585CB242E54B86CA2B4691B80508BA48D53142C48286C" +
        "56346C84E99A33277CEE772E7F86622F1EFE520102204D28A7A734A09AAE7CFB" +
        "820EE5EFB999BBA43762ED43E0514143C3EBBA95BF6045C85F1DA9B18D1FF83C" +
        "E43CB498AE2FFEBB259CADAA9E4E396AC373665AC3374C5A17584E015BE662D1" +
        "F190D24925F28D4C9CB493EA5E2011C71A3EE7B4826435A4E99A5CFDBA1E3FD0" +
        "E6044F84142F96585659B9787F6B69B57F3610249A6A9D980A6E5681CF8D77A2" +
        "E45829176B3E3B1514654FB88EA729E4202001A493E95755AE29EDFA5F3E7F33" +
        "92EE6EDCAE5F1BB0F26CF77117C7C347E6FCD44D7E535B6DF0FBF81FF06E14CE" +
        "D3420E3E73515F4CD4DE30ADC26726165147F742A6B1081AF78FF4C62344DCAC" +
        "44FEB974257F13C73AB7C2B6A254537F045E594E53A1392AB92B70018F8737FB" +
        "F224C12B6DC10EAF617A3601F8CBDDEF3A1334F7F3A8C9FA844AEF65A5D774CE" +
        "EF7F99238260FB86D7BA2E4A1572567A9C9C287DCCC2F158586B4E08150C9C12" +
        "55CCBDB8E498BD3600F0A19E274B68F502AA69CC42C3020CF246263513713FC0" +
        "6E931D8282DD7390DEBA085C2591102BC8A9ADE62FE567B8955A72FBD71C2471" +
        "ABB54766E9609EE053B1B80219940C3055893C6FB689D7E4EB8DFAD849E33CFD" +
        "F2AA26C4B5343CC05A73BF590E8D139C885B72F3B11AB22844164B1AF23D1480" +
        "7C3309824C13C7F2CEA79DA36C4CD79603A2695751970398A6E3364727B1F9D7" +
        "0A246E5388E3CD254959A671ED4234109468AD394B28E33B4FC501AFA372D788" +
        "5293D2CFB3D6A9229274D585B0592649B01011086861C904B5F36642C2A9DA39" +
        "3561DE568645E74EB5A025D43B0795211A4A86EB781EF8083F8DA31F93B00321" +
        "5E12A82376DE146598D0455856BB4F25BAE0044D2E63402E0D8F8FAAB15EE795" +
        "E4A99E0FE7F47843014234F4B53BEA6BCF5F246DD5CF85590B1AF1EE97097E4D" +
        "2AE45245DFD2E0C1DF3FAA85B0C8B4527A75CDD1E0E017578B826281A7608E85" +
        "EE10DD161672391F537AA429657C1470A03DE9A6E08529E8954E198DDCE83B6B" +
        "9DE8ABDA230376DD792F0408BE48918901822C3DD69332BCFF343CB18F9CD4DE" +
        "5D593AF9E609A01D8A3D5A682B45807ADCD25793EB7615333EDD3BBF281021E3" +
        "D683C48FEC9B5F85EFE92FDA21646691330671F6E72398B1A826A4C838C69EC3" +
        "34222F8ECCC15BE584098F35A4C35F7ED30D5C46587775746FEBC6E0B1F447DD" +
        "796AEF1E73D77470F713720734964B1FFFB9778C138886834DC84974D9A4567D" +
        "7BA07D8F11089BC025C9A3A832FD84AADA1176867EA24B40E40C5B2B608A4937" +
        "7DB0AD352617B40A5D4E58D2E261CA8F980D83CC90B10B8A458DA987210C62F6" +
        "4BFDBABA73170E459D86E3A110AD9001D67909FEE2E3CA00CBA2E5A0E3526E6E" +
        "5A92A543611EF1631785D88A244EECDF48E38B89538B94026E35DFE0AF0C6AC2" +
        "1D0AF65EAEF1BDD89F04F4766214D78D4E21219E5A8CB51A288EDBBC53784508" +
        "0F5B122DDF70B40C813B2BF1777B70A49842CC0422F8BB08FA759965156151A3" +
        "29B97D1233DCF6B7F17E59E509AD079C6DBC94FCDDDC763AC1E6CF40F7B5EA4D" +
        "71BC7EB59711BD4075F6B7C8B1E5F02C66FA4087E6D9714AEB552A94227179B3" +
        "AC1A4C4EBA9720F8783127302F8B16E1F7887DBF8D3335CFA2E62C6B3C494D77" +
        "9D63FBB3419D2576C711CBC6A72386C6E8827A88338A0B2E614167E02774BF61" +
        "4ED40F75A75B7196225538864A41044228DADDAC4B86E420417F845179A1F436" +
        "022C0D74C867DC25DC846B71EEC079A14C2AA6BB0F11F459BB657DE732521C4F" +
        "C7513039D480249909135A08DFDEB0D4CE2553B9B41E530190F56D52CC523912" +
        "C71B342013289A0E1F24E39D373E20DB9A1988F6BD6497BB021F14B6C630722D" +
        "FF04D320B97774682E1C09930558EB8F9C9112208BD251A393EADBEF6C2FD5F2" +
        "5652D4AB3F384B7CE1078B41555355325F0C2ECDE2F2273F82E3A62157AD4E77" +
        "B43773C81415C5782FAFCEBF98F151DED8FC778E4FA9A63AC2F5BE6C88778FD7" +
        "2EDAAEF04AC681730E635E5013D26F4A6A231A588DA4C8E420EC5D0D5B5D7666" +
        "56F8A8F23D2FD3B220B6129D378928E536DF1373384E257B33B7C84B397E749F" +
        "E5BB8C6F946227BB9CD41BB5CC0C5F16C296D0DF81DD213AF04211E3B56F1BC6" +
        "23D11323423BB6A0751C45987894A0BBBAF904E8483D1223F4968F4BBB949689" +
        "257B3BFE306B7B96FAE923C9DBA8E6BC4A727E41B196010926428CC34E05D373" +
        "A7B1DBD0C09C8A24FC826898FF0FD66256BE42A3CAD1C83FABD9D63FBF9D9866" +
        "250A2646EFF80CF5FBCC5E7057A950E78BF8C9E0414D0B9625F09417701350FD");

    /** 512-byte deterministic message: msg[i] = (byte)i (wraps at 256). */
    private static byte[] katMessage() {
        byte[] m = new byte[512];
        for (int i = 0; i < m.length; i++) {
            m[i] = (byte)i;
        }
        return m;
    }

    /** Decode hex string to bytes, short local alias of Util.h2b()
     * to keep the KAT vector declarations below readable. */
    private static byte[] hex(String s) {
        return Util.h2b(s);
    }

    private static final byte[] ML_DSA_44_PUBKEY = hex(
        "d8acafd82e142378f70d9a042b924867605534d9ac0bc41f46e885b92e1b103a" +
        "757ac2bc76f06d05a47848842669bd261d7360aa579d8c66b119ea11ffbbf6eb" +
        "2626ac7874466d516e92df6a9841e910f2cca87a50db1f4c4219d5bc76206f2f" +
        "bfc2c91b02b5b10946068702ac3dcfc3a51bf0ced49e84343c247d89f3bf9c18" +
        "9d1b1dd4f6dac9a414c46bd7056ded54426b5f6d1eda6b4770e54ee72506f828" +
        "2434d6e5bec54f9e5d33fcefe4e95567931f2e113a2ef2bb82098db209f32fef" +
        "6f38c656f2230863997f4ec09d089da1596ee1002c99ec832f12972f75046744" +
        "b595cec63e7a10775ebe9c0fb3c738bf9e358fe48d19c341b10b8c109a58ec4f" +
        "b3e95b724bb899349acdb069d067ef96b9e55492b71a52f60ac2238d4fad00ae" +
        "0f97face96bae77455d4afbfa132912d039fe3108c775d2676f18790f020d1ea" +
        "f7a4e82c321c55c05dc9cd4e8f0def0a27b64fa4d3a4ed3322a1d315ac1a204e" +
        "288c8cd071d1f2db3363b6a4f2173c12b0adef3191fee55399b68563fae6cdf6" +
        "b9ce4a7d4a4929d2d9c9474a8a5c145e0f7cc391b0ab37f5268d467449ad51c3" +
        "11fa8515a584c1e03c136d13a3e6a83c22ac1748577c81e24ed8335d4d65f7e1" +
        "b800780916b00bca150dcd9ad8474c9b69b2a09d9696526d89adff55de7bd63d" +
        "1d5e8df1fc481c505955b907fd6bcb95a61473db40401c44e6793088bda0de9b" +
        "b876f898564bb97af6d473896bf77d0533beb61c4da7123b3fed4a0faea76a26" +
        "0d018484a80ec1c1fde4a9e23fabce20908679a240d0ef79342be8c954a71962" +
        "cc20793f5b9c61c2c1d2367c8ee301bec4b2b80751235b5d00e67fd6bb32a97e" +
        "b430eb5e6dedb2c38881a33b1f1ef94810d601655f6dc5eb765f1079aac086e7" +
        "4495444b540c462a98016ec0b9592aff8fb38015eccd3936d72f209e3ac190e5" +
        "992716d76c301012033edcb90325b08a274d1a323654c0ba22b2e2f6392303c4" +
        "c9e40d99fb98a59b129b5844749f656151ba31609cecf84d3661d1336da62875" +
        "ba7c82cb7ebe8f2d2184b9f24e7b959911f3e1c06a44ae11cb04a0f23e17dfb2" +
        "6adf5cf38af8908664ea0a327f9f90a89d3312a6a4e774a075a965f839ae1432" +
        "79ccaa348655cc99b700058be3762812b62a3e448df4baeff6dc2908297dd11d" +
        "1715b6b65867d5d312054eb0c383e035306059a0c5975b81d3686c8c1728a924" +
        "4f8020a5219f8f15892d87ae2ecc733e0643bcb31ba672aaa3aabb6f2d6860cf" +
        "0594253e59f364615e789a7e0d50457851ab11b1c695fc2928109c1a8c37b54f" +
        "0eed4a286caab70d12fa875dd49ab72b4690584ed78b411bf8c4c2dedaec61e7" +
        "bf11dd6e4e6ad48701e4ace8af2b01e10920e0bd7d037323df7771a4258b0a93" +
        "4932451aa49431612e17398a66c9f9202d6a972fe726d8014265cfced42441fb" +
        "9b6ff1c29ed5080cdc4d8eaecb5fd4cd7cf682c6eef9883a340704b48469b3a4" +
        "67ab09c083fe59af182cc809c1bb137cce015d85aa1028a296986923a3e767bc" +
        "7c7ede4b36ab94d2b8f9dfeea169a1c8e98321ac1b39f76dbf8cdbd62fc93c3d" +
        "50cf7fbe4a8dd814ad69b03e8aafebd91a154ae4ddd9b2f86be2429e2916fc85" +
        "9c474b1f3d7b8ce16da3b80ae6fa27fe5272ab3aa658d753af9fee0385fca47a" +
        "72297e62280879a8b8c7518daa402d4ad947b4a8a20a43d0e04a39a306089ae2" +
        "f3f2f8b99f6332a0650bb05096a6a87a18dd6cd19bd94e768ffb22a61d29fcb8" +
        "4729b6d1b1634a361b10e64c65681fad4f7d6b0141185fba3da6542858d58160" +
        "df8476002153ebd3a6ec7d3cb8cd914c2f4b2e234c0f0fe014a5e7e5708d8b9c");

    private static final byte[] ML_DSA_44_SIG = hex(
        "273b58a0cf00295e1a63bfb49716a19c78d133dc72dea3fcf409b109163f8072" +
        "22686568b9805a4a0d7349e1c6deca084fcaf8b2f8453b6b8c6cfd3af4dede82" +
        "d804be4f4adb9247832dc455ed204f71b158d97073bdb03ab48fd69e32982b9e" +
        "ff2a7ccb051b8ee63a45c67ac8af62d304fa694fda1b74160db31aee71d7b0ef" +
        "69f5e2e9c2cc1566280aace26306b7210dd85c9463fd51189f07193da25040d3" +
        "e905d4111315aa46da3e5fcd3cfa42ba794ab74391a5cbbceb3794f19cb9db41" +
        "06d87b5e90e33c8a10629a152778ed69112cb5b4dbc87050624796cbd9b23e59" +
        "2f1caccbcf22c29bc792e94d8d5dcf06537ef44efe9e415d008c08f40279331c" +
        "271de394ace687a008b4600cff47dc163a1d89c06aa43d7133dd1e70fed48bed" +
        "7c91e4e21506c1832455a72a9f4ed9567a95a8ddc4f0713a9965314bb7962c53" +
        "5483ecc9972f0ca48fbb939deaaef9cbb2b9a3615f778cb65a56be5f85d1b50a" +
        "53e2c7bf768b976f10dd1f44696603c46b59f7b4c112cc0070e8bd4428f5fa96" +
        "f359ed8167e0be4775b3a89f21702e6fef54113f34af0d735b9e6d8658b734c2" +
        "c2b364d59b6eb9996ae4fdc317f310fc6ef565e19c59151100ea9681699b054d" +
        "f3cef3f0a9013f13bbb0acc3921c2b61e30122454a231980cab9ef4e7652c59d" +
        "913317c428835561497204aaf8e34b20f76a745664f9b3c9675b55299a89a514" +
        "67ea6d6ade98587325a3dbed3d62aae0797fa3d9b54ce9a8dffd593142819eb7" +
        "813f0efbef80719db7a5fcb180c97e31d947e2ca107bd1a11c28c77f5126b14e" +
        "57dd7d765c5a85a77b8cc56eac20f84916d664f5f42c32a15dfb87b614fe687c" +
        "4dced794f98bf061fde0837f13ec7ab74104516e30a201f73012ecd28f73e78e" +
        "12b4e5c1ffdf6714b1e9ba361918f4aae0e49dcde8e72b33b3dcb919d7ada468" +
        "cd8377983649d93220fdfc34e754d9b505ab0e080e168a7d914caa19043735a5" +
        "ab6ceec490f05fc7ae82fd5953e5365a56376169dae58ffd2ed49c7fb639a48d" +
        "0aab820ffe8469448aa6d039f97268e797d86c7bec858c52c997bbc47a672260" +
        "469f16f1670e1b507cc42915bc556a67f6a88566899fff3828aa8791cede8d45" +
        "5ca12595e286dda1876a0aa83e630e21a56e084d07b626a892dbed1301c3bacf" +
        "ad01bce5c0babe7c75f1b9fed3f0a52c8e10ff99cbe22ddc2f7600f8517ccc52" +
        "160f1898ea34067fb72ee940f02d303dc0674ce66340414296bb0bd6c91c227a" +
        "a94dcc5baa03c63b1e2f11ae346f0ce9169c823b904c0ef0f97f02cab9a9496d" +
        "2773d0bf156152bcd631592b525baf3cc08fdcd52c1de4e941e8d335d6b1f332" +
        "e052087399b66bbc26fb2ea7b7cd14f0f9e53ad0055b2b38bd7cdad41545fa3b" +
        "6f948e22cefa53e05fa69d1c26918aab725b187869983f8d337c21939ef0afb7" +
        "30c8acbcdb9c29176b9d0f16d6c0cc3bce11e964c8d44c987c8ff15e84e472f9" +
        "69f59dad953bfb6d307e0a475b26b24eeb1ac33716287962b436854a155ac36e" +
        "be7e00e94aa5d790cf59632d2bc2c647e677b76e9bc80d182b452bc95a6eb450" +
        "a5237d17cc49e2b3f46db4b7bb9edd209919f5531fd0ff67f38e6acd2a6e2b0a" +
        "90d7dbe1ff1c40a1b05d944d201401a1a8d115d2d91bbfc28ad002f616a1b740" +
        "e03688c8170af0b60d3c53b951edef206ff30cb5ce0e9efd0f5e3f8f3cb72adb" +
        "c6a7f2116edc0533d4d8b02d8ae5398200497dfd3229bb795dcb217b2d365873" +
        "525752964d8961f4ad1f48d57a4aaa1ca1f4b49c433b9572d00e358226d42ee3" +
        "8396975a7bfc48173cba9e5f461a53e32e787980f62d24cf62b686ebeeecf21d" +
        "00c8289d9316a7d91147e3c4b6c4a09983c117d88ede691dcbdde7866ff23607" +
        "23860de9ad87ae76989551f2b311c534f00cf8299c844f814985632516b0c3aa" +
        "d78a2e4b976074f8a739ec6c2c9b333a11bda6904865b1e73853471b62d5b7a8" +
        "d4aef512061254a2cef16b3ada632e372a25893098771d4b5a1eb73ded19ec9f" +
        "6446a82a79f370399f8cc328cc2ac0d0e680f50178727fe72e7b5f05c3413307" +
        "db9ca896a7212023d059390619a429e572396923e3fa2863f5423bca885d7e47" +
        "93a88c75f219444315390342d81d81308e84312475674ebefe0ad8c3e75be1d5" +
        "126a6999cd35ca220265b30f50b6aac6915c4dd4079346f0cce19214912143c4" +
        "ba451c4729dfff8960ee891ec3b4b90bc97ed915b08091beb9434812868e7938" +
        "4dce367fc3e8b7b992bf272054c805633bf5481aa9046cb60e11eaf359b9a6f6" +
        "f80b15ed30f9e4e5262dbbc65b36bb73a64ff5439fd7b90fbc4f8db8ec1d4219" +
        "5637c4cbd01685ffd39befc87537d192ad21941e9af62f6d30ba37c3dc11e079" +
        "a4921fe4aa7a6b2ae404b7f98695dba8fc8a53213114f74001784e7318b354d7" +
        "a693f070041ce02befeed464a7d99f814fe51ebe6ed2f63abacf8c962a3df7e5" +
        "5c59409ce3f92b6d3df26f81d6ab9cabc6f78faae571e3c98c1aebc587e7b0de" +
        "18baaa1eda123216943a6e4f84068e33f7fa35b845e45e9e46057af7f499adb9" +
        "dd55d9523b93e39b541be6a970d348f93ddb886366a0ab72836e8f789d554621" +
        "ca7cb75d16e8663b7baafe9c9c33c9c2a43c7897f35bc22936986828fe0aae6f" +
        "e5f7fb9df88cd9d04dfec7d0b0e39cdbac9e1b557e24fec412cbc2dd0ada3140" +
        "41b7fc3f6de2d38a0f21333abca76218b3af48c6e2a3dd1d2062e44b816b3ac5" +
        "b107e1f1e1baf601c6f2eac09773791906aa6242cb215f08977d72b5394d99e3" +
        "a23fb9b4edf46135e150fb567c35fd448a5722ed3033c30bf188e44446f5736d" +
        "9b988892f534851866ef70be7bc10f1c782d42132d2f4d408ee26fe004db58bc" +
        "6580bafc89eef378b2d978936dbfd47424f45c37890c14d5bdc5fc37e88be0c5" +
        "89c970b37646ce0d7c3da45d029503ba24aaf7d0753578279c6d2aefaaac85ef" +
        "8dfcc0fc7202f4a3d387fc4dce3dcbc2745bb083c57272d6a1674da1d6aae79b" +
        "e7c0fd869108fa482f50ce17ea1ce39035e66cc9667d5132200c2d4ba1bf7887" +
        "e15a280e9a85f67e3960bc64425df00ad73ebba06d7cfa75ee3439230ebd5019" +
        "7a2ab7173a8bb7b6f4d847716b211b56ccfb7b81994688234049668bac84168a" +
        "86ae38c45b1f2bfaf28b81c12261616c43168c1d37b2af3c3a9033edf50878fd" +
        "5aded3386dd71c23ebb49b8ec248478e84bbc4d0ccf9555a57b9995282213b83" +
        "da8fa3889c57e04bc1cebed3eaddf207c1736fc05e8e8572ab2fa9ac39ee0534" +
        "13161b1c2124414978878b979c9fa3a8b9bcc6ccf2fd182a46585a88a2b5ccd2" +
        "dae1e30d20232b2f47575e6487979ca7aabcc1e4e5ea0b163b3c3e4558636a6f" +
        "7c8c8d92999cadb5b7ce0000000000001623364a");

    private static final byte[] ML_DSA_65_PUBKEY = hex(
        "2c32fa5971164a0e450f21fd65ee50b0bfea8e4ea25571a6654856208a489dd7" +
        "c92c806288684d5fbe5fe5f5a475b68826ae7d114389cde9670c910bd1d88b7b" +
        "737594c1c961c73521992eabe0df4dac0dd0a2615f040883665c67470cab2cb7" +
        "6d0e324c8c2580f5e57e3ba1c6c587d868b2d567f95a8b88f8cd0cda4ffcd2af" +
        "b2a23821f9d8f11c8db4e8fb763687f47d03c406ab87ac52e8d5f763f0a80b95" +
        "bd07f11d337b8a2cef85bef8c14ba2b0e07a85fa523605a7654a0c215cc04f18" +
        "b86602e6d0456056fc4094b5a52bc757c3c530721c4c2ad575ae439f0171ac5c" +
        "df9c0a3cb589079b28253131c5b724532c3c2a96e50da297a7089d31c0cd53d5" +
        "a858a6ac432dac39012c60f68286d0afad613f8280a1e112836e1d5efec61e2a" +
        "7a44cdc20af5c8723e29c70ad14c17dd1fb69534c26cdc63d17eb05206186cb1" +
        "996abe42a9c022cc0911841f169a0edd187a3934b04944cb881f9193493fcc62" +
        "563315cb029b33e8d7ab51c091e09cd2f952050cbff19742fed0322734f8822d" +
        "653a36ced107823a6aaa56f19b98ca8e55ffa074d66a42aa0ad45974fbd4db14" +
        "10eeca788383959b77f19a48e08fa45a4da93f32784a25969c200acc5bd8ca19" +
        "4777b87c513ed630db45b0e69d6fc50a5d5f55cd0f20227e0999acb89c9df73e" +
        "7e07d7bc21768c278194ab574ae2911ca4774ad296529d33b55870d7ff22e814" +
        "ead08cd40608d873664b9341c9735b075f31c525987b7ba526839422421c51e6" +
        "8048cad453403aee2c2907eddf974419e5e535661fbd29770c156c950881e076" +
        "865e6d77787607dd219759dbd4bdb64c3f0793b64acef70886fd9c03089400ea" +
        "4bd61e17fbb5bade2595e7f8979e99ae5dddf6321af24fcf0c1755b8fbaec846" +
        "b03e862b5eef36ca24ed325bc8fb88356a26fe06540c3e2c71df98f0bbb2e09d" +
        "f7ebce07fac4ab88c314336048cf392690acfa396f2d9d6d157f846b0a1cf46c" +
        "786252932c7e9f4a517a2eadeae4e59c1515284d3e5eb43bff81e056443333d9" +
        "4bb22360ed0da54e9f7dbc6e3af97e164766b16cc726629b3c53b3a116623164" +
        "d2bb285ce821c3fcc36da7354d57e0bd541a84f79c8a543d59b3a2463b16483b" +
        "3a3c5e88c360637eca68b72f2bb5622e5189be78f7fa19ccca879af5ef0d2108" +
        "3bd69a94c5d11ba97cc89f9ab0b8f7021231705252dab59a0820c3c40c6a3458" +
        "759bdc1a6a37429f1670bb3986bd099c0444be1ae5e9509b14504f00bab0f636" +
        "4d691611405a4e8b39b4f1b211362f0215ca78de75076472fdd448ddfbf58a3d" +
        "a88e14d169e3215039fdd03ba022615c7e8891e1f0f61623dbdb500e39cc86f1" +
        "ab8960b0ac28c657e4eea91bae78c5671aebb343bcea110c64f6d252a07ecd6d" +
        "848cf880b7db26914aa061692f6f1c9d2a2044dc58af7dfe4da2102188ef422e" +
        "8efb63bcc826e780a5bfe07acbf3311cd9a312002f20c6c115fd5b0d8a4dfb84" +
        "4db464eb12f3786b4dc698464cb3b459dcb7dcbb560f091428439fb875edcb97" +
        "25afa5eb4614a6386806e06e55686bf3d86d596565ff48fddb3de221b47b786a" +
        "2e28b821c472f4effb744329f230c9ca789372fd84a495e0cdb14829e7d127f7" +
        "dc316e0004d77cfd2d25e9dbc2b81426ed63b1500a3cb2799879812ddb609799" +
        "c00a899f90190bb397d2f750a51d7d7175e658625395409ec7d372a1ae07b38a" +
        "566199813ee45e7857d18ac4043813a05d686d22aedafc67bbfb8e1adc24f7c8" +
        "f9926f4eb5e76d1388055cbbe0242a96c6705214d0d9d8b25bdc85cf62b4cf77" +
        "f1e551ebefe93ef016d2cc380a4791c0e0141af974d1328b0236055562a7ae77" +
        "b0013d2c91befadd9c1742c1014dd8273c10826611918bc852d5c11deeb29017" +
        "edf3ada5d5ebf29b78bf2d5aade553e6c13bd8f36bc54c870ae3c8c7e5422ce2" +
        "131ae727203e95131ebb03aec084146d7bf798081812b44f994acfd04a5d2116" +
        "f6df10c7bee6793b352aa6d6199cdebdaf72d225e0a4de9944186641c756f7dc" +
        "325657391831c87501c3f346cfbfc610b51c38f9a4a544a10b25489cd31c5554" +
        "159fe3745bb192b65261ba2f539117449400e443a0e70daa8a5b8143adfb50fe" +
        "cf852dfac81dadc87a7c5ef390355e67ce574da0229e074af59e5f9145d862e0" +
        "f3873bb7892fdf8b82b186c3a4a368c7739e688d246a299458574b8100e22b94" +
        "0af596a3239a7bd02dcb6a8eae1b1c34ed304eca2921fc3d7011c15f3ec29e88" +
        "7129a38f92f54677d5472d2b661c07f0fc7ba01300aea5619236eb7e43912072" +
        "e5ba7f7923123eb24b13a18c84723b4562cf2e78c49c2209fa599ddf135466e2" +
        "6ffab52a273e1782f32a4d36d3f08d43402c8468be40507da3275ede4d046fe8" +
        "969c7a1db82b8ab16ee236072250d9719348b551ce2a646b11a6b9402d6cd276" +
        "52c6e3a66bd23f39d21328a4a95899e83d08fa3c34394d7d5e107251961d4bd9" +
        "3ec9224c7263f8874be741accdd634a2e1e86681047d7095ba37869e1f9a1be4" +
        "35ace6cf48556ebb9d407996ddacf8f599ad430dada962c0708b509bca0d3e54" +
        "9c27d59e20e2e0b0b0be8e5643959b34d10528a0eed9ab6aa7bbb71b3a5d3397" +
        "2554e40e6479ed166289704aa64740d7a3d26f28ddc504ab7e7e1eb0190248b5" +
        "888275af6674caf6d7e86dfa5efaafa804aa2c09f14c3675b5dce80480d31478" +
        "095bfd526fd93c1c023b77b8a1e9a4b74262eeea43f3d8d07a5391347fe79ac6");

    private static final byte[] ML_DSA_65_SIG = hex(
        "b1d18e830b0dd271b2aa313816f0b4bc642b97a108194f52fe991aa9d4089399" +
        "88fd6ad6d8dbf0712ac90483c945595de03659531bb85aa61fb41b0afb3abae3" +
        "b75e041459099a8ec2775a3df143677478fccd34ed35163804e6e7d6d2901b28" +
        "b6661b57855ea79f861a0dc37eedbd328a35e1b301dc9b4488a10b876e5531b1" +
        "27cb85a4275633b0390dd34bd1a24707c6f4e61f887070137e2e17320a6b3834" +
        "cf2f0036588de1dda7942a8f879967024d5b56afefc43cff725395270349944f" +
        "94871f5233edb9147be56cef7a175aa4892afe68dadd48c2f092f4e4d6a64808" +
        "2ce8cd72f6943ec182b80158b2efeff4cb93632e335bc9d66adeade81e3fa3f2" +
        "3587c1c9482f1b00ea3d0429d5c0e91ac5ce5edbd1ee169c0540f92113720839" +
        "6b6319cd6f64a0c377b750ede92dd572eaa6c197b96be581918ed13611eefb2b" +
        "66bae43ed0dd17c5243bc35b75fcd5b68cba8c66b2ee40458c23bbe0c8d605fd" +
        "715b24bb37655f57922213b29a70224bbe03d154b03a30507124f7818c206774" +
        "5aefa16ae3d004d6a56eada71541f321e8d9e6e597bdc21bbbd14e7e5ad6e419" +
        "a5e476f4ce009476ef1bb347b9a332f7456d327306c0b9af9c4699be1406cd35" +
        "7c907ce7970a9fb421fff0ea83c086689f36b0ade18dc57655b5b67e1fa75b26" +
        "6cb5f9541f76c19cfc57c886c17d595592a5b803faa572d15c8d9b2e840718ee" +
        "49c5998e157cbfad8b13cd97f93ca2899c9c89c97a46b3427bd4280d556328d6" +
        "c165f5346e382ab43540ed7e80619d8f684f740c30350eb307f492ed9c7ff5ed" +
        "3e175b6e9146a1251d83509335066c2f998b214c5c34b1a782bc702856612935" +
        "890b4121f0f7ff693da4281e0d5da70eaad34a9549fe355fa9c0e4e19a03d4ac" +
        "96e3ea7ea6857eb0b8c2e807d6d31a84902404ef7c931583eae242c6e71345bf" +
        "35ae5d507916bb11171bf408889d66146aa071768051737c1db0c1ad58fbbecf" +
        "73e0d9f8d5acd749d9c959bffaf5b1d25a01cd8b078b5937c08c7da97183f97c" +
        "58a977013d39565c93fe40875a3181538e0d997edf37d9e391b8603a5bcae891" +
        "56895961c631e26c81dac75c049de4231273fc48fba5ce873747715cd12a6389" +
        "dc07e77f5d48e6d296c66fedee8ced5e4138bddf21aa9e5116224adcd812df5a" +
        "83d6d007a4424113e108c9000f37c07ddab225fcc9bca886cc380e06511b37c1" +
        "0e2a5849bc7ca7f0dad77434f5d8998c9486e31e6bf568faa66963225a3c6f29" +
        "c940c0be8db5cc826e9dd11f1363d824633859f04a8c0f288a7781a2a0231159" +
        "a95a2d718f82a7bd85264dc22f11e8ff96a12df2d5f31d54d05f7107af22a0cd" +
        "78b347b1403d6bfd101bc660ef5c24a31feec00bed1d38c8f28cec5ed9701a2b" +
        "25e6eda90cb378e19101412efe7dbdfecf486d2e05318924c4d7c4262f6443a3" +
        "dd56115c657696cc3c1242f26b20c2e6c35cfa91b1bd3bd399de597a344056b0" +
        "880219c8f9f98fe760fb428757b442b465940a5fdbf532e94928bea6640d6d08" +
        "4391167a6ca902e48403394808cccb56ad52959e9a2bf16d3f4b02c652c7096b" +
        "3fa960e2195d0a61cdc836db8e57d211491c26580407322a34f06a88cf63b7ef" +
        "7e93cc640714fa6338ddc0f0aa56a1ed16aa538c99c0d4da945813d95f989aa1" +
        "57bd89ca9d3edf7526290fb2334b83b3991f065d10f51c7597ec5b87c7f1d8bd" +
        "0e4c1ab0593b2773dcdeca0c2e1f427fd80f9b3f493f637d71e37779cc9cbfff" +
        "23a974a2dab7ca867f12c11b4135b5c71009c0a21b41315e6c35b5631319618e" +
        "bd89f60abd1615d8facc9f97028f1b3440bc4ab13912f866da3403f25c339c63" +
        "0bb68fca81a24a43e7e76641456b7cd11dbc4f91ab240b9f604736048b72b665" +
        "35fcbfc926af8404303202c09498bc173399acb14eddf046686aac6ddb85fdc6" +
        "3bc89389bfd7d994e4a437b9675284cf88ba018be4d43ede94a1a9d815b56ea0" +
        "62925cb11bbf4faff59935ce7da94ba86031f50a8358f583deb2fef312083de3" +
        "148917935c87e489cbb7673eea0e0857f1cae018d7ae5f9e625cd76a2fd63067" +
        "fb5eedcfa988040af26250c539c6a13ce49a815596ca60b25362eea11dfcd95c" +
        "51bf55651d132a1358a318526bb4ae601c263eb14cb1721b8a4caab55b8a3b2f" +
        "1fc32941e66dd79626dd37674f9d31c65451aaba73aed2000b059873d69cb42e" +
        "23d0c3ac466f3e0543f896a0e0fe173ffac2c3f61a46d005530eead8baa3abb6" +
        "58d1401c9738d4775803f58ac748197171b54b0885351cdfbda9c9d14062a3d6" +
        "3ba1f74ec6fec4072ff5c90cb6a0b3253e2a07e363e39e8d0d7a701e65954737" +
        "a8d235090970f5c9c93095d9f25d103cc36666b6dc14f691c27b4b7142f935e7" +
        "081eb69a5c0e8b41447fadca8a4b6a028196e7e1b05baff217447fd14977fd07" +
        "59538e51ac0f0cb4a3f6241647f3a436173e011ef1ec784acbbd2afd01dda5ad" +
        "7bef5e56b260b4f227c89b5b314954bc699bc61a79e7d446c850c3aafcb52887" +
        "1ea00cc61aa734d6bb9d9c0d906f1a3cdc3b95c438257ac646829f68ca6a63a7" +
        "99fe64e66f11cd2c761ee608b833644351bd52f70506d5cc6ade1aa2bef88c44" +
        "5e2dc228cd9a530496cc1ebb9607c91704f8d8d9dd35353d533060b3875df3e5" +
        "a720309db05bc436f7d7b63e449899e7c329cb70c4918bfc63602995eb617fdf" +
        "f73a693aeba1731d1318292c89825642e7a3bae9592efdffb6f7bd2ac9ff4c63" +
        "ef5463827ca51144c768f57b442ceeaba3845a992898972e8b07096ceac1810b" +
        "e0c4b7c273be8b72f8c98d5028f295548a3b2386c4e8e8e5450ddfa3e60071e8" +
        "20d26d2223af370455058dc93838124c9f28561476e51054d968cac3979fd225" +
        "2c0da0ffeaab61d2b206c293fd5afee398bf372ea57456d07a5a233bd2a01f4b" +
        "eb7f5ac55179f6951950b16a80cbcf19a467f4080f6ad93f15962c6dd5697a56" +
        "4d17c8cbba9b6e65a23d66edeae254886cc11a11de4e0c8a4204e177c30cff10" +
        "7d4a453fb840f975769f65422f785b0b32bc45fcd429493476da5fe839359eba" +
        "7f197e14e6719c726acecca672733f4e9b9e940cce0015b450ffcfcd78d3080e" +
        "954824131654b4e0a929a305772f5d476aa5b04ef3a94a82b92c26079c33c668" +
        "c2e0c07d704874b9f51e6c157fbae5a1b4364120f42d97270b1030577f3866e1" +
        "c4f6a4c98dbc2b4f14b3f01e8070c00f6906e795d15365491ca8fa9e2bcc3371" +
        "76a40b4ac7eaa0fa1b2bfba559062aef4bbf054b87703cdec7b24ff25b1abeda" +
        "043157fff2a54312ff8df49905e134a9b90ab31f3d6d0db7d3350b04447760c0" +
        "96997ba88e794a9624efb1f48a2f3e08f33df2fe5f0af70af5d8f2a01be79ec9" +
        "0bcf58979290ad3dfc42c17f39e8d135148ab377b1a9dbb43a3deb590b5b3a63" +
        "5470daf0f0b9e60769279dc6b6002dd6c7d72ef89cfe4cfbc07bbfa225b82a5c" +
        "06ca122c96a427a6730bb842935187fee68fca0053dcc038039e66138468e704" +
        "93790c3e4c90e2f781154905e18fe6fcc840ae3d7a16ecc639a5049535acdd0d" +
        "19d6a9d9d253713138a2f19c132c8c219c3a1bf2d84cebe98b2752d36c01c060" +
        "328c6efbd6d61bc693ffdcdb38f50ed515cd6576784213376b2ee8e2544d4534" +
        "731b61352cf7203ee97cf0f3ba41fc49e45dd4b807157b16c77f78efd6533fe4" +
        "a633cfcc78530c59f728a5832b5ad3d6b7b2d17363a9ad16f2ed486e8822bd16" +
        "9d6ac24883df40b70a50233d5850000204d23172287b1096e0e73fe0d061705c" +
        "0adbc07beaefbac090e0f90e838c3b052bb6cbbb37a1d3280240e376bf270b4f" +
        "82b922ee0b3acbcc561351b8b62dd36c9610d951247b2bb87bbd8dd9f25061bb" +
        "0cb771653a2518091a9d41f4db5a1c610abb43278aa883608c5d4c9ba9e5a767" +
        "9998dc7a3a550d25694721b1d70c0c4358c9bf74911b2bf3298d1041afdd420a" +
        "71e3b84d3af39c5a464e70bedb0d03eecbfb6145bd25b472d151031982538318" +
        "aba36c9ea2e915b17461a1af094b4a349bd0d28043d990537138b980581b9f9e" +
        "fe071b3324b2587f01bee825530806777d5a168367910ba2d21e5f9c39da57bc" +
        "67c539beb973031997344f1e6b4d87ef794fd1dd8013be3b0fea779a1a4663c5" +
        "2f93fe1871fb70bf853b3e54e6f8e0b9d09df52b1222396a8d13a13a95d0e707" +
        "a42c33ba431dd8b5d08e6c856ff88fd37265c1ff8ff6b5195934f9e8dbf31068" +
        "bdd559f7e5f284988dd66fccdec5eef716caecc400892e0d0db6a8e09ab0e58e" +
        "b664477d01598a90a69b2b63ad70c807363ea98fd9c2f74bec9553ec6b2d1fb5" +
        "91bf9fc585613ac75c152a0b4b3c386dc92c9111c66b44719f89d5de279981a2" +
        "598b5797834633e18cdfcf5b6bb30e171ab87d6e71e5c84ca9e25281f62f3aef" +
        "5a1b6b7b6151cbd57b5ff01cb8eb9ae40a6e53592e2d7827b747351a01250acc" +
        "67aedaaffe2263e8a21c34e66b73cf6f3e0a4a36bcda43bc5e9c91e48b342e09" +
        "87699693b4ff97bc4ed6a2b416787c62d0783f37dbf292ad9b51770819d20912" +
        "f752e8c8b2fb6fcd055bd28e0d6e0c165b8ac209133b6985bdc0cc2b4865a7c1" +
        "c3e0ea14676fa4b8c6f0123e960d232b37878dc8f70000000000000000000000" +
        "00000000000000030b131a1d25");

    private static final byte[] ML_DSA_87_PUBKEY = hex(
        "8a66e36e3c11709f82ddeb9ec0d725870c65079d47395d04425cd60adc394404" +
        "d9794387986488823a31bdec66cb0190f985ccde54697d84b3843c420d0963db" +
        "e65dc28acfe1f4861305099a4d05d431e72739fd3adb639f1c670b01ecf9fff3" +
        "daa9f49a595276c2d2d5dd8db1a2efb37399e3cd1cf5ca6e39fa268345e7d09c" +
        "1bf7b264f1700010c07c7fb232ce6d71a5437c4071095474acb5ebe00402e582" +
        "4d5a851e19863933922fa9a810d23160160899e32c9313c44b10e042ca3f32a7" +
        "a4d2fc9c93b65fe25b6e400c63f8f8e12dcd860779db61ad24fd1e663e8d76ba" +
        "988e94c757b165ce4f97fa347c976bcd3c4281a4d175eb6d0c310e6fd575e7ff" +
        "83dd7a4d8367a74bc174ad373899e0f55a4436a2202bfcc9fa68cbf06f0a461d" +
        "b5ca5b961b3aaf7d017ad209ccd4e4b1493456689c0f23e9b34bed3de78d196e" +
        "e6fa0655b8064da8452091f7fa0b6bce55a7141bf9eac57978f73ad9fc074306" +
        "90945ec94851e5966878c8cbd1f365ef1491a3ca8b774084f42ee756e3aba0a8" +
        "619317959eff3ad412ea13e68216ed147091cc725899a17ff38410f4010d0545" +
        "4dca0503757ebb442ef5eeed649bd3de3efc318cca236625ac5f0f330fd2e9c9" +
        "962ae2b8ed93d378d881e4529ac6641d2d5f939a2e73c417aec6080d2de94b10" +
        "29a84e8c085987100d5dfaecd642f65ca40daa648e20a5509f0b853757157cb1" +
        "e4ddd5193b107d22db538b7b32f7f22492b205d1fdfc11d6fd3c8dd7b0585006" +
        "8461a678041d7f920e8bb36343c5304cce2b4470537cb5bd30cb41192769fe41" +
        "92aef03733f095e4e84f75416487c568d3cefaaae85988fe2446276071367866" +
        "3c368edb9067a56afed32328913424674b016a0e02b7f0a8d476d5a81cd3b37d" +
        "74c61796a7f9ad2436d2eb345acc9c0199be214f279d6bca271b60514123e1cb" +
        "fc172e1a4d3d51b3918c534dd7bca407d717191861384e05813f438a0060dc30" +
        "f4383f9382102973a9bd63157dac2ec905c10141185ac0c8c78169e7242157af" +
        "88737c5329ae5adf7637564f1f6bfd71bb804ad75350102dfc1aaf7c1fe8d06c" +
        "a6453db53db2fc97a9bf7c0f327acca92fd0c6e6cd041d7191b9594bada0de9e" +
        "dc9c10eb8dd66557bc96fd0fcc73be39279994f5e1bb32cd277e08a0d29239eb" +
        "71c8e83457344b203fe268ecc08a71a316a29177de4112a5f52a636055d033a4" +
        "a72ecb8008e57616750457e314714e5729230ec0ccadbadc965d234942d89108" +
        "0d52f45fcdb703aa7326a8d55b0c85c884509e70184527822075ad525c804bb1" +
        "0b3b30390254185d029e85314a079c595dab134f8f6e3920b2c53193c6ccfbdc" +
        "15ba3dccbbd26f0421df0b275cd26efada865de4caa49022a280b53317db9b7b" +
        "0acc0f9b3806df1011a1d72c24f0a83424fb99ba0ab5a1946c2df8da74af1959" +
        "84b2681cefa1f5188f10f6b36d3387e025c8655c2f510783691bcea8e6e42762" +
        "5d9b7fa707c8548690a5066a94808497aa2ab979e5197a91ef8b58dcf99094a2" +
        "254c69d86e9eadf8821737c920152440e5c6c1c7bdd462ff166da5ece967419d" +
        "3efb228180613745a59f70ffd4993d7945d027c232bed4e253a88c948bbe8a43" +
        "f72a2849f4ce2e0b98c7af7d512edad07afa913ae6e764d609d85d6a97cf8996" +
        "72219761c51bd8a1f0cd9de4e913d0164120a42c33f53dfe80e8b2520e183119" +
        "50ebc69943ab9a595d6c840088457c73df56613ae155b85913cc0e53e9f474a0" +
        "f215d2a8f9d40d3de73d7d5b19898b2c4d8aebc343319a45725b25b6a2c198e3" +
        "8ad490d03e13f0d7903494ccf10aa930d1954307cdd2cab0e5d4f1a1c59bf498" +
        "28bade40d69898209c849ec657d884c4a29b5350a5a60b47e8087dd709a40c2b" +
        "27def978bca4b6c61bdace6af81af5fe7bab587cdc72029499f03c37875bd24b" +
        "5a8083d7fc9da75181b862ff4bb39f07c354fb4185429dac27812eaf98678c23" +
        "ad45fe6a579f18c5718cad3f303caa478dbac87f031c86eeba3f5945d4d0f554" +
        "9ecb08cfca400a06c01e601f33bf2ca85fce23a0e21c2d562a446158f184634f" +
        "0d5efb830f361bf48f17822e042c779d3258b8b0f944d2f684a48b2853d69981" +
        "8443f0c115c6744fab05cc80dfefcfaf1482df517c285e5b275e918b543d5426" +
        "b03fd7c5cef36d2c12c6b44860119cef29989c764e732bd223537d03c22f8aa1" +
        "e284542dd8c655779d07671f1ad3574c25798fd882c24d878433dc47ed9efbd2" +
        "62c85076da3c3c050e2d3056ca4d6ae21724269cff09ecb394ecab69b2f0a566" +
        "1892496b90f5775a18e551364a3554984804a90fcb55f171ad1a4a2c0e5d5e77" +
        "47f546176b942abc40e5a7a68841762247d1e82b184821c0e84fe2b27e03bb25" +
        "9cc8686648256af26429ec79badb34e1d4f9520efd8d869471d8e086029bd465" +
        "695e01328759d86cbc8a9f58288c97ef33b2da45a0ece55bacc665c1b6cbf785" +
        "0efa7836308490a8f84225a5dddcdc89d3f0739ad8958f04bfc1fd94ffe6f84e" +
        "c643c96030e968a876fbfadfc09bbcbc34e438fd93b047b23e836cefe1af35b4" +
        "902a32af253f3e7261c00f29bb466e2e947dddb7671f7b64cba59a586320a7c0" +
        "94a9ad907df32b612b643d8ac3d1cbad3644e6298b3d957ca7a2fa1b168d9ec4" +
        "f84c7620006807999c60e6166a6f8abe7195a1cbfe7c41596120f9543cb1195c" +
        "42673ffff332219c9e88f9970043734afc54eb27791485d3dc47b36d24d3f77a" +
        "fb907c6ecd4ebf2676d2e8cc67d1233c94161e07367c96f6e8507226566789a9" +
        "11fb1db8b92a55b785f740a2fc9f30ec8f9a1cc8e4c51fcb0a608041ec888ada" +
        "7c7aa196516216637536287cc9d0270c9e184a82f702b9408fd5977a35a93ab3" +
        "8b6bf19ad1e714385eba8cbf32aa34307c1e11cd1f9fcf4d14ce67f99c890792" +
        "446e9a16e4fb67013f4c1489338746c6e46694d4874f2c921bae82e799aab499" +
        "8126a66f1dc19580e9eae3446a2bd2e00d6942f7276b4f027a337b433def10aa" +
        "abc5a2f0bb074b260c58cd3bd26da53237884e8be375b0bb87eaa453f3ff3992" +
        "44ab7b7162316b31ca97bad741e047474f77a235627ac1b6691009cefc92ccc5" +
        "7a11f1c1a080e54217b63fabc1a241fbe3982d7ae41b1f7e713c3e908c6030b7" +
        "73061f8ace50207cfa8cf214d900a221ea1036216f7f13e36cb2d6a5a66ea9e7" +
        "1ddfc9976075a355a12c94d7854b44c69c17c2ade656721db91354fe8cecf4a3" +
        "546b31bc559e01d49b249e51af677602f7346aaab03c702ec886fa408912b749" +
        "380bf766d22e58f1223bb3406b7a684d42fdbfa0f72f634a87e799526ee7ddca" +
        "1971ee92e2680ee1b7901fc4eff8f6855318338615c829586ff01c1473a98e88" +
        "74d421f5c67cd8960fb0a67bf77215d7306b151d3fb74eaac0521d84bf98bd33" +
        "02ab8bd09c852fa3fb468d4d971a8a3c735b3b5826ba6b452e2466797dc4f88c" +
        "057d5c23b9e85dfec984e55840a4b7557469929c3e19b1b651e971cc962b0171" +
        "f5b9de77fe2e749c6a52171eead9c814be61dfe996245a9ad8d7ad71e0f4bb9e" +
        "ae95cd589481ee46846539b11b1ef550ad5658b7539b2a2f096157daf5dc9f3c" +
        "6c690d6149b2e0b2e5ef19be04f66bad414c5a50f6ac1b258adde357ab7c92e4");

    private static final byte[] ML_DSA_87_SIG = hex(
        "20ff12e187f61138ff41d08fcd7ed1f62117d046e986831bafe52b5921d16bc9" +
        "db34dcbafdd3f87149d831bc4883227bfd6a93a6394cdadb15e74114b4b8feb0" +
        "1ff90a2c0bc0ac0984695e648ca8eea15222de0dc725efa8fd8cb9454fa49cbc" +
        "70f288ea7913b0fce641481c3348a27775379fc18694cd69988747497593f1a4" +
        "2d8ea87e0f95f53e5d312dc9581c42fd796a49a384c52e8d969cc80593db6dbf" +
        "8334c2814790c9a982bde1c889a23647edfb4757011a758c6b83cf56ae52668b" +
        "ab7f0cecde5c13bebd5b7428b5d768d5d2e9963b55da3a933cd99f532a318445" +
        "3fee2bfc92b09cc616164f33411758be5d574b0482e3b368df7c93ce9df67e21" +
        "3d281cf03746f2c2737cbe980e0975a72111a9d6d147acd019483b74c13c3743" +
        "491262eeaf5c38f78aceb37a0516d4718bbe1ae01ebc4b540fb5732bb83a75f0" +
        "26cdf9ca32f97e1538759c4dbc11f8ea8ee83817c562f434fbd6f576fca3f344" +
        "f9ab2e9a68cda129ffdae8b5b0205d020162264432c894f8f1aaf9c286cb557f" +
        "8db3f663b1a49557b81dc342d24b69cd7a105b6a13d1029838879b9a5a6673cb" +
        "75d07a4bad23061cc86b0ca8fe7b8f6550d7f7768842e05e18918b9937560891" +
        "e701e705d5ed4325717e3efcc4fded8b85168ce305ee5102a44bd83ccf4d2f2d" +
        "686ec1d5fa91fd6ae06485359c75e60db8ec978862987875c71e68a7b97bab75" +
        "7a723c7bab6003b73813e4966ecb95ccdc6a476777d795c48766c27e4290594f" +
        "d6f3f4a7d029f95d4b0606f76eb2abb08e21a6ff5e7b47b63aa69e19f6df9b3b" +
        "3d0737d10ba8f39c4389eeba03ee387413098e474ea914f5b055e003e5b953ef" +
        "031560b34a71314bf1c8e4639b8b783c1fac2720a8537ddd72d3908f71a6a7eb" +
        "b0eb4296a4c3bac63ce77b151efa152337f3c8b2f94604d15e44d78f70b10ade" +
        "6ae3af9e49557879112287a9547cb483e125cd89a691217bbe3d2f46b55b501a" +
        "c88d32f3621f2464e8b6024f1f523c40fc7238d4ba408eb7c0970616d5e33945" +
        "d77c0eed6b19190a8ecb2bee4da15e842266cd4fb91a258502c067c4d51acbbb" +
        "de4d3c3c629f768f1529a5bb5a483866fa560a09bddfdf4ae70ea6b1b57ce1ed" +
        "8d630742f3f815287c09f502691b881e3dad5f46edab2b119673a8e8e6647dae" +
        "13a17d54aec082eb2ad176b79fbd338fe7e67992a6af619149bcd23c6f8bbe8f" +
        "5f1f002c2e2ca014cf3442444111d737d39944364303b9504fabfe48e24bed51" +
        "8be0043c932855c85ab3522c56bd43b94a6c4cccdaba9ce63e508b1ae583c160" +
        "55b20216543362697c7d94f2b03a22f02146d79453ec634c3ec371d1b92e16e8" +
        "17637e0c830572e6206034ae0e54a05775932eb86cecda441bacd675c5793cc2" +
        "a6a27f3ab0ecebc1e6d6aeac2e55301c81a44c350ed8a64eea0ebf79f7df55fc" +
        "f924b0a6bac3724260064403e3403c2a13f7df3db70d866cb00f2e7291164f5f" +
        "d03e8c36eda86fbc65b065994750a59ceaee8a4470f5311ae911c1cee0215270" +
        "89f7c335fa555ac51002c4c7f7e1af494861e70da12d7d030038a7d5d3bf9529" +
        "edcc703ebe958adfafbfecf86a4f9e69ee4e3d8b58a02eb5836a0e04a4a974cb" +
        "4fb039378fcfbf77e41a74cf0e0d2d6e1dbac1f57c546e92ec4b03c3a444ad3e" +
        "4fa4d9e9713ce6b6bee7fc7276869a73b1b3f384b62a400b8caeb3c4dcb52185" +
        "87dc1918d5baa45e8889a4f48875c27ab4ee9d54669770088f99845d5ea76f92" +
        "e8a365fa0e87fb3ce9172dc72d308f4182682bf1678ef70578fac361ba35e72f" +
        "19ef7136ac5bf0453070dcc7ab7b62179dc4436ffc02565f65aa683b5cfa7128" +
        "89e9282f954bfce6e7c844285c3c085f9cbc416891987a0063c95c758fcc3377" +
        "7bd02de8a298a41bfa09677b259619f47733204f19f69c6c2ed96895b0e21806" +
        "e5848ef7bf6c96a89d37c728a13d908c403de251fd5509f88343444d1c8a8d36" +
        "8464c4fa1d72040b1d491388785f079bc8019c3cfcff0fd513cd1598cce6591e" +
        "83388f6c75bedfe91bc5b96ba45a0cae988d93fa767f0d0be8a03b9e5ec8a8cc" +
        "02c9869c78af6e6af4fe49adc593ae62bde33aa8f260b529de5f12022d4390f5" +
        "9d9d9729fadd604164b7a50372102bdd5b60e6f0e1d7a597ecb49a4c3e16a282" +
        "b3c33f3e5d32ac5a40b400fad947e877a8965c60049c5cdf243ba74a5825129a" +
        "a87b3e14c8067923ea917fe178416cdb8ceb6635878781652cef3a6eaeb36ce9" +
        "86506d89d6270adbf8d4b8858e37a656f758184c44cfebc47919fc2e53180e7b" +
        "5186f35913b2afd3eef4d5bf2cb86d71747c6754a74b03a91b62959fc3f07139" +
        "2d26afafa7a558f8f88ae062903f729d2182763e4c5de0b56723e3131a29a3da" +
        "a4b45c1d47dfdfc9936cb2b522b3472bcff03687513c794170bdea70a2299055" +
        "306f3e50c838d6fa6fe3396788521fd352bf3e7b2ae51ecdf9f1911d046125bb" +
        "e133e36646ed068dc34f20c624a7b5493bc7e6a07758d970b1f5ec9419f35b0f" +
        "9ae4ad3781af687be567b5ae7f2d6478685ad18f1cc0c35b2177e4a85d0550c1" +
        "92ee362dd2ffeec21199eed748fb6aa3c9b70cc1e512bf6f5866353426aabec3" +
        "3386fdc01ca5e41e91c4554ef1cbd20be80d896a00bd7bf53d1a4a48fcf05bcd" +
        "dbb2a0274b8ff7877813db3ffb0bda22b32b3a38d2297377b8d6ecabb4febebb" +
        "6ee2c8457b0d36280f4572ea6d38025e488912241b330fe9f4cef827163729ae" +
        "e8220331a9a0730c40e4fc6be21c8d7c40827228d07de5ef0514802811320d63" +
        "8ac37cfef5060eb0785c3ab6543746a7434f05ece49fd8551f70b3e6bc46349e" +
        "fca4578f0f256f9fb380210ba1ca59cd37f7c9cbbe91ad074fc74e04bd388b63" +
        "b551acc8833aa7e177bca40c6c50eb46e1459a7b01ca54f00fa01f439a19702e" +
        "705acf3b1b41fdd39aa23614f0ddb0126dcf553fef0ac180a968c398034634ce" +
        "91b27a94d2e7b99c56b8f8d6ffbf8b39450445c9a2e2bb506813321e0951b7b9" +
        "cf5fcc54d2f3c19da08d22c87e1bc614de5f52b46971ca581d1e89cb56787a85" +
        "eefdf67ebe499bb1059512e963bd619a26f90b9f230a595593d32dca664503b7" +
        "f0889ec111bb622c6fac3e87d7e64a4483045d5dbc3cce832b114202731c2490" +
        "d91a7d968233751e59eaa799e15bdce407c54807b4bc800ebd636e66f112b667" +
        "e014749fbbb3b816d025e921801a32b0589a6217189d642d4789823b8c5d60c4" +
        "5469aab46a1d16b0e25d7debb98037cd5bf0a1a839b2d63ac8cdcaafcb3b54c2" +
        "6749f3f1114d537c468d22f69a0d9eda37c60600cab6b699c5b6817e8762cf07" +
        "76c15ffe86fc5ba0accacb7df55ac25e414835c4719dc40a796fe36d47d4aafd" +
        "97e7b07e61f17d7ef8784c2e6551eb99d03e244ce0407e2df7009d5087ce1f9a" +
        "d2760009eb101b4cf1430e35bb232e263d66a30ff6108b67ce66fdb507dc0469" +
        "ade04ddfdb2f87f7dec3778971fd7038ede627b1bd945f39207259c439d0205d" +
        "e2e7e00061c765bdef05b3c77eaec5837fc1324e2a17644e2a9a2d2699a2d737" +
        "3a106a8972430e3a034cf9fee8fc877137715a05bc4e204cd7f98d4eb8b85607" +
        "c86e346d458334f077fb18ec72f64cfbba84e9893dfdb70d70aea4486b39f862" +
        "c07f0cf2a3fa7a6483577d4c0496d79d108b344817ff745c9cbeebe552946a34" +
        "6ff79532385a9b08f6da8c0f9c5d0445d4e9a47ac4fd70fea13d21a001e521ca" +
        "a7d9f19f45e1e82d27e687c80dad13dbfe2faa2bdca61ac919781a1f10cf31e1" +
        "062866b3a7a2a6f13b2dd381af6fc98876e9836c52b97051876b8bbd5b9ca9f3" +
        "cb55d17640e190b94cbdab1da05b5b34142f878f63a02d294e504b185f86ac1b" +
        "93e95938a12a3621b2a4c079c160fc0fbf99049d4b17605bcd7803d77c4b9b17" +
        "582460b80892484f66429a982a999a8fddd709f3226662efe564d3df31aa844c" +
        "a53f4e2748379663bf8de1f0d1ef951ae6f40261bfe3bc8b3d0b7791c05dfbe6" +
        "7eab5ec51c5b16fd88a4784c0677c36e840cdabff38ed36165acf2187068846f" +
        "9f3a9481a6c7c392ee4b20154e0376515b4ee15c515e1b9c302579dd7012ecdc" +
        "45954543cdbbaea00d43b4c98c62fd7bed5078b7a694cb98b0be09d90cb2c48b" +
        "9693d926c66d2693324e8672749200720b20a32b94e610565a41719208ce6cc4" +
        "1d9e71826423e515ef4a7c4de392bca3a229b746fa8f9fc25de4c09c3f4017ae" +
        "44f328102924a91c9ed2554cee45fe4a4512f5dec76415c34a7763058da631a0" +
        "ad64af3c692c2578aea088968ac29b8dee6f2e791fec32357583198bdacad0af" +
        "6a6c42e881b569310b7dbcd8d2b77a8ffacf91071fdaa91fb72dff50152aef8c" +
        "a1e37f0895f299831f97713e353c8ce708d8a61f0ca652dc73a0fcd273e9279d" +
        "fd7a4a29d31226130fceea56996178472ca016a0e264975731f0325b4493768b" +
        "59635c5b0fe1e77498112d90e4ded43ac2fd24e31f7af440bb51928f689c51ab" +
        "dcf61e96ca565c92cab21b2e6d2028b30a8efda9a238746037a69602208a9a2b" +
        "8cb96decffbf88bd6cb410bdfa5aebb26b74132da5db6093c6ed394fc563e19e" +
        "571fe747a4fb7ffa3a46503ad8d383f5e65ef8090dfa33e150e4363e0a5de6f8" +
        "2e17878fe18c8273bddd3b77479f42d7f42d6cefcc22153ce926eabcee09d3ea" +
        "840f46a8e0dac5570254b6882b37e596c533b7455db7c7fda0fa851b2fe1ec89" +
        "c6b25171cb08823ec9ed809d37319d15de246fbd0e73a2b87e297e96e4bbd623" +
        "17ff33979c87e0e50fb9b63133adf8d8dba07113e41cced07e657ba03817534f" +
        "71756d0261c452f8e42ebc52c1b17e830aa1d1cd2fa030fd41867f26d1e7fcd7" +
        "c737e511a6c09a75180436ca8e267dcfa26a949bc4f7c7eb5113a36f8c805fae" +
        "f018a088e08db7804e8cecc87bebac29b74a0f33dd9d890a10b0ce7459a26291" +
        "c9ac56cd69d3016d51e704c3fbe9791b72721a900a205585c18beb1e9f9f4a81" +
        "479796bcc2e4c2fea020da700c2be2d4c8cb4600b67cfbbd56943d7f64f788b5" +
        "a7febe648ae40008825b8f987787daaf16254a9aedfb501845462b73ffb9b9ab" +
        "a28f3aafc50a1491b23fa693f4812077fa517962e8e6895239d501a287a35374" +
        "3c368ac3b4443b1521f6dc1802d257e510f03d61a716856f710775504b215347" +
        "38359ea7d8fd745915327b89d02cd9f6404979dcfb0a64599b174736cbf0c3cc" +
        "148e1fa812aab76aba45f9c444e7b57cddbe167652923d78b7ec8196d87f342a" +
        "a2645ffdb1424c7998c917487412722cde917ea9492acc5c6005250972208042" +
        "7b18c2fc2a5e3e2d61a6f682428381664da6e1f9f648d4c869edeeb57acbf60a" +
        "760e618bf21a8aa788b090d523aae02bd6d0ef491388c750f09ed528e1aa1daf" +
        "d973b39ea7d8fcb922970e21a0b9f9ea1e9588da857c327cbdeff844255f23fd" +
        "1478c6db86eef8dac0ae926a03a90aee4a225a6c39d3917d9143ac79adabb791" +
        "b120847f0ad7a86295ab04b6b2f1d4b0ac5289b093dfdf80260c3231b3baa1ba" +
        "6fa3145cfa373b6af2c43427081ae4fc8958793436e4ad4b3f577bc1592db654" +
        "44be4e5d0d6af3cdbfcd4d9f9a5009a46b8bb301696c695d28739eb5c2c76eff" +
        "4c5c6b9322c19fa671bf4d2d4e4e98a36dab05a0de344128a438754edf7fc9dd" +
        "bf5ad4cd380c89e70efc0f273921a4a6077b2a1356e74e55577198b93d59b5a8" +
        "241808a26e9ae597a738d9439b19173403d6bae971382690789e1c418d60dd0e" +
        "124637b47987331224c45a6c70a2b258bbe7d688422d49c8671ec5ed16a81f36" +
        "2bfb0d5196c878f2ab82a1e2af8ca4135490f1e7bbd10923760e5032c554bb1e" +
        "125d59f3e9c9a4aabc131df07954ae70c0eacb2132e6e68eaa5146251ef13f9f" +
        "f6ff195397bca2b69159271e397676020b03256b0002fa7d695ede6433bfab3e" +
        "3f243268bf908f0fc536589e9b11d12a8a0dac3a23e28ed60d4a8b450447d95a" +
        "466c7082c78167dca6fa6a86fd01ed90f6e6266dac52034a91087ba59ccad32d" +
        "79f1edcbaa8f77c817a8fb6c1562ab34d1dd943ed40c47ed0491d2d798b44357" +
        "d154ef63bae38a72c5b9f430fa163ce1bbbe5790b9a1a023faddbe2fb3ec418b" +
        "64ebc541eaa816766f28da2b5f030be81c2971d84e41df398e6a9579859ca979" +
        "d98f33af153b5a825632980cf6f66442d46a150fb97522bd9a58a6013a63f080" +
        "782280a014e1376bd4993fc2ba2b8ff356c81be47a5e9660ee7454b66d5c3d3e" +
        "05f09af6cddd06db8c21b9f528579c4fb408cfac6cfe30afa2efcf9315dd1216" +
        "197dbc57d9cebe0efce1f04a7caabf2064003459edea1258464cc62f77621d82" +
        "5ce8980def5c0eec5d2e5fd222432de102d54a0a796fa5ec48aaeef8e35fdde7" +
        "2687b5c4cfd97fa8aab6bee902495d5f818bb9bdc0c9d5fe363e4956638bceef" +
        "486ec0d4040c33456e979ea3aebcc2cedce3ff48516889adaec7d1dee2f9fe00" +
        "0000000000000000000000060c1820242f333f");



    /* NIST ACVP test vectors from
     * https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/
     *     json-files/ML-DSA-sigVer-FIPS204
     *
     * (algorithm=ML-DSA, mode=sigVer, revision=FIPS204).
     *
     * One positive (testPassed=true) and one negative (testPassed=false) per
     * FIPS 204 parameter set, all from the preHash=pure +
     * signatureInterface=external test groups. */

    private static boolean runVector(int level, byte[] pk, byte[] msg,
        byte[] sig, byte[] ctx) {

        MlDsa key = new MlDsa(level);

        try {
            key.importPublicKey(pk);
            return key.verify(sig, msg, ctx);
        }
        catch (WolfCryptException e) {
            /* Some negative-test corruptions cause native to throw rather
             * than return false; treat as expected verify-failure. */
            return false;
        }
        finally {
            key.releaseNativeStruct();
        }
    }

    /* NIST ACVP ML-DSA-sigVer-FIPS204 tgId for NIST_MLDSA44_PASS, tcId=6.
     * preHash=pure, signatureInterface=external. Expected: PASS. */
    private static final byte[] NIST_MLDSA44_PASS_PK = hex(
        "79F984109990D7ED99515D7D0AC2F6447A5D928F353DFD80617D3F94A9076A31" +
        "8A55BD960CFDAB6340343BE6F2E82B0EA208B35FB7C7EE18D4BC29A5D9799728" +
        "392B0B57388497A15EB2C72DB80695E716F2275B3E97586FB5E47BBC3A93E2B9" +
        "C1D67BF73DD1846F5DBA968C90EC36DE55AB926BBBE7383EEA70BBC93499B4E0" +
        "9070BB1C538716F60F540A9EF59B119D872B3BC000FFD981B3DF40FBD1BDF771" +
        "1634ADFDD52E4BD054AB565F735674F37C9543FCFF9AB9B02294E7581D96E5E0" +
        "1C1087392DE72E3314D156576A6D7E8997E77E297824D784FEEBDEAAC88D9016" +
        "27C25CC09B340368D875C1D82E6BD72D475D6D5768B3DDF30CF776A40FD0C851" +
        "C441A9DD55E71504F61D0E508231C4606CB0F360F7495FC7B8165F4A90AC6D45" +
        "2342F05BEB7DBE0A0ECAE9970A4773DF1EE6646F9D975034866CB5B3F77490F1" +
        "F0BE7DF8878EBD69E602DA6C892E513F75BABE6148FDF213DFE905D33CF25E61" +
        "31B93BE1B311C764E37F26E66BE28CAB17D87D1813179B7805CCCADCEF4EC684" +
        "415730136B6B4F6B654ED44C0405969A1801E48167549DAA12C5A44841CFEF66" +
        "DFFFF8A62C59706973421396F4810C6A173DCD3C16F65DC110E50FF2B49DB90B" +
        "93905360936A6258431099CA4C669286A0413C8C4925F51362EDBD0DF82B1B8D" +
        "FEA8A29BEEC210472C8E466125AE3446F600492C47DE5FC4B63C18DB0403BBEF" +
        "35B059AAF76275B54F2A46E4535FAD1F75AC4D11C3E907146179F5EA018FD04A" +
        "860994638BDCB0DA243398217B7661B6EB60E5824724C9A3FB2DBA4E27D0AC39" +
        "3CA3315B7C7154F1F1B703A3F76B345D85F251637CFFDEE281BA77F7E7D9181F" +
        "4308FB829AF3DE5EDE05A34F9C90315D45FC93D68A5BF5940A7C8578DE13EB79" +
        "88B99AD0A1EFBEEC79AF6D22932FB0EE7C679EA5D80164E4C10C722E42F09FE6" +
        "80CB221E0B7A4F5B43F260569A6DBE44340D69396166F15593BE97F083FFD36F" +
        "C08AF0AED398222915FAE98CDFF1414325AC4B748D09D7B1969D661FE20029EA" +
        "F5C02F6E37C606F83D65E8AA2583719F3C6C49F1A066CE67555C86EDC62F0563" +
        "1CBED22E824E7B883EECCBCED45F874CBD3507F90F1034DA73487BB6557FF8CB" +
        "2480D2AA51F1A324E77BCBD1F2855B997B49C408B1E87A9BD227879602D28381" +
        "3AD57D88872D35375224D069E1FC3577B646C2EFC3BF75521977F915F8A593A3" +
        "AEFCEF0E65822DC938BDC30584E2C4BDDCEC37C219E68BA9E1A3C032DD53C2AE" +
        "DA51413FEB360DCFB61DF29973DFAE5193122021034F81B585A68E31E8C7ACF0" +
        "18649767590982C7B37C420A4913315033FAFA5EA90016AA0BDBC4CBA256C753" +
        "24F7F49918765DA675AEED6479FF63A667B7EFECAE2D26BC9B3259CB12080856" +
        "9862403CCA87F65EFA03C84F0CE5E3DC0BC977F4A85C52802132AF7BE921F9A0" +
        "FA7A4091C8DFF6AC16C9C610984DA1CF3374FD4B4907F15F07ABDB1F81B4C7EB" +
        "3EB064D68A665B7216C9C171EAB0354C938AE59A160FEE2E1F9D60C0E8208DD5" +
        "361CA74A33CF36FBC63E5C700391C5AE60500DA863F1C5BB9AB9D36DB6D7523A" +
        "CBDF5FD780538CE058AF58A94711F2187512E750BE1C215B53030BADE044010C" +
        "5A27D8AFFD9978CB46B10F140407AA3B80B7995BF39EFB6FEE46ECE7303CC7F2" +
        "B6B3563CB46C2DB00752B1A7396D55B3AF8627C19B3CD8F4B24613589DDDCE76" +
        "7EB3F693344F00775AFAE048C307975C7D5C3407F6501318626D857ECA835D5F" +
        "D4C4B18FCBCBE19F6CFBD7DB620B225B552A163B6FC7499F342090E8E4E2A914" +
        "40F0C39931FA99F2D52830D9213C7C48DCF07CE587711E8192FEF186254CEE19");

    private static final byte[] NIST_MLDSA44_PASS_MSG = hex(
        "94888F9A3630C7A2AFB806B3B9D5D8B4F348A6A07FD62C795716D354BD5D8581" +
        "98215127110215692ED08245F83C65059C5A9290FCE3E6E5AFA19D4B99F67232" +
        "FEFFF01EDB740F85D8A28465BCDC1AF5626D4A2F8F838088402D9C2088ED0BB2" +
        "353F221232C873E78A21147C6C26134CC22639A5A9A872201122E74F5C99A7EC" +
        "1EF08CD028DC1B9C13F3D702A391AB277CF8BA30DA2AA3C20F4AEF4D6486DB61" +
        "24B80E174D90457D5614CF4C6A816B01704BD538FBCBA42C08D9606D5972B0E2" +
        "4042840F921B735230B6FC7F57AC9C70B848C015691BA4A8C7A033C0E2753353" +
        "9326F806F2234930613F53A0736BCD3C9A42E38DC5440939487632DC4BD49184" +
        "5670EB24E836B29BD6865A7355EC1EF97D7F9574FA8AC37E4BE13DA4BF1FB6BB" +
        "B2A88C92654BBB30B6DE1889C3551A861AF1FC0290442DE3025070A3666979EE" +
        "0F1DC86F7339EA7A8125B8286EC5CFBB84A40E380EC5D97B18FFCB50C53D556E" +
        "06864F93119E2A292A0BC869C046E3CDA035E0BCD880755EB0DA0E9D6215854A" +
        "8F786E529370F16561E6B983248A55269D2D654A87E5E774D9E30302048B0FE3" +
        "8EEDF3156C81FB068068A2BFF54E41B4DC122971F81437838EDBD38E7671CD03" +
        "A5AED2663E3239C69F5E5FBE687550AD717A74D18EB59261543248A6479A64DF" +
        "270B3545FBB32E51E4B7278A758BB5D6811B29DB51F40EDBF3CE1A6C831D7EC6" +
        "E9D44A1E4CD1C89A55C6C69C90852F6E9FCCC3C6604DB371298116C44E8417AA" +
        "54B710A4FA54A345E189290566375C0A9268F19BC7D37EF9794473EF16AA247E" +
        "CB2CD4ED90C2D690678B99DF472DB69D712D6F7203E3D629A4A167D1E50BD07B" +
        "6970321CD5CD3802DBF47E9EFC239BE01559FAE7258DEFFE48AABAC8C4B285E6" +
        "299502E20DCCF66B159400F3E11ED35F692B836AF1FA106B533FE8CB394D97DC" +
        "E760BCD082050C99C3ECE236F8433E3075F3165B8E6C46E66684E71965BA58F7" +
        "CBF9361F4F4953808712D738E177EF3B594D85914562D51D800C19D58593AB9B" +
        "25C4ADE87E977EFB855BBE648AC7F37F5A6CAC10567DBC79E2B4B7CE44D8DB45" +
        "7662FFD5F74AA8065EDC0E01DBB8D237DA5EAE60D922FE2499A533269DDCD794" +
        "5D9A1C5CFECDDE09CD853254A1551E15DA55AA1C6C38DF93BFFEA3D553758C91" +
        "30B057FACDAC8D857A1B99B8B5BD233C7A869C296D0744B494EA098C53582467" +
        "3EE811C592999B767F1823B1ED747DC98AF62E77DCCA794175EA9369230C9E9E" +
        "CC862C3286AD33A8FE79F4E749BA9E27532D98F1F7F1ED6B1B9873C64199EF73" +
        "006D6C8B9CD0F723E82569CA3694D9E8B0D50313809E0B3912C9037DD11BCE67" +
        "432A7B23A34EFD56411990032A00341E1544E11001339E7B900FDA9926383C78" +
        "2893CB6AB2EF2D91E504471F1A9C49ED622AB60D94F6FB0F952E13D1E0E25A89" +
        "38AA9F73EE9749CC527506FC4334AAA3E0BB7B81C17522C707B902FBBC7F07EB" +
        "008A53C53F2AA9DEAB7783B7BE02C9972ACF50E8CE5A138C6FDF9E9775F444D5" +
        "2CC5FF0CCCD57231A44ADCD50292A7A55177F0005534B1FF97209AB25B4D2887" +
        "4D854965A81A0F1BCFA61D7F5AAAAD0991F9E59D7C915B762AA827DBF042D7C1" +
        "C93680AF9C399F36146D91B0AADBA7BEFB8BF4330FF1BECD34E59E4851238960" +
        "57C85B0169A895862DF48F3B5E905CC9F078FF79A22E892538E95831BFCD2BA4" +
        "A8EF4107A59837FA0597629917F6B78C175E167CC7315098CF009AA0A39A1E90" +
        "8DA631151D732707F5C7ABF3C75925D28AFBCCDE5DB84AD9055E7BCD9F2CC1B0" +
        "8A29F23CC84188E33C7434120B56F64ACE39CC654BA9BA7FE3F957A557647B29" +
        "D9B749BEA3F30B5761178718382DD35C04D2321B569B68D4E89630D398EAFBC4" +
        "8C6C40DEB2FB1D00542201B37DA21514CDF090532908961996FCB9C1F3607A62" +
        "CB05BA4E42A04C94265B23ECB4FED0A1572434134CC6CA47BA827FFF8F435B77" +
        "0FB5B24E446D390103DC19F34F519B15FC49054FD889187D54FFBB7BA24F713F" +
        "4F723E5014CCEB5D740C9C65431E4676FD214F0183ABEA4E06C61B30CBAD0D9F" +
        "415D1295C898374B4A88FAC2D71E436F2F8628B0EFB39D610807E94C1836E66E" +
        "CE7483878D75FD25D23FB4200CF255EF123366B11CDC14C5E5A00BC6BE098BFF" +
        "A907B42D0E56A39638448D0478820213CDA755A336907683A292DE310B356A5F" +
        "442DA30F06229768D79C419260B657C3D117FC2969CF2D4D16BA4FA6BE7A3279" +
        "D7EDBBD046D32AC9D1BE7363DD8D3EF1389CAB3EAF424DFFFEEAE330EC68274A" +
        "FF1E209FA890607C55AB6BB6CE2B37F9EB3B0EE6C43298F78D6461A65080743C" +
        "75418E15872A2D47837071473ADA635F9133B160A59C8C8E34A7CAD6D7E3EDC7" +
        "F2A590328BC82D9D9CB48251C1CC9F583A388A3E4766E2057319DEB5C7CAFB05" +
        "C13213D9329E981B72F9C788A2FFA8125C92A1D3E9AFF9067FC3D023E4A09663" +
        "3C255169DFFBEADB0C74ED416C62C9433DC3555E2E382B129BF2D51D79A48F5F" +
        "3B34EA6B43E5D5B1F0CF0B14C195F954E049C874FFD1982791944EB5ADDAAB18" +
        "88AFD765B7AA8D05375430C65FBCA7EAA882F825BD180E129AA116D1EB0D0620" +
        "966BD06980A1D7D86F858D0EE432C8A76639C2B3FB4183591858078E83FD8BC4" +
        "6314F927630E246A35F3674071276BA13099CE77D269358F933377A40B0DCCD6" +
        "C6FF354FD3F84035B1951C30D1168D90FC129B4FD352C49864CC20A343D5FF52" +
        "243857FFB867B4CBE9A2C99602995CB3D7BB7A0B5FF10E1DFEEEB787C429D77A" +
        "2B1ECA2DCA644C761EFB41E26FC2861B54E5CD1B4F2B70EF66216304DED2C72A" +
        "85395889B5B098A4D7C937D0E0753E62F2955A8B535DB384A77FDE6209234055" +
        "CB2157AE2479B1AE70207803B0186E44836C271F28934BDCE77D02665F09C550" +
        "CDE7E84FB9C2CE1AB5821F9F399B01A9E63E6CCE730E3CB4701171F393663190" +
        "BFB29EB2C25582F03B9B2D6548BCEE587095CD909985026C99ABA43CB20AB5E2" +
        "E7675B28F3723FB4CE0553767AD660154E23FD494918F71BDB9224020A51F68F" +
        "11A83BA8D13D7C6EDF17A990A0DEFFBEADAE8EA999C78A220F2C6570E01FCC78" +
        "96F45479940DC4DDCD9610D43B064841030521D6C98D836621CFB5951A4904F0" +
        "ECE497E81F02C3CF8558361C2DACF2C5C280BAE50FB85C2EDC737C58DC493603" +
        "B33E812DCB0AC2BDEB308F26BB5FD99E2792DF504DB82E6D1163F3E1C0AFFF14" +
        "7EF17C074A1A57A2D1089D3E266E91D0543C07DC5EB4F52F45CC4723AC93C589" +
        "6FB5944C2F2EDA2F6F3D0543E7743A5986A07485386FCA133EAC352549C6DFD7" +
        "4B85B360C71770C9C23F4C29C833DB7BF191EA8C6A100E22165B64A0F89C6EBB" +
        "66CD76C3F02BEA702CDF964692E16FA24C2EC2B78246A4C148A38CB2889DA959" +
        "86DE0A37D528A9B3496CD30FD257C6A30EEC3DA1F5F49971044CEB9ADF33DD00" +
        "EE699E58857D8E89CFB8AC1BB8A90E343E6CE6659D97C224368FB464B1796BF5" +
        "888CB9E18C0410F452DB39B819D001B9B19D134B29658CA84A2A5D9571E06408" +
        "70C5ECBA63BFD251B80FCB2A400D4E932525451681DCBB74461CA15E56C8041D" +
        "0579C5676426DEF7B49527E5DAD3C4EC88B35D75FE6A81362D50E141B786E7E0" +
        "F5A5FE05F9D747839A44810312E9C4275E58E43DA8F9C2047EBF3EABAA793B35" +
        "983ACE9EFA23446DF0066EC16E00F56CFB8BBBF2BC7F1AC444F9283D44388909" +
        "05F0030855C0B2194AA1BDC3BD07FDA6FD83E4338240259C43235FAD3D8E0EAE" +
        "C92CC86BA6F2EFE0BE3E33E21C5EE8A3A665CC53E65235CD5CAAFB44A071577D" +
        "83D921A5AAA30CC9D6CA86B80E82463F68001F940C9287EBD1720FB2BCC5AA45" +
        "F64164629E50A3C6FAD9E56E3D06406B5DB8094BB74EBFE83CC0F54D6906A3BB" +
        "39C4BF4FEDA3F8724BD6E2CC7AC3ABC7C079B95F80E409B591520696C2EF9CDD" +
        "A56032E9CE01E516188A2FC003503A4256B83D06E3481B6BAD8D51D2BA10FD7B" +
        "97E61DB4060280FE7F9DA89C4FB743E224C0A7C06B33C3C21439EB4EFF64B3C1" +
        "277F7846335F03FE79A839A70B30A499DC51376ED224FB0F2C51140A00F9A6B9" +
        "44B4CDF4501F345C2E79E46642F0132943EC48A61EF875F474C96567BC32785D" +
        "0F7C971F59E78624F75666481970D892B8D03C7857B636DCD426DCD7432BB395" +
        "C2FED71A83CCF97F659F5C55D44A1B51A0A9936FC73A5BE6971AEC5267EBC354" +
        "AB3B9234C1783B4C3F03B3B39CCDF7C07943C207805ED054329993BE19388218" +
        "52F922CB0A949562B013CE978F8E802AD9058BEA04164DCE069CC957DAEC600E" +
        "9B42411DF8D0C6052EC61DCD2DD7F1FCF06DAB79471E5B94161B9CD09AC329CD" +
        "E1FB6F808A7198847FD2085FAB64E9A36D631B04BA410A0AC3CC8E905546D736" +
        "26C832167B5F600B7265BB51281E61A5ABF21772FA50961312EAE0EB7D0AEA3B" +
        "23317E0C0A959685D5155450551CF4A3B80B9B3F81FB68A5D53CAC11E43621C6" +
        "B5116D1DC219B14632986D62F56B50BEFBC4219ED1A04D914E4026BBDCC81E43" +
        "7849BCA6DBEF68D9A96CDFCF8DB7E5FBF788D90279991072B7490D2AF25BB311" +
        "68FB19DA674746D4C79A37E11204DA5C6A19168FDA863E922424ED22C43074E1" +
        "4DF2D4681350140D17B388B82B3496A56BD25A673C01043C632D2B7C555E8850" +
        "536316A9AA462EC5805390DEC2A1BF4FA042804D80C745649B7EAE42169460A8" +
        "914B5AEB8436E8EC1FDB2E82659FBA116F4111B5071A9BAE4E9AE092324EA0AF" +
        "D5F67E7CB32F90B1F888671C7694FE7B11E190B643369F10C80D1A15E8E17486" +
        "F7A416641BCBF2FFF755EBA62A63BC69AFC873A7D49853EC5A9948A52F8806E4" +
        "2E918032FDAE448588654E9722F9A911B3499DEEC5A31877D714125F517B6446" +
        "ED0EA0D47570B34DB6394BED0F2B006CF99A2194CFF3F2CE65F5A2B1FBFBBED3" +
        "525EC32366A3ABD5DE6CE2B8727E6C79C50D5A0F4FB7A5B0310677204591BA98" +
        "F1BD6B7CA4C67954A9704B74A324D5DD15E742B594B091BDDB67E9E0F7554529" +
        "E185DC475B826008C2EEC0E07580171BE66E758BBB9B1ECE04C6FF05CF3C436A" +
        "51C0F4BB3FBB4B8A72FD50B27E9684DA6CB91C3ABF97EAD6401B03A70DD30613" +
        "A13E76FA5A84D403A93422A5725FEA076D0CD9D54FE4A9C8BA4F3F14BEF4BF95" +
        "A2C211689EF2E6468F6C1E685FA4267F30C19BCC69A9D6B3A715EC41CA646FC8" +
        "9C824A98DF1AC909D9427F259750DDA79009782EBD5C18ED5AF18267FCBF880E" +
        "92B6B83D4CB789A8F05929819631A42A7CE9015373027E55BF964F68C2BA6202" +
        "C416573C7B5A90925CEB303CB2D883AA5945225FC24D24E9F23497DC49E69421" +
        "95DB591ADBFE709F48C3A098EB71895773984F57DBF7DD1E30323AEBF9D955FD" +
        "841CAD3B2FF642A99CFE579F6C541B2D1F91B59EE4183E421789101DA70D9D9F" +
        "630CED079EA9E8293633701A3AF4A7404FE1F89678B80A71244CE5171F78DD0D" +
        "18929414956B0F18272E56EE8A628FFCA13096841AB532F8208272ADC110578D" +
        "22FA7CCAF14970E566124CAAB02BF496FAA7277706FF07945C865D0650");

    private static final byte[] NIST_MLDSA44_PASS_SIG = hex(
        "B8CB5FE5A9662B215C95D5BA2B0328680F7576A148FF625E23CC5D203E97C624" +
        "69BDC078CB6438117C1E6669B88A9C2C567894394FC06BD2E4CD754FE9A0C7AA" +
        "506C004A290306D269059176635E13EAD71D0B50A99F543AEB8AA10449BC3087" +
        "CAB7420D92020E7693160454229449E0913A3D84DC884BCEBECF6DD93896DA67" +
        "D036CAB5C57E4671EFA3E21217F45CB4F91299E14F260E9F2260991D286994E6" +
        "FE96B5B92C6B289B51C1B7F8197778B26DB4208AFEBD2B61ABA5DF09B740D7AC" +
        "B49B6EE0B488AAF2AC9F2064A924D1ADD6361E19317703CA73024B1521B0247D" +
        "BFE05199DCA559B3D1037A13015237E2CD5633C27B45140F503FC142E9C16620" +
        "217CA18B9DD1A2D2ED1C353286426E63DC2AF5E7453299A67AF6E21D87D201CF" +
        "6069F7196481D6E6FA8424FC5C2D0EB9B203A635472016ADF97810DD4F9CBA8A" +
        "4B45A5EC4E550643A8349CDE7700E401B62D2B4DF65E08741BB1B79003A850D5" +
        "E1475B2985DDD770AF073614F510C8C59EE5A8FD785E61BD9AE0299E2A376F2D" +
        "8727AB02101B6A62195D526E1170643E06D682AFBAC1AD410968FF35E60F5962" +
        "F07783192498BC7563B9F2F3658816C7901F76F34A76EF8CBD4F05F14181240A" +
        "FE93BE82EC8E2067EA227AC297FE1BF8A8D456E8EE7766F1F806E55AEB16FA1F" +
        "B17BB54C382E121FFE67090F40AD5B229AC088A044304833D9E2B05F7DEE98C2" +
        "B084E2FE066E24963DC66CDD3AB2E58ECDC0718B14D6AF3A58CC7D911B71FA94" +
        "1B03F1DA25EE03D370D9CD440EE31640BCF355DE5C1C44ED382DB6AFD9A1771D" +
        "355760DD981D939BF045DFD1F08B7850808A0F5B5DABBAC64C927F9C034FA4F6" +
        "6EC183351586E5F7A19F827F0FAD68BBB7C160AF3FBBC59ECC4DF7C9ABDC6290" +
        "51ACC4CAE7E23EAB6BA006D48170AAB6C38FC6E77FA85B30A90034DEB46756C0" +
        "06D5317A044E647BDEA1D017E69304EB3B44344C73893DE13C32E0A272716F38" +
        "E899D353138BDAE0C5EA63E499C79CB9AF228BEBCC813BA99FBDF0C8F28C238A" +
        "E5F81E88376F061DC8EF0618BE3A75785921C17FF7AB6EE674FAC5CDF03B69B6" +
        "9878582062D539A41B4B79597CEFF7C7BC8C07A50BCB51577AE64272E5A01EBB" +
        "A5DC85B2C0C8D736E9EF4F81996CAAE3F12F431044194CE388A510C480D64362" +
        "44A020D3ECB8F1DB9DA2823DFD510F8F1C3AFEE9A696010E7AC50E794B9E6858" +
        "657EA7ADB70453DBA7EEF8D5CFD157DC916ABC5EEEACE1CC0EDD4114B4D00290" +
        "4ADA1AC0FFD5C15B5BC07D4F4E33A35DCBBA76573CDB18E288B037A9793D22FB" +
        "F6F784E87101693581BC905BE02F86AFA6FE9C191BFD52C21122DC17ABA542DA" +
        "8DD74DF521EE1C0994D50D494B2573BA3811A9CBB8297E2C7CB04914F3EB43BE" +
        "EDF78A947EC34B96A5EB7CC4DCE75C5B66ED6544699C117D2CC151C3D1DE4D14" +
        "4A63150B6F40DB8B3073802D089938DFE641101D75BF29477F81FDAFE39A7DED" +
        "F7B8958CC89C64C03F4E2F370BAFFDBCC12F6900189D6E8C783231E36DCA783C" +
        "4FE24FB73612A705A1744699EEBC5D15CD49427706BAB668AB933930E280E92A" +
        "94B70E0C2F874288C140AEE9AFDF91781ECCF6A523DC81612F05BD3129548CD2" +
        "C723D724AAEADB3768BC5D456E7D65C9FD1CDDD314CDF117FDE6A713DDF3754C" +
        "66B6ECDA3D24175B2ECC1D793A8745AB25FC8299FA07F256CCCFD5529205568A" +
        "448181B28BAFAA0369B84FBBE02153615D6C416875C65D3B230651EFADCEA465" +
        "076C8ECB56A684AB93F7AA71CA6FD6AF595F126D51648CEA184F2220442E16DF" +
        "AFEA25DDA77BCD2649E5804003E4AE405D186D925FC4B759B8221FC79DF55B43" +
        "33D63D44D473AF570F42E6F9C8804F7414ACBA273F1F8E72582A88DA767038C3" +
        "FC345EDBB7A885C46B313C42A30684B04EB6D00DA7DFA2E4CA882FF6B161C485" +
        "D86E8451DDCE71B15D87FFA504CE3CFC003555E6B15CC4E0667389E524C24522" +
        "487526DD37C882A4ABCCAD92EE728A742F08CA3A740BBC9BEF476443482483DD" +
        "B3A46C1B4C030C4BFC08BDE3E835212AB69811267B25840302F4E7B4B7A6A332" +
        "2A85D93058C32440B25F5FA2660889C20049D558C49910C8575B5820FA70C34D" +
        "2FC94ABDD14D987DB0EAA377712648B5D976685A4E43FD4622CD3A3AE64C4AEB" +
        "F3A3C4B29BE6555FE5E39E7F86998073F3714F260089864120BFD8A5A8385404" +
        "32E663BD2F427627BE8504B9DE113D79ECE70F08A4FB25AD3876AB352CCB71F1" +
        "5DEF83F18E33F6B9FC64B9D599E1B6FF0CF7E3C5D9F2ACDC45F10E45EEC9C134" +
        "1FB952582A58735CC1606A6411CF228F2D003C0952D98068C0BEECCB16C595B3" +
        "7037A50F60A196E9BF8338581043FA15E94F06EA4B1D0B75261F5E87202F5940" +
        "8B1B1E2152459904CDDC06D16C85E1AC48B3A6C8C533665E8CE6B384ECA2454B" +
        "A7A9D2EE5F28A84D23ED34C73BAACA66D8ABB8348444BA3E6B4F69B7FA68A6BD" +
        "52871F7DDA19C61FE5E52CF5F6A99266550489A0D366BCEB8BEACAC019ABC6DA" +
        "E7B45CCFD3EB31782AED29EC8E8CFBA79F89B038AD1BD83BB1F3829C5182AB71" +
        "AE8CDA16090C50B8EA5DA8B8A09441CAEA026BF5E010236C5291304159C87F0F" +
        "97C135449F1643B84272A2D6E7D89D1BF5ECBEBAFEAAF27944EBF7F7815B5956" +
        "39735B4260134479A6AE6C65BA4BEB766BB69588FDC50783341DB81B5B0261FD" +
        "2FFE658A2ED894D17D093A9835FE227FBB4CF4E355C5E404A7BE8A78A257D692" +
        "081F1C8EA27F5A3D12EAEDA54D7E0BB24C258C6841925ED5FB3BBC299C62E0F7" +
        "81785ADC4AA4E7A948A225DC78DE1A01EC213E1F6F88A7832218DC2FBC20B195" +
        "602F8B8F7A483C56B8A303180826B4B52C8C7B9FAC5719F15A1006BEC1557C4F" +
        "83A1B8167F74E2FE552E2E20D5A9B44B8795AE73E7081C5F9FB8C81D52527ADB" +
        "2F1E082F696E47CF8B258BCA3914369627250CB52699EE0102F402C327713BA0" +
        "092AF2DE9F06A7D3AA701D6BD1CB3F777CAA2077C3658179ABD36D938D3BA82E" +
        "D8C9C62C134DF21182843754704C1D3D999120378206DD599CC81D4C367AB0DF" +
        "E0770DD783873F58F5DE9137A40B721FD619F66D4963E65DDA82DB6554EE73EA" +
        "C7E3C66612DD55E0DF93496A9FF919F1A3DACF9D85DF3BF4699D66F5627580BC" +
        "C0B81AD240A7C1EFB29C208F723EF65A2AE11EFD9AEB25FFBF90C597E4A1F5C2" +
        "6CE6867D2FE3659B7196695648CFBD7229A5CFCA21F866FD5F31D0130EC01BE9" +
        "B5EF66E22D96685DBA3F70BF3F17973CCD157149E00660E99954ADA5A31CEA74" +
        "005C7A7E9091A3AAADB0B4C9E4E5FDFE000A0C1C213C404563708FAFB1B4BDD9" +
        "E9EBF9101D213144555A6C6D878996A9BCC5CFD5DFEB050A2730343F68727376" +
        "838FA1A4E6000000000000000000000010233645");

    private static final byte[] NIST_MLDSA44_PASS_CTX = hex(
        "F7104C4229A429B641DFA3E7BC912D04007D23181E1D1A6977116B6AA9171346" +
        "0800F8B0ACC3552F90E90FC6996C5F87D154F79889B3E9EFC1F9067ED3BA9F50" +
        "A53C531C19FF59F816ACCC080CDC627D8F3F244868B9835C1C11B006BC6CDB5C" +
        "F11CA2FBEAEFC6F69D60510C0F060171FFC2EAAF16906D48383E0BE0F5F75868" +
        "B9DB0E0D4D61407AEE3BD9D501BC9A28F1A6FD15D49538FF2AF05D2A6AB53176" +
        "3553C9AA2EF217FCD7BF444F9097389569759527");

    private static final int    NIST_MLDSA44_PASS_LEVEL = MlDsa.ML_DSA_44;

    private static final boolean NIST_MLDSA44_PASS_EXPECTED = true;

    /* NIST ACVP ML-DSA-sigVer-FIPS204 tgId for NIST_MLDSA44_FAIL, tcId=1.
     * preHash=pure, signatureInterface=external. Expected: FAIL. */
    private static final byte[] NIST_MLDSA44_FAIL_PK = hex(
        "FAA0FDC4AB2786BAB8236F2769E7654F345E5D1AEA205765FEFA7C965759A4AF" +
        "6E30AE034A74E688ED29CFC2AC23DC9A4BC97229D4796895E3AFB87E7AE14FF5" +
        "6E316384F4DE951869B5FBD302038F31EDA3B90BF5EC0DBF1DEE970E454D4F4A" +
        "D52B2B131A4085B3158AAFFB9E6905ADE287BED9A99D750DD7A98572B1A9D3D4" +
        "8CE17DAB3DA826E98F0A14F903460DFBAA7C2031F4D1A722ECB9194CAC4A06BE" +
        "3C640987158253377FC0715590CA677A625A9CDB661F5E0D9A85526EC4F746A2" +
        "19A825DD0AB0A2A9B16086A778BAAA5EEB420BFE615034E47F4C5E4B7AAF8481" +
        "B198FEDD1F98BBF3913192D52D41D207D29EABD97E2F9DC66F72DC04AB125860" +
        "B8EAE7827058D9AD1DF80CAF37E11005A8A036BC9941DBA33D01FFF9B0E85870" +
        "5E9A8E3113CAC1C3C48B1B29A6A2589AC3BC6D1E8651C2B81B7936E91E62B799" +
        "4E5C5FED5CC99AC164814D2344DDD26BF9065AE5A5D2A8165B5B4280F530762D" +
        "4589DD75275DE1C5875575C04F0F705E7A00F97885511162A0F6631A27835089" +
        "758BB941CEB99987CB072CDF74C748C6CF72D48C8F9F3D4D166F1CFFA35E236A" +
        "AAD346FF30F822C37F3A1CB85E665925F9F8607E57CE8B2B0694F75E17070C8F" +
        "8B0A652ECF5D627CB411897718C5D04EA79F0DC9E00486589D472597A774874F" +
        "8EBD12C1095CE8CC8E7EC15D1D890C3414A99AAB50FB35761CA3D0CC83D3AF90" +
        "984A3B2BEB55FA1964C3E14835CB529909EB7BA0425CF7B3358634E9AEA6B5ED" +
        "6723C4D177E7D17C4110D9D165EA59C5B30F30EE2575D78119A5C41D7FB34D00" +
        "63EEB5191A6C138B0FFF18AF4AD46B9C996D6B0269EC0E0667B89C4CEBCE8F46" +
        "54B60DDFC00500B3E439DA44B8DDE7802F4647851014ECBFB4C42D40993074DE" +
        "5BF87CB06E07985B8F861B0FD21CC08A543DB7DA30B488A7CF6E0A4A8DE69D84" +
        "A118A0F296FF4609D73E5967C7E9CA47764C4AF781E2A4C1ABD64CD4357C019C" +
        "2C6777C839F887DA64DC48B661AB18F243BB738DB365A9A7ABB16F0E183B0414" +
        "740CFF46A4A36B49A6D5E4D3AF9698C4F9791DD75D8557A2041C0270612B2907" +
        "42BCC9D7E2F4CF6F13618EA529938594B84ED1EF443356C02030E4C74F512C63" +
        "E544FB73401CACEFA72C8B7511CCC44BCD89A5CFEE566F16333540417153E3AE" +
        "AC112ED845C606F8C3BEBC6F75399E098C8B4BBC989D2AD48C015B90A919E7AC" +
        "A2B757371244C68DA1105722804C92C2C3BC5966EE743FF6DCFCDED0126FA53B" +
        "CA68874874C5FFBFB0CF72196C8AF4C3D6A52F0B9B1BC908292109C57D513BF9" +
        "BA7DF65CEB26DC65DD0D69BC2E230CD4BE8CFB4875CCA062E0CE7D8DC7AF85E0" +
        "CD944964DADACCEE2B057829818AC3825A45F3093BD0926C0FEFD379DF3F1C96" +
        "18FAA4B4E81AA8937FACBD5DEEFCFBEB7891AC71240F7124B7F4D5133FA71ECC" +
        "596645AB8D9FD959805AE1E1509CDA0339C46CB9D8123C45A3FD5A3FA87BC780" +
        "4FA5BF2131D0CCFFDA71454030173D8FE2176AAC2BA5E0915BA9AF5657C2CB5D" +
        "4C0677C0E95A35FB3B9E68091402B45B0AF96DED21220FF750FF303EF4C9DF75" +
        "6A8FBCD742A6A72D4A4977B3D0E315EC14D1688D59534EDD26E6A132E5A881B8" +
        "3DD9E9C35E26EC131E2F56B33FCA390A03047EE62390541DAD5BDCCEBE40D33A" +
        "411109037BC0D8B5E3F2976F1620BA0EA95E12BB818D9FCB278A091FA02DAAD4" +
        "205664ABBEA469B5AC7168CB3DDE3B11D366479EB2E3F15ECB000695A079256B" +
        "2E9F1931FB35A1F12F41A004202BCCF8E9BA1D96A4CC1F9EEC66D78A3342556A" +
        "E97201D4A351631571117024218A384AE12BFE50B514D5F68F4035C265EB7807");

    private static final byte[] NIST_MLDSA44_FAIL_MSG = hex(
        "59629B0554F06FB0845A1BCABE40A57680CC6E6A27D46E8A060BDBDABB72B55E" +
        "1CD640DFE2780ED62FDB89AB8B768F205D0195B1F63DDE99427E7E63C79F8C0E" +
        "06A6414E610277167D65A8056EB009846EA2794781BC045D24A1E15A8F8C3BD7" +
        "E1F85C94FBFEC3D648176DFB9B023B23D90DF002776D06623B3D4C25D9C02DEB" +
        "604308AAD4E3925FA5F1B5881F409A70C7BB1BBC779C1BEAA330778D5D69C7FD" +
        "9F8D3B367303DFF4C9689E9258AA92B2CAA98EA1BDCC789C7A7CADB3D75BC744" +
        "830D32B2F26519555DD988F039956651E34FE924AD4B0BD13F2E9C8D583CCD52" +
        "58D728BFFB7602B4CD3CEDC99DB8CB170906F0A5AD1F1CACCC2D29F51AE7914A" +
        "A226A904AC7057D4F59743CAF8D7FE6824B674EA876F7901DCD52F524AF74B11" +
        "06E5A09C21EFCD7EF177152721F981FC8073ED65F9983043C3CAF47AEE484B0A" +
        "BE65C37AD47EDC111C6D83B7B33CCCD1501E9B96020977CA5F751BFD01EAEC74" +
        "2FC863EDCAD21A1B0AEF6F70628FB8DEC8F564DBBD7BD322538D4CEF9AE7008C" +
        "DDE6476B1B94C6B5F95812D52CCA58AB64B5E50276CA5A76337F82908714741D" +
        "C59B3ABA3B1C94ADF7DBA517F207A1D51ED3030E04C62718A08387B042BE909E" +
        "7004DDCD9F767F67C4EAC89EE2FBFABB2FC44F17B2E421A269DA31BB835998C0" +
        "798813ECC3D19A6EEBB6F3266991F3D23E0B09DA7E092683F1A09F39E46B1DB8" +
        "10312FD5CE39C7399FCE21D968134308141626A111A8F1A85DE1268A0B393C0D" +
        "8F5C39AC9A07E965AD1B8370B28465172BAA722178AD144ADEC9DDB79F745522" +
        "3ED45ECD2A6EB387379E4E26F2D0723B98C5FF605B7AE1EE29641A4D8E2104FC" +
        "41764024C0FDDC2B0BCE9B599B3EAEF8176CD8A37197987FF91ECB0799BE55D3" +
        "F8EA64A1C989A7716871F8F3FADA0CF56CB40BE4F5FDE7A61709AE676F459C03" +
        "C29634A8331AAD2250CEA0583DB089A7853B4D35C117692D9397BC76ACF83F09" +
        "C935A383829230B9E9CDFC5E2A7A3DD4805A5FAF4F65396519B63B63D497F04C" +
        "2DCAD27B840902E5EB9C9BFA7D83E3CEFB910D9C446CD49CB1288C84781B5685" +
        "C879E20E4939658DF7A41C2302EA8DA53BB37F2B1CB9C60FD91BB4E996F98907" +
        "C09DE50B281F827BBC29550A7CADB86511227E01231722AD840A2DCBB421B64D" +
        "AE98D1BA4F9FC8B9B5A3423E664A1A06E7680B4D4638A0915734AAF1D8371EFF" +
        "68BC5596B39FCD1C70C43AC4A87AE22FFC0603D2211F09042E845A1DBC397EEF" +
        "67EBB9487A160CEA3A2C6C503CCF16B252672A562786EA2105D0ACC08A0849DD" +
        "147794BF2C3496275C2B580C400ED4DB45E42606169367FCAAE57C113D691593" +
        "39AD5E11AB5B96786D40E98E82950681E1EA29A09C828A73893F1AC3AC046746" +
        "B9DBA14790B6C66F84C289A006F03BC5A92915A5B0CF6FDAF4EFC871CB1B3BF6" +
        "E1F07FBE5AB0ABF78FDA6F0C5D7F6251B1E6DFE7FA48363899FCF73BAE5649F4" +
        "CEE61F6941EDAB881010EEE70809D7EC2A76C714100ADD0059C0AB0638BB087D" +
        "C17815346B8DC879FAEFF1D84990F9440230F7B6D40A6CE41B8AF60966A67702" +
        "E83777024DD91C212D9C1E7CEEF98B4FCA11ACB0BDF1B5387A630E88AFF51519" +
        "6BDFD1D4E0C356AFE0B5A78943E6472A13A5FE7BBFE3E1BA0C57C6A489FDD6D4" +
        "25626335249EF5C98D6C949FABC1904008988686C93A7BCE14F573D58DE41B75" +
        "54534BD3264FC2992BC8B63BB2F6B07F2D5389A4722B2871358984E637219144" +
        "A746955C41BD93913CF8B1F2ACB15899DCABF61E29C3BBEAB08C91BAE0FF91DD" +
        "BA62EC0B908D2A2471B2682E15D8FDC64365E6C9FE4CA7945126EA6CE20544A5" +
        "27C7CAA9789CFFC374F46BD0580D109AF873BF25A5B9A4850C64A78F519F18DD" +
        "83C03B2673F63A038A8B82A2D2B4F9F9B53B0BFBE2C86662ED3EA0B29F894FF7" +
        "973D855206C5D5046EA1ED0B1B91C3AD174719A096B01A091342EB49FBA8A478" +
        "979E3496611041CEDBA2ABFCD179A4D9879B5B4401E695CBD3E7634894B1A619" +
        "9DBF85C06A4B49728C1B872C7CEDF0768A80FBA1C242371C5E9FE1AB83CDE963" +
        "CE27EAC1EF2F59823D1D863903F46AB492E6157D157441888074EFC4CD869013" +
        "548B21E6A2825CA0FE101603CAB8914E63AE3113E03DEEEF0E8D444CCF579253" +
        "2151F19543CE63C3FAF6BB04644F15C5C0BF1C60D9B164452064B505465696B9" +
        "147A53E07E520D800E0AC545830F54C3928BA26511A7CE74316FE7514E72CEBF" +
        "3B3F13B812A85163242E07A72696B507B503781416D2F927336688CFB532AE16" +
        "B2ECDC38160AC70BA0B9380BCE01DBBA3E9D84FC8880AB187829C3DAB3F11C5D" +
        "39D5A90251F3A43A000095C2EA7151F6403CC0D290E7EC5BEE2D2CBB44C70C35" +
        "7B227C1FF81BF6FF6F14E474DC9A46A5E407A1BF279880B5F5A21D47F3144EE5" +
        "75725C301635FEE2FBE76A109DE1FE0B751FCF93AC81A7D7539355F7FDF1E6DA" +
        "248156DAA5BBC4B49B4E41CE6FD3494B991B39D9EF7367CB4C02ECDBEA99313C" +
        "B6DAE4E62C9727AEF9BF06144DF4D93F6E40902E2E9CB508688372CD69BE74A1" +
        "628EC34913B78B2A4A6876A47CCF4FBECF55995E3B94CB7923F89EB8C271166F" +
        "6383E39CB3A895089FCCC2F916D800073B343E802ED724462A76F2A9C02AF60D" +
        "618D7D7DD78AF20DD6C73660DAF5F015A15FE3B87E78FDE000BB26A6B66CD0D5" +
        "2C9DEF07EEA2661EEDBCF82BB82502511CA815900023AA50946B1F3DA9DFCACF" +
        "F3EE85DC470DBEB7EFE3DC29C9924C1FF9D085803BC3C4B27A3614AD595602C9" +
        "E6C2BD0444FB21A2295154C4D52587A9187994ABA9B091B0F3CAD869B0E70844" +
        "A8B24F513B65998D7B2F30CD74B77C52A0C594629AAB7B3513F969DE889DD259" +
        "1EC87C5178286EADDC2F5625E5A4A95DA860068241270C2504C779AA1275BCD2" +
        "5516711E1524B3A747D58AA7D080FC8CA47C534570277090E691762CCFB68366" +
        "D627A5E2314ED9FCA676AAB1B7F3B77AF4486195DC93F9FAF8A26CEE20591EF1" +
        "87419B88FAF0D505112FD86921683252809786EDA80AA871AFA0D30653EB2B7E" +
        "E0CC1AEA4637117A360AA08405A99ACBA9C0D94CD8FFBDA22CE1BF0C6B0B10B1" +
        "B3DE13BC34DC1359E35FEC66ACD4536FAC3E12649CDF5CF4884FC65991F5D923" +
        "714D585818460ABB24762C35F346F1F23B5001442F81FE0C362B033F9737CF10" +
        "94E0AD9EC68EBFAD8241E59BEB93208C8E5E9161056E031EEB1EE7D8F48DFD09" +
        "1118C913D28050CCB106B2339FEA2B1D03F8CC9541E1285EF3801F175A71B435" +
        "75858616B124845BF3D2422ECCF79E0B364149A9C2728E982F7A3757DB449EF4" +
        "357E2A3DF5615F4DA18E07D07957D82BD7FA5CF966E9B49FC27B78117125E9FB" +
        "A2BC86A5227505933BAF9276115113A88BA87CC53F41B1BB244CB3FBF49BFD33" +
        "0519228D0064D453C09B3B17A4D8EC76776DAC6E59EF14C54A860AF6C9C62E76" +
        "C7374FFEC78B153817D5B45406FC412E437CC12312C46A5418EA19169DEB2975" +
        "EF4213E6062FF23991BE32C4442CAF639CA7E2F23B1EB9DA1D562EBAC4A7F74A" +
        "99F980B560DDD5256FFD42CB9E88AA46A4DDBD9436C36E70F773C3DC556136D3" +
        "8AD14CEF735341593B18B6AA8EB04EE132831CFA7B811CE6E8F309A137113D25" +
        "A7D17CED69DDCAC0D8381552A957640115FBEE9387DEA506BFB5CD3D14199251" +
        "6A6001F3B263DC2117A4D92087DB9CB5311EBACA62A886A9C42E5146FFE165B1" +
        "599D2D460C951FCFC5513B0E87693510FCCC1F79CAEBEE98A60E88D233A27252" +
        "B26089BCEB9882509785B651402DB74C0084E871331712E25919DE8FE5B7557C" +
        "A27B3B3FB53594E53E5390DDCE48B1859D6E89881E14CDEDA03FF2807DC0A328" +
        "628499F2B255BA8A0D07860104B2224C9A5C4F89DFB8013B6DED9470C0A2ECC4" +
        "54958FF1944CE1EDF769401F4F3ADA35B0B2226A84F7BDF2762D3E9442B1F34E" +
        "27D53CDFE7D3FFBDC6D4819DAA7768AB82D722B3F0149A907477C49309A8C178" +
        "06EB97B8E65D0CD266137E1E8832693BC1473D032AFA39BE8D223CF4A665D045" +
        "F209D013B229F3BFDA4CAD29D227B3B16B6AF9DAEEB382D7FE49E1D91CE71F13" +
        "3D51463CE4D5A5BA212BB7ACD138086FFC59DBC5790D973946B4E958E315EB91" +
        "F87F62DB97B00A473072E785ECC88CE8A1C5EF077918939F2DDEEDEE1CD52C09" +
        "B1A4745E20AA35EC6154DD0CADC41733A3052D101E9C356DDD8285CD9C6B9B0D" +
        "7E944904FB2FEDCFD50EA4AF857022B2AB895AB8E3AA9EFBA8708D0D7A0BFA06" +
        "03637CCF77C3BDFDBD11BABD98DEDE6A90FFD896719F71FA64C1C7B92DABE190" +
        "CB3D8D63DBB2B28420CB5755A502BC7029BAB85B9BC54391C757822947DDC915" +
        "665FC0544E0725495B735CB4303952E6EB0F96F6C048EF8B92DB6B01FC0EF87C" +
        "80888EF7E9A77FC0B179A38A51D56D33597E383F5A4A9DF557A9FCCDC8D7C2FE" +
        "FEAD8A9D6CAB64234FF1415E3D46358EA933D9BE0DF62A0A26FAA34DCACEB2F3" +
        "D7E1D186641767323D45368555C4F0FAF7C79C7ACA9AE0D034EEB4D3DDA16885" +
        "7696222D402C5646AEA359EDC75EF9DBCE81EF33542889FA0F12B3BA5D15D696" +
        "32FDE34E9FBE7BE6FAF0A35494EFE2E7A812E8B4389A835AE4C2ECBC13513652" +
        "F8EDDCA946A1EDB63527CED7836EBCFBCFC60B9468CE840FA72AEF8C75B10EC9" +
        "C827C251EAB1AEB3A65182BCAA2A84D44E616D211AFF79BA3FC75BF4559308B7" +
        "E3780208420B5D3CE82593E188C3D6021E45207D68F241CA2F055C47EE96D93A" +
        "320A7F802DA31A6FDED6135BCAA9BF9B0F498B2ECD3AC263F830AC5D7A3B13FC" +
        "805D8A485EE64CAA74EEB72B553AFADC62D68302925A97BD53DE677A4D8E5D96" +
        "026995C4852271934C1D8965F8154160AAFAEBD7D215661622106ACF7998C7FD" +
        "54B041979AA5D64DAD5617F870BACEBDAEE013158BB14743012F6A5B6F1FE964" +
        "16F920C6D3F040BD107789195867468D6CDAEF63FDDEF774761487DB63E6C537" +
        "707060B6473A979D4410F48225BD57890ACE4234565AD577B067006B8D85CE05" +
        "F9AED7B0F1515BAE0F45BED256A7DB777F156032EBBEE647215108A2E9A7E302" +
        "E24B2A0134D69E6B002EF33CA1F6C9B80AE9127088B15024B00C878FBC5BDD03" +
        "8260C82060E5619185E9E33CE39654A8E1C4FEC6AA6562AB6B8AE796682454E3" +
        "6AD7D2F69EAB7D08B0BCD6EB5CBCAE97A2EFB4113E47DA555667CBDDEE114D5C" +
        "D43FF8912DF69895D63C0D84BAB8123668D5A7B6802923626900EC37405445BD" +
        "4090A46FF2166C4AA5343B61A94355439E0B3233CF8EEC78AEEAA89A413DCA12" +
        "9EB7C70FFBB1429A0877446DA2D14D119A2D750B66E37508A0A02035B175C1EA" +
        "A2DD33F755F0701317981644978D18CF1F591002286CEFD2AE1C006CC559321F" +
        "BBDBFABAA16D6BAB309D7755B52425A00DE68EE3957DC69C98D564C19BA1B18E" +
        "EECC69BC2D25B6AE3DA57FEE0987A713DD9B0E76E821EB249828E0571BA950B0" +
        "8B80DD5C37033B1B5D760581A25EC4782D806AEC513D0FCC29A0BF6941132543" +
        "26214CCD00D49348875FB4F7ED14C55791216B41ED77D1D84EDE31CA4BC37A11" +
        "6EF29667B6569A98C1576323155DAA5A6A0B2CBB249436BC8902249B6D54A0EB" +
        "82C955976F3063BEDD90D523345BDB72799E1EECAEFDDBC48A05971914782896" +
        "7B987EF0D023F989F8DAB80058C0C2211C381395EA1B8301BA25BB69B95B9996" +
        "902DE4F77CF7AB8D34090831FE96EA466F5175AD0EB9C35F8FFBE87BB12E9200" +
        "0CB7964207327291E6224FAE7B13FCA3A16C984C5CA54D276FEB29EF8991AF84" +
        "B88345FB398BB3079DD1535CE0334BB9EA710D61B24B8451B2D0CEBA3A106339" +
        "7F2FE2C6CDE714AFCD4B97E0F600F73DA664FFECCB2FB39A4A12E24E3B815235" +
        "B24A5DD871F11DEA5ED99066E5CE63951E093C8D451684DC0853B7EBD173885E" +
        "B17CAF5A951647E2F144034F0CBBED02FDB4C2C3DF04B162A5F2EFB8D40F2F62" +
        "299C22D3D06149E1CD1B91F77829CFF70C8CFA00D5B1FBD44F7FBCDFF714FE83" +
        "3C7C78DBB3FA8EF7B59775DAD901E261D2E6CDD2926BDEA278D5CD5E59FE7842" +
        "F66BF95A8AA2DDD95F8C6CB35373AA1DDE15DE7056F5EE35D6037E90D4ED8421" +
        "4BC84E831FC076B05723C880A1B5A5F666A14CDD20C30B45EE181B005335FD27" +
        "0C0D68F86A10BE2BF2FE34613ADC4EF204D1C6D115902FB4C1B893DEEB68AF8B" +
        "85025CEFA7A9C82C72616D4F78CDFE82F6076903C0822A69FC10A2323D318C60" +
        "4EAC2F385E44FA6ED486543FF92CC464EBD11078C9FE37B43BBB34A2179CB3C7" +
        "A0677B3D31E95306803301F737662431B2BACFF0F92DC7CAE96022B14B7AA1D6" +
        "7E8BA51E5D771FBAC109A691C820155E6D7F1CB97231534686D8B450A4140F26" +
        "C4CA184DC491B0CF7341214C744EA29EB1C6C65BA165A097D86AB00D4692FCE3" +
        "551ADF6BBEC72534DABD1F13C82CB136E6FBE3A0F86541A335D714E9C58B8C92" +
        "55EA78258489999567BFC0E209D66FED547599D32551CECE4063F4585C8CF39B" +
        "9F28E9381905AB7FCF09F1C63381072A307076B9272CBB3E22922A3009699E59" +
        "85F46310019F5ECA2EC000E190F0606A93FEC1FBE579900339EAD777CFDA3FD0" +
        "EA82B794EC9A28F26C5B32B730F529FA09FA0B493989DB3D884FAB2991CA2561" +
        "7730D6BAEB6A659E47FA85C0B61953E5146942F53CB700C13CA2FE51396FEDF1" +
        "1CE8D083DA3E634CEF47003A4A18E087A1E5997EBC424A48B4B0F84FB754E647" +
        "34D0D896A0F4CAAEE8FE378600B57235F2B5A61FB721C1F57F7178A4ED4C4B27" +
        "CE00EFBD4DD23D470451A07D37CABA2D55E59B027CB448248D2669DE3BCE0089" +
        "7C6E50BAE3C71B8DB822D300464E1BE950B473EDD5C8961EBBD3856960F56AD8" +
        "51E7CC52B30AE1C8D371CB12D203F8128FC9D3A6A7517149C104C4C490EEFE83" +
        "35A6043E61ABB2245A1B3F461258227F9715575E799F7F56262EFD662E3CE412" +
        "B7DD6AF5838F28E6284C4527A89777BF6AF2007400B660A09C87CE8992DA709F" +
        "42E7DE89178C72988A5715D93F1CDEF5B790409FDC26F995678282F628B23E3D" +
        "268543868D2F4FAB92DC9BF94CC7221F7EF73CD0189725856D6BB96738057526" +
        "5161A1623B5CEDF461593601AC660120EABAFB9ED9909EC8E77EE27A23B004C9" +
        "DE485F4DE70CDA7A961561B65F0C044FE5DC183CCE536EB1AE896F15D68309C2" +
        "0F960DB1B5E6FC02F7C9F247414C515694B9FE2D731360EBF91533E40FD14489" +
        "5DA202B1639908E3098B502E3F67C6E26E7EE61A0C6765");

    private static final byte[] NIST_MLDSA44_FAIL_SIG = hex(
        "95BBA469B6F6464A4269F47A7766E8F6F066BF3EA9C1B7196E5FB2076D3618C3" +
        "128571993395F34FE9EF40E4EE4CBF6E795E16AB4998A64178A1631218F238DD" +
        "8CA3835BF14B2E67A99E9FD14408962816E2D9E9AA86A258202ECA606F3C75E5" +
        "C81C98D3A01BCB685710F631BC253A173D79AF484B84738C90EC067C5C095FEC" +
        "F4CD9E18BF81567E4A21FA0F8EEC262EBD3256439B718CAE5F5B7FA3B7E42345" +
        "A6A93AB69B46DDBD7565C541B521E276F0EAB270F547BC37C61108899E0F5032" +
        "96CD6E5497FBF2F9BD9554448E572DC5229CE08077B71DCECAD3F5DADC49F60D" +
        "32E4471D3B92DA59B3BABE649896A341F703B51227855B2D2AA080F4E325C5DF" +
        "DC3DB47331EE713A64B0ADEDA4C518D04B1E27FBFD4477D58B6B92F3FCC3503E" +
        "64980F2E002000FF87AE717928963EA887498A2E2B58B345A6D9EA8C0AC7A7F3" +
        "E0DF03C358DF04A6ADE7C047B98C3F1DE92E116747DFA5C30714C3A47ABF55BE" +
        "8043779A1A3810415B4940014EE6CE767D2257F3BB1A03E52A0539B3ABEEF982" +
        "24F7A75AA7C7B6C0966C769994480C9803BFC94F0D4FF6B9CA70131CAB035BA4" +
        "62165534133761C07C12F1E57C12187DEE14B6D4156A9A81955B2885907B9410" +
        "8BDBBCD95F120C1E93F3B260D359DEC24DEC9C8F64EAC9A9B571B111DDE745FB" +
        "A6DF48B54F1A445C2198BEAB63D0BB43FDB7C92B79C5620FA12CFE3AA7D13215" +
        "6CA5ABC85E07B55EEE259CCF7764AEDEE054933721402266998A2C0F312C1AD7" +
        "79BD00D2ADF31ADF482226560E453ADEF749118FCA7930E7391460BBAB2800C1" +
        "614A7296CE89097AA86FA6BC7A6018C9828BA6DE105E87ACD8E157348021AC57" +
        "A11049B18CCD0195DDAC91E93CF423935917DEE2FD3FCF7EB836BDED70F73CF4" +
        "20D3E8F4567D466F29C51AC715E1648E0F35116DD233B787D404E43819CF4D16" +
        "9FC8438E14349546C86F3D0F33ECFFA7C86F2ED842228764CD8EB436676D2E24" +
        "19F9B35857EFB78C74647A785895D4EDAF1DD2391656F4DAB6317FE3845CBAC9" +
        "550E4A72D8D1CB8FA3934947DCC5FB0B2C5677470A418C21944324CFA1B8D956" +
        "6A07EE01F756747003E329ABD96578793F074959227C735A1257F269388CA865" +
        "031D6009634DA524154DDC3118F70C864C84A01CC4AFC0A68E72422823ABE627" +
        "DAD11A42DDF3ACBF9334CA5F1133E833E951E8C92F2D47C7123331CF30CDD160" +
        "784D34262E8A162D0338B1C18067C83F6EE00EC71542DB46BFA9706F61B06FF5" +
        "17142163BFDC2459DFAD14F9F5CAEBBB7E6BE12A7D4ED709A58E599C175438B9" +
        "6C845E5783DFAD5E26B9131EBBB29FF469265B9ABBC65F763F7CC47E7A0666C6" +
        "159FE9B65C1E055F34D883E4EF98A05AB1F8AD61A019FDFA4A7B493646C4B4D6" +
        "48C3A6677CC8974F9A2BF74040B750150F17EE5A064D2BE9D5A05C2FF56543F3" +
        "7B6DFCFE1A4697B158A7EF08085E4BAC2A5E5A42F98E76FEB1CD6DADCE8A13C2" +
        "85756C6E0F7A09E2F93E90275940C1F7C92D14A5D74761E1314C717952C3B050" +
        "6645939021E459DA4C1EC7B37C681FE1642D272FFCDCC64D9DE0AA00AEF29C3B" +
        "28919C7CD98D0808006EA6A0CA800B520CB39691DB033365056EADAEECA05903" +
        "8B9B2611908DB1AD0A4A1A73183E22FBC4760709878C21558156F04D00BBD24E" +
        "BD11550B0CA43D6127CFE7B365C3F3D9C4D53E6C2AB7F7919FFEC9AFA30F944D" +
        "1298282D87309C647A99C6DD50E73E59EF1BFBCC9542C627EEABC7DD75B47BA1" +
        "CA8F0BDD708AA847C4F9F5D3043606A57ED2A4B52A6C9B02494A43FF411C830D" +
        "661ED9099D8B80192C816B3EB79804B89F9CC9B746E68AD6A97A851EAC845D7E" +
        "A3375E99DDDA5D804C1A020D9C942A42224F1AA8E6812EE0BFFCDA33E998DAD5" +
        "A3E6271950732056C1BE9C6178DB71ED550F27383CC9FC257591FC0DE9163AFD" +
        "5F8DBE0CE85148FABA556F1DA792A6BD502BD5353B539463770DBB829A7F31E3" +
        "24A1570481215A69F7612111482D224C27F9A32710823F446C33CEC5A721B15B" +
        "A78239594AD78F2917FEBB064CA0AA9AABDDA40AD7EB353E14BE51980D573161" +
        "EFE175B346A481A86CCBA3CE068FDF474883A8201EAABEB9D9A0212307D8F685" +
        "2308F1B2C251E58C4B710031AAFD266CACD1A6A1FC91529452F50DD5C8486A4C" +
        "D12AA2505B472082E9E60D0B7023F92AC8919BFA63CE6FC5B79A8B3DEF92A089" +
        "A51CECC055A72C51C6B8D273C105A5E7E143CAB55A5880779275E92DF0D03713" +
        "93975F4F9A6A59D14484DE3ADAD079036AEEFE6507279E138F11D31779FFC694" +
        "558F3BEE25D4F817C754C4A3E04D6F1B22058E347A8F1D5535474C68303D94A9" +
        "B3A8718C5086994FB9AD0DDB908F538699E451355E8EFB2226A7C6542F4F3079" +
        "3B741091DA87A1AB44D4D965444AC6B4251B3C04511065C276C7F9EAFFAECE13" +
        "DEC8B61DBEE9E5806E458501A357434E258B35285EDD75900B057F763DB9EF89" +
        "3154F6E9C972DDFA134BAD5F5C26590328E080D873DE67F75142556B50F1A53C" +
        "1DED217CF6D04C522DFA4E9ECEA32073B0ECADCF7B133FE822A46A28AB2478AB" +
        "4C95B1B9E2728063F7BA9AF0ABF8AFD9FC8687D63E1F35FA8D16601A9CB7972E" +
        "8659756464D13DEFAAAD4A90B3DC0E713657E15AAAF8D11D88E117412794C527" +
        "2C452749D3AC6F8EBB80C68501631F1865FA3814F9D7093B8AD0BFDDB9C9D34D" +
        "5AA78365BACFD8354F537A284437279191715D0E4481D707BF01CE99A7BEF78B" +
        "5E4227E268A6CF7198288D46C1183D9230C2D175D54FA033A39C046170ABA8A9" +
        "EA776C31E2ECB163351B374206CED8095F236B769018011FA3453BABC9693280" +
        "A2812F1B14E040443CC3ACA86C63B4891206037B3072F95B9624440F529FA725" +
        "C025ECBCF60026C6F0DB6EB39CC392361B16E43EE71F416AA5259F36A55F52E9" +
        "2A5CA923D2D7B8A61CEE69E1145856CC222F68ABC54BD0685D7EA3040270D5FC" +
        "8F68F0DD79E3272D94F0CB85B3D88B5DA5114DE09A3CDBA24B66BC55C964103E" +
        "4B0F86A6C324AE4CC12173950F5794CE724C300E60663E5AF75D60933974929B" +
        "B7253C24EAF3FE1D1EB5B99C7A8CED8B9D250EAC4F2E337750672330389A1BB5" +
        "DE41C8ABBF45A2BBD5AF10E78730FCF93689F383F64C49066BDAAF56C9209D83" +
        "43766F30C20D6CACA3ABF975A53BDFBD6E289A10E48407FB547CAD417C50010E" +
        "B2C93CCAEED8E07892BD1026FBC3A9B0A988F965E0B8AD63E5B94B018EE52EE5" +
        "E1F9B8E12308D47019C6BDAA6D6547824D694F8B4DFFE14C1BFE291466C365C3" +
        "191B2338397C9CA9B0DFEBF10F1E384F6A8F939CAABCF4F9212B496D7478A1A2" +
        "B6BAD7313B3C7794A2B3D1D7DBE8F0FF00000002000000000000000000000000" +
        "000000000000000000000000000000000C182330");

    private static final byte[] NIST_MLDSA44_FAIL_CTX = hex(
        "EC6DA10AF5292F80772D21E1BEF4A462BF0E1E3D28F6DC03163A9A72927D9539" +
        "32116E");

    private static final int    NIST_MLDSA44_FAIL_LEVEL = MlDsa.ML_DSA_44;

    private static final boolean NIST_MLDSA44_FAIL_EXPECTED = false;

    /* NIST ACVP ML-DSA-sigVer-FIPS204 tgId for NIST_MLDSA65_PASS, tcId=31.
     * preHash=pure, signatureInterface=external. Expected: PASS. */
    private static final byte[] NIST_MLDSA65_PASS_PK = hex(
        "156EAF9AA279E22DE502D44C382A2A3F92A437F86DB4935310D8D65FFABB6240" +
        "70D91D65C6430D838032876A6BE8C2A5298F296E693E83DEB90887354174BACF" +
        "DC6604B0807D7DA9667A10E5635FE47206EC1F6CD7524EB0BA6B0269CBC55B92" +
        "2D08E62936230BC6FB1EEA5A3C0EF9D349E5C4603326525649CA5C193E2FD1EE" +
        "A093516A81B731AC8272E4C90B7E2C32733EF1F4C496183EB7E0316805158E59" +
        "FBE516987D7F9E1B287DE0CC2DC162D05B1D5688C6EE38D61E5B0F7D561FF746" +
        "20F477E6922E7B2AE79869D4C26C4F8BAC324A7CC059979932D1430D2FF3739D" +
        "4A833CFC666CFFC4443BCB7C1EFE40F4CF901F1A2FB0612AE67E0E63262FCC0E" +
        "A13C7EE606F5199238820293870CD65A76DAC4A12FF603F2388268EAE9F063CC" +
        "E59FD883434890F20034CB57B63AA206F57B75A5611B769678F14BB865348F3F" +
        "6C727F84FB88C1018B863F3BD6BFB6971D9D133FD0F424CED2F8902B87AEE696" +
        "65162DA763B8502F58BC9DF3FC73F7D88658FFF63F6D2327D8628B6E11607F79" +
        "9FD54A52B97826A05EE9555231038068CFA3D62F410663B6CCD26C985CE2B131" +
        "197B84D2D293B55198B30981F8222C37A778902F724DBE872A1E4DB59BC7B2AA" +
        "F0A4C4EA32D1C391E1D200CE8AAE0D638F8C9B65C80EB67C72495C7CDA40192A" +
        "AB3937DBB8BA70B69E17BFA53841318524F80C1EFE0FFDBF94823D6E318DBC20" +
        "213C2946C6E88319517D7B438C0240F91E003E3C83452DC3969CE544DE7A76CA" +
        "9FF16AD66E2D1FFC61FE2A5E9A3C29B067EEA5FD46746E68A55493D027DB7F1D" +
        "E737B67C17167ED4073E7E410F39D655B4FEBB962ACAE1D79C0FA7139FD5EBD3" +
        "99942249ACBB436A3942784DC2ACB2A4760D0BC2831D42F7B4421D0092D560A5" +
        "624C9F007B6704285280CD0991192D8AE63A791BF7B3E170C873EB471A89603A" +
        "A733E29344D8DD6AE8A8F5713DB8056E64261DD5F10E073244853CAFE61B3C85" +
        "46D1421BBDA1521902AFA94A6D751D1581B27C06DDDE012112DFB550DD7B7B60" +
        "C735BA37F43BD6646F2F0E3ACA6EB394FD4B59AEE3F964D1CE163EF54D0DA518" +
        "F02B1134FF26DB7F06C72EC70004478FE4C3248304CD98844C10BFD4EDEE57B9" +
        "B3781E4038B0FB681888216B6D154271EE1AAFCA8869A90DE2D0B2E34B5B998D" +
        "70921B8AF1CB2F026C0A2F4151A7B988E9DD2ABAC8B888F6F5B2903A694DA381" +
        "2C5F2BE693538563B4CA5C7B1130E65FAABD532D820A34D93B6CAFCE6F246489" +
        "71F0C37D054B4638666B0C2A3A26C7655647AE2D6BABD92C22AE984DFBC948B9" +
        "6D46800DBDAB26E430446D6C8766D8C0B67CD38491080D019C5C08A3CB6E6E12" +
        "E1B1F1C962F0C2C8E418EA2E3EB05CCCCFF6B1AE0D429CB9045A36774B172D55" +
        "03A87469CD3A304BAF464D8CD5E1B7020A3FD20270AF56433FEE8A3FF7A831A8" +
        "74289C25B38261D0B5B450C044782B184A16F8729AD199B2A5C7734B70C7F04A" +
        "9BF84D1EB1035A5B5F24CAA5A772910A993DD5DF22B7AA6F7A72B103A6CF003B" +
        "437A5248F9EBEA9E9C64D98D92A8354F6F9D1A80F65A270B48FE2C0010B4156D" +
        "2AEA2226E77E11154242DC3C63ED82E83BAAEBEA84386D9B2A72ED91C80EA1E4" +
        "7A8F0BFF28AD4269BD764063B19AEE7889B9C5D9F607D983A119AC92BBAA485B" +
        "05CEDFAAE5A4DFCB863924A27DFB4AA660EABB04FC7C4B62A3AC945C2E35B188" +
        "6A5952147A1850B14E101710F0C3E1AA9C15A71CED042544053273F85D8222FD" +
        "AA211F2D70081D46944791C9484B5519500762599BCF92F7BCD6B61FE6B7B1A1" +
        "94F73FF272ACCFF0E650E31C7104FDB4617ABCF8F5DCCCD727734E56EC445829" +
        "017CCA2AC203CCB796AE0F78238B55A8E272D8E42453EE404FEA433B31A9CB3E" +
        "FB9AE42DCAE7CD7FAC350D8C76CFD1F8991D95F6596F30F9915859885BF1E79E" +
        "0F89CEB82B94FD213713E10A8EE8BF82F474EA1826342500FC4434071145D903" +
        "B73D18EB78A28D2D07FE46448C87342EA8BCA4E4F3BC1309CE078E91D4E887AF" +
        "5F025C942D0CA867DCC8D40555A2D33B243EDF38D7E9978B80B11882CEA5057F" +
        "2A765D7EFE6E14E03896E0E7647983EEA4953A8AD9C7EB1FEDEEE96998CBA0BD" +
        "70E373CE023BE1301AD7281452DF3AC16DF1CA6B5CD93D35236E7039A57B6D95" +
        "6E9B79DA5949A6EB842CBFE7F1A8C6637410715378B7DDABD01A2AD6E05D5268" +
        "0E6554B9F429247188E27F995FAD789B9AAF2DCF90B7C263D7F0CF78F8050AD0" +
        "4B357A8D9AD85B5CDF668D0C3E4E27C2C02AA6929A4BC055E604AA9DBF6453B0" +
        "286A6C258895A689A786C0B5B335AFC3F84CC4B675CE5BDDF3AFC7F1684AAE6C" +
        "BC7CC0E315614CA2F7C1AFBD3A5EC06290B6B47C2DAAAA0B0DCE3A653DF25BF3" +
        "B4F6AF5DA185C925D6CE5DE9515005D27CE3B27774216CDFFC02DA210E17FD03" +
        "67D45A6CF66734EE99D6464B187E5E1E810F7DEAD87AC37C7561F0CE62FB7DE0" +
        "A38676DF39CF9D33E33C917C33DDD72EC953D3E9F14662CFA20F19AE4A357C3B" +
        "FB428CA0AEB4453F22983ADFE6D60CF1D383842037F6BC1B0EBEBEF5A6A033CD" +
        "E1E91111EC2D580BA8B917553A08B7EE0486DE07A4D3D356AA9DF54542489369" +
        "CCB4A45E350D3432F290A392631CA61139CD09267C6AF5481173381FF4DE5E5B" +
        "CDE50DE7D8EE6744DE246C96CC40CA834D7DAC39608F04736B7FD92CADC7AC08" +
        "ADBC40AD0881B7C566D11A1066ADAABBD290A7ECE87F47D3F42F7A3188099E0C");

    private static final byte[] NIST_MLDSA65_PASS_MSG = hex(
        "FF8B46A280AF686BE484DFE0F38A852760DAB909111BCB1BE8A6C83DEF1CFF58" +
        "23141F98B54005FAA38A8B3A786E2072C745180322DB6D1F23FCE286AA0BF570" +
        "BF584E13FD4C6C79DDDBE47F3AEF17CA2C7248E58DBFB171271CE522B9E3D587" +
        "09C62A8F394CE5102BA6C2D34C953C081E9C6A8093FF36E9E88760E25D981F9F" +
        "AE311576F8356696F3DCE4C4A899F987FF42BAD88384B91F3D22C59FE3D8EC0F" +
        "6A6A6C461D3B4AD874ED054C1F740BAD2743BA49A88A0A1B7732B2430EDB84F8" +
        "280438B44720CBBA8B62628DA03152EF65D37B68D01513A31EB466E8F5D63BD7" +
        "7AA57D71637181A2AC8B5EBC2D29CFDE1BA71949B3FF9DA6759B25C9C37745EA" +
        "1E8FB6700F6D977F1D2E676EBB893E447D29603BC0596731168DDFFAF09FD113" +
        "F91A456C6D4D077CE3DAA31A31B33354961669948B3F0463FB24BE16EA7A59C1" +
        "499821EFDED55AE6BEEC7AC5BD6356D4A4C9754A611BAC1B092341C834C6685D" +
        "9F617D8787D71E0C60CAB0385A0D873DEDF2DC52D8F923C720A9C6FCE1BAB16E" +
        "24D4D245A143C6801C4D4384E2CDC4CF202383E5348D3272A71FCA4E583A59A3" +
        "4F92051FDDA86170D711E00A6BCAE6EBF81F373B5E00012AF3B0ED02B39E92FC" +
        "57AF4FC9B8BDEF575EE2E536B7262295217EECEB37B1529F5CBDDCCCFFC052BD" +
        "4898308E5F0769E50A6FECB19F5DE7D07DEDC2065CDA94883DAFD121A2FAC74B" +
        "9385949FF69F82E48549C6CC39904E2DDF7EC7C70BE543DC37262EE2ECEE2ED0" +
        "3C2641EE8AC74E44B4CEEC9FB6CCAF6B92BD10D0CA0371D5731E6745E437B371" +
        "E87C99E8FCE0EAF04E92CA7DBBB7FB9F6C12199F60164DD50E3ECF75B89DD67F" +
        "4CA756B26B1B7EAC5C71E618D9801343941FE2BAB6FF193F2F05037A8C476235" +
        "AAA3FECEFA8FBE4FCCD09F79557CDB12B85CBC1AD380234A7550412A6A4B7CFC" +
        "EB3C95B492CB9F5139B63BD94A8F90702F6EC509434D723F58909A99E0F80508" +
        "A9E909E5ED0A807E65006746C07BDB0FEA22226F5326E5F42282BE13490451A1" +
        "FCFC54259F7A9351DD182F284295C216A4E39D31990104FE0FA85F805C5E9694" +
        "29AADB83927FF38753BC715724F49C82031B71E0997A4BD77FE6A59301E70E4E" +
        "70541DDE17C63215C437ABE5D984E5B43B61676BAD07E94689F34AC494B8BEFF" +
        "A24ADB0AA9D8E46B861EE782C0D4CBCAAB3A4BC0E6B0994B5EC6B6FC31B933AC" +
        "BA6CBAA44E90EE86224E1B4652480D40EF7C7DC865786C5CEF2A9A975E06B9A2" +
        "653ACBCE15BA462902B039520D8975F95E1503EB5B98E7853ACF5F94B9F1375C" +
        "A128CFC8416B55F267D9614CFEA62C4EBE548896625ACB34030C396BADAE0264" +
        "FC37F93AD7344DE6AC664626CDEA91743A0D43BC5534939A63A7FD8F520258AE" +
        "FF2F368F1A675B0210DDCAF6F52EDC019B8B6D065C029333C714A233375EC476" +
        "5C3B54AAEC2D00A813A0BEE8685AAE05DB34EE1679B5E954D923BD1A106FA2CF" +
        "C63251A433B7368AA2E6BC46576C56842FB2A3D92E8AA9ADDF886222B7A28ECF" +
        "E61555BFDFDEB77E0E1DA12363C9DD3B4574BD9E3F88E51BF13082EB3644A743" +
        "091F1034A89BF9EC51E26214A59BDE617498665FE698EFF74AFD5AD8CA086170" +
        "3147BE412B52D3ABD3A3372E8030184C084DF497B4D88AC8613B877C47CC9088" +
        "11E245BEE8E7AE692F1B3770615032D279A2A55B9172537605A728DABB03C60B" +
        "14987FB20292EFADA8860A084F9070891643800ED8A52190954850D79457EF3A" +
        "238701D1DA4815F9B07D00B203E8BE567FBD31AB3EEA92156959FB188CA02BA9" +
        "390EF00EE6EF4747EEBEF86BBA8AEA9060DC78C00028481395E7C0219004B8A9" +
        "E9BB3DEE791F33F77E32D486FE28FD2A7B8C1C4449146476FC692D1AE7C57AC2" +
        "45F793B8B5661D7D21C2D5649F457DC201A8E70AC7FDA07C73F254969C54B953" +
        "9773CB7BEBFFD26397E341EA91D76950FFCA6EA019113610737EB787C9B46162" +
        "AC663C08967D8C7049011CFD0D14FB2A7A1D4AFDB666BAD47B61F9776F1B64B3" +
        "E14FFE8D02E36E4AC72507D4E5B2726CF627A32E6742B1ABF43FEC04C7549550" +
        "D501B08080F2521E4BB2406712AE136866C0CC056C3AB591CF7F7F5402BAFC08" +
        "8D1983F91AD92DC32D10681CD4812A7394EEBFC45D236A59FBCA59ADB57F2EB4" +
        "CE14E93D22A85625852928D793B05C292C34D4306FCB1D7657A5A171FEB2ED55" +
        "E7FCCC30AA57A8681E2E907A99C1FE9C3C5860A2D515B19B459395CA11755315" +
        "A3C298924D98828DD7A9452067620AEC6FB2E652C891187F8F19C82DE47F1264" +
        "4EF7DCA3AE6E4F23AB2833ED9540B50EC0794923DAA20D806547009CBB2DB50B" +
        "96DA611D70CA66B9D6C1F5D5117EC78FB6845A9A8AA93FAF154D6E142725E4A0" +
        "FE456B5CD06C921B14D4CC195222CDD45B27C29FCEB3500237318903E67A8EA2" +
        "DA48F7DF5222B77824294EDBAB76E19E50548FB5C8BFE8F625BD7F87E5B64463" +
        "B0779034C11E28EBDD8A5EB7AA75C0B6B96FBA2ADD3E1A6B7CB9FE7A0D940382" +
        "E0F8516B2D9A0D0A7F6DF4E22A64AF23388C1CE839255B02E3BDCFCF29A858D1" +
        "6D891C5999F943D658F3503941FE294B8828236666700CFD52EB65707165FECF" +
        "A635E053B0374B5BF383594622ADED492E40342878FF064EDDCC90E5553659B1" +
        "3A72E72E47578BBD509B656CBEE9C9E2D0BAA7CA1739428E6328AB3BF49CF758" +
        "EF1830EB90BE03D50A4C61BA8D6A76880785814C8F49CA6A5E78ED4B2C9509B2" +
        "56F3D73572D16852063613E2A3A1065173D7D1FE4F4D4CC74DA2BDF9110A0B1D" +
        "2F055C94BBE95FD983D199DB10180C1C71FE5538B339B7B287921FD2AAEB23A0" +
        "1223FAB0BD774FC90F843706FFD3596C7568E534AB1D412AB5190B0AB26F5DBB" +
        "D799AE6985828456330155F4636DCB939DD14108A6FB3AC08D803241CE82CA65" +
        "789A73CA66F73EB6708B30E5DECEAAE75ADA8D7CD4D6554B641460C438F4E264" +
        "E634C20D55266D2A4E16DEFC479ED5EE446B35B0E6B0993BA8C8F1D3218DCD4F" +
        "887883B4BCEF53908A732D6E12FD1455E8825106436ADC6AE87EFDA8B6F89E7C" +
        "85F0FA5CF3BD709671791BC31B82BAA571A8CBC009533F82D577722C86C50AA6" +
        "3748F1CCA386FDB3425B5A83EDB1E15AAB836DC09ED5C577BD9EE2F171B3F2CC" +
        "FC0975FCDD6528DE696A96CFCAFD21B768E3DF789106AFAC45CE32CC64661ED8" +
        "2A25800E694A3E8BFBFEC74E820A45EF6A47588F8C1DF17D18DE461BF124DD31" +
        "B818D910EC8BFEC0736C958284C78B8CEA23F14197D6F104356D9A680AB2F791" +
        "814C160D9630125B88F0667D2126EAB24751CEE8B65E7DCE257040FFE687B0DA" +
        "E9B7A96F7AD2DDB80CA79F15A51674766C81F0BB8CE0482ABB90DF74E81E0228" +
        "050B93959D5634370D5AC9FE88395F05E4291DE9B0B6E57D4D46C6AE09EB13D5" +
        "A5284F041C599F8A6AA072725D9570823FE960FCF4A851550FB0EF3CE09FD87F" +
        "CD2794F9BB9EEF44251292010BF52D3C83A74DE26BE0FD3A210BA30B9DC59CFD" +
        "A27D688BD1F3298DCCCBDDF2E37360B3BC8C027D9C7BFD35B366EDE42BBB1002" +
        "0475756BA8E9C98524E95D6816B0A10EEFCFC7AEC8A17217E910759B794D7629" +
        "34F3A284815082843ACA1F0E92E74628016632A2E544F6A7F9F6BC2B6E044F44" +
        "F8F0505CD8A2752271ACF2BE496B0EA53CE39FC9926E1984507B27F672F4302D" +
        "896879A18D820BA02FC511FEC8472320ED2E1F9E31D9AD7291DDDFE443A4E783" +
        "ABBA066C8CFCD45B82D0A23FE0AA612F606B9B5A77DCE78FD5069D62DD8E71D1" +
        "04F2A92A77838B8989967B186982782F3FBD73B576EC7555E47DF017855EF1FE" +
        "E90BC159DAA1ECD3201147EC32CC0CC51E23C1CF8C5ADDC64B84CC6457AB9AD0" +
        "82ADE475489653008CFF0F53B2C0D9B0E147C3202F74ABCE810AEF2DA279D32F" +
        "64F9AC0B7DEE0DE144");

    private static final byte[] NIST_MLDSA65_PASS_SIG = hex(
        "1F1A3CCE562CA78C6C194AD3D7301177D7BE919C4B692B87EC3C0359E03E0C83" +
        "CAC411B3CD33D244292E0159B67F1223E7B206FCB9E19C27B8F9CAB98DCBB791" +
        "BC8AB111025691095BE0B68C5413CFAE82A637219EE3CAC5F5C6D65432FF4C65" +
        "0BF1B797E1AACDABEC25B5D946851D02C176ECA994BD7E2237437BD1664A7939" +
        "0CDD3BC1F03332CFA4A7BFB42E36F03148A33C920178E47CA47F05C2862B6833" +
        "4C724A4DC52EA1DD41CE61DF4F8133906C844DAD68EE7DF8B501DDAEA7BFCB14" +
        "FC86B2F2AD313AF3F233D9D7FD4EE8C31BCA2385B0558CB5121AC7006AEC652C" +
        "4B12B37B5F4183E27E3BFEB2A8C2C48A7C50B467A66078861F51F659000FC4F0" +
        "79ACD62F5953274D8A000D6102AEAB4B47620942FF185C5AABEC6B20F93E6571" +
        "60828EB120ED356A2FA1C74C87CFDE9047FE2AD22D32DAA6EBBB3BA795D1B0A7" +
        "9997139DED7AFD2C470BE4E6AC734E8F0CE556A296FB5E6F24F113BB09D4D050" +
        "39DB137B96BDB7137DA9ACD9DDD34D82DF8B5A94BE838916CDA54D305CC20FBF" +
        "879B859946D7636842BC973AB653282E6DD00E1B1C2AF346BC50FD6834C16776" +
        "349C889A5F17771FFFD7B3331AE6657F55BFB7ABB47C1218161A39F90FDCD309" +
        "17EB195065BB39A4919EEAF98F5E8D6598E5A69E728C28AA2728ED173A70BD06" +
        "1B255C1E46760632A9E29685390BEF8C00E132DF93128B7A3479C0CCE6E600DD" +
        "BEDB9BE60E0B227B3F460E1632D76282B12E7EE6681B37CE35B0B7D5895080F1" +
        "336D43140ABAFD69E475472A71C59181FDF4783D23EE254D4B1FD9C58F339B01" +
        "23B77D69CAC9F5F39A435325FC30EDB6FF124374273283CF4304D42E84A9B624" +
        "BD804D4EE509E8B25FF5EEA86426E5FE8D93A01B5AC30B7E705336B2200F7EF2" +
        "40A0B11177A2A44C2E6BA80B28DF9F5A22E8FBC6B0833D325346FFE1CCADEDC9" +
        "90B5B584CB0374C589EFEC7C6F103DEC954C973D35F769079CAE0817D24E70F1" +
        "178D098823E4EB3DF9D64F8FADED6B76F8B5A9B99C260E1ABB4DBFCD1006F245" +
        "C127A6C396B8B0D3F9348439E7EE05858AC7CEB0829BBF11A3AD8BF7C2A0026E" +
        "8E0A007E63F8B7AD1FE20788C109B51CB0C07E8EA4C6C95E039DBBE3DEA794A8" +
        "096137427CF122A7A74CF8863DCF0889D1CD5AEC8572C20799928F73AC848F6D" +
        "6461553C754A1553D2E82BB37FFB8EC630E3E7D5183A9642138BB9639798B7DA" +
        "95ABC78F00D23BB7D3A49BA43A185E5C7080C5DB176A098466FE8EB8A686F8D7" +
        "5702762E428D24A0712A3E93B631DECEF24C69D44B9B462C4938A22B09A17334" +
        "A73D92EE43E6B519C68F00CF619DCC62A7707271FBE607038106BC20293B00A3" +
        "C9FE27F491384E320C972CFB5324965BCF348872D7C0919C788A94546838DED7" +
        "16CE82BC34ACC3EBBE46BF12EDCA76E54732B5395A5C757E2B25A83C21DC3308" +
        "92A4D5633C9AA8B387BEE52446200A19601CE5A323E48C146B68BB91139A7C66" +
        "0F847A4BFBCF424BD1C91F496EFC905A0CD3E6BF103825D0FBFB0F5F875B0BF3" +
        "9852BB6EF3315B35D6C4D9E83EE86091324459D0D27AC9AEE5BCB8B452A5C88C" +
        "A06D7136D22B9EAD849A2A35E6C1F08D1EC5018B8FD55D81ECBCC30E687F988D" +
        "359293E29827C9F8E248496C63401D5D10F2382EFC97CABDDE0704A01635D484" +
        "2031D2800AC48783563D306BB84E817E8A87C565E4E5CCA5BDD579A46EC23313" +
        "B78489E460AC61E34A2A39A0A6A64B6C2041B2EF238FDE72819A868FC1E68E33" +
        "97FAFBE58DA0D2C563147EABECC2F67558493EA4F6F59AAEA844AE7CF0A0E586" +
        "005C40F7A51016E011873DFFB63CA8DF4994ECCB151B2AA853DA190420CF4631" +
        "37C3743782B0F204F9917A7E3B0217E15EF9BF94986FB9DCF4D3EB587BAAB333" +
        "072A24C151856D41139EBCBF7D396190273B63D39BD8152FC942C22426CEEA0B" +
        "F03A8B57A4C9D06AB186BAAEE822346024D5B65C7F46F7E925A0778EC397C347" +
        "E616598112E0D4E9DD9D9E32C5671012F09BB7BF2559D9F0854743277D0F8ED5" +
        "47D1736EA1754EA8953CEB7349AF472DF543268EA7D0E6A6227C7BEE705BC283" +
        "4565F5EB2B57322AF7A456504660DAF487EB3F0F1982A2204C5FCEE4F04BB82C" +
        "313979F89E5F88FD9CD7CAC8915F92DE8A7FBF6BFC1B6706FE87D2D208A65D6D" +
        "8EA6C41A0CFCA862E8F744E65ED78CBE952B8802C87D5163D11C987E318B1125" +
        "24BB450FE44433841F0C4A16A2CB1823F279A3A14C4FF6F90CC541C398C68497" +
        "BCB1B85BA8B97A4F7CF948E745155A4A07FEDB4D78582D279F1816432C0C2710" +
        "899B95F568312619AFD6E236D2E7C61E2F0F3F8C0A1E08C0B1E36A0B13C12FCF" +
        "645F70C1D18B357519197CE7E76B6C67D2A60B83550C7D0F585A8D0521ADA1E5" +
        "A297E3AF758C706DCF53532A5341A41E4EAA1EDE9E53A1AE08AD34F9B40EB2DF" +
        "740E4A7ED245980798AB59C711A5D3826E74F6214881BF182644B31DC1B42084" +
        "F5B1C0EB468AF2FBFF34A7D8321F2FAF2035420C6087BB8421A28F823A4B2AD8" +
        "25E37E6AF29E2D8B6E42D93F811C57F333590A55B114C4DF3E6574408EFB6DD2" +
        "E6B5BF1FF58507D50ECF1969B2F7683AD54F9CD9D2C2BE76BB31C705E6EA4AF6" +
        "6EDE00AEA7CBFC9241A7BCBF04838A1F4E02173F10C9774A750EB8B6CD14242B" +
        "917C4E36E93B6DA4BBC412B1C86393A759FF40293E4540319698CA242774D798" +
        "98A4F993B17FD906BC2669966CDDFC96BBDBA73E0FD1D1F2E2C3F882420E3026" +
        "3EE8E8B6B1E32197A8116054BC7AB6C4BB277061560A3ABD7D8D6E5CB7CD4AEE" +
        "955AE438476D415F25EAD503BBF3604B890D98D64CF3EDEAAED021175680CCA7" +
        "03A36B8F5CDF40A584BA6C9EDD0ADAF00F38C4BF0F0E83563CFDDA01D3BD54BA" +
        "AB71A60BAC8271640C5C87A4B5453CDDFF18DE5B8C419E6A46FB3EBA6ADD64DB" +
        "2ADB648016D711176792DB007C0D058521007E37B9F3FA3FEC7C5A995D9DA31C" +
        "2E1878C2559AFD9C376C36D6E22C962372AF268F1EE847AFD7ED36506917E632" +
        "8ED1DFC3076CB6A6DDA23C3D07E136898B9E6B184C6A92CCAAAF71D0BEBD1A28" +
        "57590DFC2B51B22D5D5986E21A00DF1B0453831CF88315B24376A3D91D843809" +
        "FBC83E987F7CCE3E8504BFDA5195D075DE8A6DB71AEC86C17D61C99A07C0BC65" +
        "2C8F833C915F996A62395FBE69F039E0CAFAEE0C907DCED4C5EFCC5F4BF83E85" +
        "05CCEE3C51A0C4C79B5DE34EF068307029D274EF22CC45C58798478F0A7FF2DD" +
        "D6A8F17349AEA481DA2F6F313B15187A85C06D9F414D0FC2EB9DCB33F7D36361" +
        "898DC68641996BC180D33D20F3DCF849B57AE255178BF82E13673E89A5E6B4B0" +
        "C665500D445A9DF05AE0A94A6493CF135E8B83D8D2BE7930370EA7B3CC0C08AA" +
        "35AF9E7A46F00B5473B50B170FA67AC2847897905A30E6ACFC6C2F97E6B3C602" +
        "0647F81F5F6C47837934AC6B904C4AF0B8215B40099958226F73A8632A2A2F14" +
        "4C2B5B6439AC430C71D161B88D377E50FB540DDB5FC6EE548BF3CCCF65867D8A" +
        "35AAD22CC8502BC67E55D662D66F33EFD3C39DD5921AECEA7B0554EAB6B85CE9" +
        "A846B32C33FD009CDCD9545C5E99B2A379700FBF2AA8C2644DCEEADA3F705942" +
        "DB7F590B44D77A09CE79DFC6C4F6B136D5475A12B7BC27068BB3A2A25B81E752" +
        "AEE54716846E62A6B83552333575EA846BF442B744094DA4404E477958D92A72" +
        "1E65472D2A07F41B3A5C3008528474D1EDD4BD129ADE19AFD3CFEC861635CFFF" +
        "25D682B5A1BF8E0F205E9FB7850318228BE44A5D5DACD58C61F69A9738ED21E4" +
        "EB893D0E188EFDCC15915FAAFA9AC571FD33E3D13B165C29AF92F63F86FD8BDA" +
        "7D953CEA1D7439116A16A1B3AA0FE64D35E20B63C4D65683F665D3AAE06AC239" +
        "90E1DC9901CE9982747843AAF69907B068B2EB3253618E7D827A3369F9E4DB6C" +
        "7E4489828299BA2EA983BC7C6102A00766141C10603742D3C01F1D8B03C1CF16" +
        "B925611FA4B23F849195CE03578948782D83D5CE258A99244380C1153C305F97" +
        "6A0E9213749D3FDCA2D132199AF621D9D4E0C46DB643B41D413F3641C9B9ACA6" +
        "6224C3562F89813A53633FE0D1E36D474E76FBAB54ED5D9E3AC4F42D2E90C300" +
        "C1F67C9CB7670EA60E151CE6681C5D1BDEEDC739B184B071013374839ED21DD0" +
        "A8C295DB64BD70BFA8350C55FAFC016F7F4041F3F3B528E96B1E963B0D2ED725" +
        "A46A9150A84F3A6850955607CB203BD923785DA60FF5C87857FB5658CCBF9D85" +
        "E5F1B28CEED0E6C21FCDB522541F99BB84476A3A78195C791C786A58C34FA552" +
        "192C4F825995A74AAA78F08869F6181704D41DDECB5728761A0C38D1B4468AE0" +
        "06EE95B586ACD6C926C986B9A0442DFA04A2156F04F0644499D54DD5483268CC" +
        "74A1EAEAE163CFF968AC752C7FE3EC22E27E2EC1175BE396C31269538AF10CE1" +
        "CB683AB9F513F65D60718EF447A21F2A0E5C7BBF5B9AE44272851FDDE7B04E78" +
        "3C10A334E61D65F2CEFCBF297C07743304725A9EE74D818C923C757A4A99AC22" +
        "102513C27F2754419E1385161B5BBF347EC8DD9EE88F873DB0654EBDD0ADD5B7" +
        "462BF6A2ADA1B5D76E57172925B5FDEF0023444B6A5D6B72A4F99BB0C922515D" +
        "7587D40B92D9DC2E39A1D8E50000000000000000000000000000000000000000" +
        "00000000000000050A0D13171C");

    private static final byte[] NIST_MLDSA65_PASS_CTX = hex(
        "C5557A339FF8EDCD2AF94A847A6E042367B4E43AD07C36A3E9432A5857392F26" +
        "FE0AA3D1843FD6EA0D69D7428BE89AE1A6D9E5CFD1205F6826FE7276E2FB3702" +
        "3BD66D1450AAFC4C83B65B2FE55DA25CB90D538F3C6BFD6B1FF37C818B5AA068" +
        "99BC9F2E4454EFF968213ACE8C7E5CA37FFDD08263D0BEDB04B2683FA3656DBE" +
        "84E7AD4100215A8A90B75FFA47011D873320E6F819244F47FEA04F9EDE7FB0C8" +
        "1C82CFA90690C366F6E9A7B317BD7B535147BF542E8940");

    private static final int    NIST_MLDSA65_PASS_LEVEL = MlDsa.ML_DSA_65;

    private static final boolean NIST_MLDSA65_PASS_EXPECTED = true;

    /* NIST ACVP ML-DSA-sigVer-FIPS204 tgId for NIST_MLDSA65_FAIL, tcId=32.
     * preHash=pure, signatureInterface=external. Expected: FAIL. */
    private static final byte[] NIST_MLDSA65_FAIL_PK = hex(
        "95DBAC429AD329918E910A5206B197D58A955A7E8041E1F8E330ABEF102A0815" +
        "52DD4BBFC1CF8631CC7D9917211EA032B8A0620DF48789C9417BB02B8ED30E92" +
        "2334D042004D3A4158006B65EE519A52E9C37124A55D0C95C581B63F4846D1DD" +
        "0A5D213B4ECFA0F0D8A761AC8163ACC3DF913F28BF701EFC05391C2123383322" +
        "E2CD145C6D1B0014A497DB93C4AE044C36FD95E017C2508F38AC5DDF8AB8F1E6" +
        "62BBD61C6AC4778697220D396CBC15BFB5C9643B47FBF80E4B209CED50A8443F" +
        "71AE52409C175F072B43FA0503335FFEB373EB34C76E18E68863E39E1D63F5E2" +
        "F98694D69E9B32F1B20D1E7A6723E946BBD44B492549A3A83907447D0E2C64C5" +
        "7A6F3B24F8CED65863F9A4757CFD26FCE38EDB5C367CF33970ACF43D2BCFAA4E" +
        "07EAC373641C819EC889141A933212601841C6BA5548F17BBF292F4BFA4341B1" +
        "E1CE32DDF60E9F53B53C646B148A893F4CDDA3A3CCF57EC88F8E409C4FDD7A5D" +
        "70CB314C195DA28AB7C685AEB1BF47FBC010FB412EB2B143DA0AE0071D63FD0C" +
        "BB27E40809D2B919DCD5E58F34EAEA26D63552F0A3984AA01C244FBB3F76F2C7" +
        "7BCB772BE79EE9DF1FA204B0C7356626646D7C48B82375378F46D215F9EF0CE8" +
        "DAA41F4E987B8F028FA5491215F264B572BD9506954BD661096D9A1688B14B1E" +
        "34A4261A2D28BF216207D5E7C2610063A9AFCFAC363009785BCAC16EC10E2D04" +
        "C1D3FD15FDCA617CD1BF54EBF91C61F01E61272D42972EC0F881F5826CEB194B" +
        "963405DB96CA4B9546B5CDEC117E4B4CEBD373BCF62C628293F572E88002B86A" +
        "C7C22CECC9E0592D889B20379E5DF69D46A6CF5BC44674A0D94B783FD20C985B" +
        "0EECD65C9A24754D9E70D4D7DB3DAABB3BE27F5F0B168FF4FA538DC052AABD59" +
        "F112C4DB3DFE09CC0BDCABBB60E6A865727E400B01B85F7E905D768C09CC5DAD" +
        "DE192AB6AECA98C8861436BEE506805C2BB5E1931FBE74BBA5F262470560E1A4" +
        "80F847F4A2D543C87E237B4F8885325D6268199759C40C8BB2E0A3BA9BFAC0BD" +
        "B07A9A42A4EDEF41B78D8B3E3DC72E6F86FC36DE0AB34B321D207BEBC117CD6D" +
        "0B09D053024D2C3C5EDD25C2727FD4846B310C10CE4958369896FE52D4C89CEB" +
        "BE2C979D2BAF18ED84C0EA4F0B344AC9663830371EFB5487965F16710DB20531" +
        "FCA3E55F544BDBF66995D4FBB406A3B9B6F5697D9709284504D67BDD892F820D" +
        "D3C78E9C438E320A2F13DF728569278748F732F2801CD75ED38754C27601798B" +
        "4EB21ED31735F60AEAE3653B7DFEB5CA90D3353911A4061C780100252A421F4F" +
        "8949787F420978C7B8459C0283122C24202CB26FA6E11C0587D93C7B29BF0968" +
        "B7ECF669BB3D6E8B45E1405E1ACABFA460005F45EDEBA4AB98D97A943E770E54" +
        "458018096DD680A16FD8F2838624AFA69D285A54D683170A5D8457FCFF9A4BBB" +
        "3A917041D7CCE27BA3B677B709AAB38C71BB6D8ED48A45BF82232B598D69F4E6" +
        "7FE3BCACC0E8D92317CD24FD0082BD6E0752D42B288B773BD8668B6366DE290C" +
        "F2C6674D2EFDDCFC43FD947E58702E7641917054544F13C9B9F42FA849C352E6" +
        "3874D3194A8E97842E7F07FBF13599BA0C29E6AC8177F4F2B9309F8AFFD5E852" +
        "C727E741096B8CF7F99E9BB7780E119B13F78E3BA4D66D165E9442D6D9830BFF" +
        "5CD2A805542CDF90EEB83D610D3B7867566FD74A1399D6958C332241736969EB" +
        "ADF98BAA38C81CD754F0A927FE30BD28E9BF1378633BCFBCB91D57C9C8A51E6A" +
        "586494A9FDC675A7C31F40770FCAE417C75A0CF0D773A58FBBE73348EB7690D8" +
        "D2D8351722E4E1101DC1E715D520605D60FCDDF0F5B687194580198F8474E8DF" +
        "5B121550C114D45640F200FB115925729FAAE429E9449E7C2367D8F41F816DBC" +
        "5412CCCE98C649848A5F79CDB825A6A301F34125CC4AFCC3592765E9CAC40CB2" +
        "AC442052578C42FC15B5ABA8CEBD4E2D2B4D9CABA1E6B3D199315281968EF282" +
        "A5C84A179BB5653DED31DD591C761B523CDF7EEAE6BC17165FA23F4B51E2AADB" +
        "8169F98C948883CDCE51566C7E31AC84CD9194F6D553DCD0FE15EE360E3963A6" +
        "E736CC5BA4CC97204E49EB1DCA0787983CB62A643D051AFA0700D2B69E25A68E" +
        "EA86211D749D824C851E1EC4AA04E40C9ED5A2201FEA5D3DEA0E31FEB0F4D245" +
        "940A5B40DE45D3A7FC9232B27D18E6FCF0425F4269FF5DEF4014E8796D58145D" +
        "1DBC93CDEA7D8E15199F12FC588D656554E0A11A65FEDC800EE70107162782D9" +
        "FB04133A4E70A792F4FE73EC39D27F4139B3F62A9AA1E1C00A708EBA9C20B856" +
        "479E476DC95C6BFD5D91E5FE13074641CB69CEC76B8CD66974A7DCE2F27B3147" +
        "E15E0D938AFAEA95FF87B026E13683E342D1C2F44B4BFF34294229A58B214AE1" +
        "E0E8D771FC07E7F6652A34990F25666232F0675F5F77FF2CA5F996374CDB2F1D" +
        "8FFE0EAA73E56E7B119D2A16C722654C104A4EB83025BB61FB89CC78C7BDD6F1" +
        "4BAFC976364DC11B3CD6BE6D518469D55C85DC2CB38B6EEF2E1CED105F7AC167" +
        "0A7D35B4BC256D250949403F6E91B35D24B3DF19430A50A13568D73D393ECE37" +
        "15F02C8FCC8AD08699BD1F472BF25869D2602FD951F159D9C13C2D0C55285A9F" +
        "20EDB8EE7E44B642902AC64AB04BA939B10247735577AE2788F36355EA54336C" +
        "6929476A64001848EBDEFF5CF49413033EAE92843A2854300D6E59415CF6DC28" +
        "0616286A89F3CFF5BFBC02DF5F209175D80FE82A77ADF36E6DB4B2F89ECD8D1A");

    private static final byte[] NIST_MLDSA65_FAIL_MSG = hex(
        "B98CA6127F0B561F4E7DBAB60BC1BD92E562F39A51B98FA9CB97563B9942AC40" +
        "753B311FAD2821F2C7AFA1AB1A203C96C53084B0662C01EBAC533AA0FD1DCFEF" +
        "28D4D6485782C2691259C753A43BFD053754586831D5154B8389A16F91334B8F" +
        "0246E6172573EA1E98B6857B7885744EC3CCD449ACD1350FEBFBBC42A05B2098" +
        "D440D91989C0D10B9E053A67E501473FCB42CAB2CC20CFDB5F6FD7F77F8823D2" +
        "1E6B7CC0C53F908E7EA06A7CAD957FC3F33BCAC32D3E0351019E591A4E50AC08" +
        "81E8FC64C53A7B9606F8F0D071D07AB88926472B91A5BB1BCF41FB40D696876F" +
        "71DC4D274D09EA3B675B69E859D392FCDE2FB0D6BF1DE4CF104A6DAF76E2F16F" +
        "E14AA404CD58E73AFC07497574CB653DF17122C80668B915E11A803544E742B0" +
        "D1DDB4BF10846D00F7B73E7933C5E9907FB297B992C34D9509B5893B59DEF23B" +
        "807D3B5E5BE5EF882AB58B54FEC2CA6A55D9143623C32D0D3C0FA4000D98B683" +
        "0B3D3BFE303F6993E8BB7CC0D089A5ADB596D30F62FE79BC7B6B9EC579D843A7" +
        "765CDEA470800029E976359D7FA979DAD51DD8513F2CDFE9E2AB7E3069530A1E" +
        "58FC6A4A647ACB8EE7133C41E85B67F99C071883F69CA3E0A6421F3B0EE73D25" +
        "B71DF9E7A315E2EDA1CFEDE20D862C01E68C18A678C23B51E30D5F46686C5DD4" +
        "F649C8155D4E86B5AE914532ED86EE068987A76CBC336F803256362ACA907FE6" +
        "01DA69FB8CB6898EF9D5DAE7426DA719372AD6E7535FAF604554CBE6DD808A88" +
        "79879F95A02531606FFBCB6C93B4D5FD3C13AA5518F86EA16F0A21BD16F889C5" +
        "416D9B176BE32DE17FEFDFC1011F6A6612E1DE6745CBF5159E0B78CE07B04F4F" +
        "BCCD8BFD1AE7DF1A7BEF210D0D0DACE8D8286E66474692CD6BB6FF4AFEA8D1A0" +
        "FDEDCEAD08428F814826AED79861CB9E567776D8514C3C8B7B9340A969274129" +
        "C6B96ED8AB03604F01C0B384D20D61AB6068723FD2975A6CC57AB068919042FB" +
        "AA80E4F90C2B06C8B64970ACB902062CFCD139AC23EBAAABB37B04B2CB179871" +
        "6D6C86D8395D7D9915952A7C430EE7CA2C7C7F2A01B06730581E578AC51C5EE1" +
        "C6B3BBA0CC32A87BFC3B5C8A1C02C90A06C9CE2AF85E25280D530BE2D879D571" +
        "20477F0D19ED94FBA7788927D8748463002F049A8D7F2945C0D48E602E50F385" +
        "6335FFA066C93A0A645CAA22A4E6FD9BB43932CCFF38A620E7E6D654F8F85751" +
        "9A2E0DD610389D32FC03D3349F102C9729865985A28EB3710B0FD804FC370E38" +
        "904933D17E26220DBFD45BB3A9B22FC0EAD38B0631E89BCDFF8CFD32455C0757" +
        "B67DE7CFD1176BB58C8A6E3D5CB2FD09421E61048FC4B5771804E8E9DBAF982D" +
        "11B765A7BC72DE4BD71BCBE65FB3D2E776D9E1DE8A190F1C24A341B06343D057" +
        "71CDF12E9A73E224FDEB1D9EE1DA1A5AB44B2DAC070AFB02E6001A9E96DC37F5" +
        "B9ACC17A0E8633A385E9E9851CF51D3F41D88C9A398A043348FFB5CE16680DE6" +
        "703A94FE195C3240E566360B3E43029BCE3107A4C2A72F4EABDBD741C71909BB" +
        "F527C81E91EB71487C4F4169D8B00E1F417CE72024020E395825EA8AA5AF8F27" +
        "CF0EBC4C624318B5522BA6D0E0887396667CF15740D9CAB1742B62A9A1C37423" +
        "1F22F14B46759C32D428FAEEB48265BBCE8C4E19D3AF4AC15A03C1FE75ECDD4C" +
        "195B5345444223B496C4078B9A24B4352AD8967F108D7E7368358E6A2932F6DB" +
        "B3951368B88F93640C5FA75122B3F7E86DEB316CC791E22DC40BD5D7A62F143D" +
        "15293E920D22215B445E11F2BA427E3E0D34993E700B05F127208ADAEBD8C21D" +
        "526294A1F1051D0629A178CD820A4D4FE5C1B0694D669FAACB2F972A284BFDBC" +
        "2B94FC089164FFBE9EE6A410B6D021BF4BB325E894EDB14E6A2605F0C3BBEDCD" +
        "B12E9DA4C998030BA94457FEB50AD0D0205BE61619AEEAC938C6A1946FA902F5" +
        "E5591A86A1411A31CA3F977FB7E9150CBB749AC6B1D327CCB43FE5E4CACD4A40" +
        "C40EE8CA168B45BA2198EA407A9F081EAA6B62B9EAC604CE233111E6FC3CC9B5" +
        "7F111EBF07BF771D2D848DB6A14AFDC626E2209383C952E2CEF08A8EA9733EAE" +
        "4E8C8B78652E00CAFFE5833CA9D2BEADC0BB5A3BEA17410B8984ED088A7703B1" +
        "C0368960F8BE81801D0BABC4D4DC66BBF81406AC24FFE5D7ED8336E7AE1DD5AB" +
        "AA58190F8EB7C2C7687E3BD0EF2E8EC06B9C266022AD09DA461718BA85E9FF58" +
        "DB9AF3639DD1581E75285A2DD92CEE063EBCD1AD76B1469DBBB6E1E6D637F0C2" +
        "AC15FCDE34CC7D3C4A9C11684BC49028FEEFF275ACAB6DD87928301A0EA2BB86" +
        "91A6F26A54EDF530327D59E489BFC6ECD0F08992BE81699F7F51CB2AFDAFBAA3" +
        "809B2712B161188782B0F7164AED2944532DCAC8463C21B9B8A4CB6D7477E029" +
        "93A4D1B203191A9BB8CFCEE03B22434ABE40A2DED94D47514D2B2BCBFCD15650" +
        "9032388E37E884F50BA3168D8D6FE5E46FC83ECBC8715CCC32089B880F263FCE" +
        "5D5C502006B212FD0C6A4F361A7A5AE9B43AF13B9FB3ACE1533F404AE591605B" +
        "D93007E859991E6004DE7F7552AF0B735380196F8119FE6444A9B9251316DB8C" +
        "E0A2E525EDAE69CDAA73559E18F18A0D645461C11D40FDBF55F496C367C8D459" +
        "7C9866DCBC6FC7B44136B07FD95459DB6C21EEE7705824477FA295B463AB045A" +
        "F22EF372CDF62E523CD11941877D62EAA9F96F6B23C687700B34D3EAC203865B" +
        "7837FC3B3F03D5DB8D11AEF7C82F7B538D58B8E9077D92EF693275A3D2BB64EA" +
        "C9E27103D0EF4261E376E9B5B5F1A280D7A6A627ED503EEA3BCC2B8264B95276" +
        "C763E96BB053F9337FA5394567CDBB95B5DA5C24312B4EB24D2256C923C2071D" +
        "BC51827186575B34CBD7523B028B0C91964F446CD60EC749D570C30B87C50BD1" +
        "E13CD1735E52E4F9473333F8752323112DDD8E2E93E95A8EC5E1C46B51A267FF" +
        "D0C75F269D3A6F257DD855309C8C2B99DB14AEEEC4DB9941626EAECE7862D29D" +
        "64D085A1BDFE26DCCC530A2D2ABDFC73B03CCD233FCBCF56691D24C3163B7988" +
        "0680ED99FFDBD6A838EDBA9431035E8731C409F1EAD81E526A857D94A75ECA87" +
        "E73C3089442E38B92DB7FC5D1E3ADBE6B1CC21E0C360C4370A32C73795046034" +
        "4BD8CE0DE9105453A5CD51AF0F288431BD139808931560B6491A9A9981DD877F" +
        "670C86A26B98F949D4B5F523160E51A4CB49151D84C841D17B3AA5E35928089B" +
        "F168BE61CD507BD2301CD0D4E7DCF0EEFEF4C18A7878E8256D54F3E76A2A66A4" +
        "8ADD0007FD50988DD38D956CEDAF256F21100EC0CD9378F16FBBB266DE4F60C5" +
        "89BE830D4B12FF0CB48E1DF06958E120BAD136CBF0EF620EEA4C19FC5C4D1CF1" +
        "7EFEC5CFCFE04158DBFEAF30A1623D89B80FB3FA40DFC44E8D52ED8D6ADB0A63" +
        "BEBE53A6E1992F6ECB76AAB43DF060D8D983D767B0DAB0D2A5A668FE4F0DCF86" +
        "B2EC20013A160C907664D4F0B169F4F6513D9A3961BD4FDFC08DBCEE29A6D2A0" +
        "675C1D32E6B11573BC392500B97060619592A421AD36E2D01E06B34F8AC9C99C" +
        "648E6112CB8A88F55E486F448E6EE574DD47B8F242362FC86EE9BC6EA773BC2C" +
        "7DB36E9FE43DA84D85E658DDFF51B9DB755AC346F6464FD32E465074D80DDBB7" +
        "256F9648495BCFA08DAE39920A5D0FBF5D947C822BE19B13FBB8FBB4DE36FCBE" +
        "78623A0E10176FF1DDEE27925A4B8C29FA2EAAD4CC541A5F7DA75FB94DAC8FB5" +
        "4094DD968609EE086848D7454119BA5B7148606DEB3C5356F9C117FE1FD839B5" +
        "3369AB15A7FD715B9C96101FAB132195A67F918661C21EECAA8594F8648A9E78" +
        "67825862AF60DB03CFC2300928FDDB8DB97C89BE50A1378CCB5B768201401ECC" +
        "9F381C86A1DA112F3EE228994EE9472008953982573DB18409F93DC19019E5F7" +
        "5C7EF26F1DE423F3FEE1FC02254086081C079CE6387A4B92A83A6AC4CE10113A" +
        "E44ED9D4F26327A47B72FCA3D05ABE74BE0BD1A154CA463553E5D345899F65FB" +
        "84CC5DE4B44414EEA8F0B07FB09E777C7FF363330B950642338E180651D0952C" +
        "F1AC4248D73E67213FDD375B0C79C46CEC25151ECB56A7C61434231C6553CBE0" +
        "4CBDF8740B63A295122F8AB35B1B7657AA7E5A1DB0E2E9EA214DAB79D47A50C9" +
        "90937683D16FEA4642C601B540C913C0ADF897B61C5C73C240C9E4F5A9E55C13" +
        "E4CA7C6FDB24504235777923A429B30543555E318E35940D0251A721B120BDBC" +
        "EAA5DFF4CE56160C2A26ECB1697514E7EA951667A146B9C3BF4BC6F1307A6821" +
        "28E399B8119E9B59BDFF7848F95359C843D89B1A42E59F835EF09369B0D30CA2" +
        "6EE505C23E57C086B0594C40CA17B452B576C43C1CD6072DA5D710D2254BB20A" +
        "40425FADA60E3E0815B8F14913455B6EC3B8B562DD4CE5CD92ABD17D5FD63EA1" +
        "A260862686770B6AD8A18902A49AD9775470A863ED556AC669E525B27917AA9F" +
        "BA96E3ECBCB0DF6C1CA2B747134EB3B85E4A940975F938864C42D665E3270D90" +
        "E99D51585237C1E97A1E5D25DCB6093F4B09D986A8933C0CEF36247D9A598A79" +
        "C794FE1C8EFEC237D13D9DB20527BD71C070BE6EA1D524E7B9DF57156F932717" +
        "D0634C9928C9B009777B5CCD7AF6EB464B9311C1715ADD142D26E53F083AB32D" +
        "0A18A8F16D0904D1322FC97EE9520D9F1E604F22C1322F7854B9A32C9AE23940" +
        "FA461F88950AA69AB6D2F3A1D332CED0538021427AAD742AA03EFC14A4BBA325" +
        "D09CB0B823601F40A2CAD0355CD0B651CE47E83E080ADDAAFE43E9B54B486486" +
        "0750718A839C173BBE2A4C5858726D8AF3475D0941AB76422733543B9CDE6BEF" +
        "2228A8CA5AAA982B502AE97F4D04DE527E8594B63887AEAF1BCC341BC76865A8" +
        "AA9A5D36C5EC1087FD9590F05A920E5C4F1CA301861589805F6DB66B3295C0E1" +
        "1A43115C602E6F21871BCCC1070D1DD23767B1874A80ECBBF6BE64340D97A3C9" +
        "5698FE776446C300A4ED8172D17F3EC4A2C402D55F167A19BB76A2242E130F09" +
        "8E9D4045D1BF973A3C119EC499A73198E293471DA0316797DED037FB80001143" +
        "B21B1A03172057EAE2A306C7AE58EAF37123244056C124A9A1586629AA79DE43" +
        "D84D1C839BA3BC06D39DDFC5DA09EF44F9E2755F43EA90CF9FB6A7D4272B88C1" +
        "69E1D19E9DE4D5E782682AE691C45F492C8E54323B4724AAEBBA67718A3E6EFE" +
        "84708A39521CD24E14B0A668947B890727321296290C32F31A24BA7032EA9729" +
        "D0BF611ACB877B3F247D3F6D3B3FCEA52A9A5B22673FBDE68A55C1CD5BF7CB54" +
        "1DE1A86321B3A183547AD6E6F2BD49DBF11667FE3EB40B782283CE6D0ACFBAFA" +
        "63322A841BC0BC92989AD673B8DF6959C3CB9D16F12F864766C423DD463A1E2A" +
        "ED8EC55C160CA78F2C592DC5FB723D456014A729FAA789298E4091C34FE9EBC5" +
        "60D2E5F525CA6E6AF598BD7B591487F88773C632007EFDD384EA2684779D27EA" +
        "D486DA836AC4B82746A7A8F87A0D14B4C5096077D3C04C3A564FBADDF2B4129D" +
        "9038886DC94D02E8EA9AF24CB953223EC818398A3AB8235DF4A3D06DADA3C239" +
        "F4614C9D4BDDCCFE949B30F71D40DE27BD6780B4EE06FFDCD6D44A964B96831A" +
        "91108D977BE0A549CC27913995FA313F391C0430BE544981F9C77EF126992625" +
        "D5C5F14F801743C1983E083888F8A454C6712F71BC59E0835F0DAFBFA13E88D5" +
        "601932394FF7B0698EC0899ED7A98FA8861F2FAE6F863F08FE40473081D28122" +
        "DDE0E118A12A74F6209EF8FB61DFC4A63D3091236065B64232D464C4EDD00887" +
        "BCEB7D9B50CDD917428F1425C871DC6304350089593D0D5A7C32E57B42B78534" +
        "C4C16D3D42C9DB3EBAEA616DC03274174FA77B7304CC482928BF652C0B9302A3" +
        "FDD4573D892C0A80A80556A167361AE15EF10F455B83091BFEF76A4C49844310" +
        "8CC8A3DA13D3095EECD7F60EE84720930CAEB14FA48E6CA0AF6B10928BF6579F" +
        "133EE988C926900F41B3D3C823B9870F89F542A124574E75506C01A4E34A12BF" +
        "9F1AC76F57AA884F50D5A6F204BD0DB10FF4DD9DB6F6BADAAD40325175E0E5E7" +
        "A6D885316A97036793F998DE32FCB683BE7784C832B898244B31065B111B48E8" +
        "B3D8EFBA40CC2894BC0F564E1B060CB49B446DBEC999C09592C5FD922BC076E9" +
        "47B3E43EB151C72C354D61F24D2AEA49C4321B8704909B9817A00C08F85DE21E" +
        "01A379054FD0E6B7CC724E6431D8369FCEF5F00EDE788DC1B8330F9809949E83" +
        "B293CA83CAB93EB440FA00915154CC2738159C96E195B1CC2743BE8D8527B2CC" +
        "049FB9FDFF6EB56B8CD1A39045B40477C194BFBB60A3236B91CAF27F24CB86E4" +
        "8B454655CB8EBCF8D1FD3A050042971AC3E3590B0B3D114BF5848CBB668669C6" +
        "D7A4D3DCCFC75A1BA0CBF872EE19F01D8659058D915D885E21161D26A95DC3CA" +
        "6F281EF1601D74C971EB69949B326113AB35182A50D8EFF59633FA4390CB060A" +
        "5F94A44F2C9B529F84566681521E921B59AEF1AF67235E14774A8DB3BCF81FD7" +
        "6CBCB22E4EBAC19DE57F4DAFED663F23E6B63BB0A372C612C3F30AED39371FD1" +
        "0554E8924279D2955E95222D3521078238C6EBDCCA252B544EF5A7204F203207" +
        "AD83D0F5E878EAD29305D5CFC714076A13590E6B3FCC55D649D00A2C4B659A34" +
        "64E9413D8C1BDB46322AA81FFB74255921F386EA5596F0EFC15D10C4BF1CFC3B" +
        "25D144EC6D295E9A44630230BB16335995C94848A1C005A8D5AF67EAB520AA34" +
        "5A63362FCEBB226A3B27AB5A3FC69E2848C6E56950579F5C0012A790949AC1EF" +
        "BE41F65A3F7B1F7B33999F401D06BB7D40FB84760F687551BE76ABEE365604DB" +
        "67C860FA43DF24CC3CF5D2C6A85DD2AB00DDE7997528B71E3B393963485C7006" +
        "60489EEFB1BB5A2794FA9FC787B18AF8DAF44AA65C642406B712B69E06B9C7DC" +
        "BC5A773355AC9F4B8443FD9A2F6F31F1D8401D10392C60D87CF49C5107DE6B92" +
        "94CE37B9A36238F70484D3BD3CA0FA5464BD7D724B5CABF4131B968EA4A4D057" +
        "003A3A29C495AF55B2696CE52174F3128241F5D7366BCDCFF8FB4E52B8EB6070" +
        "69F43130B37D955A95B3DD192BA3EF626E4E790514394B326AEEA659EF440890" +
        "82988910D76161FC460A10829E37BD9E543E97C07BE308F20508911479DB64A6" +
        "357B51E94244A1050FF5E81C2B513AFC02203554EB3E0CD381CB54786770F22E" +
        "273CD3D834C0BF899383FF88B68ABE5981F8856B0A8BE3095485A901CD34880E" +
        "7D9EA7EAAABCF5878C3FDFCE4761582BCD22ADF07F6FCDCE267E9529474BC873" +
        "5146E90FB58C7C2EE904DBD7590987E9AFF14D96A7DA5566AE5D7627EBDE8B67" +
        "1639D8CE4B071D1AB955CAD4D67B2B9DA58007D3B2DFAC29153417D2A73584B3" +
        "D8B25285A72C6AB6C5FF7554046A9BC5301D5C6F91641968BE7FFBB5BEE21A2F" +
        "AACE3F71405BBA01EF9938CC486BA911E9D6B5C1642E82172493E0612E5A50FD" +
        "CCBDC0AD7B849BE5DFC19E147B3DFC9FE1290F0FE0E7ED6A7CBAF6DC419AC38E" +
        "ADB40A440B8A3AF9E595A95199FED21A7021FBF1E8FEB1D702CB38B67D817B88" +
        "1337124E586CC1DD1BF80D91BEEF35B471745EBC22D6C5C00263B1CC6756F1F3" +
        "276741CEB3438FCEDD1EC8AEBEB33AB498A00D6F74A2F05406C692E73B9FFBE4" +
        "A6CC45F8A3CE547EE3D35E132BCB86944AED6B633A97BF6C60E59D08C272A13B" +
        "32F37A454884A103044706340E503AA3CE545ADDDB2DD720118D7D45D158C6EA" +
        "076C63656F54E9A5CA469112B8D0FADD2A6E61895DA9A89659E99A32296B4A95" +
        "5ABF05092D64122FDEB88683C43009ABBFA6B01CEE20A90C7591C98184C75D50" +
        "CA5543C27CBA84DA8B50AA07B51E27236B1EF986BC15EB9D8181C3B23F9D7F88" +
        "BF3CA2EC5475C9B92D6C32DABE2A8E3944091F04501C8C6D4197374674B247BD" +
        "2A693244576C2C8A224AA348822D35B8C73764875BAAF1F180FA588000EC04D1" +
        "B5B408F3E35670A8907BAE420E0D679A1837327884FD72325C159AC815BD06D0" +
        "8DB256EAC74DEFFAB0E884CDDC4E071AC26D3D06BD91840B9ECF41D250219114" +
        "498B9116272A07553DEF0A080811029EE8EAEAA6D14F5B1EC87D14CFA22CEABB" +
        "F08DDFDFECEF05AD140F5518AF4C89B39FE3FF3ADC82A2286A7D052CD71C6592" +
        "08BA5492C4A181E825C7297477C59CCEAAECEB07BFF275451FA3806ED72A743D" +
        "83CCDE4B1A339F8AEBBF2D52C7C1CCEAECDD564C5AE85FE7066FC5642C6DA752" +
        "19F13543B088AC013845F01FDA7CB4E408ADDC7F7D8E2FB9108FD4C634D8D0DC" +
        "DE08CE7CA6D498C95DD4DA89A27077DA35F93DFD4A865AE86DDC18485109D513" +
        "CF938F5156EADE45AA2705D8769C9528D825D009ECA0706E592566841A42F062" +
        "AC512538994F000503299DBAF4B40ED360328B416C8164F4CB28A057F0E16E47" +
        "E1F98C856FF65A63673C8B51953B96FA7D5665888AD25C39D6952EF4B368428E" +
        "7A32F68BAE8B2AC5BB1513C8BA3B8AF91C53BF326FE97AD8853B109ABB16797B" +
        "04468C1F34B34E3C89D57205AAE174E72FE90A2CE347D407522B3FFDC7B39A2D" +
        "1ABEAA2F22BAE32680A37943F0CC03C438D84E56439439AF75AFDA18DACEDF02" +
        "1962D1ADA5ADBF7E404DC01DF649B62C4319CCA7B6B390EC6C50DCE238247441" +
        "C06F8DA7F947DD0480040AD380A6FF5191123C4E0FA072A60ACBF483B13F824B" +
        "2141C3F69B483F8068DB48295A9AB761D48E21BB6F9582846529EF38C746E0C8" +
        "2D656D3807D3E0B3CDABE49225D8D0FA03BCC99208B0B08F7ACBC97CFC0C2C4C" +
        "6E6E012B94BB1D9E202A6B2024FC502FA5EC45F3934F372F9002F3247101DD38" +
        "CC098F750876E648AF5CE13FDF41916EEF3B7DDA45F856FDE40AA17A03CCFA02" +
        "694A61B66B3F6B22C68AEBE94D1B39327DF7F16C0347832DBFFAB57499ACD29A" +
        "462E5B18730E65E0A88121C82515F8997E3A27D6674031C463D5C4D12014A3E8" +
        "5311FE45B5B76DA4CE58AD350CE60384CBD6883D9426AC447410D0E1B3333956" +
        "B62DAF299AC46F0678BCFD1385A5D433B67804596A5A15023A990925BEE560CB" +
        "6C33DAE11AB9FCD030F297AA29E7DE7E358EC614FEA589900FC9E29794A0F80F" +
        "6726FA64230AC27C8C03FFF4EA25CC1D309EC5B7F4C7F16697FEEBDC3688D42F" +
        "E682CFF6040E1DFA46BADBF00C218FFAA6191F69CFDF91361CFF724004083768" +
        "F40B157A1F73375008949685FE0E66093FEFE56EF1C93BFCFCEF693B5E258FDC" +
        "40DAFE722BCEEA8C8710320BDC8D26863BD06693E57842F37D414809FFBE603A" +
        "9F72132594A1DAA583CBE634BCB93D45F969FABF602F4F5400931305746E576E" +
        "44EFC419D21FEF368FC6C335CC43869147BD78572CA529648CE64483D76A6B47" +
        "01B277434A840271C027658993DC3A4417EA70E0B55920BB320E9ED591B05DF4" +
        "50561206879E7CB79D2DB04D615C722BBBD633355FBC9E13B9FEE1C63C9F9F71" +
        "75C6E60607F61B4B20CF9C536CDABA13D5DA753021D3BB365D19FDA3E99C8639" +
        "811C271C704806310755081BF2FB2DB6A2CA63C3D9208E9DE3564E0D2722A128" +
        "EA8F4E99905DDE389E4E51B0709F8CAB2725C58AC471C9D0B6B8794E81A47F59" +
        "0678BA7FA654DC67542834A2F144555DA4CFB2A77BA7A1A50EF5EE6DC43360D2" +
        "F142F5C5FD317BD9CC41316616D7C5A4253E82E276719CFB3EB8B1222EA8A886" +
        "8E4B7AB6E97B9C27B1281817A3DF5DC0171C156DBAEF1D6BF9DE4199582D02E5" +
        "58D5457398DCC13BAC3CD194DD95DA7F510A4F318E015BD4BE1293AAB6486383" +
        "BCF6AC7D5FAECA664EA46E15C3DC7E8C89F7E1BCB0BFDB0552A52262430FE01B" +
        "5194705B21637733C6FFF06A06AE79E175D7B99663B517");

    private static final byte[] NIST_MLDSA65_FAIL_SIG = hex(
        "4FED2DCA3CA23994BC1AEF5F4D964555CA74B85ACF53E822DC2FE1B6A99EEC1A" +
        "1EED242E771DFC432D44BCFF10A308D632B4804EF1E7FF2DA5D15C2BA54D94DE" +
        "194279C6E375F2AAEAD7FDE284A815360C1DBAE409B739AA20DDABB0F4298EDE" +
        "B2E64F5F8D41D866090C96C734019FB65E051FA2E02EF2061819BDBEA5CAB521" +
        "5B809708093D526D10557A830CF40BA455C6CE9E295C6D1CB6E3BB7EC3FA74E3" +
        "53CF3FE433FF49672F89D94F345DC9E7230478791AD6C7168958FE7DD7CA2D4B" +
        "4611D1C65D540DED6C40CB3587E245B4A038679224D74E999C7D288F14B0901B" +
        "AB2DC8C382767553417D2EE8CABEC4E8B15489E6DC3BFE09D479CB7644416441" +
        "C9CDEB87C0028C3EDD983F19266A69B220E9B86CF2C99BC180267A02530235DC" +
        "A876BA3A6626A3B16EDBAC6476463E68DD9F4525FE13A47634307E5D88CB8D80" +
        "29ACD8C210A01F76B323D79F5B523DD706199145FA0A6E10BBB3ED3A4F14A25D" +
        "022FD3C001101EBEC9E2C1D6E9613C66B3D526E17619F3C926A011E906A02709" +
        "270204EE535E387EC4161C4BABD5CEC0C25DFD368F32FDD95584D6CEA9B7CDBA" +
        "645A918A0748A22BD55499764DAF8FEFD2C864CCF4370F5B027B16EDF174A045" +
        "9BE1EE2BBB4E75C90E8164A19D1D273B85DFA69DECB16A576A450F799725462B" +
        "B460E4A3CCA9DDC43DFFCE6AD460B260169FA1BFB5B40538CE868EE3946EF596" +
        "00EE80DE8177B7470741D9180B21EA0883E66E64C5911AAB774A56B9817BE93C" +
        "D3FF236E10157A758FE538307AFECF8C934A2DD9F095ED3D83BAC01EED132997" +
        "CB6D6593B9A794737333796B3A1FAD0694167D3EF71CE40EDA33E71DC5463A5B" +
        "1CF1CA58A2E7041D442507FA536B875045AA9391E4CEC0E40E3BC0E827580B91" +
        "7B4E3AAF5EBF9AA4D43E461979822D60E2603D61854A9E94A042D1AE54931009" +
        "AC47CECC4B1C70F129E6923FD90B1E9D1F9F1D8C78DAC9AEF47D5806C014590A" +
        "3235EA1A0268125276F56A4953D3DCE7C55C84BE9CB9DCE50F640EB7BA18DC49" +
        "52FCA85C0BA0700EF53EAC7F73C09B6D532093BB15BF7497CBB9850F4F7CE2C2" +
        "D4F5B58CACFA091D3D7BA7AAEFBB7B0FE420C89CA91F4576A8ADF93E7C4EF6A7" +
        "1FDB4FC98C357E34A3F59B325C0EA2FC557B77DACD2F264607CEF2CEBD48120B" +
        "A0E14E52C92E73B59293D4F9BDFD0F64D6763D52222F2C3B7D4914C84FE6BE23" +
        "E09FBF717432D386BFCD04C73057519D1A939F0048B5A2AB457FC8C06B915806" +
        "28076FCC381A578A99D6ABEB8DF9594A9A006F8DAE88A67BE26D48D35FEED01C" +
        "CED5F29669FDC500AA3E9DAA607DFBE7CCFA1B6132F00C76492515BD3D528536" +
        "2CFAFC46CE5D75D9CB82226609884462FD5C637A89CA37F27DB178093A4A0C03" +
        "A9A91D5B39E7844B4DA82B430001245F0F7515CC2246DFAC758981B540D1BA31" +
        "9CD520AE49C9487DB90A71E7A548935C7EDA4DA4A6542B4BD9AFFC5967110B72" +
        "EF55B3E085CDF6487ED7A96531201E5B647E27EC909C81262CF219DA6D477BF2" +
        "654CB4067FD95891650C2B348180052E6B60D42BEA9E80B4F387D41A1636E7C0" +
        "88084524A07819406A6154905AC0FF860D022A9837D71DCF45DCFCCC31828F2E" +
        "57E318EB073B19B9D064A787EA3535CFE13D80255503DD06DC11925E82450A27" +
        "4653D5F4B980DAA003C13C7714D4C311339E653C0C408695043A82BEC37C2D56" +
        "FCB57627BCC86C0A288CFA8714DB0720E3697CFE0F549EFC13E587C088DFEEE4" +
        "6487B14B74F99ADBBD7F89C821FE24DEA036E2BA4193E37974DB134B5DAC720D" +
        "B074A270234B304261A7CA92B12792F446FAFB9BC6B5CB11B1AD1F1F0889F2FB" +
        "2DA00C6F4BE9C81AD9E95AD143326385F6C3F1BCCAA42610B5BF7A43842ADC19" +
        "E65C26B1D187FD6E9A4941F03A8EF73431498F2E745445EFC7D8282D02900C52" +
        "38AE57BA29116FD33ADD8717CCA05DB2396ED79040C11E3ECC0B914F4E3EA8D7" +
        "8FB1CB43AD0BBA397C5D9A680084845DE642857CD84091FBD428DEA0F38F75BF" +
        "A6EDDF3A91882DBC1C665975C378F94DCC4D3C90A7E6B94D2161D06F68862DA1" +
        "D15FEBD617A2D3ACBD0F858C22F0C3BF8D280194810446958578A38FE2328A93" +
        "34FB541D2FBD906914E3F6F6A09169FC08A33D9EEBD268680E66BF706DF463E6" +
        "DDB0D2476612746ED9FFE7D49FCDECB4D385557E87CB7CDDB596045CFA332F73" +
        "2F0BB20E3684FB032DB159ACCD66DEFBD8D5CB6B20FA0DCEB916955D20C29CA1" +
        "91A62AF75E92D9429C939376485FC806CD9CFB1C31A63A927C612A8BC8638CB7" +
        "1FC10B22B9A9D8141FD236094A9E73968B05B898EFF5580E4A6662703542FD19" +
        "9078A0F5037D6F15603CAB7CF4306A3E6591A19C2D6E08B7FAEA399ED440DC44" +
        "0DDE636F1593CE5C9BBACC3413616F3BA8189A6D3421D5A8ADBCD3B09BF80672" +
        "5F80888ED0EC8F9586B6C4EA75F1E790C3CD0D5799DCC835E723B36CE1E61D94" +
        "A150258E8E3445F78B367B8A190EAA466020330FACABA2C3F7C08A517697E3E3" +
        "249A55AFA0FE3740BE82717026A0C04269F37482483EFB12CD47AD0E2CD375F8" +
        "49F4F9C0100EB86BCCEC9CC11D721BAEA81F5ABC7B04A5813B03569B52FFC7DC" +
        "DBB29E4557321880878F370D6D116861A613602CD89B6072AF413EAB6BCC1281" +
        "0E3387776896072172B0C365628B162374AECAC0F29F6200F17E51E51197FA36" +
        "FE318F796811207EE592B64A18F8F7698A74AA249AA134BCE7554DF0C36EDB75" +
        "383DB515173E9FA6C76942057917E5BA73A2FB39808466DD39AEB8DBD588D2E9" +
        "72FCA1BB4316569013A9BA176859C4E2CB5F5BD108F17AA80BFBF83DC980DEE8" +
        "6C8D4D50277C8EEF63DF4B46C5E87DBB3D4CE1FF301CD308A8FE2C40B05F7311" +
        "B6473B1181F8F6202603B975E983137DE6CBF605BA73F5F37ACE057ECF7B441B" +
        "881BABBDF84B9B41D5532D5671AB31C2738DD3D6E11E2E6927E6DFAC8A53791E" +
        "D52B75C0FFCE2C44225CC65700955E90ECA0F93F74019AB10FC213508CA07D7C" +
        "AE18B0FEA1AFC338D6B8EECE63232083D274B59236FC33F2394FC88564C77D4A" +
        "F6C1F6C7BA2969D5D5A6B1BEAB89ABBE5070F4F2FE9E21AEF69ECD4FEFB0F7A4" +
        "B34B74F55073EE17B4AF2CAAA79229B9E4E3E48579BFB8F1F235A757963C82D8" +
        "2015F3E30C54C52DCC9AB39E1FB42BC3D21BF737C1B4FEC47EB05554D9C56C99" +
        "15E21110C4DFE1339E6389820D9F9F7CF34677CC30CF931362AA272F32858207" +
        "F11AB199F858228A1D5CEC48D29D32314C11DAC734F23F56E9B6D6197C21BA00" +
        "9C5EDF82034B81F91899AEE45B450043278FD89E828017A7E8BED59CAFC83587" +
        "8205A9453870F238C37134DCB974F002BFD142FAFF8DE7C62B6DA7803B4659B0" +
        "600F376338553D7B1EEECA75516606005E1AAFDF9CBAF79CE93CBA00A41AC027" +
        "946932D4116198F094C7DC0B61BC871BE602C424A80A856149C36050FF88099C" +
        "84D57B8C1103D956614AFF646B0F27C475032300F522C87AC33F82C0348F62D6" +
        "49ADE0BF08115B76CCB7896C603F277844201EFB0FEC8E51E807E73C41F821A5" +
        "3AAC2FA86256C28279914EC9D59CC72222DC1EAE4FB0E3E81F2D4EA848C871C3" +
        "50A029243DE313FE7B8EB6C3963105F1B9B40743936793F1C66396688F8F968C" +
        "E5ACEDE9D45850EDE932F068EA398B594E93EBFDD0EF1F92119356B3D9731549" +
        "89948C1DB7DC532846AAD71381EA75206002CD6057108F31F64BF200F7A6F5A4" +
        "F3121A753B104F87D9FE23C67ECC14D5FB49A9B228F6BC9B938E1352A9B564D0" +
        "77904E593F9D92B0E35887142E0872EA6270BF70F3DDDDA8E8CA38E647E85FF5" +
        "7F389DA6E5DACBD5514C9206064322BAF77102F1B51615029BBDF7EAC8481865" +
        "8151B5DC5BA60E157F05ECC8163DABDA44FC4617B6F7ABADAF5EA0587B933109" +
        "0740E8C277B0C474ED5F68C84B2572483B3F0060BF99E72EFCDFFCB684A8F800" +
        "50599779606D0482EF76F3634214D9ED3ECAA4AEAEC40886634E14C007119347" +
        "22820446E4670475268AA1F051558376AD00F8D7A0E3079C3CBFCB5876FCA33B" +
        "B98DBFC5B9AE377244F9734295B4BFD46AB28315DB7E0BC4F73886BDEED90968" +
        "0938683F228F3B377375652B4908DA9C79EC1497163497D29BDF2E04A048FFE6" +
        "33CC6D558F35D64E872823CAF03EB83847F27533D4E401C3AFE611808712EE06" +
        "E1A373EC76D341698F8070A31C1C5D9538D7A2FE26046BAAB31E6A93B61AECF5" +
        "3B4FC5A7192BADFFCB5EA611CEFE48F3344492592A87403DEE45FC74A181D8FA" +
        "6B3F45A0F0FE0649B369599B1E9990D25DE1BDAC2CD1B11562139DC3AB78F15C" +
        "A0E4DDC60BFC252B7C1F7678AF4AC51E1B7399BE3E7E28076555DA669672349A" +
        "5F7182716E903D7A17C6158CD1F3E10560862475B998C513D59698957A641D95" +
        "ED81085552CB9B3017C65512B0ED9313EB5927C03F6311A702C038825366523B" +
        "0A1FBF0AEE0A295E342D0D877C1D6154CE9B1157C054EDD6DAF4B564695BCBE4" +
        "AC36FD9FEE0D72C14B6A96FB1298AC697DBFF9422705CA6C36CA1E1883FCC6E8" +
        "E83601758CD03DC924E988C0ED77F13401183250E7ECF0F54F767D6076C2D6F2" +
        "0C275D68AD010C132030538395A6E1FD173A3D5485B8C4000000000000000000" +
        "00000000000000080B10152026");

    private static final byte[] NIST_MLDSA65_FAIL_CTX = hex(
        "49DDC5D98D8DDD548A2EEAF3B5D878E9573FBAB78ECC3B5DC8ED2F1F9F5F3148" +
        "D2E8196C9C");

    private static final int    NIST_MLDSA65_FAIL_LEVEL = MlDsa.ML_DSA_65;

    private static final boolean NIST_MLDSA65_FAIL_EXPECTED = false;

    /* NIST ACVP ML-DSA-sigVer-FIPS204 tgId for NIST_MLDSA87_PASS, tcId=63.
     * preHash=pure, signatureInterface=external. Expected: PASS. */
    private static final byte[] NIST_MLDSA87_PASS_PK = hex(
        "85F4272441E383C40870131C394A5AAE61D4E6B20E9E2E749457072F0996512C" +
        "E2C41D8937757D10F5DCE4E8220F4BCAB954366AA1F4FC5232E5C5500EC87435" +
        "6C38FC1F31BD1B8A8A11286806F9CAAE8B79B7B86DB21FF9DA0FA5ED961E6B63" +
        "A9BC83E9944F95FD0371CA67372DCC448B37A103A1948C291F652592563D77FD" +
        "1D3F3102B4F6269F3E089F88B94B967BA30F9540E0B0B791CF8D371AA5835396" +
        "827EAC5181C2D456C3182075EACDD5079055060487E7DC5A6D172ECBF05115D3" +
        "66DA6EA5FED33362A9A794502666B089485B00ED6CE9B49B042D7B94D7E5F90F" +
        "766FEA892B468DFD16BF942F642922F3894B82EE0E7D54D0A907CAC8A342D1D5" +
        "84799AD3F4B12ECD819EB6204B41242CF597B8519CEC73554D8E692E6A132071" +
        "DBE0F948841F713D9A01F7C796D55BA820233BF7A5185E83FE7F9D3B02729188" +
        "1836AB177FC28A02CDFCFE7A23C85BB957EAD058FCEAAE1B59E53C68107830A3" +
        "C04B23B79ADC55F23EB95349D98FDED41BB2C6735252B41ACD81BD12178C43D5" +
        "8B04828FFF30D23338E7B3037C56124F8C30C4801C754BFFDE47B66DBB431C9D" +
        "228FB6C6A39AF221425D290AAB63A9F2FB2B1C13D7AC080285D4C8315678830E" +
        "DE3A5518ABCED4B9C99ED393F3284D1797E951ABD6A831631742A364DDC5E74B" +
        "DCBF9D52E205C7C913A34662C9140573F609C2EAACF41B65D5944B294445F7DB" +
        "1F663246E4247129E5FCB468A6817177A1D32733CE22E9884DD924FADBBC1582" +
        "136E3BE0919674CD295425507A4EB818AB508B7FFF988D737C2B9853D77F33E1" +
        "3E69888474C8D1D4E0A0B435F343C5872904DDA111EF5D7C70E6889AB428EFA5" +
        "ACE7E0E0434685CE58B55A0567A42F2D88F7F9BD9F0B1B88FA538F3BF5E6C909" +
        "31056A590E1600DFB8CFFB5B3C5462C9C9FDA404761DF4999B36277B3135C2E4" +
        "4CCD00C8C22E0600D3BDE4E215DD7D4A56965AFD03A62F286164CE8719DAFA0A" +
        "C78DDF571620910FD47943B8A6795576CBCA04DCBD41FCD26D67302F0C70434E" +
        "E679EC165297CD19F51B57B0FEA39FD4AA100658347F9AB8C63CB06FEABC98B1" +
        "A23512F0B6A280196EABE69581B1C1754FC3562FF716439007AD942713A217CC" +
        "33CF22AEECB797BC33ECE8B282D480CF6132D6D772766799B3AFD1F7D8466F59" +
        "62C377AE469000D8B1E20B67F5DA4420635DA1585E9637A2169E03DA81713624" +
        "A4565862EB1F79A033595F2DDC9081073FE43998DFCA99CBBBCD5B344C356E20" +
        "C56CC152182D16A678B620CFF5586E3710DCFDEED83F434703E2C74467CB2816" +
        "DB915500F97225F156B7C1C0C6C7A45CED3686F64332E25F4A4B2D32D7C904FB" +
        "85019099CE1057DC38A87F8A38D546E32DC01FAB51B6740F4FA43A2561CC5834" +
        "982FF4F1AC17B38DED41DB3576AF335E6732CB25A686553D083450C456B0EADC" +
        "C6D6F2C644A75D318D28938204E4109A5DE02D6C1BD85197A2C494D2022030C8" +
        "97D1FCDD81170383466C9B15782463856D353174715C12A0947358B314B62533" +
        "28FA601413C4AB36257C3BA0CC13F63D1FA6CE5677A5AEB096F30DF21EE4C3D3" +
        "111FD242C5AD4535B342A70A70ECE69FAA8394E28DF78B01ECF6C9C1DD3AB61E" +
        "88BB78F85F60A33AB88EE90F7B3B976B689AC92825B3771DDB0D8E42BF847469" +
        "23F7D16B6670F0D718907BCDB4E3F28124C27039B35C7BCE3AB1FCEC0D276F1E" +
        "8767D7A62882638CCD60EBA7DCD512D67B86AE69688ABF6B1847DCFEB1DE6075" +
        "C896716A05EF781E1DB20C88EB1ADFD19A5978E0F03CE282055E46352AA47DAC" +
        "6883D554E34D33B5801F0E0570D90AFFC0941E509EBB77AD51B3267D3FD093A7" +
        "F86D600AF79452A5DD5A9F2809F135E2586F8C6FDED6FED4BC4A63D9346DC0DF" +
        "DC1CC2C390510B36C2616656596A28BA692989AE65311D2EAEF1C8714D973589" +
        "20B54D20D2821CC7CADE117DE7C918F231886B05FB7D4B434C013E6A1B7467BC" +
        "02D90D2F7AB5483B71250DBE55B8646133E59F16345C2D06F6744F07788EC3B6" +
        "A1A56490D2C70DD81A07B4CD3D36682CB88FC43B5ACD9ED657168CE216F4195E" +
        "7AA11C5B6636BFB4AA50E9AC60B9E992405360A98D9837149FAB3FA713C4BDD8" +
        "BA72B2F9D865F62523BDE899311FBF1CAFBD7F06EDCC5359A1DE29663B0140BE" +
        "8B6E887169BE286D7D9190123CF3407B4D278DCF5D873CF3B787E7A1C62EADFD" +
        "4B81D7E05B99A5862EAFA910DABA7692558701693682F6D1F67AEEAC8EBD4CC8" +
        "3FCE7C744C298259730285C596F53B993A22E3D18E96D1A76ED6F5E5A2632829" +
        "DB7665392172701E63C255545FA780CCBD1705006EA89E5E69C1E3F3F11B9590" +
        "37FDA61285D5354F004890AF8322D199E452F5F1424E40283F877AFF9A05EDB0" +
        "49D00FD495FBE25441AA796391052659C946D47400CA786098AF565F503712B2" +
        "F48540663D18CBB679D4E103D40E6682DDA47A7532729D62643614F191A8B45A" +
        "8208ABA0A1BA62246768E9A933C347B8AF6A30C97F3446F1B54230D3F58CDE53" +
        "5C67D2C12CE7336564D63D92B32445D7D7F855244453CAAEDEB34CABE9CAAC0D" +
        "7D19076F59EA48605A9E97D11D04D67C1E837C7BEF9175E9B197A25CC80005F2" +
        "6470B20DB79106F591A940930E65335F62D8E542D350F53E5B3763EB96D7D689" +
        "B993FAA8FCFDC3676C05E7ED3866736B10BB15AECC904DB7FE495253FE4F6778" +
        "49C6F2107AFFC76CA6F32EFBFE9700E62CAC69AA65E196948A83B3272525F055" +
        "8B25689E8714C9CF123F07796B7856CB246951F5A50008ECBEC72333C8B3C076" +
        "C8E6FDEE977F4410AA6302B5E5D523125261F095DCD431E1B942DBB876C36DD9" +
        "E898862FB1DE30C6800E8C95A836FFE72E6746253616F90ACC5296EEF0517FF9" +
        "6EAD60F3256828B3BD4991B39EC4C0C9BAA75AA507197A38934E08C5CE1D4497" +
        "2A21F8CCAAD90C3753467B1DDF27723164CE8BA4EC0A1D32F118EA22A417B146" +
        "F82AD24AC6666A75CDFE2C1AA51D128648283B5856B499983CF924A42737C68A" +
        "3071AC6124C7922DED48D5481F6D4D7785EE86D7B1B3031BBAA14FB7FFA50597" +
        "C1DFEF2A4460591132734AD6189B5ADD1457212343F74C01B0759DD6F92FBA55" +
        "603BABF8A894950F49CA67EE93F577BE43A301AA1F678E3CC001425FD44C4AF4" +
        "CDE3EC6008DC640EF19A5693F303584DD05F36547FA25F7ACB5DCC573A02033E" +
        "16C95C755DF9A90FF2DC11E86130CA3748EDEA7926064F402627053973BE9CFD" +
        "E416FA74179453F756D8C711839767ABD61A7512ADCF5991E239CC76567A7259" +
        "B65A9402EE3EA204658EAB32E6F841672C1C7AFAA08EF4F3A2EE32F0B40013E1" +
        "90CAA1609A815A48F14E35D05BF4173BDE88F3F5E594030ED0442FD460488358" +
        "3A5A6518C2932A7D4B4EBC88F729B57A9501B26CF16D4AFB61C773991924CF56" +
        "03A7B031CECF49BE078098DE7C0B255504606DB0A792FB0C39EC3BEA0F62F77E" +
        "99A3F70A08FBFD3BA151F09486B4C5CC6C0A40CBA8B65D450BC76228ECD57A6F" +
        "5678B467E5CA068F12026BA7F1B4B6E365770928C968677125D0D68A25BB0C63" +
        "B541B4FB32B16254CAA1C33F70FD54E5C9C2F10B888A05586CA38B27725C91D5" +
        "8438F81C6BC67A042967DBEB013F1C9A79715B9F9670DB4D2F96ECEED9FF571E");

    private static final byte[] NIST_MLDSA87_PASS_MSG = hex(
        "2D841DB9C01A4F9372503461C5594D2C8A705ED53C3AC1381B4C2EA52F552B26" +
        "F474D424E335C1160C77A8F64D02CE15E0AC3DC1141E4D01A801EE82305B0B1A" +
        "468163936E2ED9C73273F48A3B6A3A09CE5F003A7072A857074252BCFCF38901" +
        "02E460870C9C75E1E7AD34BD765544FBBEEA76BA5C0DFFA6096F30E40FC07466" +
        "306BE07F65F8F4441A5D486F19B1C73827627D715ABA6CE264C68000E18F3E2F" +
        "1C4D6F3E8D6B5E3B5CD074C9EF636D897011734EF090B49FA96DEBC33450158E" +
        "2638D2863B384A9BB16D020E5916504F8AB451F61E6568EED4AA76D8060FA95E" +
        "DECDDF40B3F73DC10892B4587F88492046F2D3DDAEF45C0578857D78F9522D65" +
        "C68296A33696425D91FFEA7A6BE1745123702B34756FE0757016D6F554CEC1F3" +
        "0D1F39F4D96C907126484C8F69CD1C4E7BD247BB463A850076700FC70768A6DD" +
        "8F54488730F0236A2B716EFA6F57E580DDDD5EFAAC504855A76AE5FDD7BCE295" +
        "43BCE64F4EF92CD9CCF40B8E8F2C6A5C6EE783EAFDE99A75A396815CC9F05E36" +
        "00FE27DAB3536761C75BE447C5EBEB28C6AFEE35F2E3936B969AA3B55AF435B1" +
        "3BD17A7B55310B5C1D76CD9154310F464CDB51FFA19A087B7A7D0BBEB084D795" +
        "EC3978D532380418AE90D0FA5E0DE8A259533A318A22EAB4A7ACB35949B9ECED" +
        "712C9E3DD46899870DDB218C4EAF272DD654789D7148C28B764C3ECCBF12F3CF" +
        "1C1EAA863BBFF7D1F0AC7A4DAD6100E578736C3D89090B1BB3D9FCCB3A8A3388" +
        "28CFED4F94A0A0429201A67D63766573187856F39A1C9E0A6D3E27DC0289D397" +
        "29DEC313D4195ECF6606592814785ADBB6FE550D215D66ECE2C168F2700749EB" +
        "29BAF6BD511B716D867851000980CBD53198E34B75FD52209C152E4586E448B8" +
        "0763A9DF4E8B73994ACA0B747D02021107EED7B8BF504ED29A4449C5B5BC3791" +
        "ECCF030B92D3C40851A39CC4D0ED64E5DBE402BD7635870A6E3BB31294C53DE7" +
        "8EDB61E2E8DDF509AC4DED465BBD0E4E57DE8AF2A3C66D4EB1EBE987DD70563F" +
        "EAF881DE3BBBC366D7A583E48439F657C29083EA0427DF10BA9D9DAC43CCAF30" +
        "3271805115D1DFDAC88E1A82D628EC4F972C548CA188B06A4996AF1A958CF5F1" +
        "285A0C70888E84171D2473B59128A66AB8333939BDD78A3FE209E099E8FCFE3C" +
        "43ACAB7D92A583D16512642BC793732A30971794C9399DD3D79F150C5FEA2982" +
        "503B480552D702D0C702725BAB61DEF8153F84117E4E788CB1FE5494754BD3D8" +
        "6D108DA68B8869B4A996E341C54ED22B348A5733C29692DEE2D48DBC8BAB66AB" +
        "4437A97D8D13826C7246A7102C5A603FBBDF40DBF6170F168D1BB90EF4DCFB50" +
        "A6109B268E8D0A74664D4AD2AD1FF99BE2829986FC0CBBDF5E370A9887E8B9BD" +
        "19543026F543C254663CE8B1F76E4E98B341F7AE9A14A5D736916950E171B04E" +
        "FF4240FBB8ACDDDA31339BA2E4F270C787EC093837B9FF5A50E8D3D31DF38801" +
        "DECCA46836D684BD7A2E679A6EF6C00964874369728F1AA3AA76D23D69570899" +
        "CD0998A4FBD54FCB567BC8515CAAD023263D2A268C550A77719F3D85A2DB3842" +
        "80C4443F19E6468EADD0BF7D078C43E7FC7418A29A895D1249B28B4264FD9B15" +
        "F9CFDD9F91CD973EDFC4B0EA68532AFCE2A1823DF032125E64D50CB12526535D" +
        "BA27D1318825887FB209D4ACE8C2E75563B068B75B563DCA0066C51A4C4947B4" +
        "7098AD4FA98DAD4B58DE942EFC12C529EF58FA6CDBC3F667777ABE3670E15D46" +
        "37D1BEADECD7AE5E1D447B51BEB545BF9C35FBA9907F862F45992758EBCA8FD4" +
        "2F53E341D2615FEB028AEC61F33B019ED3AA00FFB58C991B12910F4BC3B0E909" +
        "A66E8CBF54186A9D35B1352A9A98C154E4EA08D4D43542BC1237593DFF949C37" +
        "B587FAB48FE689DC7FD535F848AC526CCE0EE05FE89E90A1231CA5DDF4EA726B" +
        "A97DD6ED058F62C54AF17265D766D8B8154E2771FF46B58B740044F2ABD4CDF2" +
        "3A0C5E206568BAF580E0A69D2905A1670F51B1C1DCAC78079E3B55C085E2A5F0" +
        "8F9C6B78CDE709C710031E784E54C7CAC0C9D551C55C8FA5852B086E2FCAF99E" +
        "58F4F2F1D06131E4A2761E6C52FD33A7AA848A7F81FDE5818E3BDAFECCAC3D2E" +
        "6F717581FC724F4B48574EAADE1EE15F2AD51B6CF9690FCE76EE641FAC7A3BF1" +
        "20FD8A335D5E7CC5F184E891CC5B70F35B8778089D5E2BFAA4D3E0783841CF31" +
        "E81B054E113CE7A3DDB8CB2563B4A156679D607CAB240C264B9B704502597EBD" +
        "A94B456DB2D790BC03242CA98577951518E2D2B6FE787D2E89B826A2F9EBC709" +
        "62519CF9C9BA3939545FF4285295DE723D6930C963E00E45450F28EC11E41BF8" +
        "4C7F3F64E9D37E48AC36970DBEC23EB1A4378614E31489A1B586CC4803E66FEB" +
        "6CB3EA904683A9C47E13DEED81C3CB11582BD381D088AB361085E79398FD5C8A" +
        "2318D189D396DD77B8579D8F4A99279C196445607193043E3DBE2724FA621B1C" +
        "A32886A860E4769E8C4514D4C7E8F537AAE2F5B31900B3A9C1316E4A3469");

    private static final byte[] NIST_MLDSA87_PASS_SIG = hex(
        "9A4120E03525D2E5A854400780AC9E407F12F821966839706C89688DC479F48C" +
        "E27679C37A88888D3290560C1AC583DE4B8597BC7BDED6C7B2262C191CCE8C56" +
        "94CEF88353B2515A657CD6A6C272323064DDEEB36136B0251A926B584CA68F1F" +
        "4DD4C6D6897D4007894256036E341737F4ACE4C0D2C0DD0C4FDB5EC1360201AA" +
        "340B4CF0EB7061CC0584BE95598E51F1CEA046DD953A74E6E0F36BF47D473CFC" +
        "55473F54E7D207D0339841F165C0D238BD9A4B6A0763F679DCFB613842546413" +
        "8702E679DD529C0B9AF31BA89640FBD507CB111B3CA305FC190FE5A905DB6270" +
        "E98350F15F98F228DB2EB0EC7DBE77063D20BA48714279DC966ED1DDFD457C8E" +
        "89FA1065326A428CBE7F317612B799FE041FCB72725EF2ECBBFDC215643469D9" +
        "E7CF7ECF9A0869B52B7A26352DAA6F1BE8118FA0F47E31D7FA94054F023CCBBF" +
        "D8932308B2E2D598D0AE76164D0AD302D22D638C62B28CEA8B95A6E8B0C41CC0" +
        "8AC215ABE7938EAEC17EE341081E12052B76FB9B35E857BE5FB38467B77245F1" +
        "8C00ABC8A76E06E4840915CB4ACDE24044C8EAE7213B905DAA10B4EF1BF121EB" +
        "7071278B9EA74788008975782717672346ED10B16CB2B9B7FDBF9C60D0ABB579" +
        "AAA3E0CC3ABCB2EC5EAF2742EBD40E0EBB5ABFC9092B025051CD11993B0B035D" +
        "3395DC9FC92BFFB6E9F9D2EE443E1617AE5F6CB154C63B1CE996CB3686B689BA" +
        "5EE5FDAD9BE284BBB5066AE8B9A12584A1C35DD48E616F96551BA65CEE2185BA" +
        "BBA520B20C8A5C34E3F06EA88861A1C41AC16F64B79980ABE7C47A2BB57166FF" +
        "C7EE1AA16AE6CBE3A6ED5C9F4FB3347812A1549B5051FE3B02B443E68BA7480A" +
        "DF560DA9A1509915A3A1AA131C907C467D83FDC5EEB4349FD28EABDD57C6ED32" +
        "6622254F19B5979C63BD2E7B28E73FA456D1D77AC97C019805D375860CAC84CB" +
        "8B3B1A668C0330BFE6C2AF3B425132FECD6F9709A36512D61AFE7AAEB0A843D0" +
        "C930B719AC2B71964286753120B6738DE7BE2036C9716FF7AD76CBFEFD4A0325" +
        "04029A416A88685CCB2669647360CCEF54902B25F9D3988F8E5E185E8CB0617C" +
        "88366DC2A0757E2C86698E15CC1820946210FD7EC208AE0FC98A6FF089780A6B" +
        "79024CF10E6A7D62123BA5A8B7D95044F1F97DDF9CDF0B64A61E226622EC9B47" +
        "7326E6C0B083D06172F2C7651E1575D11FE1000BE3D30FFBA388ACD74FC8083B" +
        "EE6A479CEF4B18EB4A6D09A5F8A5F0C36149FF16B47548E6A7F8E9C69A75EEE5" +
        "CD705E97BC36C29DEAF430009F55EB565AB17A68FA87EA60A8E1A0BB0646C2C0" +
        "A2D322831D895E6B73DF87CEF5B2A218AD15B1DFAFF707F0A314DB8F01D1771F" +
        "DB86E773E96C9F444AF1A8CC13D82B63B42688E8D45D7F1F187FD1EE36CE9E65" +
        "3A36C1BC43A1E774DB0C847D8B6AAF0CBF032655659777D0222480FF93FB353E" +
        "4BF10C9FFCBDA3F9F3AAF375F59A80016E3395A3F12337CA996557F4544A4274" +
        "DFF778CFB203D03C93F64623238C509908D0158753C06CAC12DD5B74EF5153D7" +
        "1B66F8E0FA3C470C8532851D93AF334FE6FF804DCA4C61290F237C451CDCF346" +
        "43760DEF50AC6445CDFEDC14A8164F01A6C108BB5E090FDB0015335A56478724" +
        "1B7B557EAD128B541D9B70B703612B1CAE31EB8B259D76D03F4DE9B11CED7310" +
        "5ECF85EEC7F6686B626720A8B4CEDEE71A7EF76E22A52E22C59306F771B2EBAA" +
        "370920E6C08C0D25C80506BF8539F1B58400E1DEFAE3CB381C1F952287940948" +
        "E4638639440FB16C87FE2745961F36EDAFA0A2E5B7615A7F7661BDD670897A9D" +
        "90F25BFA033DC179FF014E7C228B44C0FF2906983111EFED3C705149B0E9389A" +
        "6C350F4FBD321BEA9419A3C3596746BBE1DF30A0F8C7CFEA8763AB47A758B839" +
        "57CA140C9C720853AA34DB37595E703F8461D7999B35A58830EC6AB11F10C967" +
        "5EF519D55B77F6B1895861842CA78A060267DB9FDEEAB2E11A172C145839A7F1" +
        "3002087AA30D69312655EFB3D9E74C60EAE1926A5AB5CA99E9EC0CDDED1946D9" +
        "193A53C4492575B5C9B5121594B7E8B8E482E06BDB86389FB23E8722C9A4C211" +
        "671B576F34AB0BFA8392CEADEAD53A41F0D65BCF6FEA55B27FDA3E40F9183C94" +
        "FA4135780502BA9F5777685FD5DFB3C11A6DAB263FA5376FEB5CA3BB9114234F" +
        "06BB34718650FD24EAAD9A9786B793D88E6C463ABB886F2115A77CF667D7120B" +
        "424DD464584833AC9C8ED968A967E0B87EBDC49932D53DE98DF22949132C91AD" +
        "1C56B6A474DF8AABC50DF7D5437D34D28FFFB6B837876023F3B1E1A1E0D46E4A" +
        "11DE99D02A93FF47E474AD731BB2A3095D8BAD4028AC193F667AFF1648A938D3" +
        "ED3B80B74A1D9C0676B8837BED492DCFCF02598E289BF0BE77D9D7ABE28153BC" +
        "09B36F8B5D873E73EDE36DF876596D477C51223709CBBC46FDA52DB1AF125DD1" +
        "65FB5BFDB5947EDC2D1E0727415A993D00F747E5E5ADC08649357B489F400E0E" +
        "50F78E1955281B4DC9E7DF32864462264D685157688CE5C441E8D32C45E6D834" +
        "563F3E8AC65DF099BCF89BF4479FF43C7AC74DB9AC4E21FB9A3F24D1A02E79B9" +
        "CB2A77D602AE32FEBB41726E70A11EB4844BA458B6B8338BDBDC6F42CEC89A5C" +
        "305B73962D875A4A17CA559E8D73D30944B92C6A0DE35500F6C1C1F84C5365C5" +
        "2E2E963B76B70747200B60BA1AE47784BB4584BDA982FCDED4E3E473E537F26A" +
        "E787A5764003C34D0ACA6F9EDC2CE5B0B9F954B0B4CFD28FA4722275CBC0B662" +
        "613F79BE5CFA6CEA7AF4013C6EA740B9113E07C5BF56D97A1AE891C1E28333B5" +
        "79FCFCE1AFA7E0013867C93D007380F7FA6E72690700A926B738334C7DCE7286" +
        "CB62CC3954EDB8FACBD5816B3990F4D97E86309E404901EA47BDA968D00A7FEC" +
        "D639462AB6C2302EECE577C59DEBAA334FBDD4A5D6D1B27B564DB96BAE7D876A" +
        "43F7CC1AA484B45E12480FAE61E3C3F7E69F88A6C8395DCC11735246FA630486" +
        "C1DE15BFCA123BD3E7890956D1B9EAE7FDD2521D2A4E18383AE4EBE9301BA7FA" +
        "F38144C5AA303D527DF88AB66881B26980207E08DAC4868AD6E0AA886FEE2837" +
        "D1738DCDD8BFC3A7E0B276B1AF2D69AFC0C14F37A68DD6FC2FDD2E4ED787E6AA" +
        "ABDFA7E7E416DB56B5BEE693B76FAF7F663C05412C812FA48F33AA8F4ED4D4F9" +
        "2F076696F5E3DFE05BD9C47234531FAE7444FF3CCDEA260E16EF6A4227C8A7E7" +
        "F5F0F8769DE26C156415D20EFF5BC6C39A10CD9E743520EB39C4E8A4D0202E5C" +
        "F5CBBA2DE6F95AE6115B8E887A616F5248A8B4E55D10F917F372ECA217BE4119" +
        "9D62E86231F2FAF5A2C8A9C11DCB89EBE98CD9E4341F2D90B30DB56489F68C78" +
        "7EBD4DDC1F6861B975E416CD47417D680AD68AA76F786C30D56A9F2FD40CB4AC" +
        "6325AB92E0FAC0CB11752F6744426628CA6E91CEFBF82045FFC5796E082F3170" +
        "06F9BC48E8BBB9727B5F1B13979C91D72CC0C6D9E7D70D59C8703879EB7C338C" +
        "B11D1AC58C0A12384240773C2B6279F102D76E0FEE042DE9CEDDBDE555E14E3F" +
        "1B271551E9AF2EA6CD07FF9E4B87B01702703D3072634FCA51C9A77AC307590F" +
        "9D811263B08A6ACF233C557C2E08B35139C7C651D59ACD71878F50A0A3F0B6BE" +
        "A093DEDE2142C0487FC51990813BF167DDEB2888F4CBA5567F46EABF449E6F3D" +
        "D0EEC784FE2D670F58B1030D2A76F0AA88508D07A0C74E34F29D7D7582FD4081" +
        "114BE93D883E4B3270BE393369D494403F12A76205DC0C0EF5B75419DBD94E0B" +
        "64FEC5C8414FD1E0732BF90349F35056E0C8B342515ECC8FBDBE7EB0FCE8FD18" +
        "E0356E24E9EE3D87EEEFD03718DE7AE26D4FB2003D6C2DA430AB0EFDC786F39D" +
        "B3E18C47773D1062ECCE80086A8CD9AC091EC5D0870D091DA13A87D72453500C" +
        "4CD51EF9833A2A4ABA84AD9A860313232CAB3C429E5BB347FC37CBE2B3B76AB0" +
        "0BA7590BC634EADF9A31EA2A0809EAD59A3DFA5A3FC8D716ACB70EEDE168F6F7" +
        "AE0CDE29B5FE1AD5163656D4C83ED601114E438577EF9FE99159BF58C5A368F7" +
        "097D1BAE7886F018951AEDDFCD0A75D709148DCC73392CE72B0C8DCA3C77D2E6" +
        "E0A3DCF7FA2EBF7E4016CA355D6593EE85CB6FDFFF7BAC0DD3A5E37F3A428B2C" +
        "FEBB8529674545C69ED786CFC8D0EF07C3306A0BA7F6F5E8C544BDEBF8E11240" +
        "33CA303FC5491AD6A3DA0D9922691BE0799EA3EE440B1621DE99251BDEF19949" +
        "49C16ED224FEE7E6351142E587E3776717CC66C2819F0EF4B0BBD178399EC057" +
        "EA6E7D7B9C46F621FD13A60C4A217EEC5B3481FAA40F2BDF296F45FD63EF7096" +
        "B1452CC5F8E4141DC3C592CAEE21AC845B5CBF25EFE282CC799D48226AC52784" +
        "C829C3B32C631721DE719621A3F0EED9202EE046BB20633F6533F54FE5CE6834" +
        "353106108AC2AC25D6D1D8FAD328AECB5083CEAF80EB2B677AE75205DDAD4A0B" +
        "650138913C5F25EA74ECD2E09A66CB2D3478A6644A9E3298D85554C1217CEB69" +
        "8223448A505663950AE0A70A29F8F75E3CE92AD5938DCCD0221C4B024A1F8687" +
        "DD9FF64F21542E913F6FE6C4BA6A198C639448A0DDE88D6824F594B5F0967711" +
        "7512E9FDC2E32D8FB22283A1C4330AC1D40396F452002323AB74CA09706E7EB7" +
        "E1B80F99691CFE525965326CE5458467F4088FC5D11250F01AE268A79F31FF81" +
        "16EB430485493DDC0C133C9EEF482E99101F5162B43C938ECBE7D5B18C0917B5" +
        "2A9E6997C93F5FDDBB0BC9A5066563AD5D6024B9708A11B4EBAC2C0940684407" +
        "94D4066F06A4362932C61434490B9CFB031B89934D12FD3C375AB134685BC405" +
        "947F16918D7A953805E29FB65B1EFDAB191D7AFB19FAC9990489B121B398881A" +
        "8FB7F1580E5E76BE91B7FC6695834E7DA7BAE877966AE4DFC2A509A142E2634E" +
        "4558F235EB000AF2AF21955645956AA8B08ED9DA392FD7F06515DED8C641E71A" +
        "4F945D167A4A33014DB58EFEA472FD2227E9547FF1A4AFA9A450D99ACB856201" +
        "31C52EF71F45388BDB1BFDB2EC7AA5E353ED4D0400AC6C6C2E357FED4D4D708D" +
        "74735FFF6E048C42DDD70F2C0A454BD3524A9BE75886340E41DB92635A373B3B" +
        "80C3BB0C7B204768E9FC6C53D5F1F50ABC94B4532DD70DA521DD5E3E94108F5C" +
        "E516FC2726D1DB22F0A107D0EB0CDB53AD585C4CC7C5679FD7AB60AD791DF093" +
        "434F040B0B989D17BD77F3ABD1738CBE31C5D0641A8EA9CB9322E33EBBD1AE94" +
        "EAF62D9AC42172BEE8C668194BE92D16AAA3724B1C2F8B22385984893582AE8E" +
        "43C2C96F65ADC70901C075646F635237AC972314B79AAFC10001CB888896C5EF" +
        "7BDE1CE64459080FBE5F0153160B238DFB90A2A60CA09A8D8BA1D2B13FD51EB1" +
        "E8BF4B9CF0C6F6263F666AAC9C3A1F59271D36CFE61274BC60ABD29BFF097696" +
        "D0E36FD2E415D68970EE7ED4AC2C12AA397EFCE5AE3217E796615E28797CBBFC" +
        "C66D111FAC922186BA58C38A878F2F2F5244309DE7409B9EF4DBF788C03AD748" +
        "42D050E528F8E7F85307BF72BD64A2B8757C4E6E322A1175A7E0C4E662E3C019" +
        "C74226DE286D99B7D434CF634CF9E690D9777B6BB5927126F8E77E54925360E4" +
        "4F44700FBB35A3499FA93A06215389B37294CE359291F7C834C5C68670E480A7" +
        "4023AEC95D35FA9900D23107A6360ED767F246A97592A3CBE7DDF9068DA809EA" +
        "B99BBCEF42A0384FA0E715ED2DD2119728E2EA191B6457563455920B19991F0B" +
        "7BC04CFE4B7D1E3E5A1F65CDB2C2343153E111E120E9FE1D4A626474CBC4FA9C" +
        "59850C07F4166DEAF63B3112EA3051272507B903B5C04AAD22F5F070FE19EAEA" +
        "5C9D6DBAA455E0695B810689E5F24BA332BE15ADA5BF1305DB4D5D18E7B9E541" +
        "4285BE099E7E8BCA1B3AC71B7CD1B36C1CB03EBD2EB312A6F0633F72AE1FD29E" +
        "FF4E86FED9EE5DA27BAFCB42F186E16A45DF9F0129ABE14C66A2F978E9B09DF5" +
        "AA49741CC5DBD8699135656E3D95B5FA908B00A0D37D013CD037DBC4D8068E52" +
        "778F3B0140096A373B2FA8735A44096C4F93A4F7E1C0B6F61D27FF26344EC8A2" +
        "1AA31D31DFEA5F0401333B5F49043698B3E7724324F2211CFD0B54BA8B1FF81D" +
        "4A7E363E43DF26DABD14838A37038580CC9B200A9F1228555F4DAE5E956F2CC2" +
        "A09A04E3D72E0C6EC64C51B4BA8C7E0276825CA3ADEEB34A671292966202C153" +
        "3D8DA0E1984301FA713945147439F4445A891180F3221099E5E470A8A26E3273" +
        "1BF28E75DEC55B173A88DBC73A027F7F30661F70782B3A5DA08FDBE62C21D83A" +
        "130AAF5EAD062DDAD708FE8D3962A2359CCFACDB06BAD37CCEA15BB1D1CF6B6B" +
        "E5FF67453E75E64925254E8A3EAF72CCB32B48D1457AE4999441C9C378A32917" +
        "0AFC6867B291D2E2EF4413F6E9AF5CDCCED3C0F75FDBE69CE290FF9D5632C2C0" +
        "E02D8811A340C7F2FD3F8BCDD3B6D83F58CB22583C6D8BBE0EFFD738A4BD7164" +
        "006078AECAE7EF11154B64686987A32A61627C8B97B2D5E4E7F2258E236BB5B9" +
        "C5E0F2949598ABE23EAEE0ED05293B3C9C9D9EB6000000000000000000000000" +
        "0000000000000000000000070F1A1C23282C34");

    private static final byte[] NIST_MLDSA87_PASS_CTX = hex(
        "DFD489E3F57FBD6270B6A149E970BD322D445CFD4485B6F2F9594517A76DC835" +
        "BD42FCF3DBC3F3904F90C2CD3FDA6D5031B285489AE0A3DBC765A7E80F0DF332" +
        "83E02357C1EEE5B28CF6DDE7617E57A04254249AA04C16E19ABEE2C0767F862D" +
        "78244C967AAFA5554D2594B0C13D99AA261D68953A6B57D0779E07674432D820" +
        "A79F25FB297DBEAAEA5F05F71C8D80A12527F34EA02DCD9D1F7514395A8FB453" +
        "1DB13D42DFBFD1196B08C3070877468BD861F6F985");

    private static final int    NIST_MLDSA87_PASS_LEVEL = MlDsa.ML_DSA_87;

    private static final boolean NIST_MLDSA87_PASS_EXPECTED = true;

    /* NIST ACVP ML-DSA-sigVer-FIPS204 tgId for NIST_MLDSA87_FAIL, tcId=61.
     * preHash=pure, signatureInterface=external. Expected: FAIL. */
    private static final byte[] NIST_MLDSA87_FAIL_PK = hex(
        "7558086BA7694DEFDB07F3772EEFF60AE2A39CC903E665A12E391918C12D9387" +
        "61E9DAC282F8E7BF2496FC05E41F5F7192F017946EC87C27F82FC281E2FD8794" +
        "1DB55A1762280823A0CFC5E320A38374D0EA5432F2F15EF23996CEC76DB5BBF7" +
        "391B79BB262F8E4DA4D7FCF97E379AA250A7207C7D1A945A94EE5E49FA84C26E" +
        "627337499CE6D08FB9DB53B8D11B1B129AD4A83ACE1C8AD4E2B26A924BF84BD2" +
        "E8A0B860D3B3B0F570C5D8CB59E2E862809C7DCD4C7226E5721BCB3CFA6030D1" +
        "DD98EB056CBFC539A23AD3DBEC3A253C04CD58D4256057B8B7B54C6D82C9A1DD" +
        "38BC35D9BB17213697F0C93D0802F9BBFCA76950DFDA106D64CC1387F9B3D9AC" +
        "3267D9E10509C96BF976BB339027B32E863F78F7D5469D61E54176020AA2CA1C" +
        "8973AADA92F883A6BAF3AE4FD8F3B1FC2A70B8F754532BA209AD60227BD08522" +
        "5627E909AEB2CE051A0E6ED25CF843C404C27FA28353D5C554C1F59CCAC3B6BB" +
        "88AD06C06772DC14E1F98E114036A4F5E9AE3F314884BDE847D2964513F8F655" +
        "527A5F22C588450A537826593D5B21FD89F81FC085EA8704E2B4755C2B86A77A" +
        "B663F31DF3E2B5E976C697FCEF1A30A968083F31662E8DAB62FF29B25B6098A6" +
        "69688A450CDDE85ED9A8D97BF4E8F2802A1286D3D9AE933EDD72D2BF194CF741" +
        "1C2FDBB7F8A9F10632DD0C4E6EBE37FC9976869540DA8238D8131BF46FE9F5DD" +
        "F72AECD042F5D8C7C177D8CCAD408AE136468EC814EC356354A3287F0FF7C92A" +
        "AFD2AAA6B4264BE1B9037904BFD8C110E58638A30DB565847C14D4D2A4117ECA" +
        "A113B0F3FE36AF61EEFF1B351233F3CBE3D7D46E13B5E5D6C2993AABCB07AA07" +
        "62C493A277AC6E01C868DFF8EE6CEA3865BC9EF95B17C4D120F7CC22347BD1EF" +
        "A7BD8E20BCCFC297C1A832438B64120E6D521840C9B25A62A3A2EE4A0ED67BE6" +
        "55559AB8522C9399DFDBD75C01774AC3F9A9387B9B2A1C5E1D330E1403FF9758" +
        "4DDCA2E8966D58D144EB96EFF1E50E7B16AA62DF262314768965B8D795A78437" +
        "07EE1EC0EEB89118608170E89EE3AA1D96E17A6CDB198AC5D7B817BC9340408A" +
        "607BAE16659A1BAFA816C628A6086F6BE87DD4C2A6D6F73F846378A5F69A5BE5" +
        "4F282602EE1CD1CB9FB7D1D6A0D5B5AA2E747F146068A994602C2EE7D17C34A5" +
        "E47E358BD4CA4E4A6E67AE54428C9B6D5B1802F50168E15D265D687734CD2DF8" +
        "BDF2C3BE5252E8E62F3F04BB0E8235886B327845DA2351135C5AE87013E54A9A" +
        "B810011AB0E9860686630E5C0150B9D74227F60FCE2F139D57718DFEFC37CF75" +
        "2F9CD1B9CEA23D649308C2C0C9CC9B9F452B6766718AAAC294BF1B0EF2922161" +
        "D2D77A7F8080C81B1AEE381A1429C96A23652E7D373240E979896B65E7AA4CA1" +
        "37F33CBA1C19A10606911F3DE2BB1C1937AD72843E18857B307DC742A92F0E0E" +
        "93FA390C90811F106CCB78DD2B15A9BCC0B3B98C41CFFAE3BC264151698F3DC1" +
        "2D41AB2B1C5B423F8B86584E7D3380F7493B73A41871BC0E735BC117FA66E468" +
        "899DD4175389288579B439C0EE25C50C68E941B10F8311214C1C60AB23A4BD2C" +
        "D84C75B111FF2AD46134FD586FFB80C74A85C01CC6469E59C24118ECBC4DF971" +
        "2EC0843D95A708B6E7E52DCD36DD3F05AA4ABEC27B78A0A8D0B2D3C0CAEF44F0" +
        "A43232011DC29CD1FB599AB1B5553C7479EEF6505CC0F953FFF04C10801A1BA6" +
        "5AE51EA294CC527E9F6AFBD69E3FAA0C637B386FCE1E6E9FB4AD7F7734A428EE" +
        "6723015EFE93DCD2033488F8EC461BF1AD99F5C166F827AFEE19981320D78F06" +
        "131A3105F54C5F7E85049C463D95E4DDB9B4FE60BFD7CD5827BE4850B0D4589F" +
        "673EA18C67A31DF7B8E982174455145037D2BEB7D8FCF3CAE9A7964ED48E8182" +
        "DEDEB58E58538127EDEC25D6379C53628DD3379B92FF4EF43CE73192BD652B62" +
        "E772C9A8328277AAC921E0F92DAACB7EC9B5B68C620578D06436E2758B63EF11" +
        "571D5E172F1610CFC939916BB2779917A4006D2AA795FCDEA31705CE847A50C8" +
        "3BD8CDC0E272C6C3D072089CCF07823815420C66618CB5FBEBC6494E682C3D42" +
        "F95BBDCE87EA0A89EC8391BDD400B10708356B0A232CD737781FF556AECBCAF1" +
        "7805D776CCF149D5983EA9E6E359D2B0B9F6CE617038CC10DC2E71A8477762FF" +
        "F85957D5344D12E69728F9635BF9F4538B989631A0BF24EE5C38BF9844E41277" +
        "45BD2F37A7329097C4D0303EC2E7B6FC2B1A4B784DF142FB84A08C30194FAE7D" +
        "D798CF9AB550B3E5D3DA7C9708AD850A8AE5ED758323CA46E5F063D43D56261D" +
        "80835B68FD5369A60DDAB802B70A86FC3462AF6B5A8F6C606B8EFCAA919394D4" +
        "23CFB3A1E815910E39CB35368903354DAC2DD796DE5A73389A8C7A13E48B7B1E" +
        "4A099F0887DC9F4E757B675B96DDEFBDDF3C76960312FDD809F38C3A3A14AF74" +
        "46B5A24FDC69F436145982980F14854DBED836295B20363AC0AB866E2399B55A" +
        "A67BD8690E646242046A817A29CD1F7B321831F88E49A08B9F8772BE65BAA4FF" +
        "8E08BA58B01DDE2D1381D1D4E520BD6EB472FA6A34DE5BD4327F50AB61993BA4" +
        "857D294BD3BFDBC3CEAA5273CFF37FDA704C0A86006C1204D7E1F99DD77E2B6A" +
        "FE023E9733386D4825AFA8B13F59E7FB98E879ED4416949CF41EEF148D4C8AF8" +
        "04BB6671A2FF3BA6FECC5FA7D0F2E20E51656C399BDB93E2C66B7F30DA8C0894" +
        "EC40D15384CDD4A0EDF8983364E3CA4E93862B7356D7870C81E0E3A52EB8FD14" +
        "6F6F8CEB6A6372B320C6615BEE2BEE858012AA1B9B370B5EA38118034FB5BC9A" +
        "A3F72EAF7ECCF6454B0AEE05C123E1AE339122B9EFB384F91A1C747C9CE405C8" +
        "356FAE618BEE872218475CA40494777718DFEFCDB46E212581A28A9ABEF88545" +
        "A0A7F4FB693101C60398CC145BED5DAB908267649808FAC2B383A38C8AB68242" +
        "BC29B131C4B4C28B7B010D54368BE5FE3D171B58920415FB112CCC79AEF366AE" +
        "5FFABD1AD2EC2D18BCF6CD2A4F41A85F90BAA1541929882D7598610E7B505B4E" +
        "77DC69219FF129AA58DCF8BA71B82ECB0750F25480D779A9D57C6DC4383DB489" +
        "FFC202114B600953BFC61378661DD553A9C77E73465F8D6BC61DD9B13C66B9B7" +
        "AAAF2C070E0C754707EF93A1DB60F3F9378656BE3013CFF4287481F6C493B306" +
        "556EC56DEE23DBDF5E23761244E4C3B7FB050BE3FD58AE2C132D5BE9F77325C1" +
        "869E4996EC5DB3F29A82F481ECE26FB1F4941C7B821C19FC9F4F74D1340CC041" +
        "B4E914642FB671C4DEFD915FD6E7D64334E02D0B42ECB85BD00B0069D674CBE6" +
        "AF3EBCC835B58CF33CE33F0D4AE8B746B990D97B58D7B5FCDD4A7335E8DDFB52" +
        "C70AFFF0C5CB4FA7053643D7FEF5CD263AE0BC256A2FE9E174D824B59EDAA698" +
        "BA2F4687E20CD38DA9EB0F186FA560CF3B68EC10A99FEC35F5FD687FF9FF1F79" +
        "DA2D5EB98F871BB11583990D5609E227A6DB4A699668F7F4794E3E7806A57978" +
        "DA2AD6FE1D6633ED4D6FD2DD1DA596BEE0EE643D20F7CD4A491D4CE10F6CAC43" +
        "AD46142797BF514CA9B0B3ED42CA6B12594D7BB618080900640FAB4FBC9F23EC" +
        "A1D2ECA45E0830AE8AFAFF692E0AC1397EEB3663E6304DD0DBAA22D4559345EA" +
        "76E7AEBCF5F56F529BCB4405EDE0142D8CBC3C3EA80AEB21F82C3666ABBA6CCC");

    private static final byte[] NIST_MLDSA87_FAIL_MSG = hex(
        "FD7A5BEC8BA3C3236AB776CF96BF64761D50A924F254375FBA00DA21EB7DD41F" +
        "C9AD1022CE6C35392A78EFC75D9C93CC08156263966B1B0D9C2A58C1DCEE9C5A" +
        "7ED46B298B6D8B80B3408F0E61D38913C2B60F87D753F334D69C8F5AECE979BA" +
        "86519BE7AF5583189C39B68A9FF2A92C8445AB56A823AB1ABC1A7E0F8528B96A" +
        "CB2F000BFF0D586D0DB7AB826DAF4F55AB1482A65444E9875C9BF507C290CF47" +
        "BC243AEF47554007ECFF9A91AA08B5B12241A05570758E051E48604014446DA7" +
        "48558A236071974B69F21CE34907CFBDDB094C2F38189D47479B60DFA0AAF908" +
        "E2E49879C591BB6E71D86D0DBCD6A07E2701EA0E4C4F8CE1CF50B41CE00824D7" +
        "00D9B9EA85F6BFC618997FC5F96C97FCB740E8C481F9E19CCF1D708558D308F1" +
        "9E667A54D357BF0FC66C082EEC5CFE3FD50CEFE8FAC23D7A2D8C424406853321" +
        "C76C21F8AC6D09A629E286BF740F291162760A8BF4CF5EBF5E26C2DCFEE8F24D" +
        "2C7C3D166E61B5E097E4B858819CA0F068412DF8D25F9D04828F59624EA08BE1" +
        "3B085C15FF92528F6FDCEA92D4E14FB888107D8AC92E5588913DA8C1F125BD82" +
        "778C39D1552901E5CBF72628E72F412B504A870B23026E75DAB13E01781E8695" +
        "05D2C2160CA0030F1CA08D38A33039D03E21DF77BAC25439A3467258391E8658" +
        "2FCA582000804D30C242CD783C11BB4C09771FFF76B65F5DF3C2965AD0C552EA" +
        "19CA4A5F7C43485E20562E1A1F48FC3AA0421D8B089F227929D46348DE6D86F0" +
        "5DEDC0394C5C8F2703279F992F8932570A75C757B6AFD8D90396BB0B6A4B86BF" +
        "EF5DA4529F07AF689AD43AE079260FE5E0CE93642D764E01405F41FCC529FB3D" +
        "0818BF3F6E13259EDAF5CD04B018394492813565898ED8AF9D1265C4A68A5D67" +
        "D8EBF8B36BA26616341DF30526EB13A524E7862391D42801CB2BE2D52959BBCD" +
        "FBF4F0C4BE5D2C18A4C63AB28FA3DA7FE78F1E6157585BC9AFB71097BB0ADD6E" +
        "CF83A9016BFB354349DD7CED9DD8B8DCC29DDF06C88B50A4F55CBFF3A175F620" +
        "B4D78A48809D1CC795E7ECA8FD51256FAAB20CB12A91465ACB2A9E88C3CA2A36" +
        "86793EC347628ECE4F0A980EE51CCE93E483BECBAB7C99F29AD2AB0F6C6CD12E" +
        "F5D2C4CCE50AF2687DB82EC484E02C77390AF494F81F084A4623CD39CB0C877E" +
        "CE1CEF1193089ED917B6EBB4C7E016680C761BF3EAA04AE4E358D583E40A1F68" +
        "6CF6A59A4838ED55FEDF354304ECA21BA7B144EA74F37474B6384A815D9CB94D" +
        "FAEFA06AFCBD19506190E75E14011C2ED932209D5719580C60A15862894FE5E5" +
        "3E4A44211A7C4EC74E9B04CC00D5150F9AD3D04282F7973E10BAE64A8568EB66" +
        "5DE8342A10B701AA75A394EE5868C747EBDDCB75B542CE727455D91C26C36BE3" +
        "8A5C35C81C00EC66488685516A0B93EAD60D0EF04B75C392B0502BFD1D4A31FA" +
        "F4FEFAEC529E54F9CE17EA78D57FC39F52F76657BE5FE28449886671FABB7D33" +
        "FF5BD02DABE6E13D65CC502EFA0C1B17C225B89B7D3056C42CA5D234DBBAC61F" +
        "45E584F09686C40A92E48814240E2A1BBC422BC0DAC219844C66B36FF07321ED" +
        "E1753C2428D759EEE6925D96B4A22BE015C3A7FCA7A794810AADC8F074AB9DF0" +
        "7B3CB64FEE3FDF643ED3686E4423311556281B8E639C2A98C52B64073C98C24E" +
        "01A1BAE6B7820830510B98D23F59AD6FB4058836F99E9135226DD2F770316FD7" +
        "A6A7C7F192E61ADF5F142CF5D14D069723D438AB6F68F6C8934DCCD16168457E" +
        "006A1F45F0D043EDB0F79FEF672583EF3F3360B5AF7041C5EDB8C2D6D4CBD6FE" +
        "04941A543C45CB838AE81CB02EE3815523A09C37664A121BBF5C8ABB54CED6CD" +
        "A8CDD3E97AA68FDB6BC7FFC28B0022787416A5AA987ECCD77D95FBCC21364A8A" +
        "ABA8B1505BF66CC94B34B633228FB0BB28ACF29E598275591E2FDFE770DB1021" +
        "FA21523CBC4A2466B5FE2D0ED8EA075C7C6CA7315745ACFEE46D9A7F5D21C878" +
        "428E1E29EC2D27CFDD4AE305805AC7B9AF3C08385353B0184B3E69E31901B199" +
        "04AE68A0A3B69985A4FB85085DF73D4E51B4810EBBCC27AB2EC2DF85B2CCCA62" +
        "5241FDBEA9196D304BC3047BFEDEDA2AC41BAFE46403DA016C11B911E7E449A9" +
        "7684E73821016A0199E61295CE93BDE8D3C669FB7540E6397A1FBF131B07175D" +
        "59D30EBCC7AEF02E1725254B3D55202B25D419FE41A27C8440AEE712308127BF" +
        "314FEBEFBFE2BCEDC4AB9EF2C527E76131EF9542C649AC45C2CD9E849CB5DAB5" +
        "18EB7224B7521BBA16DF47EEE73F52DF3283C70A363FAAA473A241DA9CD3CD0C" +
        "998532180619E5F9F9CB8170ED20E703A83B5769C2733A4A03793E9C4B158598" +
        "50350ECF43FB1B89ED897D7189AD1DB23F8CF0226B1D42A855751321A3D28277" +
        "3D0B1E0BD22690985EC387041C90BF169AE26FCD8CC2A36E41E1F5D393794D74" +
        "8E9A0149C3B894AE5A7CE50F8C83894B48A69AF14610113E54E2C367D5EA1544" +
        "D31388A5DB07BD35D3B6DE9E01F8510548CBBDA9BD20881640DC5181ED686439" +
        "1BE707DE88D11606505811CE27521BA563B1CF3A23312BDAF11177F10D0D8EE5" +
        "8506F01D9DB4B61705E1DAE9FB7927B8CE5F8E7B4DEA3F0C04A5923FE91BE72A" +
        "420D484E0AE904F22D1C24633E307F8450610DF538D0F2CD55FB06A2A7E33429" +
        "4518197BFE7719DB54C74B40B794070B473A221D452D435B8847C623C459B978" +
        "5DDCF8453BC7BF727E52237C2C7B151B1ECBFB605C91063D5E5542BDEA982D77" +
        "4378BBCDB026D7429A7EAF4B6AA2B1CB05B0BBF2D1FCF118A9A86B120A59F12E" +
        "9E8E1EDD461BCBDABECC5D4DA9AFE6CA684D17DBC6CC06615501E87B00950FF7" +
        "CC59FB516C19181D8B82BED75E461992246BA81A51BD8799DF8BF65E38575C7D" +
        "A4BB93C3410A36116768994D65E5ED4C6020D35C13B4B35F1C3D5CA22A7F8525" +
        "CF24BC4B927AB2F8C8BCCE041DA4D63B2E21DEBD7C2BA16006263DF403FECD35" +
        "6CB6F13B201B6D3EDE5088B515BA855A315FA1F7B5F2DBC160DD66FFB8914850" +
        "71E3BEA3FE079ACF1893B058ED013E6D25F6854C4E3E192B59F043BBEA86D18F" +
        "A875B65327AB51B7ABEF35CE1E34B2A39851858A20F1C52837E64E50BF46BF4E" +
        "62CE8CA0A5D7BEAB80A63D14665011A8410301A9D4335D35155C2AE656D15DE9" +
        "049C1F2FDCF3A69AFA5ABD7E27DB8461CCA5211D2FC3EA81FE69934C71B9053E" +
        "2465F0EAB2DD4D6220316DBFB55B9FA9A89BA05C10814EF486D10D2A56C6CB68" +
        "1973D9C7852DFD6C02329F7EB871520B94EA133C221EB1FE2C7618AF4A4F94BF" +
        "AF253007673494BBD8C27BC1807B6A9F80577AEB867A8E497A41FB1AE9D52E7D" +
        "F31FF92310D3630FD699B7B0682C3F2790018579CD88DEA84941DBCA436A548F" +
        "72E4EDBFA2FBA006D047746422D78B560B3E843E65A161E1DF9C1EB1D933564A" +
        "FDDA88F3824B66143FEB1A2E6ABD4468F3B5FE9AB45269FAD8700A090FE0F1EB" +
        "76DE21673F7E0B0AD83890CF9C3951EAA52E92CB1FCD281F41C8728D553F4DD0" +
        "BAB668BCA7E99685801D68DC72ABC24AFD60485CB0ABA1DF9AC951D6038B2741" +
        "15027A5F834F4AED8A4277C0ACC2E8929E75197C8062D23415EC0BF1D720C7F7" +
        "DE159F5A3E61BF17DDC8BF83E0B7CBA6BB28F7CB830556B45DB8C0436727B649" +
        "C657777868A4BB95409C82D61630ECD53073198D6A8D4E558D07FEF9F600B45F" +
        "9FD6B4CC8CFB19D4B56159D25BE3BC5CB1B6441B8655207A240474817871F799" +
        "6EDEBAD38D9E8C758EA0E28A08725A0289776AED9A223D59A9416B1971A77498" +
        "EC6144B6E545D31CA4DF3EC4AEC9BB8F1DE529EC09E4FBB3949F1860BA3154CC" +
        "649054C30278E7B36373D195D6D1F9C1A2254AC574D8294124472ECDF8379076" +
        "751596A78A5DB568AA9EC532251FFBC26D11984AA7C9E1FB38DF20B7E0925129" +
        "A6F7B5D19466D23A70F28E56D3612045FE0F604A60366D2AE62B0E5D97255A39" +
        "F499944565F9D2CD5BF98114F4C826463CB8DD3BCC46C23B3C1ACB66342E34F1" +
        "07831FFAA85DFEDB4B2C902372A945B292428BCC1761BD14933CA263D51DFAEB" +
        "1DF3BE397BB889C884F49D895A5578DF7EA1842F1951E4C5BC9AB2312682D0E8" +
        "B6EB79EA89C3531671A51DFC2779AF456EC8E6A505B1D696DD47FDCECEFA6EA2" +
        "F0C403099BE6A7644789E0F0E7C20DBA69802C9425C0ACBAF515D030289AA052" +
        "9605BE353418C69A5D0B66B26BCBABAE7825696E4C04A7AEF938226180046FAD" +
        "3B4BBC937086E0D2EF7898CC6FA6F2177651359748DB9D52982FBC14EAB513F6" +
        "D8D6585DE322FFAEBDB14AEA5640DEB54C0D1794FB478494A99FB570359D8439" +
        "63EF0C4D5C3F248DE530DFCC7046F24E9FF1B26FEE76E6E523B59C08B0E5DF9D" +
        "7EBB31498E7DA7FF7C050AE12CA74A45A86556143A02F494399BCB033EA193F0" +
        "110C74BA8C9AB4F606ED71E30B1F80EFB9DBA943D6F1A9F275BEE34273ADECEE" +
        "E91600AD97032051A92D06E4F46A521DDE3FB12B8F7C0712BA0BBDADEC5D230C" +
        "D2664D5E3C5E2F6A0638C0DE0364FE336BD0A097B9BF5436743C0CC66D268A69" +
        "0B0949F39EBEED7ED66BEAE3B37C4FC6D22BD476C72E151B59EB1C2ADD05D6F0" +
        "1C735A522BD05F404767C5CFDAAE229167EACC4317A7DD655C74C3FDFE34E59C" +
        "3BC491D60DB6B19E6FEB1EA493728F1DE91B5EC3A111B5AE496808DC6FCF2B65" +
        "0B59426ACB0CADC5AD6E55CC5627CD645032CD2A99F1F57D2E5DE2BB7B5E0CC5" +
        "B874CB61D7E050B746F8B5978EE30B2C23843A7B94E4D9D7BA194A1BC3F3BE62" +
        "05E3B06153F1E98BAE620E73C9AF967978A6AE3AC112A968D61F52C06BFE1955" +
        "6C7E47255C84D3D2BFFB8D3D4CAFF70DD9B51ADD482AE04C090DE627C3A8863C" +
        "A05B23C0BD702E9284F765A15EB275BC471669F23BB9B08F3E04958B1657C924" +
        "9DECF0C26C3E2343A75597F9BA1F519E98FD7F8DCD2429901D8FFFE1B3D6E81B" +
        "F01FC1AF500EB9C6A436166449CD1E3DE54962FF73BA445F9C40D02504C87ABE" +
        "BAE1C6D95D36E8FBFCF2481183C5D1EDB504A92E95A2FCB7F91FE63809B5B9EC" +
        "489A2A1BBBD4418E77F8A16F723D7E8379DADBBEB4C359E4FC82AD9FC560F39D" +
        "62BA4F02484BC890C25DF1EF87F83AA6BEAB99FD531BA6989D7366846404EC69" +
        "E72868ACE43D2E12D82FD95B5BF658620712A3B1C9DBC6CA66333F775EA0BF9B" +
        "B94CE6DF5A41B9625C62D919E60DCBDCEBC425249FA5B6CE08C3ED9D9F8B75B1" +
        "48BF6927D343262C37435680AACE8E54D1DE03D352085B2274B923816DF0A5B3" +
        "E283E874629DBAEE97772DFAC72A872C445B8E443F58353034CBC48D32BEA364" +
        "3E1EAA31FAD2AF5F23422C87398FED3847563F1155E3D18DB5E24711FDDE31C4" +
        "FF668AB563CF82846CE32811E6EA137BDDC16B6382A3CBC8D30E017D571B434C" +
        "5312724C0BCAFAB2BAC2B421ACA59CB65F9E2D402A84D672B395805E823C4620" +
        "04D5B782A1731A0A0195E858157F5E546C83B99E3C47210A9414C025D5FC48A2" +
        "1ACAA00AFA0839193C69884B8F6A8673BA555ACADF61EAA5E0B18BDB8C56748A" +
        "E178C39CF319AAC74D99FF27ED01BC20EF4C7C49862A1BDE669424A4CF87B23C" +
        "90754D4B8A76C0379FE0F5FB3F513904565B623F9305FF2EC44E12B45049A743" +
        "943F782606127B528B0F4E8559DF2C794874ED77CA477B099C535E06C84C46EE" +
        "664EDA6CCA817843D32D860E0E9B822254DB0097370E916FAB43A87F564E7F11" +
        "1E5D21DB028155480B25865CB6274C45D2B455485D644B8829DDEE1FCA846959" +
        "893C355BE054D7A9245DFB8297BB4C99627303BFA8094E53B8022FD92B79A607" +
        "A81D1702C0AFB8D674FD52ABB8038B59B71999708C1177A13FF60A992A4BA776" +
        "09B486221504B3FCE38FD11FAB8D4AC39B5A25D2F0B0BB2E402C0774AB9C6645" +
        "1DFD3902C627B4DCEC89204740B7CE466BB6359090C47443B74D49C9E09F8604" +
        "D711D779D3B579D1EBB69765F3727C89F6E71432A03D56F4770DB840F89F9283" +
        "EF13BABC41C42E7FE8D5CEE7B9EB506F8D41697323751892CE183D013462A6B9" +
        "9D505143E20ACB5F5A37A7B8D0250DB50FEDA29F5930D440579DC70C2388B690" +
        "8D9E0CC6A15F5D30E0C3A3F7B56F2F9524618AEBF23458AA17F2A33F3AAC22FE" +
        "2F5D27FFBB32169AD895D3B2DAEB32FADD02B84687E6EDB59EC7F8B7F936C5B4" +
        "757EE3E7690C97DDA712D1E0E9F67210A99C750061977C1345910C520FBEACAA" +
        "75BDA94DFBDC96520219DE04F93246AA1A0875A6E03B721ECBDFC3005F9AF785" +
        "16CB1330A18D181F42563CD3B648F309916CED0743C37689EE4ADA14FBD9A93F" +
        "ED944CEC3CD7170810B96956C56069A6F4BFD909DAE51A63B84F08B99529D9AB" +
        "AD01331FEEE7C96B75C8EC5E262ED8F603703DD585564120B43BD405438CD0FD" +
        "178F859E566D1632955F601C05CE9E8C544B466626F13B32A08A8D05195ECAD5" +
        "E4F22CC5BA2D4149D664C6C089E1AA4140ED630D62B4EF44543FCB98B7ED965C" +
        "1FE9FDB010DF79B859A81A16358F726B2244F2AFBAE9BFE1A33CA434E59BF2F0" +
        "7AFC4FFB4DCD86339D1DF721969381F973B133A9DD10586FE54B7E961317D550" +
        "CAB0A9B789E51D56EED0C01259A42D21D3B84BBBECBDA124B3D9E16A2474035E" +
        "3050C6C3B554B1BE6C1F677F350C48C6B5A20A167506A191745F0B3BA4897655" +
        "4FF61FA16BE3C4DDCFC0C18D4E1583BF");

    private static final byte[] NIST_MLDSA87_FAIL_SIG = hex(
        "BE3C501024B2D5FC5064DF31A9A325038DEC3AEB98D5369A3B0A64E68A674015" +
        "AFEA24152F632C4A7EB9ED305BFE7101EAD2DB77C565079768CA6B8CE87C011C" +
        "2714EAA896E3296C4A323F9CA290120630B5A93B1113BAB635A3801DCB771623" +
        "82F0A041F21B1EA3A837FA5B0F3D0F5831059EEDF9EF7D0913ABFCA777C49FCF" +
        "90503230E82A56E1A3A60335BF5C79DC9181CC3A4756D53E47F746F9DCDF6F36" +
        "8A9A39230EAA7A24D76D1DA19DB9AFD39B65C9EEF65DE818CC285C756DBE16A4" +
        "F1BD9D84AD8C049100A023BFDC6AE790B000D390E746C7896A539FF6867C5EE5" +
        "FDE1C3041E94B6D79130F056B4D1EA4D6C1C82A381C700B5338804389FF18783" +
        "36920F47AC141B7A225CC823BA93193FABB2D613B3BD7CF952CF7ECBFE4678B6" +
        "BA85D09A63731FDA4B1ED2CC6AE2ACDAC1E1C44105504B2BA0D2947C62C79DFC" +
        "A06F480D9DF01DF68BF4A0BEB216EB8957753C1B56BE93F39ED17F57ECA0A785" +
        "E91C866DF0B4C5D4A72E32CCFBA36D5C61AF885A837CFF8AAFF739A1AF2A688A" +
        "9A59D09C1D6BEC0A963C44D33630B47AD30C2CD74EE6D1250322E8046B5EA23A" +
        "8267FCB5E5A78AD0A944010EA5FB6E65243C6B1536D4653C2752E70D528EC610" +
        "3BBABEB235F0C61C5B6CAE8ED7B455D54D966B92DE2BC41940999D246B956967" +
        "B199C56DBA6C4C668A96BBA72A5D1433116AF54014444F74448BDF7F685593AA" +
        "AF64365493575279345D8E02A15B1E463EFF19A4F1411FF1CD222C2CF4894930" +
        "060F79DBFB4C19625A72A402D8DF07B5D39E7AB10C3D851FBD2E804A45D3363E" +
        "774C6946044C5EBF2000B22872A00ED12A547B79AC6911886D4B5913364B56BD" +
        "BDF69C6AE224F72568A4A587FC41E599803D52AF57BF2A4C253E38D3AB45382A" +
        "F853B7AA41BA6C60942F0C2C6DAA87FD58D8D7B2FBF1E9EB7F00D3FBC1C0DC0C" +
        "6FA7179CC5F2A2DBFCACB0DEE6EA100B757CFA43F3B6A5E9C6198272ECA11E08" +
        "4AFBAFAD95765D773A5ED3E4A979EB9679E18BA79EA405423E5A3B873AB22FA3" +
        "547B209959840DC4C73B130225CC6D7439E8125C9818AFF5E61448ACEA3B3678" +
        "678B2C40E9D36B4FBA3767E6FF2E2AF79D2F5DD907B20B763895E4170962D01E" +
        "9D09074650CC343B66BD5667EC8D24F4948033534B10DD4E6B299C3E38B0E53D" +
        "0C71B18763F9B31808EE4367D447CC9B9B5FC4CD01A392C5E1A1CE030048DFAA" +
        "6781D62C0F5DD26CE05F9F6E18BE8C3707F3ABCFF7563591ECD06103A66DB6E2" +
        "C9E627E57F2073BE9F9D7339B57E0434E2BFFC4DC6B069942FC2FD01F189334F" +
        "B095EA791041895BE3C8CA66E4E2F1BFB32E51790264845AFD965E2F45673F5A" +
        "1F515B071131DECE3F730408FA34B0F83B16A3C93CA42503657E7680D12AC137" +
        "46249FC6BBA56A7F0ECECF34C61E95741F7A9238BF493489BF65B1A7A91E5525" +
        "CFC3F207223687A654B17EB6862B35A2E3E299750C7D087D95DE8C28DB9BC860" +
        "BEFCCE4F4BE63A8FDF0EDE061B83E3355D4BF455B836D82404513789E613A736" +
        "B100851284429375D5519A07C9BAD3219E92E6F6BF45AD240750D8D54C29A426" +
        "FB1E3082C481E25AED0F8DDDEFE70C93E0DDC4D2F8BB91FF69F8F697F07CD72E" +
        "C949DD6B3B554156F818816C6E402A030CE7E7C26B7BFC1F17F3BE06D9654B09" +
        "BBD62C82F9607B1B9337DFB9B30D5004F141CBCD47A8C8DA6FB86D94053F8FFE" +
        "50800EAAD8E8FD6AC2D7E2A86758CFEE848961B8701FE6C7A1C87CAF375894C0" +
        "5F38D063F0ED5A173FB9C734233F3A0F32AB548F6F5A5AF552B84C0A2F919ABE" +
        "FCA76B8F7B2373C7D26A479C9FAF2933F34666BAAD45D7411FD9CF328AD69E32" +
        "59F8C832DC76547E07A4414A5F1F18594F13C70AA94E0D3D2749D7A3ECA9CCD8" +
        "C588F60465A7A5E1AEA8EADEDAD511A3BF6577FA7D851FE731F2385FCC43A008" +
        "E2093BF8854323E41B429BD65FA114C93817C169EA9BB73B53421C14DBF9AEFB" +
        "97A995FCCA3E28DB5341BB6721A891744163858A07942184C5200974D1A23730" +
        "1ADC98FD5BF9B88D698645824E32E3ECE0CFAD0CCB5FDF973269CDA1FFBDE4A3" +
        "4ABAB1B4ECADD98E28F288B12F5AA2AB7FD4954E111DCB5D9F4C19600BD686ED" +
        "1E44F5FBCAA7BD3A35A45414708D560C95897D18905E2E0C94CA5F7A7ECDFD7D" +
        "BDDDF4D6BDFC8EA82867CCF0BA72F311F72868C0E4E72F3AD52051E377D2388A" +
        "F322CF3C7C755D40CA111EEC6CA985FFA78FB1892EA51B15026A17300FE17419" +
        "048CAFEBD552E9F3576B00FF8A7AB8C276AD9B353264B080CA6705CE2C020A2C" +
        "B78C246F803CFC1F73DFC4B32FC864E3CD1AB618109AED9A22AA7DF21610D8FD" +
        "8E1D71D5EF8A77EDC4BE81004A8D7A1572E76A72B5E79CF8B51EDC1F8FC580FD" +
        "0CD3BECEEEA0C3C8814210C69C184AC89F170BB17A3FD0317D19AC2083D775D2" +
        "BBBC05543CAA5F3FC0728118D374A36F19F329F35E42DF68167B37309F820572" +
        "A2887FD90E9F448B23338FD14C8E317792BB6670828AC20C05A0A9281139E679" +
        "B7C1C0A31D3EA5A2392DD77547526276F4AA99FE95A703C287A825AAF86FDD6C" +
        "1C3D8A972A3E07DBF1B75A9D502764BB6A801DD49E6A5E3C08780E4388F65578" +
        "6A5CB297D49AD6FEE1B9DA64046348BA11F74F10D38A7D10BBC5FB1C1AF24AD4" +
        "9C2FBB722D23EBD890F113BA635E3CC458D0E56508688D994EAFCE958176AC44" +
        "DC8E7C2B984F17494C1A378E5C8B8D009F7E5740D735992ACE67B9075B9FA7A0" +
        "68D18A0F4DBF5A5E7B581288B56871669988B9B3B69F5A31772A08487E5B332A" +
        "FF805FAA2C8DFA622A157714558BE41047D613B383121D96AC4EFD6D1DCEC044" +
        "AE4004EB28DB2A81BC38C5BF6A919F04C1DBDB532B79F3929DB70236DD09AEAC" +
        "0F15DDB5619DDE63768028E45B26B9EDFB5FE6C9019B61DA66F79DF2C206AD91" +
        "CCBA38EEB117BBF97C875A9385675F36AA50360C25ECC9FCB5FAB9BBE487564F" +
        "111D50E34C4C9BFDA5377776EFEFA399467A19EF138F8BE1DA5609A117ECC2CE" +
        "A32F026FAE306A19EC556179E130084A1B691D5C201161194A678497A527E3F9" +
        "4532836C019D4BF4646EAC203B7E3FF951A5B0ED6A9A0B975318D3AA10A64CAD" +
        "7D5A57E24C572CD48CF1CCD710306D63888A409D573ADDADCE5EBB463DAE809B" +
        "AD78B1B9392E8C208568EB77E06E62DA6427FA5AE64359A1CF2583446BD946C6" +
        "5B198DBBB4390EEEA081272D73FF9523D3AED8D5A9C36CEEC4D6863BF89BE168" +
        "23FC008681E31361F56B9ED0FC530DDD9AD2A022ABB6C5F7B6EFDA4FFC9ABA72" +
        "B2CA0C2E45DA892DE58EB66F00211F93FDC352EA77DC4CAC94240FB419C78E4B" +
        "715E1C147FCF944B6C50FE8A3DA6319AD8DB9CE4F520DCA42791B1019328B373" +
        "0C30441092B20945664854CAA9B49C3891D1C225EA040AB4E13920C5EE5FE4C3" +
        "E42F0A3E192A7C7B151C4D89A82F6E33BAA6EF03688C50B2B31D40CB04D2C9EE" +
        "8FC9F820DD7DF44810081AD0F78F54FD1A0DF6901B6D70889198AF5327F8286A" +
        "34F65C28EB00E72151B2CB3A634EEE9FE687C63B69D39845C42ED078CD601A40" +
        "ADFB9DE9FF68F6F9B95B684C1B617006F1399AFFDF305E51BA24770345F2A292" +
        "7F9649F2B1F4D12862EBEA2FCAFD2D1ED15BB03CDA3A0FEE73CCC9D4CC6141FA" +
        "797E9292EA6A1C25714E2F4480B335393730F2C10CD1FB935EC073C8815F2C16" +
        "818CA5498DA4C71E2F979AE86F00F10E603A5AC814D7305904D6026F5FD08EAD" +
        "DF81D89BA0FCF5236046928DB224316E2C67ECF90E9E29C3EC71B5BC287340C9" +
        "7A29A9F74335410EF962E5660A2A5EEAC4781291FE984323C8B0BB56D34ABCB8" +
        "BC085A06A8D9FD316BB4261BCB091C114C6DE5B37F837C0EAAE6BDCC3B642DD6" +
        "3629EB32C28D60D61EC8D01EC8E08A4CF4C257E35DC90533409B142B651D248F" +
        "58668B7E022E0D7BB85A371F13CA3AA2330D0F0538238A756B579E508C6AB034" +
        "64D6A7D3EAC55531CBB4D528DD94A339505147E5E01F28E2549A2D710580AD1D" +
        "D2ED69B180C9A400D578A79E4464587A020CD7BDC6E191C122C82AF09C0EA5B3" +
        "B252D2376DFE6DAE28B1A7AECA878F241830FDD143F30DBF55C1E7358950A0DD" +
        "D3DCDEBB9E213F9B84FCA740601192F1AA8A83C0BCDFDB4CD0E251F24224A453" +
        "D297D89011CEA598F2D5882850DB51E6BF1E5AD8AB3A7DAC28427637645FF3C2" +
        "A30EE20B6C2F39A56D2839DA9667CD028F254C1478B416C57B531CD3E151896C" +
        "086203ABBB5FAFD72318FA4D4AADDF3F9B1B6A47B845E31FC4F304B33DE5879A" +
        "2943A1F9FCB0BAC2FCF6313680B0D6F86EF4445E06AA6FE90E7C90D29AA6F577" +
        "5A854BA5734B8EFFA2210CD405D4C333A9DADC4A8C59D6F8BF38BE5AEA64AC75" +
        "B9B8AE41D6DA0AE63444707925983E1252392B61A3BED6D599E289A51373F1D3" +
        "36EA0C092C93D00DFF9AEE47FE27C7C242FBCDC687A73319E75002973BECD7AF" +
        "4D6F5E37E7902EBA9926BCA89549DE4FA19D8B25A91A1AE9E53A79C8AD515312" +
        "A87A88355D64BA70959A64B0A6647E8DC73AA6C3805060525FADCD9F285A538E" +
        "FF3888224DFD9042EDB48AD2F9E81C9C96A8225CC6FC6CE5CC6588B052E48630" +
        "459733B066BBA7C9750E2E7FCC90360C9E626503C0208F431D30782EE59E7EBA" +
        "C8E89577ECCE4BC59782F53A3B9DAD308F5AD1532FCC7D868CB65EF5DA5D441A" +
        "1F151E084CBBF819EB5D33DFB58A585C41F0860B0FA73E2C3CEA4FCEA5328A2A" +
        "6AECC73A55A023AEBEFDBA73FDEDB3D6AEEAF94F0E43CCB1A7C9B7851D80C7AB" +
        "B9CBC2FFED0932B791AD11EA7FF7597C5F21868FB747760BD4C1D466E3FC89D4" +
        "72CF4D3131861D65390EFFDA83112E903E79737BA313C97EB70A70C2B8E43DF8" +
        "A5F9B06EA6C4E992482CFA366907EFDC3F95E385312E1994BAC32D054D28113A" +
        "6291FF5A796C92E2178325B0284D090E5A00250B4053D74A0376860251676044" +
        "11381672AF5C0765D14DC86262E358435FB2BD9C108C19306D9E1FA128EBD990" +
        "067E3654508ABABF8A63FE0E44F9F0CEF861F18F38F256BDD383F71365612DAA" +
        "4D9B3213236413F88075EFA61069975EE4E2FD598C7A429975317ED3B7D16014" +
        "A4762EEF82BCE258CCCF7F4946F11F18743B0F8F4DDF9F2BB9EC01DE8E392055" +
        "B0408A084F6F93C77F7FAC31CA4D110CDF6ED7A3971BBA0571472D7D0FEF6613" +
        "01708DA2D99858B4A60C170EED2EC997116EE87F5B0FE7FA2CEF48273FC310EE" +
        "5B4DDEC70A02F10FF96436760CBAE2D72EE0D234B4AF8F3DE6C8926FB7333723" +
        "46100A8D3B8AB7953F6A5C3FC8C71FD53FBEC62E8BF343770A3444692D207D05" +
        "CCABF1F8F20D08F8183B081E358D1A3F9313F8015FE928F0F3AA13E0F2392141" +
        "BEDF470EC145E9AD5E5A123FAE0F3CBBE79956716AE1C10383F1C9A7A23BF3A0" +
        "DF914E6D0F2336ED99D9B85BBD7449F28B26FB47C40F6100C339DCFDCA7C9245" +
        "8ED84392BE70862F2D9D83B9D4C7824D031EF652343E269316E83E974A5367F4" +
        "3D498BDF3487FC82233BD4C2DD4D04477A4F2E1710D6DC6B59686DA1498CC040" +
        "194D0693F7DD627B4B209E3F6519A5CFBC9A2132EB028743E5F62665ED8B2FBF" +
        "96ECF8DEB94B6459E1A5788C64213CE98668F85E4D5ECF981F7300CADE46FFE4" +
        "4AFBA7367B93C126AEA00B209A4AC9866E65365BFACBADC09BC2C308A7B345A6" +
        "6ABB24B1CA60384F491736B38C83F7BCC13C036984B88606453A38F68927823E" +
        "026FCC52179BC85DCD41FA389A5251F586B6D629B2082C4E82B0284FDB619BFF" +
        "8373A4B4CB3BB77F8FE693E49CA8042ABED8E693EA4836ED24B31244EC3F9452" +
        "FDAB6559A5CE45655CC59C78A7BBC439F0284E913B9B336B40B06EE016354AD6" +
        "FCF7D5278EC8B04B3C1D7ED36FC7F2E82DA0E55951890F82CB218142FDFA3A30" +
        "CB02A21B9749FE8D5D058EEA2B096EFD0949E69F4C93C95BCE926B5F8D123B68" +
        "63790A787ED6ADD4EF36E17CF2842E372ABFB487BDB7F568C5CE6037D7BAEB44" +
        "1D76660B564F944C0F350EF89C1626CD7F30A9305F6CC9DCB7A3B6EF96D0384A" +
        "E03A38556657B046F95BB501691B754F1F8E7ECBCB29D73B637C253B2B930BD9" +
        "7913E0E2BF7F481D725945DD402D6FA43054C41A25B33AF0C2A4BDF8CB67B9B5" +
        "C2A096333D954DDCD6FB65F6199D9A2D09A6CDD639026AC1C535FEBA34D0A59A" +
        "1D5BEB5C49924FB6DF51B7FF0834ECB853986F207F376EE04456F7E63164A0F1" +
        "B9E96C44B1296871930A34CD4FE70A050492843A12979BE6D7F097D5C00F5288" +
        "AEB5671B5BF51C657FB96E7137E779160AE37253A2EE2805BBB8030C117462E8" +
        "1A2E958A49E29B03E7B0D4339F62F09F3D063B8152843460B2B944E9ED124BDB" +
        "B4FBEE9E79F92B62DBB5EBD6CAC83274DD5994D411D170789D25088646B824C5" +
        "1A3182BEC1D3FD33494C6C8295F11142595F707386900347607C96BECEE7ECED" +
        "1C26484A4C59909FC30B20365A68C3CBDEEAFA2045474B7077949DA6C4D20E5A" +
        "DE00000000000000000000070E162029333E40");

    private static final byte[] NIST_MLDSA87_FAIL_CTX = hex(
        "61F1F91DB513AB7DF62BFE24B42995C28E32C9552BBFE323EF4F1EAD511C6FC9" +
        "D3EA23B4EAF1F9A57F03BBBC68DAFD5E901949FAC3676785A6E30FAFB92A80B2" +
        "E767FEB28725DCD72C8CBD92448907FFFFD7D8D1CF5630D19CABDAC6C826323C" +
        "9600456FD9FD3669EB1850F339033080AAD7D6EB6717B22DD6D7AFBE8EC7EF7D" +
        "80F6967509B1D6D5C340E8828307A94B69688EB8A4B3332D754E21AFD3F9A9D4" +
        "9AD4FBE24F9AE8388F7A9F9A44277BF88782B7389B8A527CD9E50FF2EA665062" +
        "DA2DA9FFFF30CE21A12942F6300C1284410B15235C840144D4FB13");

    private static final int    NIST_MLDSA87_FAIL_LEVEL = MlDsa.ML_DSA_87;

    private static final boolean NIST_MLDSA87_FAIL_EXPECTED = false;

    @Test
    public void nistMlDsa44PassVector() {
        assumeEnabled();
        assertEquals(NIST_MLDSA44_PASS_EXPECTED,
            runVector(NIST_MLDSA44_PASS_LEVEL, NIST_MLDSA44_PASS_PK,
                NIST_MLDSA44_PASS_MSG, NIST_MLDSA44_PASS_SIG,
                NIST_MLDSA44_PASS_CTX));
    }

    @Test
    public void nistMlDsa44FailVector() {
        assumeEnabled();
        assertEquals(NIST_MLDSA44_FAIL_EXPECTED,
            runVector(NIST_MLDSA44_FAIL_LEVEL, NIST_MLDSA44_FAIL_PK,
                NIST_MLDSA44_FAIL_MSG, NIST_MLDSA44_FAIL_SIG,
                NIST_MLDSA44_FAIL_CTX));
    }

    @Test
    public void nistMlDsa65PassVector() {
        assumeEnabled();
        assertEquals(NIST_MLDSA65_PASS_EXPECTED,
            runVector(NIST_MLDSA65_PASS_LEVEL, NIST_MLDSA65_PASS_PK,
                NIST_MLDSA65_PASS_MSG, NIST_MLDSA65_PASS_SIG,
                NIST_MLDSA65_PASS_CTX));
    }

    @Test
    public void nistMlDsa65FailVector() {
        assumeEnabled();
        assertEquals(NIST_MLDSA65_FAIL_EXPECTED,
            runVector(NIST_MLDSA65_FAIL_LEVEL, NIST_MLDSA65_FAIL_PK,
                NIST_MLDSA65_FAIL_MSG, NIST_MLDSA65_FAIL_SIG,
                NIST_MLDSA65_FAIL_CTX));
    }

    @Test
    public void nistMlDsa87PassVector() {
        assumeEnabled();
        assertEquals(NIST_MLDSA87_PASS_EXPECTED,
            runVector(NIST_MLDSA87_PASS_LEVEL, NIST_MLDSA87_PASS_PK,
                NIST_MLDSA87_PASS_MSG, NIST_MLDSA87_PASS_SIG,
                NIST_MLDSA87_PASS_CTX));
    }

    @Test
    public void nistMlDsa87FailVector() {
        assumeEnabled();
        assertEquals(NIST_MLDSA87_FAIL_EXPECTED,
            runVector(NIST_MLDSA87_FAIL_LEVEL, NIST_MLDSA87_FAIL_PK,
                NIST_MLDSA87_FAIL_MSG, NIST_MLDSA87_FAIL_SIG,
                NIST_MLDSA87_FAIL_CTX));
    }
}
