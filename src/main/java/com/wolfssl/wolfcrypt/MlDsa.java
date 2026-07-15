/* MlDsa.java
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

package com.wolfssl.wolfcrypt;

/**
 * Wrapper for the native WolfCrypt ML-DSA (FIPS 204) implementation.
 *
 * <p>Mirrors the native wolfCrypt {@code wc_dilithium_*} API. Uses the
 * FIPS 204 sign/verify path ({@code wc_dilithium_sign_ctx_msg} /
 * {@code wc_dilithium_verify_ctx_msg}) and passes an empty context by default
 * to match JDK 24 (JEP 497) semantics.</p>
 *
 * <p>Level constants match native {@code WC_ML_DSA_44/65/87}.</p>
 */
public class MlDsa extends NativeStruct {

    /** ML-DSA-44 parameter set, NIST security category 2. */
    public static final int ML_DSA_44 = 2;

    /** ML-DSA-65 parameter set, NIST security category 3. */
    public static final int ML_DSA_65 = 3;

    /** ML-DSA-87 parameter set, NIST security category 5. */
    public static final int ML_DSA_87 = 5;

    /** FIPS 204 maximum context length, in bytes. */
    public static final int ML_DSA_MAX_CTX_LEN = 255;

    /** ML-DSA key generation seed (xi) length, in bytes (FIPS 204). */
    public static final int ML_DSA_SEED_LEN = 32;

    /** ML-DSA signing random seed (rnd) length, in bytes (FIPS 204). */
    public static final int ML_DSA_RND_LEN = 32;

    /** ML-DSA external mu length, in bytes (FIPS 204). */
    public static final int ML_DSA_MU_LEN = 64;

    /**
     * Get the standard algorithm name for an ML-DSA level.
     *
     * @param level ML-DSA level, one of ML_DSA_44/65/87
     *
     * @return standard algorithm name (e.g. "ML-DSA-44"), or null
     *         if level is unknown
     */
    public static String getParamSetName(int level) {

        switch (level) {
            case ML_DSA_44:
                return "ML-DSA-44";
            case ML_DSA_65:
                return "ML-DSA-65";
            case ML_DSA_87:
                return "ML-DSA-87";
            default:
                return null;
        }
    }

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state. */
    protected final Object stateLock = new Object();

    /* Used by no-arg constructor before a DER import auto detects the level */
    private static final int LEVEL_UNSET = 0;

    /** ML-DSA parameter level. Volatile so {@link #getLevel()} sees the
     * latest value after auto-detect refresh inside DER import paths. */
    private volatile int level;

    /**
     * Create a new ML-DSA object for the given parameter set.
     *
     * @param level one of {@link #ML_DSA_44}, {@link #ML_DSA_65},
     *              {@link #ML_DSA_87}.
     *
     * @throws WolfCryptException if ML-DSA is not compiled into native
     *         wolfCrypt or {@code level} is not a valid parameter set.
     */
    public MlDsa(int level) throws WolfCryptException {

        if (!FeatureDetect.MlDsaEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        if (level != ML_DSA_44 && level != ML_DSA_65 && level != ML_DSA_87) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }

        this.level = level;
        /* Native struct lazy init in checkStateAndInitialize() */
    }

    /**
     * Create a new ML-DSA object with parameter level deferred. The level is
     * auto-detected on first {@link #importPublicKeyDer(byte[])} or
     * {@link #importPrivateKeyDer(byte[])} call (post-PR-10310 native wolfSSL).
     *
     * <p>Cannot be used with {@link #makeKey(Rng)},
     * {@link #importPublicKey(byte[])}, or
     * {@link #importPrivateKey(byte[])}. Those paths require the level to be
     * set up front, since raw key bytes do not carry it.</p>
     *
     * @throws WolfCryptException if ML-DSA not compiled into native wolfCrypt.
     */
    public MlDsa() throws WolfCryptException {

        if (!FeatureDetect.MlDsaEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        this.level = LEVEL_UNSET;
        /* Native struct lazy init in checkStateAndInitialize(). Level is set
         * later by a DER import. */
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_dilithium_free();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Allocate native dilithium_key struct.
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_dilithium_init();
    private native void wc_dilithium_free();
    private native void wc_dilithium_set_level(int level);
    private native int  wc_dilithium_get_level();
    private native void wc_dilithium_make_key(Rng rng);
    private native byte[] wc_dilithium_sign_ctx_msg(byte[] ctx, byte[] msg,
        Rng rng);
    private native boolean wc_dilithium_verify_ctx_msg(byte[] sig, byte[] ctx,
        byte[] msg);
    private native byte[] wc_dilithium_export_public();
    private native byte[] wc_dilithium_export_private();
    private native void wc_dilithium_import_public(byte[] in);
    private native void wc_dilithium_import_private(byte[] in);
    private native byte[] wc_Dilithium_PublicKeyToDer(boolean withAlg);
    private native byte[] wc_Dilithium_KeyToDer();
    private native void wc_Dilithium_PublicKeyDecode(byte[] der);
    private native void wc_Dilithium_PrivateKeyDecode(byte[] der);
    private native int wc_dilithium_pub_size();
    private native int wc_dilithium_priv_size();
    private native int wc_dilithium_sig_size();
    private native void wc_dilithium_make_key_from_seed(byte[] seed);
    private native byte[] wc_dilithium_sign_ctx_hash(byte[] ctx, int hashAlg,
        byte[] hash, Rng rng);
    private native byte[] wc_dilithium_sign_ctx_msg_with_seed(byte[] ctx,
        byte[] msg, byte[] seed);
    private native byte[] wc_dilithium_sign_ctx_hash_with_seed(byte[] ctx,
        int hashAlg, byte[] hash, byte[] seed);
    private native boolean wc_dilithium_verify_ctx_hash(byte[] sig, byte[] ctx,
        int hashAlg, byte[] hash);
    private native byte[] wc_MlDsaKey_SignMuWithSeed(byte[] mu, byte[] seed);
    private native boolean wc_MlDsaKey_VerifyMu(byte[] sig, byte[] mu);
    private native void wc_dilithium_import_key(byte[] priv, byte[] pub);
    private native void wc_dilithium_check_key();
    private native byte[] wc_Dilithium_PrivateKeyToDer();

    /**
     * Allocate, initialize, and set parameter level. State advances
     * UNINITIALIZED to INITIALIZED on success.
     *
     * @throws IllegalStateException if releaseNativeStruct() has been called
     *         or initialization fails
     */
    private synchronized void checkStateAndInitialize()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.RELEASED) {
                throw new IllegalStateException("Object has been released");
            }

            if (state == WolfCryptState.UNINITIALIZED) {
                synchronized (pointerLock) {
                    initNativeStruct();
                    wc_dilithium_init();
                    /* Skip set_level when constructed via no-arg constructor.
                     * Native wc_Dilithium_PublicKeyDecode / PrivateKeyDecode
                     * will auto detects the level on import later. */
                    if (this.level != LEVEL_UNSET) {
                        wc_dilithium_set_level(this.level);
                    }
                }
                state = WolfCryptState.INITIALIZED;
            }
        }
    }

    /**
     * Throw exception if this object already has a key loaded.
     *
     * @throws IllegalStateException if state is READY (key loaded)
     */
    private void throwIfKeyExists() throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.READY) {
                throw new IllegalStateException("Object already has a key");
            }
        }
    }

    /**
     * Throw exception if this object does not have a key loaded.
     *
     * @throws IllegalStateException if state is not READY (no key loaded)
     */
    private void throwIfKeyNotLoaded() throws IllegalStateException {

        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                throw new IllegalStateException(
                    "No key available to perform the operation");
            }
        }
    }

    /**
     * Get parameter set selected for this object.
     *
     * <p>For objects constructed via {@link #MlDsa(int)} this returns the
     * level supplied at construction. For objects constructed via the no-arg
     * {@link #MlDsa()}, returns {@code 0} until a DER import has auto detected
     * the level, then returns the detected value.</p>
     *
     * @return one of {@link #ML_DSA_44}, {@link #ML_DSA_65},
     *         {@link #ML_DSA_87}, or {@code 0} if the no-arg constructor
     *         was used and no DER has been imported yet.
     */
    public int getLevel() {
        return this.level;
    }

    /**
     * Generate ML-DSA key pair for this object's parameter set.
     *
     * @param rng initialized {@link Rng}
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key has already been loaded or
     *         the object has been released
     */
    public void makeKey(Rng rng)
        throws WolfCryptException, IllegalStateException {

        requireLevelSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_dilithium_make_key(rng);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Reject operations that require a level set up front (raw imports,
     * keygen) when this object was created via the no-arg constructor and
     * has not yet auto-detected via a DER import.
     *
     * @throws WolfCryptException if the level is not set
     */
    private void requireLevelSet() throws WolfCryptException {

        if (this.level == LEVEL_UNSET) {
            throw new WolfCryptException(
                WolfCryptError.BAD_FUNC_ARG.getCode());
        }
    }

    /**
     * Throw exception if FIPS 204 context exceeds maximum length.
     *
     * @param ctx context bytes, may be null
     *
     * @throws IllegalArgumentException if ctx length exceeds 255
     */
    private static void checkCtxLength(byte[] ctx)
        throws IllegalArgumentException {

        if (ctx != null && ctx.length > ML_DSA_MAX_CTX_LEN) {
            throw new IllegalArgumentException(
                "ML-DSA context length exceeds 255 bytes");
        }
    }

    /**
     * Generate ML-DSA key pair deterministically from a seed, implements
     * FIPS 204 ML-DSA.KeyGen_internal.
     *
     * @param seed key generation seed (xi), must be
     *             {@link #ML_DSA_SEED_LEN} bytes long
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if seed is null or not
     *         {@link #ML_DSA_SEED_LEN} bytes long
     * @throws IllegalStateException if a key has already been loaded or
     *         the object has been released
     */
    public void makeKeyFromSeed(byte[] seed)
        throws WolfCryptException, IllegalStateException {

        if (seed == null || seed.length != ML_DSA_SEED_LEN) {
            throw new IllegalArgumentException(
                "ML-DSA keygen seed must be " + ML_DSA_SEED_LEN + " bytes");
        }

        requireLevelSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_dilithium_make_key_from_seed(seed);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Sign {@code msg} with an empty FIPS 204 context.
     *
     * @param msg message to sign (may be empty, must not be null)
     * @param rng initialized {@link Rng}
     *
     * @return signature bytes, length matches {@link #signatureSize()}
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] sign(byte[] msg, Rng rng)
        throws WolfCryptException, IllegalStateException {

        return sign(msg, null, rng);
    }

    /**
     * Sign {@code msg} with the given FIPS 204 context.
     *
     * @param msg message to sign (may be empty, must not be null)
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 204)
     * @param rng initialized {@link Rng}
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] sign(byte[] msg, byte[] ctx, Rng rng)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_sign_ctx_msg(ctx, msg, rng);
        }
    }

    /**
     * Sign {@code msg} deterministically with the given FIPS 204 context
     * and signing random seed (rnd). Mainly useful for known answer tests,
     * general signing should use {@link #sign(byte[], byte[], Rng)}.
     *
     * @param msg message to sign (may be empty, must not be null)
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 204)
     * @param seed signing random seed (rnd), must be
     *             {@link #ML_DSA_RND_LEN} bytes long
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255 or
     *         seed is null or not {@link #ML_DSA_RND_LEN} bytes long
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signWithSeed(byte[] msg, byte[] ctx, byte[] seed)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);

        if (seed == null || seed.length != ML_DSA_RND_LEN) {
            throw new IllegalArgumentException(
                "ML-DSA signing seed must be " + ML_DSA_RND_LEN + " bytes");
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_sign_ctx_msg_with_seed(ctx, msg, seed);
        }
    }

    /**
     * Sign a message digest with an empty FIPS 204 context, implements
     * HashML-DSA (pre-hash variant) from FIPS 204 Section 5.4.
     *
     * @param hash digest of the message to sign
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values (for example
     *                {@code WolfCrypt.WC_HASH_TYPE_SHA512})
     * @param rng initialized {@link Rng}
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signHash(byte[] hash, int hashAlg, Rng rng)
        throws WolfCryptException, IllegalStateException {

        return signHash(hash, hashAlg, null, rng);
    }

    /**
     * Sign a message digest with the given FIPS 204 context, implements
     * HashML-DSA (pre-hash variant) from FIPS 204 Section 5.4.
     *
     * @param hash digest of the message to sign
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values (for example
     *                {@code WolfCrypt.WC_HASH_TYPE_SHA512})
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 204)
     * @param rng initialized {@link Rng}
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signHash(byte[] hash, int hashAlg, byte[] ctx, Rng rng)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_sign_ctx_hash(ctx, hashAlg, hash, rng);
        }
    }

    /**
     * Sign a message digest deterministically with the given FIPS 204
     * context and signing random seed (rnd), implements HashML-DSA
     * (pre-hash variant) from FIPS 204 Section 5.4. Mainly useful for known
     * answer tests, general signing should use
     * {@link #signHash(byte[], int, byte[], Rng)}.
     *
     * @param hash digest of the message to sign
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values (for example
     *                {@code WolfCrypt.WC_HASH_TYPE_SHA512})
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 204)
     * @param seed signing random seed (rnd), must be
     *             {@link #ML_DSA_RND_LEN} bytes long
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255 or
     *         seed is null or not {@link #ML_DSA_RND_LEN} bytes long
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signHashWithSeed(byte[] hash, int hashAlg, byte[] ctx,
        byte[] seed) throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);

        if (seed == null || seed.length != ML_DSA_RND_LEN) {
            throw new IllegalArgumentException(
                "ML-DSA signing seed must be " + ML_DSA_RND_LEN + " bytes");
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_sign_ctx_hash_with_seed(ctx, hashAlg, hash,
                seed);
        }
    }

    /**
     * Sign a pre-computed mu value deterministically with the given signing
     * random seed (rnd), implements ML-DSA.Sign_internal from FIPS 204
     * Section 6.2. The caller provides mu directly (already computed from
     * tr||M'), bypassing the external message hashing step. Mainly useful
     * for ACVP internal interface tests.
     *
     * <p>Only available when native wolfSSL provides the wc_MlDsaKey API
     * (wc_mldsa.h), throws NOT_COMPILED_IN on older versions.</p>
     *
     * @param mu pre-computed mu value, must be {@link #ML_DSA_MU_LEN}
     *           bytes long
     * @param seed signing random seed (rnd), must be
     *             {@link #ML_DSA_RND_LEN} bytes long
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if mu is null or not
     *         {@link #ML_DSA_MU_LEN} bytes long, or seed is null or not
     *         {@link #ML_DSA_RND_LEN} bytes long
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signMuWithSeed(byte[] mu, byte[] seed)
        throws WolfCryptException, IllegalStateException {

        if (mu == null || mu.length != ML_DSA_MU_LEN) {
            throw new IllegalArgumentException(
                "ML-DSA mu must be " + ML_DSA_MU_LEN + " bytes");
        }
        if (seed == null || seed.length != ML_DSA_RND_LEN) {
            throw new IllegalArgumentException(
                "ML-DSA signing seed must be " + ML_DSA_RND_LEN + " bytes");
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_MlDsaKey_SignMuWithSeed(mu, seed);
        }
    }

    /**
     * Verify {@code sig} over {@code msg} with an empty context.
     *
     * @param sig signature to verify
     * @param msg message bytes
     *
     * @return true if signature verifies, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verify(byte[] sig, byte[] msg)
        throws WolfCryptException, IllegalStateException {

        return verify(sig, msg, null);
    }

    /**
     * Verify {@code sig} over {@code msg} with the given context.
     *
     * @param sig signature to verify
     * @param msg message bytes
     * @param ctx context bytes (may be null or empty; length 0..255)
     *
     * @return true if signature verifies, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verify(byte[] sig, byte[] msg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_verify_ctx_msg(sig, ctx, msg);
        }
    }

    /**
     * Verify {@code sig} over a message digest with an empty context,
     * implements HashML-DSA (pre-hash variant) from FIPS 204 Section 5.4.
     *
     * @param sig signature to verify
     * @param hash digest of the message that was signed
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values (for example
     *                {@code WolfCrypt.WC_HASH_TYPE_SHA512})
     *
     * @return true if signature verifies, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verifyHash(byte[] sig, byte[] hash, int hashAlg)
        throws WolfCryptException, IllegalStateException {

        return verifyHash(sig, hash, hashAlg, null);
    }

    /**
     * Verify {@code sig} over a message digest with the given context,
     * implements HashML-DSA (pre-hash variant) from FIPS 204 Section 5.4.
     *
     * @param sig signature to verify
     * @param hash digest of the message that was signed
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values (for example
     *                {@code WolfCrypt.WC_HASH_TYPE_SHA512})
     * @param ctx context bytes (may be null or empty; length 0..255)
     *
     * @return true if signature verifies, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verifyHash(byte[] sig, byte[] hash, int hashAlg,
        byte[] ctx) throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_verify_ctx_hash(sig, ctx, hashAlg, hash);
        }
    }

    /**
     * Verify {@code sig} over a pre-computed mu value, implements
     * ML-DSA.Verify_internal from FIPS 204 Section 6.3. The caller provides
     * mu directly (already computed from tr||M'), bypassing the external
     * message hashing step. Mainly useful for ACVP internal interface tests.
     *
     * <p>Only available when native wolfSSL provides the wc_MlDsaKey API
     * (wc_mldsa.h), throws NOT_COMPILED_IN on older versions.</p>
     *
     * @param sig signature to verify
     * @param mu pre-computed mu value, must be {@link #ML_DSA_MU_LEN}
     *           bytes long
     *
     * @return true if signature verifies, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if mu is null or not
     *         {@link #ML_DSA_MU_LEN} bytes long
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verifyMu(byte[] sig, byte[] mu)
        throws WolfCryptException, IllegalStateException {

        if (mu == null || mu.length != ML_DSA_MU_LEN) {
            throw new IllegalArgumentException(
                "ML-DSA mu must be " + ML_DSA_MU_LEN + " bytes");
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_MlDsaKey_VerifyMu(sig, mu);
        }
    }

    /**
     * Export raw public key bytes for this object's ML-DSA level.
     *
     * @return public key as a byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] exportPublicKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_export_public();
        }
    }

    /**
     * Export raw private key bytes for this object's ML-DSA level.
     *
     * @return private key as a byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] exportPrivateKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_dilithium_export_private();
        }
    }

    /**
     * Import a raw ML-DSA public key matching this object's parameter set.
     *
     * @param in raw public key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPublicKey(byte[] in)
        throws WolfCryptException, IllegalStateException {

        requireLevelSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_dilithium_import_public(in);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import a raw ML-DSA private key matching this object's parameter set.
     *
     * @param in raw private key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPrivateKey(byte[] in)
        throws WolfCryptException, IllegalStateException {

        requireLevelSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_dilithium_import_private(in);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import a raw ML-DSA private and public key pair matching this
     * object's parameter set.
     *
     * @param priv raw private key bytes
     * @param pub raw public key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importKeyPair(byte[] priv, byte[] pub)
        throws WolfCryptException, IllegalStateException {

        requireLevelSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_dilithium_import_key(priv, pub);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Check that the loaded private and public key halves form a consistent
     * ML-DSA key pair.
     *
     * <p>Only available when native wolfSSL is compiled with key checking
     * support (WOLFSSL_MLDSA_CHECK_KEY), throws NOT_COMPILED_IN
     * otherwise.</p>
     *
     * @throws WolfCryptException if the key pair is inconsistent or the
     *         native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public void checkKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_dilithium_check_key();
        }
    }

    /**
     * Export public key as DER, optionally wrapped in a SubjectPublicKeyInfo
     * AlgorithmIdentifier (X.509 SPKI).
     *
     * @param withAlg if true, output is X.509 SubjectPublicKeyInfo;
     *                if false, output is the raw key DER without the
     *                AlgorithmIdentifier wrapper.
     *
     * @return DER-encoded public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] exportPublicKeyDer(boolean withAlg)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_Dilithium_PublicKeyToDer(withAlg);
        }
    }

    /**
     * Export private key as PKCS#8 PrivateKeyInfo DER.
     *
     * @return PKCS#8 DER-encoded private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] exportPrivateKeyDer()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_Dilithium_KeyToDer();
        }
    }

    /**
     * Export private key as PKCS#8 PrivateKeyInfo DER, optionally including
     * the public key in the encoding.
     *
     * @param withPublicKey if true, the encoding includes both the private
     *                      and public key, same as
     *                      {@link #exportPrivateKeyDer()}; if false, the
     *                      encoding contains the private key only.
     *
     * @return PKCS#8 DER-encoded private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] exportPrivateKeyDer(boolean withPublicKey)
        throws WolfCryptException, IllegalStateException {

        if (withPublicKey) {
            return exportPrivateKeyDer();
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_Dilithium_PrivateKeyToDer();
        }
    }

    /**
     * Import a public key from X.509 SubjectPublicKeyInfo DER.
     *
     * @param der X.509 SPKI DER bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPublicKeyDer(byte[] der)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_Dilithium_PublicKeyDecode(der);
                /* Refresh level: native may have auto-detected if this object
                 * was constructed via the no-arg constructor. Always read
                 * back to keep this.level consistent with native. */
                this.level = wc_dilithium_get_level();
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import a private key from PKCS#8 PrivateKeyInfo DER.
     *
     * @param der PKCS#8 DER bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPrivateKeyDer(byte[] der)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_Dilithium_PrivateKeyDecode(der);
                this.level = wc_dilithium_get_level();
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Get raw public key size, in bytes, for this object's parameter set.
     *
     * @return public key size in bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if the object has been released
     */
    public int publicKeySize()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        synchronized (pointerLock) {
            return wc_dilithium_pub_size();
        }
    }

    /**
     * Get raw private key size, in bytes, for this object's parameter set.
     *
     * @return private key size in bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if the object has been released
     */
    public int privateKeySize()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        synchronized (pointerLock) {
            return wc_dilithium_priv_size();
        }
    }

    /**
     * Get signature size, in bytes, for this object's parameter set.
     *
     * @return signature size in bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if the object has been released
     */
    public int signatureSize()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        synchronized (pointerLock) {
            return wc_dilithium_sig_size();
        }
    }

    /**
     * Parse and validate an X.509 SubjectPublicKeyInfo DER blob carrying
     * an ML-DSA public key, return the parameter set level encoded in the
     * AlgorithmIdentifier OID.
     *
     * <p>Validation and level extraction are both performed by native
     * wolfCrypt {@code wc_Dilithium_PublicKeyDecode}, which post wolfSSL
     * PR 10310 auto-detects the level. On older native wolfSSL builds we fall
     * back to try each of the three FIPS 204 levels (44/65/87) explicitly.</p>
     *
     * <p>The decoded native key is freed before this method returns. Only the
     * level is retained. The caller is expected to do their own decode for
     * actual sign/verify/etc use.</p>
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER bytes
     *
     * @return one of {@link #ML_DSA_44}, {@link #ML_DSA_65}, {@link #ML_DSA_87}
     *
     * @throws WolfCryptException if the DER is malformed or the OID is not a
     *         recognized ML-DSA parameter set
     */
    public static int parseAndValidateMlDsaPublicKeyDer(byte[] x509Der)
        throws WolfCryptException {

        return parseAndValidate(x509Der, true);
    }

    /**
     * Parse and validate a PKCS#8 PrivateKeyInfo DER blob carrying an ML-DSA
     * private key, and return the parameter set level encoded in the
     * AlgorithmIdentifier OID.
     *
     * <p>Validation and level extraction are both performed by native
     * wolfCrypt {@code wc_Dilithium_PrivateKeyDecode}, which post wolfSSL
     * PR 10310 auto-detects the level. On older native wolfSSL builds we fall
     * back to try each of the three FIPS 204 levels (44/65/87) explicitly.</p>
     *
     * <p>The decoded native key is freed before this method returns. Only the
     * level is retained. The caller is expected to do their own decode for
     * actual sign/verify/etc use.</p>
     *
     * @param pkcs8Der PKCS#8 PrivateKeyInfo DER bytes
     *
     * @return one of {@link #ML_DSA_44}, {@link #ML_DSA_65}, {@link #ML_DSA_87}
     *
     * @throws WolfCryptException if the DER is malformed or the OID is not a
     *         recognized ML-DSA parameter set
     */
    public static int parseAndValidateMlDsaPrivateKeyDer(byte[] pkcs8Der)
        throws WolfCryptException {

        return parseAndValidate(pkcs8Der, false);
    }

    /**
     * Parse ML-DSA DER blob to determine ML-DSA level.
     *
     * Imports the DER once via wc_Dilithium_Public/PrivateKeyDecode, which
     * internally validates the ASN.1 encoding, parses the AlgorithmIdentifier
     * OID, and unpacks the key components. We ead the level back, then free
     * the native key.
     *
     * We try using the no-arg constructor first, since that does auto detection
     * of level. Then fall back to trying each level explicitly for pre PR 10310
     * (May 2026) native wolfSSL installs.
     *
     * @param der DER-encoded key blob (X.509 SPKI for public, PKCS#8 for
     *        private)
     * @param isPublic true if this is a public key DER blob, false if
     *        private key
     *
     * @return one of {@link #ML_DSA_44}, {@link #ML_DSA_65}, {@link #ML_DSA_87}
     *
     * @throws WolfCryptException if the DER is malformed or the OID is not a
     *         recognized ML-DSA parameter set.
     */
    private static int parseAndValidate(byte[] der, boolean isPublic)
        throws WolfCryptException {

        if (der == null || der.length == 0) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }

        /* Try with native auto-level detect first. Will throw exception/fail
         * if using native wolfSSL without PR 10310 changes. */
        try {
            MlDsa k = new MlDsa();
            try {
                if (isPublic) {
                    k.importPublicKeyDer(der);
                }
                else {
                    k.importPrivateKeyDer(der);
                }
                return k.getLevel();
            }
            finally {
                k.releaseNativeStruct();
            }
        }
        catch (WolfCryptException ignored) {
            /* fall through to per-level fallback */
        }

        /* Fallback to trying each level explicitly to find a success path */
        for (int lvl : new int[] {ML_DSA_44, ML_DSA_65, ML_DSA_87}) {
            try {
                MlDsa k = new MlDsa(lvl);
                try {
                    if (isPublic) {
                        k.importPublicKeyDer(der);
                    }
                    else {
                        k.importPrivateKeyDer(der);
                    }
                    return lvl;
                }
                finally {
                    k.releaseNativeStruct();
                }
            }
            catch (WolfCryptException ignored) {
                /* try next level */
            }
        }

        throw new WolfCryptException(
            WolfCryptError.ASN_PARSE_E.getCode());
    }
}
