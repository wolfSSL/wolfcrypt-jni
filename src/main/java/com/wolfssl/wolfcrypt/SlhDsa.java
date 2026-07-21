/* SlhDsa.java
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
 * Wrapper for the native WolfCrypt SLH-DSA (FIPS 205) implementation.
 *
 * <p>Mirrors the native wolfCrypt {@code wc_SlhDsaKey_*} API. SLH-DSA is a
 * stateless hash-based signature scheme (formerly SPHINCS+). The parameter
 * set is fixed at construction and maps directly to the native
 * {@code enum SlhDsaParam} integer value. An empty FIPS 205 context is used
 * by default.</p>
 *
 * <p>Parameter set constants match the native {@code enum SlhDsaParam}: the
 * six SHAKE sets are 0-5, the six SHA2 sets are 6-11. Note this ordering is
 * the reverse of the NIST OID ordering (SHA2 OIDs come before SHAKE).</p>
 */
public class SlhDsa extends NativeStruct {

    /** SLH-DSA-SHAKE-128s parameter set, NIST security category 1. */
    public static final int SLH_DSA_SHAKE_128S = 0;

    /** SLH-DSA-SHAKE-128f parameter set, NIST security category 1. */
    public static final int SLH_DSA_SHAKE_128F = 1;

    /** SLH-DSA-SHAKE-192s parameter set, NIST security category 3. */
    public static final int SLH_DSA_SHAKE_192S = 2;

    /** SLH-DSA-SHAKE-192f parameter set, NIST security category 3. */
    public static final int SLH_DSA_SHAKE_192F = 3;

    /** SLH-DSA-SHAKE-256s parameter set, NIST security category 5. */
    public static final int SLH_DSA_SHAKE_256S = 4;

    /** SLH-DSA-SHAKE-256f parameter set, NIST security category 5. */
    public static final int SLH_DSA_SHAKE_256F = 5;

    /** SLH-DSA-SHA2-128s parameter set, NIST security category 1. */
    public static final int SLH_DSA_SHA2_128S = 6;

    /** SLH-DSA-SHA2-128f parameter set, NIST security category 1. */
    public static final int SLH_DSA_SHA2_128F = 7;

    /** SLH-DSA-SHA2-192s parameter set, NIST security category 3. */
    public static final int SLH_DSA_SHA2_192S = 8;

    /** SLH-DSA-SHA2-192f parameter set, NIST security category 3. */
    public static final int SLH_DSA_SHA2_192F = 9;

    /** SLH-DSA-SHA2-256s parameter set, NIST security category 5. */
    public static final int SLH_DSA_SHA2_256S = 10;

    /** SLH-DSA-SHA2-256f parameter set, NIST security category 5. */
    public static final int SLH_DSA_SHA2_256F = 11;

    /** FIPS 205 maximum context length, in bytes. */
    public static final int SLH_DSA_MAX_CONTEXT_LEN = 255;

    /**
     * Get the standard algorithm name for an SLH-DSA parameter set.
     *
     * @param param SLH-DSA parameter set, one of SLH_DSA_*
     *
     * @return standard algorithm name (e.g. "SLH-DSA-SHA2-128s"), or
     *         null if param is unknown
     */
    public static String getParamSetName(int param) {

        switch (param) {
            case SLH_DSA_SHAKE_128S:
                return "SLH-DSA-SHAKE-128s";
            case SLH_DSA_SHAKE_128F:
                return "SLH-DSA-SHAKE-128f";
            case SLH_DSA_SHAKE_192S:
                return "SLH-DSA-SHAKE-192s";
            case SLH_DSA_SHAKE_192F:
                return "SLH-DSA-SHAKE-192f";
            case SLH_DSA_SHAKE_256S:
                return "SLH-DSA-SHAKE-256s";
            case SLH_DSA_SHAKE_256F:
                return "SLH-DSA-SHAKE-256f";
            case SLH_DSA_SHA2_128S:
                return "SLH-DSA-SHA2-128s";
            case SLH_DSA_SHA2_128F:
                return "SLH-DSA-SHA2-128f";
            case SLH_DSA_SHA2_192S:
                return "SLH-DSA-SHA2-192s";
            case SLH_DSA_SHA2_192F:
                return "SLH-DSA-SHA2-192f";
            case SLH_DSA_SHA2_256S:
                return "SLH-DSA-SHA2-256s";
            case SLH_DSA_SHA2_256F:
                return "SLH-DSA-SHA2-256f";
            default:
                return null;
        }
    }

    /* Lowest and highest valid native enum SlhDsaParam values. */
    private static final int PARAM_MIN = 0;
    private static final int PARAM_MAX = 11;

    /* Used by no-arg constructor before DER import detects the param set. */
    private static final int PARAM_UNSET = -1;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state. */
    protected final Object stateLock = new Object();

    /** SLH-DSA parameter set. Volatile so {@link #getParam()} sees the latest
     * value after the auto-detect refresh inside the DER import paths. */
    private volatile int param;

    /**
     * Create a new SLH-DSA object for the given parameter set.
     *
     * @param param one of the {@code SLH_DSA_*} parameter set constants
     *              (0-11, matching native {@code enum SlhDsaParam}).
     *
     * @throws WolfCryptException if SLH-DSA is not compiled into native
     *         wolfCrypt or {@code param} is not a valid parameter set.
     */
    public SlhDsa(int param) throws WolfCryptException {

        if (!FeatureDetect.SlhDsaEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        if (param < PARAM_MIN || param > PARAM_MAX) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }

        this.param = param;
        /* Native struct lazy init in checkStateAndInitialize() */
    }

    /**
     * Create a new SLH-DSA object with the parameter set deferred. The
     * parameter set is auto-detected on the first
     * {@link #importPublicKeyDer(byte[])} or
     * {@link #importPrivateKeyDer(byte[])} call from the AlgorithmIdentifier
     * OID.
     *
     * <p>Cannot be used with {@link #makeKey(Rng)},
     * {@link #importPublicKey(byte[])}, or {@link #importPrivateKey(byte[])}.
     * Those paths require the parameter set to be set up front, since raw key
     * bytes do not carry it (and several sets share the same byte sizes).</p>
     *
     * @throws WolfCryptException if SLH-DSA not compiled into native wolfCrypt.
     */
    public SlhDsa() throws WolfCryptException {

        if (!FeatureDetect.SlhDsaEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }

        this.param = PARAM_UNSET;
        /* Native struct lazy init in checkStateAndInitialize(). Parameter set
         * is detected later by DER import. */
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_SlhDsaKey_free();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Allocate native SlhDsaKey struct.
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_SlhDsaKey_init(int param);
    private native void wc_SlhDsaKey_free();
    private native int  wc_SlhDsaKey_get_param();
    private native void wc_SlhDsaKey_make_key(Rng rng);
    private native void wc_SlhDsaKey_make_key_with_seeds(byte[] skSeed,
        byte[] skPrf, byte[] pkSeed);
    private native byte[] wc_SlhDsaKey_sign(byte[] ctx, byte[] msg, Rng rng);
    private native byte[] wc_SlhDsaKey_sign_deterministic(byte[] ctx,
        byte[] msg);
    private native byte[] wc_SlhDsaKey_sign_hash(byte[] ctx, int hashAlg,
        byte[] hash, Rng rng);
    private native byte[] wc_SlhDsaKey_sign_msg_prehash(byte[] ctx, byte[] msg,
        Rng rng);
    private native boolean wc_SlhDsaKey_verify(byte[] sig, byte[] ctx,
        byte[] msg);
    private native boolean wc_SlhDsaKey_verify_hash(byte[] sig, byte[] ctx,
        int hashAlg, byte[] hash);
    private native boolean wc_SlhDsaKey_verify_msg_prehash(byte[] sig,
        byte[] ctx, byte[] msg);
    private native byte[] wc_SlhDsaKey_export_public();
    private native byte[] wc_SlhDsaKey_export_private();
    private native void wc_SlhDsaKey_import_public(byte[] in);
    private native void wc_SlhDsaKey_import_private(byte[] in);
    private native byte[] wc_SlhDsaKey_PublicKeyToDer(boolean withAlg);
    private native byte[] wc_SlhDsaKey_KeyToDer();
    private native void wc_SlhDsaKey_PublicKeyDecode(byte[] der);
    private native void wc_SlhDsaKey_PrivateKeyDecode(byte[] der);
    private native int wc_SlhDsaKey_pub_size();
    private native int wc_SlhDsaKey_priv_size();
    private native int wc_SlhDsaKey_sig_size();
    private native void wc_SlhDsaKey_check_key();

    /**
     * Allocate, initialize, and set the parameter set. State advances
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
                    try {
                        if (this.param != PARAM_UNSET) {
                            wc_SlhDsaKey_init(this.param);
                        }
                        else {
                            /* No-arg object, init placeholder. Real set is
                             * detected later from DER import. */
                            initDeferredPlaceholder();
                        }
                    } catch (WolfCryptException e) {
                        /* Init failed for every candidate parameter set.
                         * The struct was already allocated, free it since
                         * state stays UNINITIALIZED and releaseNativeStruct()
                         * would otherwise skip it. */
                        super.releaseNativeStruct();
                        throw e;
                    }
                }
                state = WolfCryptState.INITIALIZED;
            }
        }
    }

    /**
     * Native initialize the already allocated struct with the first
     * compiled-in parameter set, for a deferred (no-arg) object whose real
     * parameter set is detected later from DER import OID. Caller holds
     * pointerLock. The native struct is reused across attempts. Native Init
     * validates the parameter set before touching the struct, so retrying a
     * different set after a failure is safe.
     *
     * @throws WolfCryptException if no parameter set is compiled in
     */
    private void initDeferredPlaceholder() throws WolfCryptException {

        WolfCryptException lastErr = null;

        for (int p = PARAM_MIN; p <= PARAM_MAX; p++) {
            try {
                wc_SlhDsaKey_init(p);
                return;

            } catch (WolfCryptException e) {
                lastErr = e;
            }
        }

        if (lastErr != null) {
            throw lastErr;
        }

        throw new WolfCryptException(WolfCryptError.NOT_COMPILED_IN.getCode());
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
     * Reject operations that require the parameter set up front (raw imports,
     * keygen) when this object was created via the no-arg constructor and has
     * not yet auto-detected via a DER import.
     *
     * @throws WolfCryptException if the parameter set is not set
     */
    private void requireParamSet() throws WolfCryptException {

        if (this.param == PARAM_UNSET) {
            throw new WolfCryptException(
                WolfCryptError.BAD_FUNC_ARG.getCode());
        }
    }

    /**
     * Throw exception if FIPS 205 context exceeds maximum length.
     *
     * @param ctx context bytes, may be null
     *
     * @throws IllegalArgumentException if ctx length exceeds 255
     */
    private static void checkCtxLength(byte[] ctx)
        throws IllegalArgumentException {

        if (ctx != null && ctx.length > SLH_DSA_MAX_CONTEXT_LEN) {
            throw new IllegalArgumentException(
                "SLH-DSA context length exceeds 255 bytes");
        }
    }

    /**
     * Get the security parameter n, in bytes, for an SLH-DSA parameter set.
     *
     * @param param SLH-DSA parameter set (0-11)
     *
     * @return n in bytes (16, 24, or 32)
     *
     * @throws WolfCryptException if {@code param} is not a valid parameter
     *         set (including {@code -1} from {@link #getParam()} on a no-arg
     *         object before DER import)
     */
    public static int paramToN(int param) throws WolfCryptException {

        if (param < PARAM_MIN || param > PARAM_MAX) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }

        /* Both the SHAKE (0-5) and SHA2 (6-11) blocks order the sets as
         * 128s,128f,192s,192f,256s,256f, so (param % 6) / 2 gives the
         * category index 0=128, 1=192, 2=256 and n = 16 + 8 * index. */
        return 16 + 8 * ((param % 6) / 2);
    }

    /**
     * Get the parameter set selected for this object.
     *
     * @return one of the {@code SLH_DSA_*} constants (0-11), or {@code -1} if
     *         the no-arg constructor was used and no DER has been imported yet.
     */
    public int getParam() {
        return this.param;
    }

    /**
     * Generate an SLH-DSA key pair for this object's parameter set.
     *
     * @param rng initialized {@link Rng}
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key has already been loaded or the
     *         object has been released
     */
    public void makeKey(Rng rng)
        throws WolfCryptException, IllegalStateException {

        requireParamSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_SlhDsaKey_make_key(rng);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Generate an SLH-DSA key pair deterministically from the three secret
     * seeds, implements FIPS 205 SLH-DSA.KeyGen_internal. Mainly useful for
     * known answer tests, general key generation should use
     * {@link #makeKey(Rng)}.
     *
     * @param skSeed SK.seed value, must be {@code paramToN(param)} bytes
     * @param skPrf  SK.prf value, must be {@code paramToN(param)} bytes
     * @param pkSeed PK.seed value, must be {@code paramToN(param)} bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if any seed is null or not the expected
     *         length
     * @throws IllegalStateException if a key has already been loaded or the
     *         object has been released
     */
    public void makeKeyWithSeeds(byte[] skSeed, byte[] skPrf, byte[] pkSeed)
        throws WolfCryptException, IllegalStateException {

        requireParamSet();

        int n = paramToN(this.param);
        if (skSeed == null || skSeed.length != n ||
            skPrf == null || skPrf.length != n ||
            pkSeed == null || pkSeed.length != n) {
            throw new IllegalArgumentException(
                "SLH-DSA keygen seeds must each be " + n + " bytes");
        }

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_SlhDsaKey_make_key_with_seeds(skSeed, skPrf, pkSeed);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Sign {@code msg} with an empty FIPS 205 context.
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
     * Sign {@code msg} with the given FIPS 205 context.
     *
     * @param msg message to sign (may be empty, must not be null)
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 205)
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
            return wc_SlhDsaKey_sign(ctx, msg, rng);
        }
    }

    /**
     * Sign {@code msg} deterministically with the given FIPS 205 context.
     * Mainly useful for known answer tests, general signing should use
     * {@link #sign(byte[], byte[], Rng)}.
     *
     * @param msg message to sign (may be empty, must not be null)
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 205)
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signDeterministic(byte[] msg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_SlhDsaKey_sign_deterministic(ctx, msg);
        }
    }

    /**
     * Sign a message digest with an empty FIPS 205 context, implements
     * HashSLH-DSA (pre-hash variant) from FIPS 205 Section 10.2.2.
     *
     * @param hash digest of the message to sign
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values
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
     * Sign a message digest with the given FIPS 205 context, implements
     * HashSLH-DSA (pre-hash variant) from FIPS 205 Section 10.2.2.
     *
     * @param hash digest of the message to sign
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 205)
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
            return wc_SlhDsaKey_sign_hash(ctx, hashAlg, hash, rng);
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
            return wc_SlhDsaKey_verify(sig, ctx, msg);
        }
    }

    /**
     * Sign {@code msg} using HashSLH-DSA (pre-hash variant) from FIPS 205
     * Section 10.2.2 with an empty context.
     *
     * <p>The message is hashed with the parameter set's standardized pre-hash
     * function (SHA-256 for SHA2-128, SHA-512 for SHA2-192/256, SHAKE128 for
     * SHAKE-128, SHAKE256 for SHAKE-192/256) and the resulting digest is signed
     * as HashSLH-DSA. The hashing is performed natively.</p>
     *
     * @param msg message to sign (may be empty, must not be null)
     * @param rng initialized {@link Rng}
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signPreHash(byte[] msg, Rng rng)
        throws WolfCryptException, IllegalStateException {

        return signPreHash(msg, null, rng);
    }

    /**
     * Sign {@code msg} using HashSLH-DSA (pre-hash variant) from FIPS 205
     * Section 10.2.2 with the given context.
     *
     * <p>The message is hashed with the parameter set's standardized pre-hash
     * function and the resulting digest is signed as HashSLH-DSA. The hashing
     * is performed natively.</p>
     *
     * @param msg message to sign (may be empty, must not be null)
     * @param ctx context bytes (may be null or empty for an empty context;
     *            length must be 0..255 per FIPS 205)
     * @param rng initialized {@link Rng}
     *
     * @return signature bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] signPreHash(byte[] msg, byte[] ctx, Rng rng)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_SlhDsaKey_sign_msg_prehash(ctx, msg, rng);
        }
    }

    /**
     * Verify {@code sig} over {@code msg} using HashSLH-DSA (pre-hash variant)
     * from FIPS 205 Section 10.2.2 with an empty context.
     *
     * @param sig signature to verify
     * @param msg message bytes
     *
     * @return true if signature verifies, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verifyPreHash(byte[] sig, byte[] msg)
        throws WolfCryptException, IllegalStateException {

        return verifyPreHash(sig, msg, null);
    }

    /**
     * Verify {@code sig} over {@code msg} using HashSLH-DSA (pre-hash variant)
     * from FIPS 205 Section 10.2.2 with the given context.
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
    public boolean verifyPreHash(byte[] sig, byte[] msg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_SlhDsaKey_verify_msg_prehash(sig, ctx, msg);
        }
    }

    /**
     * Verify {@code sig} over a message digest with an empty context,
     * implements HashSLH-DSA (pre-hash variant) from FIPS 205 Section 10.2.2.
     *
     * @param sig signature to verify
     * @param hash digest of the message that was signed
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values
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
     * implements HashSLH-DSA (pre-hash variant) from FIPS 205 Section 10.2.2.
     *
     * @param sig signature to verify
     * @param hash digest of the message that was signed
     * @param hashAlg hash algorithm used to compute {@code hash}, one of the
     *                {@code WolfCrypt.WC_HASH_TYPE_*} values
     * @param ctx context bytes (may be null or empty; length 0..255)
     *
     * @return true if signature verifies, false otherwise
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if {@code ctx} length exceeds 255
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verifyHash(byte[] sig, byte[] hash, int hashAlg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        checkCtxLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_SlhDsaKey_verify_hash(sig, ctx, hashAlg, hash);
        }
    }

    /**
     * Export raw public key bytes for this object's SLH-DSA parameter set.
     *
     * @return public key as a byte array (2n bytes)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] exportPublicKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_SlhDsaKey_export_public();
        }
    }

    /**
     * Export raw private key bytes for this object's SLH-DSA parameter set.
     *
     * @return private key as a byte array (4n bytes)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public byte[] exportPrivateKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_SlhDsaKey_export_private();
        }
    }

    /**
     * Import a raw SLH-DSA public key matching this object's parameter set.
     *
     * @param in raw public key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPublicKey(byte[] in)
        throws WolfCryptException, IllegalStateException {

        requireParamSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_SlhDsaKey_import_public(in);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import a raw SLH-DSA private key matching this object's parameter set.
     *
     * @param in raw private key bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPrivateKey(byte[] in)
        throws WolfCryptException, IllegalStateException {

        requireParamSet();
        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_SlhDsaKey_import_private(in);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Check that the loaded private and public key halves form a consistent
     * SLH-DSA key pair.
     *
     * @throws WolfCryptException if the key pair is inconsistent or the native
     *         operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public void checkKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_SlhDsaKey_check_key();
        }
    }

    /**
     * Export public key as DER, optionally wrapped in a SubjectPublicKeyInfo
     * AlgorithmIdentifier (X.509 SPKI).
     *
     * @param withAlg if true, output is X.509 SubjectPublicKeyInfo; if false,
     *                output is the raw key DER without the AlgorithmIdentifier
     *                wrapper.
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
            return wc_SlhDsaKey_PublicKeyToDer(withAlg);
        }
    }

    /**
     * Export private key as PKCS#8 PrivateKeyInfo DER (RFC 9909). For SLH-DSA
     * the private key is a flat OCTET STRING, there is no separate
     * private-only form.
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
            return wc_SlhDsaKey_KeyToDer();
        }
    }

    /**
     * Import a public key from X.509 SubjectPublicKeyInfo DER. The parameter
     * set is auto-detected from the AlgorithmIdentifier OID.
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
                wc_SlhDsaKey_PublicKeyDecode(der);
                /* Refresh param from native, which detects it from the OID. */
                this.param = wc_SlhDsaKey_get_param();
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import a private key from PKCS#8 PrivateKeyInfo DER. The parameter set
     * is auto-detected from the AlgorithmIdentifier OID.
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
                wc_SlhDsaKey_PrivateKeyDecode(der);
                this.param = wc_SlhDsaKey_get_param();
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Get raw public key size, in bytes, for this object's parameter set.
     *
     * <p>For parameter set, requires either the explicit param constructor,
     * or a no-arg object after a DER import has detected it.</p>
     *
     * @return public key size in bytes
     *
     * @throws WolfCryptException if native operation fails or the parameter
     *         set is not yet set
     * @throws IllegalStateException if the object has been released
     */
    public int publicKeySize()
        throws WolfCryptException, IllegalStateException {

        requireParamSet();
        checkStateAndInitialize();
        synchronized (pointerLock) {
            return wc_SlhDsaKey_pub_size();
        }
    }

    /**
     * Get raw private key size, in bytes, for this object's parameter set.
     *
     * <p>For parameter set, requires either the explicit param constructor,
     * or a no-arg object after a DER import has detected it.</p>
     *
     * @return private key size in bytes
     *
     * @throws WolfCryptException if native operation fails or the parameter
     *         set is not yet set
     * @throws IllegalStateException if the object has been released
     */
    public int privateKeySize()
        throws WolfCryptException, IllegalStateException {

        requireParamSet();
        checkStateAndInitialize();
        synchronized (pointerLock) {
            return wc_SlhDsaKey_priv_size();
        }
    }

    /**
     * Get signature size, in bytes, for this object's parameter set.
     *
     * <p>For parameter set, requires either the explicit param constructor,
     * or a no-arg object after a DER import has detected it.</p>
     *
     * @return signature size in bytes
     *
     * @throws WolfCryptException if native operation fails or the parameter
     *         set is not yet set
     * @throws IllegalStateException if the object has been released
     */
    public int signatureSize()
        throws WolfCryptException, IllegalStateException {

        requireParamSet();
        checkStateAndInitialize();
        synchronized (pointerLock) {
            return wc_SlhDsaKey_sig_size();
        }
    }

    /**
     * Parse and validate an X.509 SubjectPublicKeyInfo DER blob carrying an
     * SLH-DSA public key, return the parameter set encoded in the
     * AlgorithmIdentifier OID.
     *
     * <p>The decoded native key is freed before this method returns, only the
     * parameter set is retained.</p>
     *
     * @param x509Der X.509 SubjectPublicKeyInfo DER bytes
     *
     * @return one of the {@code SLH_DSA_*} parameter set constants (0-11)
     *
     * @throws WolfCryptException if the DER is malformed or the OID is not a
     *         recognized SLH-DSA parameter set
     */
    public static int parseAndValidateSlhDsaPublicKeyDer(byte[] x509Der)
        throws WolfCryptException {

        return parseAndValidate(x509Der, true);
    }

    /**
     * Parse and validate a PKCS#8 PrivateKeyInfo DER blob carrying an SLH-DSA
     * private key, return the parameter set encoded in the
     * AlgorithmIdentifier OID.
     *
     * <p>The decoded native key is freed before this method returns, only the
     * parameter set is retained.</p>
     *
     * @param pkcs8Der PKCS#8 PrivateKeyInfo DER bytes
     *
     * @return one of the {@code SLH_DSA_*} parameter set constants (0-11)
     *
     * @throws WolfCryptException if the DER is malformed or the OID is not a
     *         recognized SLH-DSA parameter set
     */
    public static int parseAndValidateSlhDsaPrivateKeyDer(byte[] pkcs8Der)
        throws WolfCryptException {

        return parseAndValidate(pkcs8Der, false);
    }

    /**
     * Parse an SLH-DSA DER blob to determine the parameter set.
     *
     * Imports the DER once via wc_SlhDsaKey_Public/PrivateKeyDecode, which
     * validates the ASN.1 encoding and detects the parameter set from the
     * AlgorithmIdentifier OID. Native wolfSSL detects the OID.
     *
     * @param der DER-encoded key blob (X.509 SPKI for public, PKCS#8 for
     *        private)
     * @param isPublic true if this is a public key DER blob, false if private
     *
     * @return one of the {@code SLH_DSA_*} parameter set constants (0-11)
     *
     * @throws WolfCryptException if the DER is malformed or the OID is not a
     *         recognized SLH-DSA parameter set.
     */
    private static int parseAndValidate(byte[] der, boolean isPublic)
        throws WolfCryptException {

        if (der == null || der.length == 0) {
            throw new WolfCryptException(WolfCryptError.BAD_FUNC_ARG.getCode());
        }

        try {
            SlhDsa k = new SlhDsa();
            try {
                if (isPublic) {
                    k.importPublicKeyDer(der);
                }
                else {
                    k.importPrivateKeyDer(der);
                }
                return k.getParam();
            }
            finally {
                k.releaseNativeStruct();
            }
        }
        catch (WolfCryptException e) {
            /* Pass through NOT_COMPILED_IN, normalize other decode
             * failures to ASN_PARSE_E. */
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                throw e;
            }
            throw new WolfCryptException(WolfCryptError.ASN_PARSE_E.getCode());
        }
    }
}
