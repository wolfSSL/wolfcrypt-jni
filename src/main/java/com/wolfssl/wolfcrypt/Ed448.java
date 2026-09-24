/* Ed448.java
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

package com.wolfssl.wolfcrypt;

import java.lang.ref.WeakReference;

/**
 * Wrapper for the native wolfCrypt Ed448 implementation (RFC 8032).
 *
 * <p>Ed448 always takes a context (empty by default). Pure (Ed448) and
 * pre-hash (Ed448ph) variants are selected by the method called, or explicitly
 * through {@code *Ex} methods with an {@code ED448_TYPE_*} value.</p>
 *
 * <p>Native wolfSSL requires both the private and the public key to be loaded
 * before signing. Importing only a private key (raw or PKCS#8 without a public
 * key) needs {@link #ensurePublicKey()} before {@link #sign(byte[])}.
 * {@link #importPrivateKeyDer(byte[])} does this automatically.</p>
 */
public class Ed448 extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Ed448 private key size, from native ED448_KEY_SIZE.
     */
    public static final int ED448_KEY_SIZE = 57;

    /**
     * Ed448 public key size, from native ED448_PUB_KEY_SIZE.
     */
    public static final int ED448_PUB_KEY_SIZE = 57;

    /**
     * Ed448 private + public key size, from ED448_PRV_KEY_SIZE. This is
     * the buffer size returned by {@link #exportPrivate()}.
     */
    public static final int ED448_PRV_KEY_SIZE = 114;

    /**
     * Ed448 signature size, from native ED448_SIG_SIZE.
     */
    public static final int ED448_SIG_SIZE = 114;

    /**
     * Ed448ph pre-hash size in bytes (SHAKE256 output length). Hash passed
     * to {@link #signPhHash(byte[], byte[])} and
     * {@link #verifyPhHash(byte[], byte[], byte[])} must be this size.
     */
    public static final int ED448_PREHASH_SIZE = 64;

    /**
     * Maximum EdDSA context length in bytes (RFC 8032).
     */
    public static final int ED448_MAX_CONTEXT_LEN = 255;

    /**
     * Pure Ed448 variant, from native enum value {@code Ed448}.
     */
    public static final int ED448_TYPE_PURE = 0;

    /**
     * Ed448ph (pre-hash) variant, from native enum value {@code Ed448ph}.
     */
    public static final int ED448_TYPE_PH = 1;

    /**
     * Device ID value meaning "no crypto callback device", from native
     * INVALID_DEVID.
     */
    public static final int INVALID_DEVID = -2;

    /* Java-side selectors for the native entry point to call */
    private static final int FN_MSG     = 0;
    private static final int FN_PH_MSG  = 1;
    private static final int FN_PH_HASH = 2;
    private static final int FN_MSG_EX  = 3;

    /** Crypto callback device ID used at native init, or INVALID_DEVID */
    private final int devId;

    /** True between verifyInit() and verifyFinal() */
    private boolean streamingVerifyActive = false;

    /** Signature rejected in verifyInit(), verifyFinal() returns false */
    private boolean streamingVerifyFailed = false;

    /** Thread that started the streaming verify, stream is bound to it */
    private WeakReference<Thread> streamingVerifyOwner = null;

    /**
     * Create new Ed448 object.
     *
     * @throws WolfCryptException if Ed448 has not been compiled into native
     *         wolfCrypt library.
     */
    public Ed448() {
        this(INVALID_DEVID);
    }

    /**
     * Create new Ed448 object bound to a crypto callback device ID. Native
     * key is initialized with wc_ed448_init_ex() on first use.
     *
     * @param devId crypto callback device ID, or {@link #INVALID_DEVID}
     *
     * @throws WolfCryptException if Ed448 has not been compiled into native
     *         wolfCrypt library.
     */
    public Ed448(int devId) {
        if (!FeatureDetect.Ed448Enabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        this.devId = devId;
        /* Internal state is initialized on first use */
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_ed448_free();
                    super.releaseNativeStruct();
                }
                streamingVerifyActive = false;
                streamingVerifyFailed = false;
                streamingVerifyOwner = null;
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Malloc native JNI Ed448 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_ed448_init();
    private native void wc_ed448_init_ex(int devId);
    private native void wc_ed448_free();
    private native void wc_ed448_make_key(Rng rng, int size);
    private native byte[] wc_ed448_make_public();
    private native void wc_ed448_check_key();
    private native boolean ed448_key_privKeySet();
    private native boolean ed448_key_pubKeySet();
    private native int wc_ed448_size();
    private native int wc_ed448_priv_size();
    private native int wc_ed448_pub_size();
    private native int wc_ed448_sig_size();
    private native void wc_ed448_import_private(byte[] privKey, byte[] pubKey);
    private native void wc_ed448_import_private_key_ex(byte[] privKey,
        byte[] pubKey, boolean trusted);
    private native void wc_ed448_import_private_only(byte[] privKey);
    private native void wc_ed448_import_public(byte[] pubKey);
    private native void wc_ed448_import_public_ex(byte[] pubKey,
        boolean trusted);
    private native byte[] wc_ed448_export_private();
    private native byte[] wc_ed448_export_private_only();
    private native byte[] wc_ed448_export_public();
    private native byte[][] wc_ed448_export_key();
    private native byte[] wc_ed448_sign_msg(byte[] msg, byte[] ctx);
    private native byte[] wc_ed448ph_sign_msg(byte[] msg, byte[] ctx);
    private native byte[] wc_ed448ph_sign_hash(byte[] hash, byte[] ctx);
    private native byte[] wc_ed448_sign_msg_ex(byte[] msg, int type,
        byte[] ctx);
    private native boolean wc_ed448_verify_msg(byte[] sig, byte[] msg,
        byte[] ctx);
    private native boolean wc_ed448ph_verify_msg(byte[] sig, byte[] msg,
        byte[] ctx);
    private native boolean wc_ed448ph_verify_hash(byte[] sig, byte[] hash,
        byte[] ctx);
    private native boolean wc_ed448_verify_msg_ex(byte[] sig, byte[] msg,
        int type, byte[] ctx);
    private native void wc_ed448_verify_msg_init(byte[] sig, int type,
        byte[] ctx);
    private native void wc_ed448_verify_msg_update(byte[] seg, int offset,
        int len);
    private native boolean wc_ed448_verify_msg_final(byte[] sig);
    private native void wc_Ed448PublicKeyDecode(byte[] der);
    private native void wc_Ed448PrivateKeyDecode(byte[] der);
    private native byte[] wc_Ed448PublicKeyToDer(boolean withAlg);
    private native byte[] wc_Ed448PrivateKeyToDer();
    private native byte[] wc_Ed448KeyToDer();

    /**
     * Internal helper method to initialize object if/when needed.
     *
     * @throws IllegalStateException on failure to initialize properly or
     *         if releaseNativeStruct() has been called and object has been
     *         released
     */
    private synchronized void checkStateAndInitialize()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (state == WolfCryptState.RELEASED) {
                throw new IllegalStateException("Object has been released");
            }

            if (state == WolfCryptState.UNINITIALIZED) {
                init();
                if (state != WolfCryptState.INITIALIZED) {
                    throw new IllegalStateException(
                        "Failed to initialize Object");
                }
            }
        }
    }

    /**
     * Initialize Ed448 object
     */
    private void init() {
        synchronized (pointerLock) {
            /* Allocate native struct pointer from NativeStruct */
            initNativeStruct();
            try {
                if (this.devId == INVALID_DEVID) {
                    wc_ed448_init();
                }
                else {
                    wc_ed448_init_ex(this.devId);
                }
            }
            catch (Throwable e) {
                super.releaseNativeStruct();
                throw e;
            }
        }
        state = WolfCryptState.INITIALIZED;
    }

    /**
     * Throw exception if key has been loaded already.
     *
     * @throws IllegalStateException if key has been loaded already
     */
    private void throwIfKeyExists() throws IllegalStateException {
        synchronized (stateLock) {
            if (state == WolfCryptState.READY) {
                throw new IllegalStateException("Object already has a key");
            }
        }
    }

    /**
     * Throw exception if releaseNativeStruct() has been called. Caller
     * holds stateLock.
     *
     * @throws IllegalStateException if the object has been released
     */
    private void throwIfReleased() throws IllegalStateException {
        if (state == WolfCryptState.RELEASED) {
            throw new IllegalStateException("Object has been released");
        }
    }

    /**
     * Throw exception if key has not been loaded.
     *
     * @throws IllegalStateException if key has not been loaded
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
     * Throw exception if an EdDSA context exceeds the RFC 8032 maximum.
     *
     * @param ctx context bytes, may be null
     *
     * @throws IllegalArgumentException if ctx length exceeds 255
     */
    private static void checkContextLength(byte[] ctx)
        throws IllegalArgumentException {

        if (ctx != null && ctx.length > ED448_MAX_CONTEXT_LEN) {
            throw new IllegalArgumentException(
                "Ed448 context length exceeds " + ED448_MAX_CONTEXT_LEN +
                " bytes");
        }
    }

    /**
     * Throw exception if a pre-hash value is not exactly 64 bytes.
     *
     * @param hash hash bytes
     *
     * @throws IllegalArgumentException if hash is null or not 64 bytes
     */
    private static void checkPrehashLength(byte[] hash)
        throws IllegalArgumentException {

        if (hash == null || hash.length != ED448_PREHASH_SIZE) {
            throw new IllegalArgumentException(
                "Ed448ph hash must be " + ED448_PREHASH_SIZE + " bytes");
        }
    }

    /**
     * Throw exception if type is not one of the ED448_TYPE_* constants.
     *
     * @param type variant type
     *
     * @throws IllegalArgumentException on unknown type
     */
    private static void checkType(int type) throws IllegalArgumentException {

        if (type != ED448_TYPE_PURE && type != ED448_TYPE_PH) {
            throw new IllegalArgumentException("Invalid Ed448 type: " + type);
        }
    }

    /**
     * Throw exception if a streaming verify is in progress. One-shot sign and
     * verify paths share the native persistent hash state with streaming
     * verify, so they must not run between verifyInit() and verifyFinal().
     * Caller holds stateLock.
     *
     * @throws IllegalStateException if verifyInit() was called and
     *         verifyFinal() has not completed
     */
    private void throwIfStreamingVerifyActive() throws IllegalStateException {

        if (streamingVerifyActive) {
            throw new IllegalStateException(
                "Streaming verify in progress, call verifyFinal() first");
        }
    }

    /**
     * Throw if a streaming verify started by another thread is active.
     * Caller holds stateLock.
     *
     * @throws IllegalStateException if another thread owns the stream
     */
    private void throwIfStreamOwnedByAnotherThread()
        throws IllegalStateException {

        Thread owner = null;

        if (streamingVerifyOwner != null) {
            owner = streamingVerifyOwner.get();
        }

        if (streamingVerifyActive && owner != Thread.currentThread()) {
            throw new IllegalStateException(
                "Streaming verify in progress on another thread");
        }
    }

    /**
     * Throw if no private key is loaded. Caller holds pointerLock. Native
     * export functions copy key/k without checking privKeySet on some
     * releases and would export zeros.
     *
     * @throws WolfCryptException with ECC_PRIV_KEY_E if no private key loaded
     */
    private void throwIfNoPrivateKey() throws WolfCryptException {

        if (!ed448_key_privKeySet()) {
            throw new WolfCryptException(
                WolfCryptError.ECC_PRIV_KEY_E.getCode());
        }
    }

    /**
     * Throw if no public key is loaded. Caller holds pointerLock. Native
     * wc_ed448_export_public() copies key/p without checking pubKeySet and
     * would export zeros.
     *
     * @throws WolfCryptException with PUBLIC_KEY_E if no public key loaded
     */
    private void throwIfNoPublicKey() throws WolfCryptException {

        if (!ed448_key_pubKeySet()) {
            throw new WolfCryptException(
                WolfCryptError.PUBLIC_KEY_E.getCode());
        }
    }

    /**
     * Generate Ed448 key.
     *
     * @param rng initialized Rng object
     * @param size key size, must be ED448_KEY_SIZE
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if rng is null or size is not
     *         {@link #ED448_KEY_SIZE}
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void makeKey(Rng rng, int size)
        throws WolfCryptException, IllegalStateException {

        if (rng == null) {
            throw new IllegalArgumentException("Rng cannot be null");
        }
        if (size != ED448_KEY_SIZE) {
            throw new IllegalArgumentException(
                "Key size must be " + ED448_KEY_SIZE);
        }

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_ed448_make_key(rng, size);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Generate Ed448 key of the standard size.
     *
     * @param rng initialized Rng object
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if rng is null
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void makeKey(Rng rng)
        throws WolfCryptException, IllegalStateException {

        makeKey(rng, ED448_KEY_SIZE);
    }

    /**
     * Derive public key from the loaded private key. wolfSSL also stores the
     * derived key in the object, so afterwards {@link #hasPublicKey()} is true
     * and the object can sign. {@link #ensurePublicKey()} wraps this for the
     * case where the public key may already be loaded.
     *
     * @return raw public key ({@link #ED448_PUB_KEY_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or no private
     *         key is loaded
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public byte[] makePublic()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            throwIfStreamingVerifyActive();
            synchronized (pointerLock) {
                throwIfNoPrivateKey();
                return wc_ed448_make_public();
            }
        }
    }

    /**
     * Check correctness of Ed448 key.
     *
     * @throws WolfCryptException if native operation fails or key is
     *         incorrect or invalid
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public void checkKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            throwIfStreamingVerifyActive();
            synchronized (pointerLock) {
                wc_ed448_check_key();
            }
        }
    }

    /**
     * Check whether a private key is loaded.
     *
     * @return true if a private key is loaded, false otherwise (including
     *         when no key has been loaded or the object was released, no
     *         exception so cleanup code can call it)
     */
    public boolean hasPrivateKey() {
        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                return false;
            }
            synchronized (pointerLock) {
                return ed448_key_privKeySet();
            }
        }
    }

    /**
     * Check whether a public key is loaded.
     *
     * @return true if a public key is loaded, false otherwise (including when
     *         no key has been loaded or the object was released, no
     *         exception so cleanup code can call it)
     */
    public boolean hasPublicKey() {
        synchronized (stateLock) {
            if (state != WolfCryptState.READY) {
                return false;
            }
            synchronized (pointerLock) {
                return ed448_key_pubKeySet();
            }
        }
    }

    /**
     * Derive and load the public key if only a private key is loaded. Native
     * wolfSSL cannot sign until both halves are present and does not auto
     * derive public from private internally before sign op. Call this after
     * {@link #importPrivateOnly(byte[])} before signing. Nothing is derived
     * when the public key is already loaded.
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public void ensurePublicKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            throwIfStreamingVerifyActive();
            synchronized (pointerLock) {
                if (!ed448_key_pubKeySet()) {
                    throwIfNoPrivateKey();
                    wc_ed448_make_public();
                }
            }
        }
    }

    /**
     * Get the private key size.
     *
     * @return key size in bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize or has
     *         been released
     */
    public int size()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        synchronized (stateLock) {
            throwIfReleased();
            synchronized (pointerLock) {
                return wc_ed448_size();
            }
        }
    }

    /**
     * Get the private plus public key size.
     *
     * @return size in bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize or has
     *         been released
     */
    public int privSize()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        synchronized (stateLock) {
            throwIfReleased();
            synchronized (pointerLock) {
                return wc_ed448_priv_size();
            }
        }
    }

    /**
     * Get the public key size.
     *
     * @return size in bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize or has
     *         been released
     */
    public int pubSize()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        synchronized (stateLock) {
            throwIfReleased();
            synchronized (pointerLock) {
                return wc_ed448_pub_size();
            }
        }
    }

    /**
     * Get the signature size.
     *
     * @return size in bytes
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object fails to initialize or has
     *         been released
     */
    public int sigSize()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        synchronized (stateLock) {
            throwIfReleased();
            synchronized (pointerLock) {
                return wc_ed448_sig_size();
            }
        }
    }

    /**
     * Import private and public Ed448 key.
     *
     * <p>{@code privKey} may be the {@link #ED448_KEY_SIZE}-byte secret
     * with {@code pubKey} given separately, or the
     * {@link #ED448_PRV_KEY_SIZE}-byte private-plus-public form from
     * {@link #exportPrivate()} with {@code pubKey} null. When
     * {@code pubKey} is null and {@code privKey} is the bare secret, only
     * the private key is imported (see {@link #ensurePublicKey()}).</p>
     *
     * <p>With both halves present the pair is validated on import, which
     * guards against signing with a mismatched public key. The private-only
     * form has nothing to check against.</p>
     *
     * @param privKey byte array holding private key
     * @param pubKey byte array holding public key, or null
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivate(byte[] privKey, byte[] pubKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_ed448_import_private(privKey, pubKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import private and public Ed448 key with an explicit trust flag.
     *
     * <p>With {@code trusted = false} the public key is validated against
     * the private key. With {@code trusted = true} the check is skipped.
     * Only use this for a public key that is known to belong to the private
     * key, as signing with a mismatched pair can leak the private key.</p>
     *
     * @param privKey byte array holding private key
     * @param pubKey byte array holding public key, or null (see
     *               {@link #importPrivate(byte[], byte[])})
     * @param trusted true to skip pair validation
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivateEx(byte[] privKey, byte[] pubKey,
        boolean trusted) throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_ed448_import_private_key_ex(privKey, pubKey, trusted);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import only private Ed448 key.
     *
     * @param privKey byte array holding private key bytes.
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivateOnly(byte[] privKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_ed448_import_private_only(privKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import only public Ed448 key. Validates point is on the curve.
     *
     * @param pubKey byte array holding public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPublic(byte[] pubKey)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_ed448_import_public(pubKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import only public Ed448 key with an explicit trust flag.
     * With {@code trusted = false}, this also validates the point is on the
     * curve.
     *
     * @param pubKey byte array holding public key
     * @param trusted true to skip point validation
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPublicEx(byte[] pubKey, boolean trusted)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_ed448_import_public_ex(pubKey, trusted);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Export raw private Ed448 key including public part.
     *
     * @return private key as byte array ({@link #ED448_PRV_KEY_SIZE}
     *         bytes: secret followed by public key)
     *
     * @throws WolfCryptException if native operation fails or either half
     *         of the key is not loaded
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPrivate()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            synchronized (pointerLock) {
                throwIfNoPrivateKey();
                throwIfNoPublicKey();
                return wc_ed448_export_private();
            }
        }
    }

    /**
     * Export only raw private Ed448 key.
     *
     * @return private key as byte array ({@link #ED448_KEY_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or no private
     *         key is loaded
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPrivateOnly()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            synchronized (pointerLock) {
                throwIfNoPrivateKey();
                return wc_ed448_export_private_only();
            }
        }
    }

    /**
     * Export only raw public Ed448 key.
     *
     * @return public key as byte array ({@link #ED448_PUB_KEY_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or no public
     *         key is loaded
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public byte[] exportPublic()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            synchronized (pointerLock) {
                throwIfNoPublicKey();
                return wc_ed448_export_public();
            }
        }
    }

    /**
     * Export raw private and public Ed448 keys in one call.
     *
     * @return two element array: {@code [0]} private key in the
     *         private-plus-public form ({@link #ED448_PRV_KEY_SIZE} bytes,
     *         as {@link #exportPrivate()}), {@code [1]} public key
     *         ({@link #ED448_PUB_KEY_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or either half
     *         of the key is not loaded
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[][] exportKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            synchronized (pointerLock) {
                throwIfNoPrivateKey();
                throwIfNoPublicKey();
                return wc_ed448_export_key();
            }
        }
    }

    /**
     * Single sign implementation, used in all sign methods.
     *
     * @param in message or pre-hash
     * @param type ED448_TYPE_* value, only used by FN_MSG_EX
     * @param ctx context bytes or null
     * @param fn native function selector
     *
     * @return signature bytes
     */
    private byte[] doSign(byte[] in, int type, byte[] ctx, int fn)
        throws WolfCryptException, IllegalStateException {

        if (in == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }

        checkContextLength(ctx);

        if (fn == FN_MSG_EX) {
            checkType(type);
        }

        if (fn == FN_PH_HASH || (fn == FN_MSG_EX && type == ED448_TYPE_PH)) {
            /* native takes the 64 byte pre-hash for the ph type */
            checkPrehashLength(in);
        }

        checkStateAndInitialize();

        synchronized (stateLock) {
            /* re-checked under the lock, a concurrent release must not
             * surface as a native error below */
            throwIfKeyNotLoaded();
            throwIfStreamingVerifyActive();
            synchronized (pointerLock) {
                /* wolfSSL before 5.9.2 signs with zeroed private half instead
                 * of failing */
                throwIfNoPrivateKey();
                throwIfNoPublicKey();
                switch (fn) {
                    case FN_PH_MSG:
                        return wc_ed448ph_sign_msg(in, ctx);
                    case FN_PH_HASH:
                        return wc_ed448ph_sign_hash(in, ctx);
                    case FN_MSG_EX:
                        return wc_ed448_sign_msg_ex(in, type, ctx);
                    case FN_MSG:
                    default:
                        return wc_ed448_sign_msg(in, ctx);
                }
            }
        }
    }

    /**
     * Generate Ed448 signature with an empty context.
     *
     * @param msg input data to be signed (may be empty, must not be null)
     *
     * @return signature as byte array ({@link #ED448_SIG_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or either half
     *         of the key is not loaded
     * @throws IllegalArgumentException if msg is null
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public byte[] sign(byte[] msg)
        throws WolfCryptException, IllegalStateException {

        return doSign(msg, ED448_TYPE_PURE, null, FN_MSG);
    }

    /**
     * Generate Ed448 signature with a context. Signer and verifier must
     * use the same context.
     *
     * @param msg input data to be signed (may be empty, must not be null)
     * @param ctx context bytes (may be null or empty, at most 255 bytes)
     *
     * @return signature as byte array ({@link #ED448_SIG_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or either half
     *         of the key is not loaded
     * @throws IllegalArgumentException if msg is null or ctx exceeds
     *         255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public byte[] sign(byte[] msg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doSign(msg, ED448_TYPE_PURE, ctx, FN_MSG);
    }

    /**
     * Generate Ed448ph (pre-hash) signature over a message.
     * The SHAKE256 pre-hash is computed natively.
     *
     * @param msg input data to be signed (may be empty, must not be null)
     * @param ctx context bytes (may be null or empty, at most 255 bytes)
     *
     * @return signature as byte array ({@link #ED448_SIG_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or either half
     *         of the key is not loaded
     * @throws IllegalArgumentException if msg is null or ctx exceeds
     *         255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public byte[] signPh(byte[] msg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doSign(msg, ED448_TYPE_PH, ctx, FN_PH_MSG);
    }

    /**
     * Generate Ed448ph (pre-hash) signature over a caller-computed
     * SHAKE256 hash.
     *
     * @param hash SHAKE256 digest of the message
     *             ({@link #ED448_PREHASH_SIZE} bytes)
     * @param ctx context bytes (may be null or empty, at most 255 bytes)
     *
     * @return signature as byte array ({@link #ED448_SIG_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or either half
     *         of the key is not loaded
     * @throws IllegalArgumentException if hash is not 64 bytes or ctx
     *         exceeds 255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public byte[] signPhHash(byte[] hash, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doSign(hash, ED448_TYPE_PH, ctx, FN_PH_HASH);
    }

    /**
     * Generate signature with an explicit variant.
     *
     * @param msg input data to be signed (may be empty, must not be null), or
     *            for {@link #ED448_TYPE_PH} the 64-byte SHAKE256 pre-hash
     *            of it.
     * @param type one of {@link #ED448_TYPE_PURE} or {@link #ED448_TYPE_PH}
     * @param ctx context bytes (may be null or empty, at most 255 bytes)
     *
     * @return signature as byte array ({@link #ED448_SIG_SIZE} bytes)
     *
     * @throws WolfCryptException if native operation fails or either half
     *         of the key is not loaded
     * @throws IllegalArgumentException if type is invalid or ctx exceeds
     *         255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public byte[] signEx(byte[] msg, int type, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doSign(msg, type, ctx, FN_MSG_EX);
    }

    /**
     * Single verify implementation, used by all verify methods.
     *
     * @param sig signature bytes
     * @param in message or pre-hash
     * @param type ED448_TYPE_* value, only used by FN_MSG_EX
     * @param ctx context bytes or null
     * @param fn native function selector
     *
     * @return true if the signature verifies, false if it does not or has
     *         the wrong length
     */
    private boolean doVerify(byte[] sig, byte[] in, int type, byte[] ctx,
        int fn) throws WolfCryptException, IllegalStateException {

        if (sig == null) {
            throw new IllegalArgumentException("Signature cannot be null");
        }

        if (in == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }

        checkContextLength(ctx);

        if (fn == FN_MSG_EX) {
            checkType(type);
        }

        if (fn == FN_PH_HASH || (fn == FN_MSG_EX && type == ED448_TYPE_PH)) {
            /* native takes the 64 byte pre-hash for the ph type */
            checkPrehashLength(in);
        }

        checkStateAndInitialize();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            throwIfStreamingVerifyActive();

            /* Wrong-length signature can never verify, return false */
            if (sig.length != ED448_SIG_SIZE) {
                return false;
            }

            synchronized (pointerLock) {
                throwIfNoPublicKey();
                switch (fn) {
                    case FN_PH_MSG:
                        return wc_ed448ph_verify_msg(sig, in, ctx);
                    case FN_PH_HASH:
                        return wc_ed448ph_verify_hash(sig, in, ctx);
                    case FN_MSG_EX:
                        return wc_ed448_verify_msg_ex(sig, in, type, ctx);
                    case FN_MSG:
                    default:
                        return wc_ed448_verify_msg(sig, in, ctx);
                }
            }
        }
    }

    /**
     * Verify Ed448 signature made with an empty context.
     *
     * @param sig signature to verify
     * @param msg input data that was signed (may be empty, must not be null)
     *
     * @return true if signature verified, otherwise false (including a
     *         signature of the wrong length)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if sig or msg is null
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public boolean verify(byte[] sig, byte[] msg)
        throws WolfCryptException, IllegalStateException {

        return doVerify(sig, msg, ED448_TYPE_PURE, null, FN_MSG);
    }

    /**
     * Verify Ed448 signature made with a context.
     *
     * @param sig signature to verify
     * @param msg input data that was signed (may be empty, must not be null)
     * @param ctx context bytes used when signing (may be null or empty)
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if sig or msg is null or ctx
     *         exceeds 255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public boolean verify(byte[] sig, byte[] msg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doVerify(sig, msg, ED448_TYPE_PURE, ctx, FN_MSG);
    }

    /**
     * Verify Ed448ph (pre-hash) signature over a message.
     *
     * @param sig signature to verify
     * @param msg input data that was signed (may be empty, must not be null)
     * @param ctx context bytes used when signing (may be null or empty)
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if sig or msg is null or ctx
     *         exceeds 255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public boolean verifyPh(byte[] sig, byte[] msg, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doVerify(sig, msg, ED448_TYPE_PH, ctx, FN_PH_MSG);
    }

    /**
     * Verify Ed448ph (pre-hash) signature over a caller-computed SHAKE256 hash.
     *
     * @param sig signature to verify
     * @param hash SHAKE256 digest of the message
     *             ({@link #ED448_PREHASH_SIZE} bytes)
     * @param ctx context bytes used when signing (may be null or empty)
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if hash is not 64 bytes or ctx
     *         exceeds 255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public boolean verifyPhHash(byte[] sig, byte[] hash, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doVerify(sig, hash, ED448_TYPE_PH, ctx, FN_PH_HASH);
    }

    /**
     * Verify signature with an explicit variant.
     *
     * @param sig signature to verify
     * @param msg input data that was signed (may be empty, must not be null),
     *            or for {@link #ED448_TYPE_PH} the 64-byte SHAKE256 pre-hash
     *            of it.
     * @param type {@link #ED448_TYPE_PURE} or {@link #ED448_TYPE_PH}
     * @param ctx context bytes used when signing (may be null or empty)
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if type is invalid or ctx exceeds
     *         255 bytes
     * @throws IllegalStateException if key has not been set, if a streaming
     *         verify is in progress, if object fails to initialize, or if
     *         releaseNativeStruct() has been called and object has been
     *         released.
     */
    public boolean verifyEx(byte[] sig, byte[] msg, int type, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        return doVerify(sig, msg, type, ctx, FN_MSG_EX);
    }

    /**
     * Drop an active streaming verify without finishing it, so the object
     * is usable again after a thread abandoned a stream. Any thread may
     * call it.
     */
    public void verifyAbort() {
        synchronized (stateLock) {
            streamingVerifyActive = false;
            streamingVerifyFailed = false;
            streamingVerifyOwner = null;
        }
    }

    /**
     * Begin a streaming verify.
     *
     * Requires native wolfSSL built with WOLFSSL_ED448_STREAMING_VERIFY.
     * Feed the message with verifyUpdate(byte[]) and finish with
     * verifyFinal(byte[]). For ED448_TYPE_PH the data fed through
     * verifyUpdate() must be the 64-byte SHAKE256 pre-hash of the message, not
     * the message itself. One-shot sign and verify calls on this object are
     * rejected until verifyFinal(byte[]) completes. The pre-hash length is not
     * validated on the streaming path, a wrong-sized input fails to verify. A
     * signature rejected as malformed is remembered and verifyFinal(byte[])
     * returns false, like the one-shot verify. A started stream stays active
     * until verifyFinal() or another verifyInit(). A verifyInit() rejected by
     * argument or state checks leaves an earlier stream active, only a failure
     * inside the native call clears it. The stream is bound to the thread that
     * started it: verifyUpdate(), verifyFinal(), and a restarting verifyInit()
     * from another thread throw IllegalStateException, so each concurrently
     * verifying thread needs its own object. An abandoned stream blocks
     * streaming and one-shot calls on every thread until verifyAbort().
     *
     * @param sig signature to verify (ED448_SIG_SIZE bytes)
     * @param type ED448_TYPE_PURE or ED448_TYPE_PH
     * @param ctx context bytes (may be null or empty, at most 255 bytes)
     *
     * @throws WolfCryptException if native operation fails or streaming
     *         verify is not compiled in
     * @throws IllegalArgumentException if sig is null or not ED448_SIG_SIZE
     *         bytes, type is invalid or ctx exceeds 255 bytes
     * @throws IllegalStateException if key has not been set, if another
     *         thread's streaming verify is active, if object fails to
     *         initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public void verifyInit(byte[] sig, int type, byte[] ctx)
        throws WolfCryptException, IllegalStateException {

        if (sig == null) {
            throw new IllegalArgumentException("Signature cannot be null");
        }

        if (sig.length != ED448_SIG_SIZE) {
            throw new IllegalArgumentException(
                "Signature must be " + ED448_SIG_SIZE + " bytes");
        }

        checkType(type);
        checkContextLength(ctx);
        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            throwIfStreamOwnedByAnotherThread();
            synchronized (pointerLock) {
                throwIfNoPublicKey();
                streamingVerifyActive = false;
                streamingVerifyFailed = false;
                streamingVerifyOwner = null;
                try {
                    wc_ed448_verify_msg_init(sig, type, ctx);
                }
                catch (WolfCryptException e) {
                    /* malformed signature, verifyFinal() returns false */
                    if (e.getError() != WolfCryptError.SIG_VERIFY_E) {
                        throw e;
                    }
                    streamingVerifyFailed = true;
                }
                streamingVerifyActive = true;
                streamingVerifyOwner =
                    new WeakReference<Thread>(Thread.currentThread());
            }
        }
    }

    /**
     * Feed a message segment to a streaming verify. After verifyInit()
     * rejected the signature the segment is ignored and verifyFinal() returns
     * false. If this method throws, the stream stays active until
     * verifyFinal() (which returns false) or verifyAbort().
     *
     * @param seg message segment (may be empty, must not be null)
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if seg is null
     * @throws IllegalStateException if verifyInit(byte[], int, byte[]) has
     *         not been called on this thread, no key is loaded, or object has
     *         been released
     */
    public void verifyUpdate(byte[] seg)
        throws WolfCryptException, IllegalStateException {

        if (seg == null) {
            throw new IllegalArgumentException("Segment cannot be null");
        }

        verifyUpdate(seg, 0, seg.length);
    }

    /**
     * Feed part of a message segment to a streaming verify.
     *
     * @param seg message segment buffer
     * @param offset offset into seg
     * @param len number of bytes to use from offset
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if seg is null or offset/len are out
     *         of bounds
     * @throws IllegalStateException if verifyInit(byte[], int, byte[]) has
     *         not been called on this thread, no key is loaded, or object has
     *         been released
     */
    public void verifyUpdate(byte[] seg, int offset, int len)
        throws WolfCryptException, IllegalStateException {

        if (seg == null || offset < 0 || len < 0 ||
            offset > seg.length || len > seg.length - offset) {
            throw new IllegalArgumentException(
                "Invalid segment, offset or length");
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            if (!streamingVerifyActive) {
                throw new IllegalStateException(
                    "verifyInit() has not been called");
            }
            throwIfStreamOwnedByAnotherThread();
            throwIfKeyNotLoaded();
            if (streamingVerifyFailed) {
                /* rejected in verifyInit(), verifyFinal() returns false */
                return;
            }
            synchronized (pointerLock) {
                try {
                    wc_ed448_verify_msg_update(seg, offset, len);
                }
                catch (WolfCryptException e) {
                    streamingVerifyFailed = true;
                    throw e;
                }
            }
        }
    }

    /**
     * Finish a streaming verify.
     *
     * The streaming state is cleared whether or not the signature verifies.
     *
     * @param sig signature to verify, the same bytes given to
     *            {@link #verifyInit(byte[], int, byte[])}
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalArgumentException if sig is null
     * @throws IllegalStateException if verifyInit(byte[], int, byte[]) has
     *         not been called on this thread, no key is loaded, or object has
     *         been released
     */
    public boolean verifyFinal(byte[] sig)
        throws WolfCryptException, IllegalStateException {

        if (sig == null) {
            throw new IllegalArgumentException("Signature cannot be null");
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            if (!streamingVerifyActive) {
                throw new IllegalStateException(
                    "verifyInit() has not been called");
            }
            throwIfStreamOwnedByAnotherThread();
            try {
                throwIfKeyNotLoaded();

                if (sig.length != ED448_SIG_SIZE || streamingVerifyFailed) {
                    return false;
                }

                synchronized (pointerLock) {
                    return wc_ed448_verify_msg_final(sig);
                }
            }
            finally {
                streamingVerifyActive = false;
                streamingVerifyFailed = false;
                streamingVerifyOwner = null;
            }
        }
    }

    /**
     * Import public key from X.509 SubjectPublicKeyInfo DER.
     *
     * @param der SubjectPublicKeyInfo DER
     *
     * @throws WolfCryptException if native operation fails or DER is not
     *         an Ed448 SubjectPublicKeyInfo
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPublicKeyDer(byte[] der)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_Ed448PublicKeyDecode(der);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import private key from PKCS#8 DER.
     *
     * Accepts both v1 (private key only) and v2 forms. When the encoding
     * carries no public key it is derived and loaded so the object is
     * immediately usable for signing. If derivation fails, the exception
     * propagates but private key stays loaded, ensurePublicKey() retries it.
     *
     * @param der PKCS#8 PrivateKeyInfo / OneAsymmetricKey DER
     *
     * @throws WolfCryptException if native operation fails or DER is not an
     *         Ed448 PKCS#8 key
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivateKeyDer(byte[] der)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            throwIfReleased();
            throwIfKeyExists();
            synchronized (pointerLock) {
                wc_Ed448PrivateKeyDecode(der);
            }
            /* Private key is loaded natively. Mark READY before deriving
             * public half so a failed derive leaves a private-only key like
             * importPrivateOnly() does. */
            state = WolfCryptState.READY;
            synchronized (pointerLock) {
                if (!ed448_key_pubKeySet()) {
                    /* Derive public key from PKCS#8 v1 private */
                    throwIfNoPrivateKey();
                    wc_ed448_make_public();
                }
            }
        }
    }

    /**
     * Export public key as DER.
     *
     * @param withAlg true for a full X.509 SubjectPublicKeyInfo, false for
     *                the raw public key bytes only
     *
     * @return DER encoded public key
     *
     * @throws WolfCryptException if native operation fails or no public key
     *         is loaded
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public byte[] exportPublicKeyDer(boolean withAlg)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            synchronized (pointerLock) {
                throwIfNoPublicKey();
                return wc_Ed448PublicKeyToDer(withAlg);
            }
        }
    }

    /**
     * Export private key as PKCS#8 v1 DER (RFC 8410 form), private key only.
     *
     * @return PKCS#8 DER
     *
     * @throws WolfCryptException if native operation fails or no private key
     *         is loaded
     * @throws IllegalStateException if key has not been set, if object fails
     *         to initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public byte[] exportPrivateKeyDer()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            synchronized (pointerLock) {
                throwIfNoPrivateKey();
                return wc_Ed448PrivateKeyToDer();
            }
        }
    }

    /**
     * Export private key as PKCS#8 DER, optionally including the public key.
     *
     * With {@code withPublicKey} the RFC 5958 v2 OneAsymmetricKey form is
     * produced, deriving and retaining the public key first if it is not
     * loaded (as ensurePublicKey() does). Note that some decoders reject the
     * v2 form.
     *
     * @param withPublicKey true to include
     *
     * @return PKCS#8 DER
     *
     * @throws WolfCryptException if native operation fails or no private key
     *         is loaded
     * @throws IllegalStateException if key has not been set, if
     *         withPublicKey is true and a streaming verify is in progress,
     *         if object fails to
     *         initialize, or if releaseNativeStruct() has been called and
     *         object has been released.
     */
    public byte[] exportPrivateKeyDer(boolean withPublicKey)
        throws WolfCryptException, IllegalStateException {

        if (!withPublicKey) {
            return exportPrivateKeyDer();
        }

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (stateLock) {
            throwIfKeyNotLoaded();
            throwIfStreamingVerifyActive();
            synchronized (pointerLock) {
                throwIfNoPrivateKey();
                if (!ed448_key_pubKeySet()) {
                    /* Derive public half for v2 form under export lock */
                    wc_ed448_make_public();
                }
                return wc_Ed448KeyToDer();
            }
        }
    }
}
