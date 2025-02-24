/* Ed25519.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * Wrapper for the native WolfCrypt Ed25519 implementation
 */
public class Ed25519 extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state */
    protected final Object stateLock = new Object();

    /**
     * Create new Ed25519 object.
     *
     * @throws WolfCryptException if Ed25519 has not been compiled into native
     *         wolfCrypt library.
     */
    public Ed25519() {
        if (!FeatureDetect.Ed25519Enabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Internal state is initialized on first use */
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_ed25519_free();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Malloc native JNI Ed25519 structure
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails with memory error
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_ed25519_init();
    private native void wc_ed25519_free();
    private native void wc_ed25519_make_key(Rng rng, int size);
    private native void wc_ed25519_check_key();
    private native void wc_ed25519_import_private(byte[] privKey, byte[] key);
    private native void wc_ed25519_import_private_only(byte[] privKey);
    private native void wc_ed25519_import_public(byte[] privKey);
    private native byte[] wc_ed25519_sign_msg(byte[] msg);
    private native boolean wc_ed25519_verify_msg(byte[] sig, byte[] msg);
    private native byte[] wc_ed25519_export_private();
    private native byte[] wc_ed25519_export_private_only();
    private native byte[] wc_ed25519_export_public();

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
     * Initialize Ed25519 object
     */
    private void init() {
        synchronized (pointerLock) {
            /* Allocate native struct pointer from NativeStruct */
            initNativeStruct();
            wc_ed25519_init();
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
     * Generate Ed25519 key.
     *
     * @param rng initialized Rng object
     * @param size key size
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void makeKey(Rng rng, int size)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_ed25519_make_key(rng, size);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Check correctness of Ed25519 key.
     *
     * @throws WolfCryptException if native operation fails or key is
     *         incorrect or invalid
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void checkKey()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            wc_ed25519_check_key();
        }
    }

    /**
     * Import private and public Ed25519 key.
     *
     * @param privKey byte array holding private key
     * @param Key byte array holding public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPrivate(byte[] privKey, byte[] Key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_ed25519_import_private(privKey, Key);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import only private Ed25519 key.
     *
     * @param privKey byte array holding private key
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
            synchronized (pointerLock) {
                wc_ed25519_import_private_only(privKey);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Import only public Ed25519 key.
     *
     * @param Key byte array holding public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has already been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public void importPublic(byte[] Key)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_ed25519_import_public(Key);
            }
            state = WolfCryptState.READY;
        }
    }

    /**
     * Export raw private Ed25519 key including public part.
     *
     * @return private key as byte array, including public part
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPrivate()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ed25519_export_private();
        }
    }

    /**
     * Export only raw private Ed25519 key.
     *
     * @return private key as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPrivateOnly()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ed25519_export_private_only();
        }
    }

    /**
     * Export only raw public Ed25519 key.
     *
     * @return public key as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] exportPublic()
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ed25519_export_public();
        }
    }

    /**
     * Generate Ed25519 signature.
     *
     * @param msg_in input data to be signed
     *
     * @return signature as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public byte[] sign_msg(byte[] msg_in)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ed25519_sign_msg(msg_in);
        }
    }

    /**
     * Verify Ed25519 signature.
     *
     * @param msg input data to be verified
     * @param signature input signature to verify
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if key has not been set, if object
     *         fails to initialize, or if releaseNativeStruct() has been
     *         called and object has been released.
     */
    public boolean verify_msg(byte[] msg, byte[] signature)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_ed25519_verify_msg(signature, msg);
        }
    }
}

