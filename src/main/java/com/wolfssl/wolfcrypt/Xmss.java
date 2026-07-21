/* Xmss.java
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

/**
 * Wrapper for the native wolfCrypt XMSS/XMSS^MT (RFC 8391) verification API.
 *
 * <p>Mirrors the verify-only subset of the native wolfCrypt
 * {@code wc_XmssKey_*} API. XMSS is a stateful hash-based signature scheme.
 * XMSS^MT is its multi-tree (hypertree) variant. wolfJCE exposes verification
 * only: stateful signing and key generation belong in hardware (NIST SP
 * 800-208).</p>
 *
 * <p>A verify-only key is created with the no-argument constructor
 * {@link #Xmss()} and {@link #importPublicRaw(byte[], boolean)}. The
 * parameter set is derived from the imported public key. Signatures are
 * checked with {@link #verify(byte[], byte[])}.</p>
 *
 * <p>Native wolfCrypt XMSS keys are not thread-safe. Callers must serialize
 * all operations on a given {@code Xmss} instance. This class synchronizes its
 * native calls but concurrent use of one key from multiple threads is not
 * supported.</p>
 */
public class Xmss extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state. */
    protected final Object stateLock = new Object();

    /* Parameter set string, filled in from the imported public key (for
     * example "XMSS-SHA2_10_256" or "XMSSMT-SHA2_20/2_256"). Volatile so
     * getters see the latest value after an import refresh. */
    private volatile String paramStr = null;

    /* Authoritative family of the loaded key, recorded from the isXmssMt flag
     * passed to importPublicRaw() (the X.509 OID), rather than re-derived from
     * the native parameter string. */
    private volatile boolean isMultiTree = false;

    /**
     * Create a new verify-only XMSS/XMSS^MT key.
     *
     * <p>The parameter set is derived from the public key supplied to
     * {@link #importPublicRaw(byte[], boolean)}.</p>
     *
     * @throws WolfCryptException if XMSS is not compiled into native wolfCrypt
     */
    public Xmss() throws WolfCryptException {

        if (!FeatureDetect.XmssEnabled()) {
            throw new WolfCryptException(
                WolfCryptError.NOT_COMPILED_IN.getCode());
        }
        /* Parameters are filled in from an imported public key. */
    }

    @Override
    public void releaseNativeStruct() {
        synchronized (stateLock) {
            if ((state != WolfCryptState.UNINITIALIZED) &&
                (state != WolfCryptState.RELEASED)) {

                synchronized (pointerLock) {
                    wc_XmssKey_free();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Allocate native XmssKey context struct.
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_XmssKey_init();
    private native void wc_XmssKey_free();
    private native String wc_XmssKey_get_param_str();
    private native boolean wc_XmssKey_verify(byte[] sig, byte[] msg);
    private native void wc_XmssKey_import_public(byte[] in, boolean isXmssMt);

    /**
     * Allocate, initialize, and (for a verify-only key) leave the parameter
     * set to be derived from an imported public key. State advances
     * UNINITIALIZED to INITIALIZED on success.
     *
     * @throws IllegalStateException if releaseNativeStruct() has been called
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
                    wc_XmssKey_init();
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
     * Refresh the cached parameter set from the native key. Used after an
     * import where native has derived the parameter set.
     */
    private void refreshParameters() {

        synchronized (pointerLock) {
            this.paramStr = wc_XmssKey_get_param_str();
        }
    }

    /**
     * Verify a signature over a message.
     *
     * @param sig signature to verify
     * @param msg message bytes
     *
     * @return true if the signature verifies, false otherwise
     *
     * @throws WolfCryptException if the native operation fails
     * @throws IllegalStateException if no key is loaded or object released
     */
    public boolean verify(byte[] sig, byte[] msg)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyNotLoaded();

        synchronized (pointerLock) {
            return wc_XmssKey_verify(sig, msg);
        }
    }

    /**
     * Import a raw XMSS/XMSS^MT public key (RFC 8391 wire format) for
     * verification.
     *
     * <p>The raw public key is the 4-byte big-endian parameter-set OID
     * followed by the root node and public SEED. The specific parameter set
     * is derived from that OID prefix, but the raw key does not indicate
     * whether it is single-tree XMSS or multi-tree XMSS^MT: the two parameter
     * registries share the same OID numbers, so the caller must specify the
     * family via {@code isXmssMt}. This is normally taken from the X.509
     * AlgorithmIdentifier OID (RFC 9802 id-alg-xmss-hashsig 1.3.6.1.5.5.7.6.34
     * vs id-alg-xmssmt-hashsig 1.3.6.1.5.5.7.6.35).</p>
     *
     * @param in raw public key bytes
     * @param isXmssMt true if the key is a multi-tree XMSS^MT key, false for
     *        single-tree XMSS
     *
     * @throws WolfCryptException if the native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPublicRaw(byte[] in, boolean isXmssMt)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_XmssKey_import_public(in, isXmssMt);
            }
            this.isMultiTree = isXmssMt;
            refreshParameters();
            state = WolfCryptState.READY;
        }
    }

    /**
     * Get the parameter set string for this key.
     *
     * @return the RFC 8391 parameter set name (for example
     *         "XMSS-SHA2_10_256" or "XMSSMT-SHA2_20/2_256"), or null if not
     *         yet known (before a public key has been imported)
     */
    public String getParamStr() {
        return this.paramStr;
    }

    /**
     * Determine whether this key uses a multi-tree XMSS^MT parameter set.
     *
     * @return true if the parameter set is XMSS^MT, false if single-tree XMSS
     *         or not yet known
     */
    public boolean isXmssMt() {
        return this.isMultiTree;
    }
}
