/* Lms.java
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
 * Wrapper for the native wolfCrypt LMS/HSS (RFC 8554) verification API.
 *
 * <p>Mirrors the verify-only subset of the native wolfCrypt
 * {@code wc_LmsKey_*} API. LMS is a stateful hash-based signature scheme. HSS
 * is its multi-level (hierarchical) variant. wolfJCE exposes verification
 * only: stateful signing and key generation belong in hardware (NIST SP
 * 800-208), matching the verify-only JDK SUN provider.</p>
 *
 * <p>A verify-only key is created with the no-argument constructor
 * {@link #Lms()} and {@link #importPublicRaw(byte[])}. The parameter set is
 * derived from the imported public key. Signatures are checked with
 * {@link #verify(byte[], byte[])}.</p>
 *
 * <p>Native wolfCrypt LMS keys are not thread-safe. Callers must serialize all
 * operations on a given {@code Lms} instance. This class synchronizes its
 * native calls but concurrent use of one key from multiple threads is not
 * supported.</p>
 */
public class Lms extends NativeStruct {

    /* Hash-family selectors, mirror native wc_lms.h LMS_* values reported by
     * wc_LmsKey_GetParameters_ex(). The low bits encode the LMS/LM-OTS type.
     * These high-bit values select the hash family. */

    /** SHA-256/256 hash family (RFC 8554 default). */
    public static final int LMS_SHA256 = 0x0000;

    /** SHA-256/192 hash family (NIST SP 800-208, 192-bit truncation). */
    public static final int LMS_SHA256_192 = 0x1000;

    /** SHAKE256/256 hash family (NIST SP 800-208). Requires native SHA-3. */
    public static final int LMS_SHAKE256 = 0x2000;

    /** SHAKE256/192 hash family (NIST SP 800-208). Requires native SHA-3. */
    public static final int LMS_SHAKE256_192 = 0x3000;

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /** Lock around object state. */
    protected final Object stateLock = new Object();

    /* Parameter set, filled in from the imported public key. Volatile so
     * getters see the latest value after an import refresh. */
    private volatile int levels;
    private volatile int height;
    private volatile int winternitz;
    private volatile int hashType;

    /**
     * Create a new verify-only LMS/HSS key.
     *
     * <p>The parameter set is derived from the public key supplied to
     * {@link #importPublicRaw(byte[])}.</p>
     *
     * @throws WolfCryptException if LMS is not compiled into native wolfCrypt
     */
    public Lms() throws WolfCryptException {

        if (!FeatureDetect.LmsEnabled()) {
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
                    wc_LmsKey_free();
                }
                super.releaseNativeStruct();
                state = WolfCryptState.RELEASED;
            }
        }
    }

    /**
     * Allocate native LmsKey context struct.
     *
     * @return native allocated pointer
     *
     * @throws OutOfMemoryError when malloc fails
     */
    protected native long mallocNativeStruct() throws OutOfMemoryError;

    private native void wc_LmsKey_init();
    private native void wc_LmsKey_free();
    private native int[] wc_LmsKey_get_parameters();
    private native boolean wc_LmsKey_verify(byte[] sig, byte[] msg);
    private native void wc_LmsKey_import_public(byte[] in);

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
                    wc_LmsKey_init();
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

        int[] params;

        synchronized (pointerLock) {
            params = wc_LmsKey_get_parameters();
        }

        if (params != null && params.length == 4) {
            this.levels = params[0];
            this.height = params[1];
            this.winternitz = params[2];
            this.hashType = params[3];
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
            return wc_LmsKey_verify(sig, msg);
        }
    }

    /**
     * Import a raw HSS/LMS public key (RFC 8554 wire format) for verification.
     *
     * <p>The parameter set is derived from the imported key.</p>
     *
     * @param in raw public key bytes
     *
     * @throws WolfCryptException if the native operation fails
     * @throws IllegalStateException if a key is already loaded or object
     *         released
     */
    public void importPublicRaw(byte[] in)
        throws WolfCryptException, IllegalStateException {

        checkStateAndInitialize();
        throwIfKeyExists();

        synchronized (stateLock) {
            synchronized (pointerLock) {
                wc_LmsKey_import_public(in);
            }
            refreshParameters();
            state = WolfCryptState.READY;
        }
    }

    /**
     * Get the number of HSS levels for this key's parameter set.
     *
     * @return number of levels (1 for single-tree LMS), or 0 if not yet known
     *         (before a public key has been imported)
     */
    public int getLevels() {
        return this.levels;
    }

    /**
     * Get the per-level Merkle tree height for this key's parameter set.
     *
     * @return tree height, or 0 if not yet known
     */
    public int getHeight() {
        return this.height;
    }

    /**
     * Get the LM-OTS Winternitz parameter for this key's parameter set.
     *
     * @return Winternitz parameter, or 0 if not yet known
     */
    public int getWinternitz() {
        return this.winternitz;
    }

    /**
     * Get the hash family selector for this key's parameter set.
     *
     * @return one of {@link #LMS_SHA256}, {@link #LMS_SHA256_192},
     *         {@link #LMS_SHAKE256}, {@link #LMS_SHAKE256_192}
     */
    public int getHashType() {
        return this.hashType;
    }
}
