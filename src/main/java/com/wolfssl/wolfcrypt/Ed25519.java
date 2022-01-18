/* Ed25519.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.wolfcrypt;

import java.security.InvalidAlgorithmParameterException;

/**
 * Wrapper for the native WolfCrypt Ed25519 implementation
 */
public class Ed25519 extends NativeStruct {

    private WolfCryptState state = WolfCryptState.UNINITIALIZED;

    /**
     * Create new Ed25519 object
     */
    public Ed25519() {
        init();
    }

    @Override
    public void releaseNativeStruct() {
        free();

        super.releaseNativeStruct();
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
     * Initialize Ed25519 object
     */
    protected void init() {
        if (state == WolfCryptState.UNINITIALIZED) {
            wc_ed25519_init();
            state = WolfCryptState.INITIALIZED;
        } else {
            throw new IllegalStateException(
                    "Native resources already initialized.");
        }
    }

    /**
     * Free Ed25519 object
     */
    protected void free() {
        if (state != WolfCryptState.UNINITIALIZED) {
            wc_ed25519_free();
            state = WolfCryptState.UNINITIALIZED;
        }
    }

    /**
     * Generate Ed25519 key
     *
     * @param rng initialized Rng object
     * @param size key size
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object already has a key
     */
    public void makeKey(Rng rng, int size) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_ed25519_make_key(rng, size);
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

    /**
     * Check correctness of Ed25519 key
     *
     * @throws WolfCryptException if native operation fails or key is
     *         incorrect or invalid
     * @throws IllegalStateException if object does not have a key
     */
    public void checkKey() {
        if (state == WolfCryptState.READY) {
            wc_ed25519_check_key();
        } else {
            throw new IllegalStateException(
                    "No available key to perform the operation.");
        }
    }

    /**
     * Import private and public Ed25519 key
     *
     * @param privKey byte array holding private key
     * @param Key byte array holding public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object already has a key
     */
    public void importPrivate(byte[] privKey, byte[] Key) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_ed25519_import_private(privKey, Key);
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

    /**
     * Import only private Ed25519 key
     *
     * @param privKey byte array holding private key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object already has a key
     */
    public void importPrivateOnly(byte[] privKey) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_ed25519_import_private_only(privKey);
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

    /**
     * Import only public Ed25519 key
     *
     * @param Key byte array holding public key
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object already has a key
     */
    public void importPublic(byte[] Key) {
        if (state == WolfCryptState.INITIALIZED) {
            wc_ed25519_import_public(Key);
            state = WolfCryptState.READY;
        } else {
            throw new IllegalStateException("Object already has a key.");
        }
    }

    /**
     * Export raw private Ed25519 key including public part
     *
     * @return private key as byte array, including public part
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public byte[] exportPrivate() {
        if (state == WolfCryptState.READY) {
            return wc_ed25519_export_private();
        } else {
            throw new IllegalStateException(
                    "No available key to perform the operation.");
        }
    }

    /**
     * Export only raw private Ed25519 key
     *
     * @return private key as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public byte[] exportPrivateOnly() {
        if (state == WolfCryptState.READY) {
            return wc_ed25519_export_private_only();
        } else {
            throw new IllegalStateException(
                    "No available key to perform the operation.");
        }
    }

    /**
     * Export only raw public Ed25519 key
     *
     * @return public key as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public byte[] exportPublic() {
        if (state == WolfCryptState.READY) {
            return wc_ed25519_export_public();
        } else {
            throw new IllegalStateException(
                    "No available key to perform the operation.");
        }
    }

    /**
     * Generate Ed25519 signature
     *
     * @param msg_in input data to be signed
     *
     * @return signature as byte array
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public byte[] sign_msg(byte[] msg_in) {

        byte[] msg_out = null;
        if (state == WolfCryptState.READY) {
            msg_out = wc_ed25519_sign_msg(msg_in);
        } else {
            throw new IllegalStateException(
                    "No available key to perform the operation.");
        }

        return msg_out;
    }

    /**
     * Verify Ed25519 signature
     *
     * @param msg input data to be verified
     * @param signature input signature to verify
     *
     * @return true if signature verified, otherwise false
     *
     * @throws WolfCryptException if native operation fails
     * @throws IllegalStateException if object has no key
     */
    public boolean verify_msg(byte[] msg, byte[] signature) {
        boolean result = false;

        if (state == WolfCryptState.READY) {
            result = wc_ed25519_verify_msg(signature, msg);
        } else {
            throw new IllegalStateException(
                    "No available key to perform the operation.");
        }

        return result;
    }
}

