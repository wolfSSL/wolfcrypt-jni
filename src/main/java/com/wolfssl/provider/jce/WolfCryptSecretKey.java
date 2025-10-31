/* WolfCryptSecretKey.java
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

package com.wolfssl.provider.jce;

import java.util.Arrays;
import java.util.Objects;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import javax.crypto.SecretKey;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Des3;

/**
 * wolfCrypt SecretKey implementation for symmetric algorithms.
 *
 * Supports AES and 3DES/DESede algorithms with key size validation.
 */
public class WolfCryptSecretKey implements SecretKey {

    private static final long serialVersionUID = 1L;

    /** Encoded key byte array */
    private byte[] encoded = null;

    /** Key algorithm name */
    private String algorithm = null;

    /** Has object been destroyed or not */
    private boolean destroyed = false;

    /**
     * Create new WolfCryptSecretKey object.
     *
     * @param algorithm key algorithm name ("AES", "DESede")
     * @param encoded encoded key byte array
     *
     * @throws InvalidKeyException if algorithm is null/empty,
     *       encoded is null/zero length, or key size is invalid
     */
    public WolfCryptSecretKey(String algorithm, byte[] encoded)
        throws InvalidKeyException {

        if (algorithm == null || algorithm.isEmpty()) {
            throw new InvalidKeyException(
                "Algorithm String cannot be null or empty");
        }

        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeyException(
                "Encoded key cannot be null or zero length");
        }

        /* Validate key size based on algorithm. Sanitize matching wolfCrypt
         * aes.c and des3.c input sizes. */
        if (algorithm.equalsIgnoreCase("AES")) {
            if (encoded.length != Aes.KEY_SIZE_128 &&
                encoded.length != Aes.KEY_SIZE_192 &&
                encoded.length != Aes.KEY_SIZE_256) {
                throw new InvalidKeyException(
                    "AES key must be 16, 24, or 32 bytes, got: " +
                    encoded.length);
            }
        }
        else if (algorithm.equalsIgnoreCase("DESede") ||
                 algorithm.equalsIgnoreCase("TripleDES")) {
            if (encoded.length != Des3.KEY_SIZE) {
                throw new InvalidKeyException(
                    "DESede key must be 24 bytes, got: " + encoded.length);
            }
        }
        else {
            throw new InvalidKeyException(
                "Unsupported algorithm: " + algorithm);
        }

        this.algorithm = algorithm;
        this.encoded = encoded.clone();
    }

    /**
     * Check if this object has been destroyed with destroy().
     * Must be called from synchronized context.
     *
     * @throws IllegalStateException if object has been destroyed
     */
    private void checkDestroyed()
        throws IllegalStateException {

        if (this.destroyed) {
            throw new IllegalStateException(
                "SecretKey has been destroyed");
        }
    }

    /**
     * Return algorithm String representing this SecretKey.
     *
     * @return algorithm string matching this object
     *
     * @throws IllegalStateException if object has been destroyed
     */
    @Override
    public synchronized String getAlgorithm() {

        checkDestroyed();

        return this.algorithm;
    }

    /**
     * Return encoding format for this SecretKey.
     *
     * @return encoding format string, will be "RAW" for this object
     *
     * @throws IllegalStateException if object has been destroyed
     */
    @Override
    public synchronized String getFormat() {

        checkDestroyed();

        return "RAW";
    }

    /**
     * Return encoded byte array of this SecretKey.
     *
     * @return encoded byte array
     *
     * @throws IllegalStateException if object has been destroyed
     */
    @Override
    public synchronized byte[] getEncoded() {

        checkDestroyed();

        return this.encoded.clone();
    }

    /**
     * Destroy this object.
     *
     * Zeroize key bytes contained in this object and mark it as unusable.
     */
    @Override
    public synchronized void destroy() {

        if (this.encoded != null) {
            Arrays.fill(this.encoded, (byte)0);
            this.encoded = null;
        }

        this.algorithm = null;
        this.destroyed = true;
    }

    /**
     * Return if this object has been destroyed.
     *
     * Object can be destroyed by calling destroy(), which will zeroize
     * internal buffers for this object.
     *
     * @return true if object has been destroyed, otherwise false
     */
    @Override
    public synchronized boolean isDestroyed() {
        return this.destroyed;
    }

    @Override
    public synchronized int hashCode() {
        checkDestroyed();
        return Arrays.hashCode(encoded);
    }

    @Override
    public synchronized boolean equals(Object obj) {

        byte[] sKeyEncoded = null;
        byte[] thisEncoded = null;
        SecretKey sKey;

        checkDestroyed();

        if (obj == this) {
            return true;
        }

        if (!(obj instanceof SecretKey)) {
            return false;
        }
        sKey = (SecretKey)obj;

        try {
            sKeyEncoded = sKey.getEncoded();
            thisEncoded = getEncoded();

            if (sKeyEncoded == null || thisEncoded == null) {
                return false;
            }

            /* MessageDigest.isEqual() for constant-time comparison */
            if (!MessageDigest.isEqual(sKeyEncoded, thisEncoded)) {
                return false;
            }

            if (!Objects.equals(sKey.getAlgorithm(), getAlgorithm())) {
                return false;
            }

            if (!Objects.equals(sKey.getFormat(), getFormat())) {
                return false;
            }

            return true;

        } catch (Exception e) {
            /* If encoding fails for either key, cannot be equal */
            return false;

        } finally {
            if (sKeyEncoded != null) {
                Arrays.fill(sKeyEncoded, (byte)0);
            }
            if (thisEncoded != null) {
                Arrays.fill(thisEncoded, (byte)0);
            }
        }
    }
}

