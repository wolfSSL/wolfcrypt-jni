/* WolfCryptPBEKey.java
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

package com.wolfssl.provider.jce;

import java.util.Arrays;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.interfaces.PBEKey;

/**
 * wolfCrypt PBEKey implementation.
 */
public class WolfCryptPBEKey implements PBEKey {

    private static final long serialVersionUID = 1L;

    /** PBKDF2 iterations used to derive encoded key */
    private int iterations = 0;

    /** Password used to derive encoded key */
    private char[] password = null;

    /** Salt used to derive encoded key */
    private byte[] salt = null;

    /** Key encoded as byte array */
    private byte[] encoded = null;

    /** Algorithm used by this key */
    private String algorithm = null;

    /** Track if object has been destroyed */
    private boolean destroyed = false;

    /** Lock around use of destroyed boolean */
    private transient final Object destroyedLock = new Object();

    /**
     * Create new WolfCryptPBEKey object.
     *
     * @param password password used to derive the encoded key
     * @param salt salt used to derive the encoded key
     * @param iterations PBKDF iterations used to derive the encoded key
     * @param algorithm algorithm of this key
     * @param encoded encoded byte array of key
     *
     * @throws InvalidKeySpecException if arguments are not compatible
     *         with creation of this object
     */
    protected WolfCryptPBEKey(char[] password, byte[] salt,
        int iterations, String algorithm, byte[] encoded)
        throws InvalidKeySpecException {

        if (salt == null || salt.length == 0) {
            throw new InvalidKeySpecException(
                "Salt cannot be null or zero length");
        }

        if (iterations <= 0) {
            throw new InvalidKeySpecException(
                "Iterations cannot be less than or equal to zero");
        }

        if (algorithm == null || algorithm.isEmpty()) {
            throw new InvalidKeySpecException(
                "Algorithm String cannot be null or empty");
        }

        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeySpecException(
                "Encoded key cannot be null or zero length");
        }

        this.password = password.clone();
        this.salt = salt.clone();
        this.iterations = iterations;
        this.algorithm = algorithm;
        this.encoded = encoded.clone();
    }

    /**
     * Check if this object has been destroyed with destroy().
     *
     * @throws IllegalStateException if object has been destroyed
     */
    private synchronized void checkDestroyed()
        throws IllegalStateException {

        synchronized (destroyedLock) {
            if (this.destroyed == true) {
                throw new IllegalStateException(
                    "PBEKey has been destroyed");
            }
        }
    }

    /**
     * Return password used with this PBEKey.
     *
     * @return a copy of the internal password buffer
     *
     * @throws IllegalStateException if object has been destroyed
     */
    public synchronized char[] getPassword() {

        checkDestroyed();

        if (this.password == null) {
            return null;
        }

        return this.password.clone();
    }

    /**
     * Return salt used with this PBEKey.
     *
     * @return a copy of the internal salt buffer
     *
     * @throws IllegalStateException if object has been destroyed
     */
    public synchronized byte[] getSalt() {

        checkDestroyed();

        return this.salt.clone();
    }

    /**
     * Return iteration count used with this PBEKey.
     *
     * @return iteration count
     *
     * @throws IllegalStateException if object has been destroyed
     */
    public synchronized int getIterationCount() {

        checkDestroyed();

        return this.iterations;
    }

    /**
     * Return algorithm String representing this PBEKey.
     *
     * @return PBE algorithm string matching this object
     *
     * @throws IllegalStateException if object has been destroyed
     */
    public synchronized String getAlgorithm() {

        checkDestroyed();

        return this.algorithm;
    }

    /**
     * Return encoding format for this PBEKey.
     *
     * @return encoding format string, will be "RAW" for this object
     *
     * @throws IllegalStateException if object has been destroyed
     */
    public synchronized String getFormat() {

        checkDestroyed();

        return "RAW";
    }

    /**
     * Return encoded byte array of this PBEKey.
     *
     * @return encoded byte array
     *
     * @throws IllegalStateException if object has been destroyed
     */
    public synchronized byte[] getEncoded() {

        checkDestroyed();

        return this.encoded.clone();
    }

    /**
     * Destroy this object.
     *
     * Calling this method will zeroize the password and salt arrays
     * contained in this object and mark it as unusable.
     */
    public synchronized void destroy() {
        synchronized (destroyedLock) {
            if (this.password != null) {
                Arrays.fill(this.password, (char)0);
            }
            if (this.salt != null) {
                Arrays.fill(this.salt, (byte)0);
            }
            this.iterations = 0;
            this.algorithm = null;
            this.destroyed = true;
        }
    }

    /**
     * Return if this object has been destroyed.
     *
     * Object can be destroyed by calling destroy(), which will zeroize
     * internal buffers for this object.
     *
     * @return true if object has been destroyed, otherwise false
     */
    public synchronized boolean isDestroyed() {
        synchronized (destroyedLock) {
            if (this.destroyed) {
                return true;
            }
            return false;
        }
    }

    @Override
    public synchronized int hashCode() {
        return Arrays.hashCode(encoded);
    }

    @Override
    public synchronized boolean equals(Object obj) {

        PBEKey pKey = null;

        synchronized (destroyedLock) {
            if (obj == this) {
                return true;
            }

            if (!(obj instanceof PBEKey)) {
                return false;
            }
            pKey = (PBEKey)obj;

            if (!Arrays.equals(pKey.getEncoded(), getEncoded())) {
                return false;
            }

            if (!Arrays.equals(pKey.getSalt(), getSalt())) {
                return false;
            }

            if (!Arrays.equals(pKey.getPassword(), getPassword())) {
                return false;
            }

            if (pKey.getIterationCount() != getIterationCount()) {
                return false;
            }

            if (!pKey.getAlgorithm().equals(getAlgorithm())) {
                return false;
            }

            if (!pKey.getFormat().equals(getFormat())) {
                return false;
            }

            return true;
        }
    }
}

