/* WolfCryptRandom.java
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

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.security.SecureRandomSpi;

import com.wolfssl.wolfcrypt.Rng;

/**
 * wolfCrypt JCE RNG/SecureRandom wrapper
 */
public final class WolfCryptRandom extends SecureRandomSpi {

    private static final long serialVersionUID = 1L;

    /** Internal reference to wolfCrypt JNI RNG object.
     * Marked as transient since this is not serializable. When class
     * is reloaded, this object will be initialized back to null. */
    private transient Rng rng = null;

    /**
     * Create new WolfCryptRandom object
     */
    public WolfCryptRandom() {
        checkRngInitialized();
        log("initialized new object");
    }

    @Override
    protected synchronized byte[] engineGenerateSeed(int numBytes)
        throws IllegalArgumentException {

        if (numBytes == 0) {
            return new byte[0];
        }

        if (numBytes < 0) {
            throw new IllegalArgumentException("numBytes must be non-negative");
        }

        if (numBytes > Rng.RNG_MAX_BLOCK_LEN) {
            throw new IllegalArgumentException(
                "numBytes too large. wolfCrypt max is " +
                Rng.RNG_MAX_BLOCK_LEN);
        }

        checkRngInitialized();

        return rng.generateBlock(numBytes);
    }

    @Override
    protected synchronized void engineNextBytes(byte[] bytes) {

        if (bytes == null) {
            throw new NullPointerException("Input byte[] should not be null");
        }

        checkRngInitialized();

        rng.generateBlock(bytes);
    }

    @Override
    protected synchronized void engineSetSeed(byte[] seed) {

        if (seed == null) {
            throw new NullPointerException("Input seed[] should not be null");
        }

        /* wolfCrypt reseeds internally automatically */
        log("setSeed() not supported by wolfJCE");

    }

    /**
     * Initialize the RNG if needed (null). This handles cases where the object
     * was created through deserialization, reflection, etc. and the
     * constructor was not called.
     */
    private void checkRngInitialized() {
        if (this.rng == null) {
            this.rng = new Rng();
            this.rng.init();
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO, () -> msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable {
        try {

            if (this.rng != null) {
                this.rng.free();
                this.rng.releaseNativeStruct();
            }

        } finally {
            super.finalize();
        }
    }

    /**
     * Called when object is being serialized.
     *
     * Since Rng class variable is transient, we want to free that memory
     * before serializaing.
     *
     * @param out output stream written to during serialization of this object
     *
     * @throws IOException on error writing to ObjectOutputStream
     */
    private synchronized void writeObject(ObjectOutputStream out)
        throws IOException {

        if (this.rng != null) {
            this.rng.free();
            this.rng.releaseNativeStruct();
            this.rng = null;
        }

        out.defaultWriteObject();
    }

    /**
     * Called when object is being deserialized.
     *
     * When loading back in, we want to instantiate the Rng class variable
     * again.
     *
     * @param in input stream read during deserialization of this object
     * @throws IOException on error reading from ObjectInputStream
     * @throws ClassNotFoundException if object class not found
     */
    private synchronized void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {

        in.defaultReadObject();

        checkRngInitialized();
    }

    @Override
    public String toString() {
        /* Native wolfCrypt DRBG details:
         *     Hash_DRBG = DRBG implementation
         *     SHA-256 = hash function used in Hash_DRBG implementation
         *     128 = security strength in bits
         *     reseed_only = NIST implementation default, prediction resistance
         *     not enabled for every generate call, only when explicitly
         *     reseeded.
         *
         * This output format matches other JCE providers, some callers
         * may expect this format.
         */
        return "Hash_DRBG,SHA-256,128,reseed_only";
    }
}

