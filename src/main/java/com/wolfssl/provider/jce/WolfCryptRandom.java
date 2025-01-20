/* WolfCryptRandom.java
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

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.security.SecureRandomSpi;

import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.provider.jce.WolfCryptDebug;

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

        this.rng = new Rng();
        this.rng.init();

        log("initialized new object");
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {

        return rng.generateBlock(numBytes);
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {

        rng.generateBlock(bytes);
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        /* wolfCrypt reseeds internally automatically */
        log("setSeed() not supported by wolfJCE");
    }

    private void log(String msg) {
        WolfCryptDebug.print("[Random] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
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
    private void writeObject(ObjectOutputStream out) throws IOException {
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
    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException {

        if (rng == null) {
            this.rng = new Rng();
            this.rng.init();
        }

        in.defaultReadObject();
    }
}

