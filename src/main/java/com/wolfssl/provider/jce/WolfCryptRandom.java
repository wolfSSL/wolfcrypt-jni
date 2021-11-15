/* WolfCryptRandom.java
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

package com.wolfssl.provider.jce;

import java.security.SecureRandomSpi;

import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfCrypt JCE RNG/SecureRandom wrapper
 */
public final class WolfCryptRandom extends SecureRandomSpi {

    /* internal reference to wolfCrypt JNI RNG object */
    private Rng rng;

    /* for debug logging */
    private WolfCryptDebug debug;

    public WolfCryptRandom() {
        this.rng = new Rng();
        this.rng.init();

        if (debug.DEBUG)
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
        if (debug.DEBUG)
            log("setSeed() not supported by wolfJCE");
    }

    private void log(String msg) {
        debug.print("[Random] " + msg);
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
}

