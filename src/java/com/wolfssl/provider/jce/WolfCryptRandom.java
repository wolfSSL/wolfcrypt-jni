/* WolfCryptRandom.java
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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

/**
 * wolfCrypt JCE RNG/SecureRandom wrapper
 *
 * @author wolfSSL
 * @version 1.0, March 2017
 */
public final class WolfCryptRandom extends SecureRandomSpi {

    /* internal reference to wolfCrypt JNI RNG object */
    private Rng rng;

    public WolfCryptRandom() {
        this.rng = new Rng();
        this.rng.init();
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
    }

    @Override
    protected void finalize() throws Throwable {
        try {

            this.rng.free();
            this.rng.releaseNativeStruct();

        } finally {
            super.finalize();
        }
    }
}

