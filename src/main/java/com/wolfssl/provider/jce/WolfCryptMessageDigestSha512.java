/* WolfCryptMessageDigestSha512.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

import java.util.Arrays;
import java.security.MessageDigestSpi;
import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfCrypt JCE SHA2-512 MessageDigest wrapper
 */
public final class WolfCryptMessageDigestSha512 extends MessageDigestSpi {

    /* internal reference to wolfCrypt JNI Sha object */
    private Sha512 sha;

    /* for debug logging */
    private WolfCryptDebug debug;

    /**
     * Create new WolfCryptMessageDigestSha512 object
     */
    public WolfCryptMessageDigestSha512() {

        sha = new Sha512();
        sha.init();
    }

    @Override
    protected byte[] engineDigest() {

        byte[] digest = new byte[Sha512.DIGEST_SIZE];

        try {

            this.sha.digest(digest);

        } catch (ShortBufferException e) {
            throw new RuntimeException(e.getMessage());
        }

        if (debug.DEBUG)
            log("generated final digest, len: " + digest.length);

        return digest;
    }

    @Override
    protected void engineReset() {

        this.sha.init();

        if (debug.DEBUG)
            log("engine reset");
    }

    @Override
    protected void engineUpdate(byte input) {

        byte[] tmp = new byte[1];
        tmp[0] = input;

        this.sha.update(tmp, 1);

        if (debug.DEBUG)
            log("update with single byte");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

        this.sha.update(input, offset, len);

        if (debug.DEBUG)
            log("update, offset: " + offset + ", len: " + len);
    }

    @Override
    protected int engineGetDigestLength() {
        return this.sha.digestSize();
    }

    private void log(String msg) {
        debug.print("[MessageDigest, SHA512] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.sha != null)
                this.sha.releaseNativeStruct();
        } finally {
            super.finalize();
        }
    }
}

