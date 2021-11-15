/* WolfCryptMessageDigestMd5.java
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

import java.util.Arrays;
import java.security.MessageDigestSpi;
import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Md5;
import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfCrypt JCE MD5 MessageDigest wrapper
 */
public final class WolfCryptMessageDigestMd5 extends MessageDigestSpi {

    /* internal reference to wolfCrypt JNI Md5 object */
    private Md5 md5;

    /* for debug logging */
    private WolfCryptDebug debug;

    public WolfCryptMessageDigestMd5() {

        md5 = new Md5();
        md5.init();
    }

    @Override
    protected byte[] engineDigest() {

        byte[] digest = new byte[Md5.DIGEST_SIZE];

        try {

            this.md5.digest(digest);

        } catch (ShortBufferException e) {
            throw new RuntimeException(e.getMessage());
        }

        if (debug.DEBUG)
            log("generated final digest, len: " + digest.length);

        return digest;
    }

    @Override
    protected void engineReset() {

        this.md5.init();

        if (debug.DEBUG)
            log("engine reset");
    }

    @Override
    protected void engineUpdate(byte input) {

        byte[] tmp = new byte[1];
        tmp[0] = input;

        this.md5.update(tmp, 1);

        if (debug.DEBUG)
            log("update with single byte");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

        this.md5.update(input, offset, len);

        if (debug.DEBUG)
            log("update, offset: " + offset + ", len: " + len);
    }

    private void log(String msg) {
        debug.print("[MessageDigest, MD5] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.md5 != null)
                this.md5.releaseNativeStruct();
        } finally {
            super.finalize();
        }
    }
}

