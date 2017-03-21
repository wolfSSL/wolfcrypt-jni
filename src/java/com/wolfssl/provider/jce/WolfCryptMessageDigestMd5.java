/* WolfCryptMessageDigestMd5.java
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

import java.util.Arrays;
import java.security.MessageDigestSpi;
import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Md5;

/**
 * wolfCrypt JCE Md5 MessageDigest wrapper
 *
 * @author wolfSSL
 * @version 1.0, March 2017
 */
public final class WolfCryptMessageDigestMd5 extends MessageDigestSpi {

    /* internal reference to wolfCrypt JNI Md5 object */
    private Md5 md5;

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

        return digest;
    }

    @Override
    protected void engineReset() {

        this.md5.init();
    }

    @Override
    protected void engineUpdate(byte input) {

        byte[] tmp = new byte[1];
        tmp[0] = input;

        try {

            this.md5.update(tmp, 1);

        } catch (ShortBufferException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

        try {

            this.md5.update(input, offset, len);

        } catch (ShortBufferException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            this.md5.releaseNativeStruct();
        } finally {
            super.finalize();
        }
    }
}

