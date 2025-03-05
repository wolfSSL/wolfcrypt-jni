/* WolfCryptMessageDigestMd5.java
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

import java.security.MessageDigestSpi;
import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Md5;

/**
 * wolfCrypt JCE MD5 MessageDigest wrapper
 */
public final class WolfCryptMessageDigestMd5
    extends MessageDigestSpi implements Cloneable {

    /* internal reference to wolfCrypt JNI Md5 object */
    private Md5 md5;

    /**
     * Create new WolfCryptMessageDigestMd5 object
     */
    public WolfCryptMessageDigestMd5() {

        md5 = new Md5();
        md5.init();
    }

    /**
     * Create new WolfCryptMessageDigestMd5 based on existing Md5 object.
     * Existing object should already be initialized.
     *
     * @param md5 initialized Md5 object to be used with this MessageDigest
     */
    private WolfCryptMessageDigestMd5(Md5 md5) {
        this.md5 = md5;
    }

    @Override
    protected byte[] engineDigest() {

        byte[] digest = new byte[Md5.DIGEST_SIZE];

        try {

            this.md5.digest(digest);

        } catch (ShortBufferException e) {
            throw new RuntimeException(e.getMessage());
        }

        log("generated final digest, len: " + digest.length);

        return digest;
    }

    @Override
    protected void engineReset() {

        this.md5.init();

        log("engine reset");
    }

    @Override
    protected void engineUpdate(byte input) {

        byte[] tmp = new byte[1];
        tmp[0] = input;

        this.md5.update(tmp, 1);

        log("update with single byte");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

        this.md5.update(input, offset, len);

        log("update, offset: " + offset + ", len: " + len);
    }

    private void log(String msg) {
        WolfCryptDebug.print("[MessageDigest, MD5] " + msg);
    }

    @Override
    protected int engineGetDigestLength() {
        return this.md5.digestSize();
    }

    @Override
    public Object clone() {
        Md5 md5Copy = (Md5)this.md5.clone();
        return new WolfCryptMessageDigestMd5(md5Copy);
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

