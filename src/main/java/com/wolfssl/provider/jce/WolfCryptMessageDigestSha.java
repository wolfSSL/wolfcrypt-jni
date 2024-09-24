/* WolfCryptMessageDigestSha.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
import java.security.MessageDigestSpi;
import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Sha;
import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfCrypt JCE SHA-1 MessageDigest wrapper
 */
public final class WolfCryptMessageDigestSha
    extends MessageDigestSpi implements Cloneable {

    /* internal reference to wolfCrypt JNI Sha object */
    private Sha sha;

    /**
     * Create new WolfCryptMessageDigestSha object
     */
    public WolfCryptMessageDigestSha() {

        sha = new Sha();
        sha.init();
    }

    /**
     * Create new WolfCryptMessageDigestSha based on existing Sha object.
     * Existing object should already be initialized.
     *
     * @param sha initialized Sha object to be used with this MessageDigest
     */
    private WolfCryptMessageDigestSha(Sha sha) {
        this.sha = sha;
    }

    @Override
    protected byte[] engineDigest() {

        byte[] digest = new byte[Sha.DIGEST_SIZE];

        try {

            this.sha.digest(digest);

        } catch (ShortBufferException e) {
            throw new RuntimeException(e.getMessage());
        }

        log("generated final digest, len: " + digest.length);

        return digest;
    }

    @Override
    protected void engineReset() {

        this.sha.init();

        log("engine reset");
    }

    @Override
    protected void engineUpdate(byte input) {

        byte[] tmp = new byte[1];
        tmp[0] = input;

        this.sha.update(tmp, 1);

        log("update with single byte");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

        this.sha.update(input, offset, len);

        log("update, offset: " + offset + ", len: " + len);
    }

    private void log(String msg) {
        WolfCryptDebug.print("[MessageDigest, SHA] " + msg);
    }

    @Override
    protected int engineGetDigestLength() {
        return this.sha.digestSize();
    }

    @Override
    public Object clone() {
        Sha shaCopy = new Sha(this.sha);
        return new WolfCryptMessageDigestSha(shaCopy);
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

