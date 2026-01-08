/* WolfCryptMessageDigestSha3.java
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

import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Sha3;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE SHA-3 MessageDigest wrapper
 */
public class WolfCryptMessageDigestSha3
    extends MessageDigestSpi implements Cloneable {

    /* internal reference to wolfCrypt JNI Sha object */
    private Sha3 sha;

    /**
     * Create new WolfCryptMessageDigestSha3 object
     *
     * @param hashType hash type to be used with this MessageDigest
     * @throws NoSuchAlgorithmException if digest type is not
     *         available in native wolfCrypt library
     */
    public WolfCryptMessageDigestSha3(int hashType)
        throws NoSuchAlgorithmException {

        try {
            sha = new Sha3(hashType);
            sha.init();

        } catch (WolfCryptException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        }
    }

    /**
     * Create new WolfCryptMessageDigestSha3 based on existing Sha3 object.
     * Existing object should already be initialized.
     *
     * @param sha initialized Sha3 object to be used with this MessageDigest
     */
    private WolfCryptMessageDigestSha3(Sha3 sha) {
        this.sha = sha;
    }

    @Override
    protected byte[] engineDigest() {

        byte[] digest = new byte[sha.digestSize()];

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

    @Override
    protected int engineGetDigestLength() {
        return this.sha.digestSize();
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[SHA-3] " + msg);
    }

    @Override
    public Object clone() {
        Sha3 shaCopy = (Sha3)this.sha.clone();
        return new WolfCryptMessageDigestSha3(shaCopy);
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

    /**
     * wolfJCE SHA1wECDSA message digest class
     */
    public static final class wcSHA3_224 extends WolfCryptMessageDigestSha3 {
        /**
         * Create new wcSHA3_224 object
         *
         * @throws NoSuchAlgorithmException if digest type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_224() throws NoSuchAlgorithmException {
            super(Sha3.TYPE_SHA3_224);
        }
    }

    /**
     * wolfJCE SHA3-256 message digest class
     */
    public static final class wcSHA3_256 extends WolfCryptMessageDigestSha3 {
        /**
         * Create new wcSHA3_256 object
         *
         * @throws NoSuchAlgorithmException if digest type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_256() throws NoSuchAlgorithmException {
            super(Sha3.TYPE_SHA3_256);
        }
    }

    /**
     * wolfJCE SHA3-384 message digest class
     */
    public static final class wcSHA3_384 extends WolfCryptMessageDigestSha3 {
        /**
         * Create new wcSHA3_384 object
         *
         * @throws NoSuchAlgorithmException if digest type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_384() throws NoSuchAlgorithmException {
            super(Sha3.TYPE_SHA3_384);
        }
    }

    /**
     * wolfJCE SHA3-512 message digest class
     */
    public static final class wcSHA3_512 extends WolfCryptMessageDigestSha3 {
        /**
         * Create new wcSHA3_512 object
         *
         * @throws NoSuchAlgorithmException if digest type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_512() throws NoSuchAlgorithmException {
            super(Sha3.TYPE_SHA3_512);
        }
    }
}

