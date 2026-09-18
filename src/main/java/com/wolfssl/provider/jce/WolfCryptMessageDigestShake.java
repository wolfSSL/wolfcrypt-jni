/* WolfCryptMessageDigestShake.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import com.wolfssl.wolfcrypt.Shake;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE SHAKE-128 / SHAKE-256 MessageDigest wrapper.
 *
 * Implements fixed-length "SHAKE128-256" (32-byte) and "SHAKE256-512"
 * (64-byte) algorithms. For arbitrary-length XOF output use
 * com.wolfssl.wolfcrypt.Shake directly.
 */
public class WolfCryptMessageDigestShake
    extends MessageDigestSpi implements Cloneable {

    /* internal reference to wolfCrypt JNI Shake object */
    private Shake shake;

    /**
     * Create new WolfCryptMessageDigestShake object
     *
     * @param hashType hash type to be used with this MessageDigest
     * @throws NoSuchAlgorithmException if digest type is not
     *         available in native wolfCrypt library
     */
    public WolfCryptMessageDigestShake(int hashType)
        throws NoSuchAlgorithmException {

        try {
            shake = new Shake(hashType);
            shake.init();

        } catch (WolfCryptException e) {
            throw new NoSuchAlgorithmException(e.getMessage());
        }
    }

    /**
     * Create new WolfCryptMessageDigestShake based on existing Shake object.
     * Existing object should already be initialized.
     *
     * @param shake initialized Shake object to be used with this MessageDigest
     */
    private WolfCryptMessageDigestShake(Shake shake) {
        this.shake = shake;
    }

    @Override
    protected byte[] engineDigest() {

        byte[] digest = new byte[shake.digestSize()];

        try {
            this.shake.digest(digest);

        } catch (ShortBufferException e) {
            throw new RuntimeException(e.getMessage());
        }

        log("generated final digest, len: " + digest.length);

        return digest;
    }

    @Override
    protected void engineReset() {

        this.shake.init();

        log("engine reset");
    }

    @Override
    protected void engineUpdate(byte input) {

        byte[] tmp = new byte[1];
        tmp[0] = input;

        this.shake.update(tmp, 1);

        log("update with single byte");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

        this.shake.update(input, offset, len);

        log("update, offset: " + offset + ", len: " + len);
    }

    @Override
    protected int engineGetDigestLength() {
        return this.shake.digestSize();
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[SHAKE] " + msg);
    }

    @Override
    public Object clone() {
        Shake shakeCopy = (Shake)this.shake.clone();
        return new WolfCryptMessageDigestShake(shakeCopy);
    }

    @SuppressWarnings({"deprecation", "removal"})
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.shake != null)
                this.shake.releaseNativeStruct();
        } finally {
            super.finalize();
        }
    }

    /**
     * wolfJCE SHAKE128-256 message digest class, SHAKE-128 with fixed 32-byte
     * output length
     */
    public static final class wcSHAKE128_256
        extends WolfCryptMessageDigestShake {
        /**
         * Create new wcSHAKE128_256 object
         *
         * @throws NoSuchAlgorithmException if digest type is not available
         *         in native wolfCrypt library
         */
        public wcSHAKE128_256() throws NoSuchAlgorithmException {
            super(Shake.TYPE_SHAKE_128);
        }
    }

    /**
     * wolfJCE SHAKE256-512 message digest class, SHAKE-256 with fixed 64-byte
     * output length
     */
    public static final class wcSHAKE256_512
        extends WolfCryptMessageDigestShake {
        /**
         * Create new wcSHAKE256_512 object
         *
         * @throws NoSuchAlgorithmException if digest type is not available
         *         in native wolfCrypt library
         */
        public wcSHAKE256_512() throws NoSuchAlgorithmException {
            super(Shake.TYPE_SHAKE_256);
        }
    }
}
