/* WolfCryptMac.java
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

import javax.crypto.MacSpi;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Md5;
import com.wolfssl.wolfcrypt.Sha;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.Hmac;

import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfCrypt JCE Mac wrapper
 */
public class WolfCryptMac extends MacSpi {

    enum HmacType {
        WC_HMAC_MD5,
        WC_HMAC_SHA,
        WC_HMAC_SHA256,
        WC_HMAC_SHA384,
        WC_HMAC_SHA512
    }

    private Hmac hmac = null;
    private HmacType hmacType = null;
    private int nativeHmacType = 0;
    private int digestSize = 0;

    /* for debug logging */
    private String algString;

    private WolfCryptMac(HmacType type)
        throws NoSuchAlgorithmException {

        this.hmacType = type;
        hmac = new Hmac();

        switch (type) {
            case WC_HMAC_MD5:
                this.digestSize = Md5.DIGEST_SIZE;
                this.nativeHmacType = Hmac.MD5;
                break;

            case WC_HMAC_SHA:
                this.digestSize = Sha.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA;
                break;

            case WC_HMAC_SHA256:
                this.digestSize = Sha256.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA256;
                break;

            case WC_HMAC_SHA384:
                this.digestSize = Sha384.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA384;
                break;

            case WC_HMAC_SHA512:
                this.digestSize = Sha512.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA512;
                break;

            default:
                throw new NoSuchAlgorithmException(
                    "Unsupported HMAC type");
        }

        if (WolfCryptDebug.DEBUG) {
            algString = typeToString(type);
        }
    }

    @Override
    protected byte[] engineDoFinal() {

        byte[] out = this.hmac.doFinal();

        if (out != null) {
            log("final digest generated, len: " + out.length);
        } else {
            log("final digest was null");
        }

        return out;
    }

    @Override
    protected int engineGetMacLength() {
        return this.digestSize;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        int ret = 0;
        byte[] encodedKey;

        /* key must be of type SecretKey */
        if (!(key instanceof SecretKey))
            throw new InvalidKeyException("Key is not of type SecretKey");

        /* get encoded key */
        encodedKey = key.getEncoded();
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        this.hmac.setKey(nativeHmacType, encodedKey);

        log("init with key and spec");
    }

    @Override
    protected void engineReset() {
        this.hmac.reset();

        log("engine reset");
    }

    @Override
    protected void engineUpdate(byte input) {
        this.hmac.update(input);

        log("update with single byte");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        this.hmac.update(input, offset, len);

        log("update, offset: " + offset + ", len: " + len);
    }

    private String typeToString(HmacType type) {
        switch (type) {
            case WC_HMAC_MD5:
                return "MD5";
            case WC_HMAC_SHA:
                return "SHA";
            case WC_HMAC_SHA256:
                return "SHA256";
            case WC_HMAC_SHA384:
                return "SHA384";
            case WC_HMAC_SHA512:
                return "SHA512";
            default:
                return "None";
        }
    }

    private void log(String msg) {
        WolfCryptDebug.print("[Mac, " + algString + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.hmac != null)
                this.hmac.releaseNativeStruct();
        } finally {
            super.finalize();
        }
    }

    /**
     * wolfJCE HMAC-MD5 class
     */
    public static final class wcHmacMD5 extends WolfCryptMac {
        /**
         * Create new wcHmacMD5 object
         *
         * @throws NoSuchAlgorithmException if HMAC-MD5 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacMD5() throws NoSuchAlgorithmException {
            super(HmacType.WC_HMAC_MD5);
        }
    }

    /**
     * wolfJCE HMAC-SHA-1 class
     */
    public static final class wcHmacSHA1 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA1 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA-1 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA1() throws NoSuchAlgorithmException {
            super(HmacType.WC_HMAC_SHA);
        }
    }

    /**
     * wolfJCE HMAC-SHA2-256 class
     */
    public static final class wcHmacSHA256 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA256 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA2-256 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA256() throws NoSuchAlgorithmException {
            super(HmacType.WC_HMAC_SHA256);
        }
    }

    /**
     * wolfJCE HMAC-SHA2-384 class
     */
    public static final class wcHmacSHA384 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA384 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA2-384 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA384() throws NoSuchAlgorithmException {
            super(HmacType.WC_HMAC_SHA384);
        }
    }

    /**
     * wolfJCE HMAC-SHA2-512 class
     */
    public static final class wcHmacSHA512 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA512 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA2-512 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA512() throws NoSuchAlgorithmException {
            super(HmacType.WC_HMAC_SHA512);
        }
    }
}

