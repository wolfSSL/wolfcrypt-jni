/* WolfCryptMac.java
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

import javax.crypto.MacSpi;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;

import com.wolfssl.wolfcrypt.Md5;
import com.wolfssl.wolfcrypt.Sha;
import com.wolfssl.wolfcrypt.Sha224;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.Sha3;
import com.wolfssl.wolfcrypt.Hmac;
import com.wolfssl.wolfcrypt.AesCmac;
import com.wolfssl.wolfcrypt.AesGmac;
import com.wolfssl.wolfcrypt.Aes;

/**
 * wolfCrypt JCE Mac wrapper
 */
public class WolfCryptMac extends MacSpi {

    enum MacType {
        WC_HMAC_MD5,
        WC_HMAC_SHA,
        WC_HMAC_SHA224,
        WC_HMAC_SHA256,
        WC_HMAC_SHA384,
        WC_HMAC_SHA512,
        WC_HMAC_SHA3_224,
        WC_HMAC_SHA3_256,
        WC_HMAC_SHA3_384,
        WC_HMAC_SHA3_512,
        WC_AES_CMAC,
        WC_AES_GMAC
    }

    private Hmac hmac = null;
    private AesCmac aesCmac = null;
    private AesGmac aesGmac = null;
    private int nativeHmacType = 0;
    private int digestSize = 0;
    private MacType macType;

    /* GMAC-specific fields */
    private byte[] gmacIv = null;
    private int gmacTagLen = 16; /* default tag length */
    private ByteArrayOutputStream gmacAuthData = null;

    /* for debug logging */
    private String algString;

    private WolfCryptMac(MacType type)
        throws NoSuchAlgorithmException {

        this.macType = type;

        switch (type) {
            case WC_HMAC_MD5:
                hmac = new Hmac();
                this.digestSize = Md5.DIGEST_SIZE;
                this.nativeHmacType = Hmac.MD5;
                break;

            case WC_HMAC_SHA:
                hmac = new Hmac();
                this.digestSize = Sha.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA;
                break;

            case WC_HMAC_SHA224:
                hmac = new Hmac();
                this.digestSize = Sha224.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA224;
                break;

            case WC_HMAC_SHA256:
                hmac = new Hmac();
                this.digestSize = Sha256.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA256;
                break;

            case WC_HMAC_SHA384:
                hmac = new Hmac();
                this.digestSize = Sha384.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA384;
                break;

            case WC_HMAC_SHA512:
                hmac = new Hmac();
                this.digestSize = Sha512.DIGEST_SIZE;
                this.nativeHmacType = Hmac.SHA512;
                break;

            case WC_HMAC_SHA3_224:
                hmac = new Hmac();
                this.digestSize = Sha3.DIGEST_SIZE_224;
                this.nativeHmacType = Hmac.SHA3_224;
                break;

            case WC_HMAC_SHA3_256:
                hmac = new Hmac();
                this.digestSize = Sha3.DIGEST_SIZE_256;
                this.nativeHmacType = Hmac.SHA3_256;
                break;

            case WC_HMAC_SHA3_384:
                hmac = new Hmac();
                this.digestSize = Sha3.DIGEST_SIZE_384;
                this.nativeHmacType = Hmac.SHA3_384;
                break;

            case WC_HMAC_SHA3_512:
                hmac = new Hmac();
                this.digestSize = Sha3.DIGEST_SIZE_512;
                this.nativeHmacType = Hmac.SHA3_512;
                break;

            case WC_AES_CMAC:
                aesCmac = new AesCmac();
                this.digestSize = Aes.BLOCK_SIZE;
                break;

            case WC_AES_GMAC:
                aesGmac = new AesGmac();
                this.digestSize = Aes.BLOCK_SIZE;
                gmacAuthData = new ByteArrayOutputStream();
                break;

            default:
                throw new NoSuchAlgorithmException(
                    "Unsupported MAC type");
        }

        if (WolfCryptDebug.DEBUG) {
            algString = typeToString(type);
        }
    }

    @Override
    protected byte[] engineDoFinal() {

        byte[] out = null;

        if (macType == MacType.WC_AES_CMAC) {
            out = this.aesCmac.doFinal();
        } else if (macType == MacType.WC_AES_GMAC) {
            /* Compute GMAC using accumulated auth data */
            byte[] authData = gmacAuthData.toByteArray();
            out = this.aesGmac.update(gmacIv, authData, gmacTagLen);
            /* Reset for next operation */
            gmacAuthData.reset();
        } else {
            out = this.hmac.doFinal();
        }

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

        byte[] encodedKey;

        /* key must be of type SecretKey */
        if (!(key instanceof SecretKey))
            throw new InvalidKeyException("Key is not of type SecretKey");

        /* get encoded key */
        encodedKey = key.getEncoded();
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        try {
            if (macType == MacType.WC_AES_CMAC) {
                this.aesCmac.setKey(encodedKey);
            } else if (macType == MacType.WC_AES_GMAC) {
                /* GMAC requires GCMParameterSpec with IV */
                if (params == null || !(params instanceof GCMParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "AES-GMAC requires GCMParameterSpec with IV");
                }
                GCMParameterSpec gcmSpec = (GCMParameterSpec) params;
                this.gmacIv = gcmSpec.getIV();
                /* Convert bits to bytes */
                this.gmacTagLen = gcmSpec.getTLen() / 8;
                this.aesGmac.setKey(encodedKey);
                /* Reset auth data accumulator */
                gmacAuthData.reset();
            } else {
                this.hmac.setKey(nativeHmacType, encodedKey);
            }
        } catch (com.wolfssl.wolfcrypt.WolfCryptException e) {
            throw new InvalidKeyException("Invalid key: " + e.getMessage());
        }

        log("init with key and spec");
    }

    @Override
    protected void engineReset() {
        if (macType == MacType.WC_AES_CMAC) {
            this.aesCmac.reset();
        } else if (macType == MacType.WC_AES_GMAC) {
            /* Reset GMAC auth data accumulator */
            if (gmacAuthData != null) {
                gmacAuthData.reset();
            }
        } else {
            this.hmac.reset();
        }

        log("engine reset");
    }

    @Override
    protected void engineUpdate(byte input) {
        if (macType == MacType.WC_AES_CMAC) {
            this.aesCmac.update(input);
        } else if (macType == MacType.WC_AES_GMAC) {
            /* Accumulate auth data for GMAC */
            gmacAuthData.write(input);
        } else {
            this.hmac.update(input);
        }

        log("update with single byte");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (macType == MacType.WC_AES_CMAC) {
            this.aesCmac.update(input, offset, len);
        } else if (macType == MacType.WC_AES_GMAC) {
            /* Accumulate auth data for GMAC */
            gmacAuthData.write(input, offset, len);
        } else {
            this.hmac.update(input, offset, len);
        }

        log("update, offset: " + offset + ", len: " + len);
    }

    private String typeToString(MacType type) {
        switch (type) {
            case WC_HMAC_MD5:
                return "MD5";
            case WC_HMAC_SHA:
                return "SHA";
            case WC_HMAC_SHA224:
                return "SHA224";
            case WC_HMAC_SHA256:
                return "SHA256";
            case WC_HMAC_SHA384:
                return "SHA384";
            case WC_HMAC_SHA512:
                return "SHA512";
            case WC_HMAC_SHA3_224:
                return "SHA3-224";
            case WC_HMAC_SHA3_256:
                return "SHA3-256";
            case WC_HMAC_SHA3_384:
                return "SHA3-384";
            case WC_HMAC_SHA3_512:
                return "SHA3-512";
            case WC_AES_CMAC:
                return "AES-CMAC";
            case WC_AES_GMAC:
                return "AES-GMAC";
            default:
                return "None";
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[" + algString + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.hmac != null)
                this.hmac.releaseNativeStruct();
            if (this.aesCmac != null)
                this.aesCmac.releaseNativeStruct();
            if (this.aesGmac != null)
                this.aesGmac.releaseNativeStruct();
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
            super(MacType.WC_HMAC_MD5);
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
            super(MacType.WC_HMAC_SHA);
        }
    }

    /**
     * wolfJCE HMAC-SHA2-224 class
     */
    public static final class wcHmacSHA224 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA224 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA2-224 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA224() throws NoSuchAlgorithmException {
            super(MacType.WC_HMAC_SHA224);
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
            super(MacType.WC_HMAC_SHA256);
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
            super(MacType.WC_HMAC_SHA384);
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
            super(MacType.WC_HMAC_SHA512);
        }
    }

    /**
     * wolfJCE HMAC-SHA3-224 class
     */
    public static final class wcHmacSHA3_224 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA3_224 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA3-224 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA3_224() throws NoSuchAlgorithmException {
            super(MacType.WC_HMAC_SHA3_224);
        }
    }

    /**
     * wolfJCE HMAC-SHA3-256 class
     */
    public static final class wcHmacSHA3_256 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA3_256 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA3-256 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA3_256() throws NoSuchAlgorithmException {
            super(MacType.WC_HMAC_SHA3_256);
        }
    }

    /**
     * wolfJCE HMAC-SHA3-384 class
     */
    public static final class wcHmacSHA3_384 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA3_384 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA3-384 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA3_384() throws NoSuchAlgorithmException {
            super(MacType.WC_HMAC_SHA3_384);
        }
    }

    /**
     * wolfJCE HMAC-SHA3-512 class
     */
    public static final class wcHmacSHA3_512 extends WolfCryptMac {
        /**
         * Create new wcHmacSHA3_512 object
         *
         * @throws NoSuchAlgorithmException if HMAC-SHA3-512 is not available at
         *         native wolfCrypt level.
         */
        public wcHmacSHA3_512() throws NoSuchAlgorithmException {
            super(MacType.WC_HMAC_SHA3_512);
        }
    }

    /**
     * wolfJCE AES-CMAC class
     */
    public static final class wcAesCmac extends WolfCryptMac {
        /**
         * Create new wcAesCmac object
         *
         * @throws NoSuchAlgorithmException if AES-CMAC is not available at
         *         native wolfCrypt level.
         */
        public wcAesCmac() throws NoSuchAlgorithmException {
            super(MacType.WC_AES_CMAC);
        }
    }

    /**
     * wolfJCE AES-GMAC class
     */
    public static final class wcAesGmac extends WolfCryptMac {
        /**
         * Create new wcAesGmac object
         *
         * @throws NoSuchAlgorithmException if AES-GMAC is not available at
         *         native wolfCrypt level.
         */
        public wcAesGmac() throws NoSuchAlgorithmException {
            super(MacType.WC_AES_GMAC);
        }
    }
}
