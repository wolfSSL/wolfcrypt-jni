/* WolfCryptCipher.java
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

import java.util.Arrays;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;

import java.security.SecureRandom;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.AesEcb;
import com.wolfssl.wolfcrypt.AesCtr;
import com.wolfssl.wolfcrypt.AesOfb;
import com.wolfssl.wolfcrypt.AesGcm;
import com.wolfssl.wolfcrypt.AesCcm;
import com.wolfssl.wolfcrypt.Des3;
import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Rng;

/**
 * wolfCrypt JCE Cipher (AES, 3DES) wrapper
 */
public class WolfCryptCipher extends CipherSpi {

    enum CipherType {
        WC_AES,
        WC_DES3,
        WC_RSA
    }

    enum CipherMode {
        WC_ECB,
        WC_CBC,
        WC_CTR,
        WC_OFB,
        WC_GCM,
        WC_CCM
    }

    enum PaddingType {
        WC_NONE,
        WC_PKCS1,
        WC_PKCS5
    }

    enum OpMode {
        WC_ENCRYPT,
        WC_DECRYPT
    }

    enum RsaKeyType {
        WC_RSA_PRIVATE,
        WC_RSA_PUBLIC
    }

    private CipherType cipherType   = null;
    private CipherMode cipherMode   = null;
    private PaddingType paddingType = null;
    private OpMode direction        = null;
    private RsaKeyType rsaKeyType   = null;

    private int blockSize = 0;

    private Aes  aes      = null;
    private AesEcb aesEcb = null;
    private AesCtr aesCtr = null;
    private AesOfb aesOfb = null;
    private AesGcm aesGcm = null;
    private AesCcm aesCcm = null;
    private Des3 des3     = null;
    private Rsa  rsa      = null;
    private Rng  rng      = null;

    /* for debug logging */
    private String algString;
    private String algMode;

    /* stash key and IV here for easy lookup */
    private Key storedKey = null;
    private AlgorithmParameterSpec storedSpec = null;
    private byte[] iv = null;

    /* AES-GCM tag length (bytes) */
    private int gcmTagLen = 0;

    /* AAD data for AES-GCM, populated via engineUpdateAAD() */
    private byte[] aadData = null;

    /* Has update/final been called yet, gates setting of AAD for GCM */
    private boolean operationStarted = false;

    /* Has this Cipher been inintialized? */
    private boolean cipherInitialized = false;

    /* buffered data from update calls */
    private byte[] buffered = new byte[0];

    private WolfCryptCipher(CipherType type, CipherMode mode,
            PaddingType pad) {

        this.cipherType = type;
        this.cipherMode = mode;
        this.paddingType = pad;

        this.rng = new Rng();
        this.rng.init();

        switch (cipherType) {
            case WC_AES:
                blockSize = Aes.BLOCK_SIZE;
                break;

            case WC_DES3:
                blockSize = Des3.BLOCK_SIZE;
                break;

            case WC_RSA:
                break;
        }

        if (WolfCryptDebug.DEBUG) {
            algString = typeToString(cipherType);
            algMode = modeToString(cipherMode);
        }
    }

    /**
     * Reset / re-create internal native struct for algorithm.
     * Should be called during wolfCryptInit() and wolfCryptFinal()
     */
    private void InitializeNativeStructs() {
        switch (this.cipherType) {
            case WC_AES:
                if (cipherMode == CipherMode.WC_CBC) {
                    if (aes != null) {
                        aes.releaseNativeStruct();
                        aes = null;
                    }
                    aes = new Aes();
                }
                else if (cipherMode == CipherMode.WC_ECB) {
                    if (aesEcb != null) {
                        aesEcb.releaseNativeStruct();
                        aesEcb = null;
                    }
                    aesEcb = new AesEcb();
                }
                else if (cipherMode == CipherMode.WC_CTR) {
                    if (aesCtr != null) {
                        aesCtr.releaseNativeStruct();
                        aesCtr = null;
                    }
                    aesCtr = new AesCtr();
                }
                else if (cipherMode == CipherMode.WC_OFB) {
                    if (aesOfb != null) {
                        aesOfb.releaseNativeStruct();
                        aesOfb = null;
                    }
                    aesOfb = new AesOfb();
                }
                else if (cipherMode == CipherMode.WC_GCM) {
                    if (aesGcm != null) {
                        aesGcm.releaseNativeStruct();
                        aesGcm = null;
                    }
                    aesGcm = new AesGcm();
                }
                else if (cipherMode == CipherMode.WC_CCM) {
                    if (aesCcm != null) {
                        aesCcm.releaseNativeStruct();
                        aesCcm = null;
                    }
                    aesCcm = new AesCcm();
                }
                break;

            case WC_DES3:
                if (des3 != null) {
                    des3.releaseNativeStruct();
                    des3 = null;
                }
                des3 = new Des3();
                break;

            case WC_RSA:
                if (rsa != null) {
                    rsa.releaseNativeStruct();
                    rsa = null;
                }
                rsa = new Rsa();
                rsa.setRng(this.rng);
                break;
        }
    }

    @Override
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException {

        int supported = 0;

        if (mode.equals("ECB")) {

            /* RSA and AES support ECB mode */
            if (cipherType == CipherType.WC_RSA ||
                cipherType == CipherType.WC_AES) {
                cipherMode = CipherMode.WC_ECB;
                supported = 1;

                log("set mode to ECB");
            }

        } else if (mode.equals("CBC")) {

            /* AES and 3DES support CBC */
            if (cipherType == CipherType.WC_AES ||
                cipherType == CipherType.WC_DES3 ) {
                cipherMode = CipherMode.WC_CBC;
                supported = 1;

                log("set mode to CBC");
            }

        } else if (mode.equals("CTR")) {

            /* AES supports CTR */
            if (cipherType == CipherType.WC_AES) {
                cipherMode = CipherMode.WC_CTR;
                supported = 1;

                log("set mode to CTR");
            }

        } else if (mode.equals("OFB")) {

            /* AES supports OFB */
            if (cipherType == CipherType.WC_AES) {
                cipherMode = CipherMode.WC_OFB;
                supported = 1;

                log("set mode to OFB");
            }

        } else if (mode.equals("GCM")) {

            /* AES supports GCM */
            if (cipherType == CipherType.WC_AES) {
                cipherMode = CipherMode.WC_GCM;
                supported = 1;

                log("set mode to GCM");
            }

        } else if (mode.equals("CCM")) {

            /* AES supports CCM */
            if (cipherType == CipherType.WC_AES) {
                cipherMode = CipherMode.WC_CCM;
                supported = 1;

                log("set mode to CCM");
            }
        }

        if (supported == 0) {
            throw new NoSuchAlgorithmException(
                "Unsupported cipher mode for active algorithm choice: " +
                mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException {

        int supported = 0;

        if (padding.equals("NoPadding")) {

            if (cipherType == CipherType.WC_AES ||
                cipherType == CipherType.WC_DES3) {
                paddingType = PaddingType.WC_NONE;
                supported = 1;

                log("set padding to NoPadding");
            }

        } else if (padding.equals("PKCS1Padding")) {

            if (cipherType == CipherType.WC_RSA) {
                paddingType = PaddingType.WC_PKCS1;
                supported = 1;

                log("set padding to PKCS1Padding");
            }

        } else if (padding.equals("PKCS5Padding")) {

            if ((cipherType == CipherType.WC_AES) &&
                (cipherMode == CipherMode.WC_CBC ||
                 cipherMode == CipherMode.WC_ECB)) {

                paddingType = PaddingType.WC_PKCS5;
                supported = 1;

                log("set padding to PKCS5Padding");
            }
        }

        if (supported == 0) {
            throw new NoSuchPaddingException(
                "Unsupported padding type for active algorithm choice: " +
                padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return this.blockSize;
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
        throws IllegalStateException {

        int size = 0;

        if (!this.cipherInitialized) {
            throw new IllegalStateException(
                "Cipher has not been initialized yet");
        }

        switch (this.cipherType) {
            case WC_AES:
                if (paddingType == PaddingType.WC_NONE) {
                    if (cipherMode == CipherMode.WC_GCM) {
                        /* In AES-GCM mode we append the authentication tag
                         * to the end of ciphertext, When decrypting, output
                         * size will have it taken off. */
                        if (this.direction == OpMode.WC_ENCRYPT) {
                            size = inputLen + this.gcmTagLen;
                        }
                        else {
                            size = inputLen - this.gcmTagLen;
                        }
                        size = Math.max(size, 0);
                    }
                    else {
                        /* wolfCrypt expects input to be padded by application
                         * to block size, thus output is same size as input */
                        size = inputLen;
                    }
                }
                else if (paddingType == PaddingType.WC_PKCS5) {
                    size = buffered.length + inputLen;
                    size += Aes.getPKCS7PadSize(size, Aes.BLOCK_SIZE);
                }
                else {
                    throw new IllegalStateException(
                        "Unsupported padding mode for Cipher Aes");
                }

                break;

            case WC_DES3:
                if (paddingType == PaddingType.WC_NONE) {
                    /* wolfCrypt expects input to be padded by application to
                     * block size, thus output is same size as input */
                    size = inputLen;
                }
                else if (paddingType == PaddingType.WC_PKCS5) {
                    size = buffered.length + inputLen;
                    size += Des3.getPKCS7PadSize(size, Des3.BLOCK_SIZE);
                }
                else {
                    throw new IllegalStateException(
                        "Unsupported padding mode for Cipher Des3");
                }

                break;

            case WC_RSA:
                size = this.rsa.getEncryptSize();
                break;
        }

        return size;
    }

    @Override
    protected byte[] engineGetIV() {
        return this.iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        /* not currently supported by wolfCrypt JCE provider */
        return null;
    }

    private void wolfCryptSetDirection(int opmode)
        throws InvalidKeyException {

        /* we don't currently support AES key wrap in JCE yet,
         * so don't allow WRAP_MODE or UNWRAP_MODE */
        switch (opmode) {
            case Cipher.ENCRYPT_MODE:
                this.direction = OpMode.WC_ENCRYPT;
                break;

            case Cipher.DECRYPT_MODE:
                this.direction = OpMode.WC_DECRYPT;
                break;

            default:
                throw new InvalidKeyException(
                    "Cipher opmode must be ENCRYPT_MODE or DECRPYT_MODE");
        }
    }

    private void wolfCryptSetIV(AlgorithmParameterSpec spec,
            SecureRandom random) throws InvalidAlgorithmParameterException {

        /* store AlgorithmParameterSpec for class reset */
        this.storedSpec = spec;

        /* RSA and AES-ECB don't need an IV */
        if (this.cipherType == CipherType.WC_RSA ||
            (this.cipherType == CipherType.WC_AES &&
             this.cipherMode == CipherMode.WC_ECB))
            return;

        /* store IV, or generate random IV if not available */
        if (spec == null) {
            this.iv = new byte[this.blockSize];

            if (random != null) {
                random.nextBytes(this.iv);
            } else {
                SecureRandom rand = new SecureRandom();
                rand.nextBytes(this.iv);
            }

        } else {
            if (cipherMode == CipherMode.WC_GCM) {
                if (!(spec instanceof GCMParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec must be of type " +
                        "GCMParameterSpec");
                }

                GCMParameterSpec gcmSpec = (GCMParameterSpec)spec;

                if (gcmSpec.getIV() == null ||
                    gcmSpec.getIV().length == 0) {
                    throw new InvalidAlgorithmParameterException(
                        "AES-GCM IV is null or 0 length");
                }

                this.iv = gcmSpec.getIV().clone();

                /* store tag length as bytes */
                if (gcmSpec.getTLen() == 0) {
                    throw new InvalidAlgorithmParameterException(
                        "Tag length cannot be zero");
                }
                this.gcmTagLen = (gcmSpec.getTLen() / 8);
            }
            else if (cipherMode == CipherMode.WC_CCM) {
                /*
                 * CCM Parameter Handling:
                 * We use GCMParameterSpec for CCM mode to maintain
                 * compatibility with:
                 * 1. Java 8+ (CCMParameterSpec only available in Java 11+)
                 * 2. BouncyCastle provider (uses GCMParameterSpec for CCM)
                 * 3. Existing developer expectations and code patterns
                 */
                if (!(spec instanceof GCMParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec must be of type " +
                        "GCMParameterSpec for AES-CCM");
                }

                GCMParameterSpec ccmSpec = (GCMParameterSpec)spec;

                if (ccmSpec.getIV() == null || ccmSpec.getIV().length == 0) {
                    throw new InvalidAlgorithmParameterException(
                        "AES-CCM nonce is null or 0 length");
                }

                /* CCM nonce length validation (7-15 bytes typical) */
                if (ccmSpec.getIV().length < 7 || ccmSpec.getIV().length > 15) {
                    throw new InvalidAlgorithmParameterException(
                        "CCM nonce length must be 7-15 bytes, got: " +
                        ccmSpec.getIV().length);
                }

                this.iv = ccmSpec.getIV().clone();

                /* store tag length as bytes */
                if (ccmSpec.getTLen() == 0) {
                    throw new InvalidAlgorithmParameterException(
                        "Tag length cannot be zero");
                }
                this.gcmTagLen = (ccmSpec.getTLen() / 8);
            }
            else {
                if (!(spec instanceof IvParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec must be of type " +
                        "IvParameterSpec");
                }

                IvParameterSpec ivSpec = (IvParameterSpec)spec;

                /* IV should be of block size length */
                if (ivSpec.getIV().length != this.blockSize) {
                    throw new InvalidAlgorithmParameterException(
                            "Bad IV length (" + ivSpec.getIV().length +
                            "), must be " + blockSize + " bytes long");
                }

                this.iv = ivSpec.getIV().clone();
            }
        }
    }

    private void wolfCryptSetKey(Key key)
        throws InvalidKeyException {

        byte[] encodedKey;

        /* validate key class type */
        if (this.cipherType == CipherType.WC_RSA) {

            if (key instanceof RSAPrivateKey) {
                this.rsaKeyType = RsaKeyType.WC_RSA_PRIVATE;

            } else if (key instanceof RSAPublicKey) {
                this.rsaKeyType = RsaKeyType.WC_RSA_PUBLIC;

            } else {
                throw new InvalidKeyException(
                    "Cipher key must be of type RSAPrivateKey or " +
                    "RSAPublicKey when used for RSA encrypt or decrypt");
            }

        } else if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException(
                "Cipher key must be of type SecretKey");
        }

        /* save key for class state resets */
        this.storedKey = key;

        /* import key */
        encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }

        switch (cipherType) {
            case WC_AES:
                if (this.direction == OpMode.WC_ENCRYPT) {
                    if (cipherMode == CipherMode.WC_GCM) {
                        this.aesGcm.setKey(encodedKey);
                    }
                    else if (cipherMode == CipherMode.WC_CCM) {
                        this.aesCcm.setKey(encodedKey);
                    }
                    else if (cipherMode == CipherMode.WC_ECB) {
                        this.aesEcb.setKey(
                            encodedKey, null, AesEcb.ENCRYPT_MODE);
                    }
                    else if (cipherMode == CipherMode.WC_CTR) {
                        this.aesCtr.setKey(encodedKey, iv);
                    }
                    else if (cipherMode == CipherMode.WC_OFB) {
                        this.aesOfb.setKey(encodedKey, iv, AesOfb.ENCRYPT_MODE);
                    }
                    else {
                        this.aes.setKey(encodedKey, iv, Aes.ENCRYPT_MODE);
                    }
                } else {
                    if (cipherMode == CipherMode.WC_GCM) {
                        this.aesGcm.setKey(encodedKey);
                    }
                    else if (cipherMode == CipherMode.WC_CCM) {
                        this.aesCcm.setKey(encodedKey);
                    }
                    else if (cipherMode == CipherMode.WC_ECB) {
                        this.aesEcb.setKey(
                            encodedKey, null, AesEcb.DECRYPT_MODE);
                    }
                    else if (cipherMode == CipherMode.WC_CTR) {
                        this.aesCtr.setKey(encodedKey, iv);
                    }
                    else if (cipherMode == CipherMode.WC_OFB) {
                        this.aesOfb.setKey(encodedKey, iv, AesOfb.ENCRYPT_MODE);
                    }
                    else {
                        this.aes.setKey(encodedKey, iv, Aes.DECRYPT_MODE);
                    }
                }
                break;

            case WC_DES3:
                if (this.direction == OpMode.WC_ENCRYPT) {
                    this.des3.setKey(encodedKey, iv, Des3.ENCRYPT_MODE);
                } else {
                    this.des3.setKey(encodedKey, iv, Des3.DECRYPT_MODE);
                }
                break;

            case WC_RSA:

                /* reset key struct if needed */
                if (this.rsa != null)
                    this.rsa.releaseNativeStruct();

                this.rsa = new Rsa();
                this.rsa.setRng(this.rng);

                if (this.rsaKeyType == RsaKeyType.WC_RSA_PRIVATE) {

                    this.rsa.decodePrivateKeyPKCS8(encodedKey);

                } else {
                    this.rsa.decodePublicKey(encodedKey);
                }
                break;
        }
    }

    /* called by engineInit() functions */
    private void wolfCryptCipherInit(int opmode, Key key,
            AlgorithmParameterSpec spec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        InitializeNativeStructs();
        wolfCryptSetDirection(opmode);
        wolfCryptSetIV(spec, random);
        wolfCryptSetKey(key);
        this.operationStarted = false;
        this.cipherInitialized = true;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {

        try {

            wolfCryptCipherInit(opmode, key, null, random);

            log("initialized with key");

        } catch (InvalidAlgorithmParameterException iape) {
            throw new InvalidKeyException("Invalid algorithm parameters");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key,
            AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        wolfCryptCipherInit(opmode, key, params, random);

        log("initialized with key and AlgorithmParameterSpec");
    }

    @Override
    protected void engineInit(int opmode, Key key,
            AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        AlgorithmParameterSpec spec;

        try {

            if (this.cipherMode == CipherMode.WC_GCM) {
                spec = params.getParameterSpec(GCMParameterSpec.class);
            }
            else {
                spec = params.getParameterSpec(IvParameterSpec.class);
            }

            log("initialized with key and AlgorithmParameters");

        } catch (InvalidParameterSpecException ipe) {
            throw new InvalidAlgorithmParameterException(ipe);
        }

        wolfCryptCipherInit(opmode, key, spec, random);
    }

    /* return 1 if this is a block cipher, otherwise 0 */
    private boolean isBlockCipher() {

        boolean isBlockCipher = false;

        switch (this.cipherType) {
            case WC_AES:
            case WC_DES3:
                isBlockCipher = true;
                break;
            default:
                isBlockCipher = false;
                break;
        };

        return isBlockCipher;
    }

    private byte[] wolfCryptUpdate(byte[] input, int inputOffset, int len)
        throws IllegalArgumentException {

        int  blocks    = 0;
        int  bytesToProcess = 0;
        byte[] output  = null;
        byte[] tmpIn   = null;
        byte[] tmpBuf  = null;

        if (input == null || len < 0)
            throw new IllegalArgumentException("Null input buffer or len < 0");

        this.operationStarted = true;

        if ((buffered.length + len) == 0) {
            /* no data to process */
            return null;
        }

        if (len > 0) {
            /* add input bytes to buffered */
            tmpIn = new byte[buffered.length + len];
            System.arraycopy(buffered, 0, tmpIn, 0, buffered.length);
            System.arraycopy(input, inputOffset, tmpIn, buffered.length, len);
            buffered = tmpIn;
        }

        /* keep buffered data if RSA or data is less than block size, or doing
         * AES-GCM/CCM without stream mode compiled natively, but not for
         * CTR/OFB which are stream ciphers */
        if ((cipherType == CipherType.WC_RSA) ||
            ((cipherType == CipherType.WC_AES) &&
             (cipherMode == CipherMode.WC_GCM ||
              cipherMode == CipherMode.WC_CCM)) ||
            ((buffered.length < blockSize) &&
             (cipherMode != CipherMode.WC_CTR) &&
             (cipherMode != CipherMode.WC_OFB))) {
            return new byte[0];
        }

        /* calculate blocks and partial non-block size remaining */
        blocks    = buffered.length / blockSize;
        bytesToProcess = blocks * blockSize;

        /* CTR and OFB are stream ciphers, process all available data */
        if (cipherMode == CipherMode.WC_CTR ||
            cipherMode == CipherMode.WC_OFB) {
            bytesToProcess = buffered.length;
        }
        /* if PKCS#5/7 padding, and decrypting, hold on to last block for
         * padding check in wolfCryptFinal() */
        else if (paddingType == PaddingType.WC_PKCS5 &&
                 direction == OpMode.WC_DECRYPT) {
            bytesToProcess -= blockSize;
        }

        /* not enough data to process yet return until more or final */
        if (bytesToProcess == 0) {
            return new byte[0];
        }

        tmpIn = new byte[bytesToProcess];
        System.arraycopy(buffered, 0, tmpIn, 0, bytesToProcess);

        /* buffer remaining non-block size input, or reset */
        tmpBuf = new byte[buffered.length - bytesToProcess];
        System.arraycopy(buffered, bytesToProcess, tmpBuf, 0, tmpBuf.length);
        buffered = tmpBuf;

        /* process tmpIn[] */
        switch (this.cipherType) {

            /* Only CBC/ECB/CTR/OFB mode reaches this point currently, GCM
             * caches all data internally above until final call */
            case WC_AES:
                if (cipherMode == CipherMode.WC_ECB) {
                    output = this.aesEcb.update(tmpIn, 0, tmpIn.length);
                }
                else if (cipherMode == CipherMode.WC_CTR) {
                    output = this.aesCtr.update(tmpIn, 0, tmpIn.length);
                }
                else if (cipherMode == CipherMode.WC_OFB) {
                    output = this.aesOfb.update(tmpIn, 0, tmpIn.length);
                }
                else {
                    output = this.aes.update(tmpIn, 0, tmpIn.length);

                    /* truncate */
                    output = Arrays.copyOfRange(output, 0, tmpIn.length);
                }

                break;

            case WC_DES3:
                output = this.des3.update(tmpIn, 0, tmpIn.length);

                /* truncate */
                output = Arrays.copyOfRange(output, 0, tmpIn.length);

                break;

            default:
                throw new RuntimeException("Unsupported algorithm type");
        };

        if (output == null) {
            /* For interop compatibility, return empty byte array */
            output = new byte[0];
        }

        return output;
    }

    private byte[] wolfCryptFinal(byte[] input, int inputOffset, int len)
        throws IllegalBlockSizeException, BadPaddingException {

        int  totalSz  = 0;
        byte tmpIn[]  = null;
        byte tmpOut[] = null;

        this.operationStarted = true;
        totalSz = buffered.length + len;

        /* AES-GCM, AES-CCM, AES-CTR, and AES-OFB do not require
         * block size inputs */
        if (isBlockCipher() &&
            (cipherMode != CipherMode.WC_GCM) &&
            (cipherMode != CipherMode.WC_CCM) &&
            (cipherMode != CipherMode.WC_CTR) &&
            (cipherMode != CipherMode.WC_OFB) &&
            (this.direction == OpMode.WC_DECRYPT ||
            (this.direction == OpMode.WC_ENCRYPT &&
             this.paddingType != PaddingType.WC_PKCS5)) &&
            (totalSz % blockSize != 0)) {
            throw new IllegalBlockSizeException(
                    "Input length not multiple of " + blockSize + " bytes");
        }

        /* do final encrypt over totalSz */
        tmpIn = new byte[totalSz];
        System.arraycopy(buffered, 0, tmpIn, 0, buffered.length);
        if (input != null && len > 0) {
            System.arraycopy(input, inputOffset, tmpIn, buffered.length, len);
        }

        /* add padding if encrypting and PKCS5 padding is used. PKCS#5 padding
         * is treated the same as PKCS#7 padding here, using each algorithm's
         * specific block size. CCM, CTR and OFB modes do not use padding */
        if (this.direction == OpMode.WC_ENCRYPT &&
            this.paddingType == PaddingType.WC_PKCS5 &&
            cipherMode != CipherMode.WC_CCM &&
            cipherMode != CipherMode.WC_CTR &&
            cipherMode != CipherMode.WC_OFB) {
            if (this.cipherType == CipherType.WC_AES) {
                tmpIn = Aes.padPKCS7(tmpIn, Aes.BLOCK_SIZE);
            } else if (this.cipherType == CipherType.WC_DES3) {
                tmpIn = Des3.padPKCS7(tmpIn, Des3.BLOCK_SIZE);
            }
        }

        switch (this.cipherType) {

            case WC_AES:
                if (cipherMode == CipherMode.WC_GCM) {
                    if (this.direction == OpMode.WC_ENCRYPT) {
                        byte[] tag = new byte[this.gcmTagLen];
                        tmpOut = this.aesGcm.encrypt(tmpIn, this.iv, tag,
                                    this.aadData);

                        /* Concatenate auth tag to end of ciphertext */
                        byte[] totalOut = new byte[tmpOut.length + tag.length];
                        System.arraycopy(tmpOut, 0, totalOut, 0, tmpOut.length);
                        System.arraycopy(tag, 0, totalOut, tmpOut.length,
                                         tag.length);
                        tmpOut = totalOut;
                    }
                    else {
                        /* Get auth tag from end of ciphertext */
                        byte[] tag = Arrays.copyOfRange(tmpIn,
                                        tmpIn.length - this.gcmTagLen,
                                        tmpIn.length);

                        /* Shrink ciphertext array down to not include tag */
                        tmpIn = Arrays.copyOfRange(tmpIn, 0,
                                    tmpIn.length - this.gcmTagLen);

                        tmpOut = this.aesGcm.decrypt(tmpIn, this.iv, tag,
                                    this.aadData);
                    }
                }
                else if (cipherMode == CipherMode.WC_CCM) {
                    if (this.direction == OpMode.WC_ENCRYPT) {
                        byte[] tag = new byte[this.gcmTagLen];
                        tmpOut = this.aesCcm.encrypt(tmpIn, this.iv, tag,
                                    this.aadData);

                        /* Concatenate auth tag to end of ciphertext */
                        byte[] totalOut = new byte[tmpOut.length + tag.length];
                        System.arraycopy(tmpOut, 0, totalOut, 0, tmpOut.length);
                        System.arraycopy(tag, 0, totalOut, tmpOut.length,
                                         tag.length);
                        tmpOut = totalOut;
                    }
                    else {
                        /* Get auth tag from end of ciphertext */
                        byte[] tag = Arrays.copyOfRange(tmpIn,
                                        tmpIn.length - this.gcmTagLen,
                                        tmpIn.length);

                        /* Shrink ciphertext array down to not include tag */
                        tmpIn = Arrays.copyOfRange(tmpIn, 0,
                                    tmpIn.length - this.gcmTagLen);

                        tmpOut = this.aesCcm.decrypt(tmpIn, this.iv, tag,
                                    this.aadData);
                    }
                }
                else if (cipherMode == CipherMode.WC_ECB) {
                    tmpOut = this.aesEcb.update(tmpIn, 0, tmpIn.length);
                }
                else if (cipherMode == CipherMode.WC_CTR) {
                    tmpOut = this.aesCtr.update(tmpIn, 0, tmpIn.length);
                }
                else if (cipherMode == CipherMode.WC_OFB) {
                    tmpOut = this.aesOfb.update(tmpIn, 0, tmpIn.length);
                }
                else {
                    tmpOut = this.aes.update(tmpIn, 0, tmpIn.length);

                    /* truncate */
                    tmpOut = Arrays.copyOfRange(tmpOut, 0, tmpIn.length);
                }

                /* strip PKCS#5/PKCS#7 padding if required,
                 * CCM, CTR and OFB modes do not use padding */
                if (this.direction == OpMode.WC_DECRYPT &&
                    this.paddingType == PaddingType.WC_PKCS5 &&
                    cipherMode != CipherMode.WC_CCM &&
                    cipherMode != CipherMode.WC_CTR &&
                    cipherMode != CipherMode.WC_OFB) {
                    tmpOut = Aes.unPadPKCS7(tmpOut, Aes.BLOCK_SIZE);
                }

                break;

            case WC_DES3:
                tmpOut = this.des3.update(tmpIn, 0, tmpIn.length);

                /* truncate */
                tmpOut = Arrays.copyOfRange(tmpOut, 0, tmpIn.length);

                /* strip PKCS#5/PKCS#7 padding if required */
                if (this.direction == OpMode.WC_DECRYPT &&
                    this.paddingType == PaddingType.WC_PKCS5) {
                    tmpOut = Des3.unPadPKCS7(tmpOut, Des3.BLOCK_SIZE);
                }

                break;

            case WC_RSA:

                if (this.direction == OpMode.WC_ENCRYPT) {

                    if (this.rsaKeyType == RsaKeyType.WC_RSA_PRIVATE) {
                        tmpOut = this.rsa.sign(tmpIn, this.rng);

                    } else {
                        tmpOut = this.rsa.encrypt(tmpIn, this.rng);
                    }

                } else {
                    if (this.rsaKeyType == RsaKeyType.WC_RSA_PRIVATE) {
                        tmpOut = this.rsa.decrypt(tmpIn);
                    } else {
                        tmpOut = this.rsa.verify(tmpIn);
                    }
                }
                break;

            default:
                throw new RuntimeException("Unsupported algorithm type");
        };

        /* reset state, user doesn't need to call init again before use */
        try {
            buffered = new byte[0];

            if (this.direction == OpMode.WC_ENCRYPT) {
                wolfCryptSetDirection(Cipher.ENCRYPT_MODE);
            } else {
                wolfCryptSetDirection(Cipher.DECRYPT_MODE);
            }

            InitializeNativeStructs();

            /* Preserve the existing IV during cipher reset to maintain
             * consistency with JCE getIV() behavior. If storedSpec is null
             * (no IV was provided initially), wolfCryptSetIV would generate
             * a new random IV, overwriting the original one. */
            if (storedSpec == null && this.iv != null) {
                /* Create an IvParameterSpec with the current IV to avoid
                 * generating a new random IV during reset */
                AlgorithmParameterSpec currentIvSpec =
                    new IvParameterSpec(this.iv.clone());
                wolfCryptSetIV(currentIvSpec, null);
            } else {
                wolfCryptSetIV(storedSpec, null);
            }

            wolfCryptSetKey(storedKey);

            this.aadData = null;
            this.operationStarted = false;
            this.cipherInitialized = true;

        } catch (InvalidKeyException e) {
            throw new RuntimeException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e.getMessage());
        }

        return tmpOut;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
        throws IllegalStateException {

        byte output[];

        if (!this.cipherInitialized) {
            throw new IllegalStateException(
                "Cipher has not been initialized yet");
        }

        log("update (offset: " + inputOffset + ", len: " + inputLen + ")");

        output = wolfCryptUpdate(input, inputOffset, inputLen);

        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset)
        throws IllegalStateException, ShortBufferException {

        byte tmpOut[];

        if (!this.cipherInitialized) {
            throw new IllegalStateException(
                "Cipher has not been initialized yet");
        }

        log("update (in offset: " + inputOffset + ", len: " +
            inputLen + ", out offset: " + outputOffset + ")");

        tmpOut = wolfCryptUpdate(input, inputOffset, inputLen);
        if (tmpOut == null) {
            return 0;
        }
        System.arraycopy(tmpOut, 0, output, outputOffset, tmpOut.length);

        return tmpOut.length;
    }

    private void zeroArray(byte[] in) {

        if (in == null)
            return;

        for (int i = 0; i < in.length; i++) {
            in[i] = 0;
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset,
            int inputLen)
        throws IllegalStateException, IllegalBlockSizeException,
               BadPaddingException {

        if (!this.cipherInitialized) {
            throw new IllegalStateException(
                "Cipher has not been initialized yet");
        }

        log("final (offset: " + inputOffset + ", len: " + inputLen + ")");

        return wolfCryptFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset,
            int inputLen, byte[] output, int outputOffset)
        throws IllegalStateException, ShortBufferException,
               IllegalBlockSizeException, BadPaddingException {

        byte tmpOut[];

        if (!this.cipherInitialized) {
            throw new IllegalStateException(
                "Cipher has not been initialized yet");
        }

        log("final (in offset: " + inputOffset + ", len: " +
            inputLen + ", out offset: " + outputOffset + ")");

        tmpOut = wolfCryptFinal(input, inputOffset, inputLen);

        System.arraycopy(tmpOut, 0, output, outputOffset, tmpOut.length);

        return tmpOut.length;
    }

    @Override
    protected int engineGetKeySize(Key key)
        throws InvalidKeyException {

        byte encodedKey[] = null;

        /* validate key class type */
        if (this.cipherType == CipherType.WC_RSA) {

            if (key instanceof RSAPrivateKey) {
                this.rsaKeyType = RsaKeyType.WC_RSA_PRIVATE;

            } else if (key instanceof RSAPublicKey) {
                this.rsaKeyType = RsaKeyType.WC_RSA_PUBLIC;

            } else {
                throw new InvalidKeyException(
                    "Cipher key must be of type RSAPrivateKey or " +
                    "RSAPublicKey when used for RSA encrypt or decrypt");
            }

        } else if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException(
                "Cipher key must be of type SecretKey");
        }

        encodedKey = key.getEncoded();
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        return encodedKey.length;
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len)
        throws IllegalArgumentException, IllegalStateException {

        if (this.cipherType != CipherType.WC_AES ||
            (this.cipherMode != CipherMode.WC_GCM &&
             this.cipherMode != CipherMode.WC_CCM)) {
            throw new IllegalStateException(
                "AAD only supported for AES-GCM and AES-CCM");
        }

        if (this.operationStarted) {
            throw new IllegalStateException(
                "Must set AAD before calling Cipher.update/final");
        }

        if (!this.cipherInitialized ||
            (this.cipherMode == CipherMode.WC_GCM && this.aesGcm == null) ||
            (this.cipherMode == CipherMode.WC_CCM && this.aesCcm == null)) {
            throw new IllegalStateException(
                "Cipher not initialized yet");
        }

        if (src == null || offset < 0 || len < 0 ||
            (src.length < (offset + len))) {
            throw new IllegalArgumentException(
                "Source buffer is null or bad offset/len");
        }

        if (this.aadData == null) {
            /* Store as new array inside object */
            this.aadData = new byte[len];
            System.arraycopy(src, offset, this.aadData, 0, len);
        }
        else {
            /* Append to existing AAD array held inside object */
            byte[] tmp = new byte[this.aadData.length + len];
            System.arraycopy(this.aadData, 0, tmp, 0, this.aadData.length);
            System.arraycopy(src, offset, tmp, this.aadData.length, len);
            this.aadData = tmp;
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src)
        throws IllegalArgumentException, IllegalStateException {

        int originalPos = 0;
        byte[] remaining = null;

        if (src == null) {
            throw new IllegalArgumentException("Source buffer is null");
        }

        originalPos = src.position();
        remaining = new byte[src.remaining()];

        src.get(remaining);

        try {
            engineUpdateAAD(remaining, 0, remaining.length);
        } catch (IllegalStateException | IllegalArgumentException e) {
            /* restore state of ByteBuffer on state error before returning */
            src.position(originalPos);
            throw e;
        }
    }

    private String typeToString(CipherType type) {
        switch (type) {
            case WC_AES:
                return "AES";
            case WC_DES3:
                return "3DES";
            case WC_RSA:
                return "RSA";
            default:
                return "None";
        }
    }

    private String modeToString(CipherMode type) {
        switch (type) {
            case WC_ECB:
                return "ECB";
            case WC_CBC:
                return "CBC";
            case WC_GCM:
                return "GCM";
            case WC_CCM:
                return "CCM";
            default:
                return "None";
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[" + algString + "-" + algMode + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.aes != null) {
                this.aes.releaseNativeStruct();
                this.aes = null;
            }

            if (this.aesEcb != null) {
                this.aesEcb.releaseNativeStruct();
                this.aesEcb = null;
            }

            if (this.aesGcm != null) {
                this.aesGcm.releaseNativeStruct();
                this.aesGcm = null;
            }

            if (this.aesCcm != null) {
                this.aesCcm.releaseNativeStruct();
                this.aesCcm = null;
            }

            if (this.des3 != null) {
                this.des3.releaseNativeStruct();
                this.des3 = null;
            }

            if (this.rsa != null) {
                this.rsa.releaseNativeStruct();
                this.rsa = null;
            }

            if (this.rng != null) {
                this.rng.releaseNativeStruct();
                this.rng = null;
            }

            zeroArray(this.iv);

            this.storedKey = null;
            this.storedSpec = null;

        } finally {
            super.finalize();
        }
    }

    /**
     * Class for AES-CBC with no padding
     */
    public static final class wcAESCBCNoPadding extends WolfCryptCipher {
        /**
         * Create new wcAESCBCNoPadding object
         */
        public wcAESCBCNoPadding() {
            super(CipherType.WC_AES, CipherMode.WC_CBC, PaddingType.WC_NONE);
        }
    }

    /**
     * Class for AES-CBC with PKCS#5 padding
     */
    public static final class wcAESCBCPKCS5Padding extends WolfCryptCipher {
        /**
         * Create new wcAESCBCPkcs5Padding object
         */
        public wcAESCBCPKCS5Padding() {
            super(CipherType.WC_AES, CipherMode.WC_CBC, PaddingType.WC_PKCS5);
        }
    }

    /**
     * Class for AES-GCM with no padding
     */
    public static final class wcAESGCMNoPadding extends WolfCryptCipher {
        /**
         * Create new wcAESGCMNoPadding object
         */
        public wcAESGCMNoPadding() {
            super(CipherType.WC_AES, CipherMode.WC_GCM, PaddingType.WC_NONE);
        }
    }

    /**
     * Class for AES-CCM with no padding
     */
    public static final class wcAESCCMNoPadding extends WolfCryptCipher {
        /**
         * Create new wcAESCCMNoPadding object
         */
        public wcAESCCMNoPadding() {
            super(CipherType.WC_AES, CipherMode.WC_CCM, PaddingType.WC_NONE);
        }
    }

    /**
     * Class for DES-EDE-CBC with no padding
     */
    public static final class wcDESedeCBCNoPadding extends WolfCryptCipher {
        /**
         * Create new wcDESedeCBCNoPadding object
         */
        public wcDESedeCBCNoPadding() {
            super(CipherType.WC_DES3, CipherMode.WC_CBC, PaddingType.WC_NONE);
        }
    }

    /**
     * Class for AES-ECB with no padding
     */
    public static final class wcAESECBNoPadding extends WolfCryptCipher {
        /**
         * Create new wcAESECBNoPadding object
         */
        public wcAESECBNoPadding() {
            super(CipherType.WC_AES, CipherMode.WC_ECB, PaddingType.WC_NONE);
        }
    }

    /**
     * Class for AES-ECB with PKCS#5 padding
     */
    public static final class wcAESECBPKCS5Padding extends WolfCryptCipher {
        /**
         * Create new wcAESECBPKCS5Padding object
         */
        public wcAESECBPKCS5Padding() {
            super(CipherType.WC_AES, CipherMode.WC_ECB, PaddingType.WC_PKCS5);
        }
    }

    /**
     * Class for AES-CTR with no padding
     */
    public static final class wcAESCTRNoPadding extends WolfCryptCipher {
        /**
         * Create new wcAESCTRNoPadding object
         */
        public wcAESCTRNoPadding() {
            super(CipherType.WC_AES, CipherMode.WC_CTR, PaddingType.WC_NONE);
        }
    }

    /**
     * Class for AES-OFB with no padding
     */
    public static final class wcAESOFBNoPadding extends WolfCryptCipher {
        /**
         * Create new wcAESOFBNoPadding object
         */
        public wcAESOFBNoPadding() {
            super(CipherType.WC_AES, CipherMode.WC_OFB, PaddingType.WC_NONE);
        }
    }

    /**
     * Class for RSA-ECB with PKCS1 padding
     */
    public static final class wcRSAECBPKCS1Padding extends WolfCryptCipher {
        /**
         * Create new wcRSAECBPKCS1Padding object
         */
        public wcRSAECBPKCS1Padding() {
            super(CipherType.WC_RSA, CipherMode.WC_ECB, PaddingType.WC_PKCS1);
        }
    }
}

