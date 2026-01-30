/* WolfCryptCipher.java
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

import java.util.Arrays;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.AEADBadTagException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.AesEcb;
import com.wolfssl.wolfcrypt.AesCtr;
import com.wolfssl.wolfcrypt.AesOfb;
import com.wolfssl.wolfcrypt.AesGcm;
import com.wolfssl.wolfcrypt.AesCcm;
import com.wolfssl.wolfcrypt.AesCts;
import com.wolfssl.wolfcrypt.Des3;
import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

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
        WC_CCM,
        WC_CTS
    }

    enum PaddingType {
        WC_NONE,
        WC_PKCS1,
        WC_PKCS5,
        WC_OAEP_SHA1,
        WC_OAEP_SHA256
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
    private AesCts aesCts = null;
    private Des3 des3     = null;
    private Rsa  rsa      = null;
    private Rng  rng      = null;

    /* RSA-OAEP parameters */
    private int oaepHashType = 0;
    private int oaepMgf = 0;

    /* for debug logging */
    private String algString;
    private String algMode;

    /* stash key and IV here for easy lookup */
    private Key storedKey = null;
    private AlgorithmParameterSpec storedSpec = null;
    private byte[] iv = null;

    /* AES-GCM/CCM tag length (bytes), default to 128 bits */
    private int gcmTagLen = 16;

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

        /* Initialize OAEP parameters if using OAEP padding */
        if (pad == PaddingType.WC_OAEP_SHA256) {
            initOaepParams();
        } else if (pad == PaddingType.WC_OAEP_SHA1) {
            initOaepParamsSha1();
        }

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
     * Initialize OAEP parameters for RSA-OAEP padding.
     * Uses SHA-256 for OAEP hash and SHA-1 for MGF1 hash to match
     * JCE default behavior for OAEPWithSHA-256AndMGF1Padding.
     */
    private void initOaepParams() {
        this.oaepHashType = WolfCrypt.WC_HASH_TYPE_SHA256;
        this.oaepMgf = Rsa.WC_MGF1SHA1;
    }

    /**
     * Initialize OAEP parameters for RSA-OAEP padding with SHA-1.
     * Uses SHA-1 for OAEP hash and SHA-1 for MGF1 hash to match
     * JCE default behavior for OAEPWithSHA-1AndMGF1Padding.
     */
    private void initOaepParamsSha1() {
        this.oaepHashType = WolfCrypt.WC_HASH_TYPE_SHA;
        this.oaepMgf = Rsa.WC_MGF1SHA1;
    }

    /**
     * Convert JCE hash algorithm name to wolfCrypt hash type constant.
     *
     * @param hashAlgo JCE hash algorithm name (e.g., "SHA-256", "SHA-1")
     * @return wolfCrypt hash type constant
     * @throws InvalidAlgorithmParameterException if hash algorithm is not
     *         supported
     */
    private int hashNameToWolfCryptType(String hashAlgo)
        throws InvalidAlgorithmParameterException {

        if (hashAlgo == null) {
            throw new InvalidAlgorithmParameterException(
                "Hash algorithm name cannot be null");
        }

        switch (hashAlgo.toUpperCase()) {
            case "SHA-1":
            case "SHA1":
                return WolfCrypt.WC_HASH_TYPE_SHA;
            case "SHA-224":
            case "SHA224":
                return WolfCrypt.WC_HASH_TYPE_SHA224;
            case "SHA-256":
            case "SHA256":
                return WolfCrypt.WC_HASH_TYPE_SHA256;
            case "SHA-384":
            case "SHA384":
                return WolfCrypt.WC_HASH_TYPE_SHA384;
            case "SHA-512":
            case "SHA512":
                return WolfCrypt.WC_HASH_TYPE_SHA512;
            default:
                throw new InvalidAlgorithmParameterException(
                    "Unsupported OAEP hash algorithm: " + hashAlgo);
        }
    }

    /**
     * Convert MGF1ParameterSpec to wolfCrypt MGF type constant.
     *
     * @param mgfSpec MGF1ParameterSpec containing the hash algorithm
     * @return wolfCrypt MGF type constant
     * @throws InvalidAlgorithmParameterException if MGF hash algorithm is not
     *         supported
     */
    private int mgf1SpecToWolfCryptMgf(MGF1ParameterSpec mgfSpec)
        throws InvalidAlgorithmParameterException {

        if (mgfSpec == null) {
            throw new InvalidAlgorithmParameterException(
                "MGF1ParameterSpec cannot be null");
        }

        String hashAlgo = mgfSpec.getDigestAlgorithm();

        switch (hashAlgo.toUpperCase()) {
            case "SHA-1":
            case "SHA1":
                return Rsa.WC_MGF1SHA1;
            case "SHA-224":
            case "SHA224":
                return Rsa.WC_MGF1SHA224;
            case "SHA-256":
            case "SHA256":
                return Rsa.WC_MGF1SHA256;
            case "SHA-384":
            case "SHA384":
                return Rsa.WC_MGF1SHA384;
            case "SHA-512":
            case "SHA512":
                return Rsa.WC_MGF1SHA512;
            default:
                throw new InvalidAlgorithmParameterException(
                    "Unsupported MGF1 hash algorithm: " + hashAlgo);
        }
    }

    /**
     * Set OAEP parameters from OAEPParameterSpec.
     *
     * @param spec OAEPParameterSpec containing OAEP parameters
     * @throws InvalidAlgorithmParameterException if parameters are invalid
     */
    private void setOaepParams(OAEPParameterSpec spec)
        throws InvalidAlgorithmParameterException {

        AlgorithmParameterSpec mgfParams = null;
        PSource pSource = null;

        if (spec == null) {
            throw new InvalidAlgorithmParameterException(
                "OAEPParameterSpec cannot be null");
        }

        /* Validate MGF algorithm is MGF1 */
        if (!spec.getMGFAlgorithm().equals("MGF1") &&
            !spec.getMGFAlgorithm().equals(OAEPParameterSpec.DEFAULT.
                getMGFAlgorithm())) {
            throw new InvalidAlgorithmParameterException(
                "Only MGF1 is supported for OAEP, got: " +
                spec.getMGFAlgorithm());
        }

        /* Get MGF parameters */
        mgfParams = spec.getMGFParameters();
        if (!(mgfParams instanceof MGF1ParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                "MGF parameters must be MGF1ParameterSpec");
        }

        /* Validate PSource is PSpecified with empty label (default) */
        pSource = spec.getPSource();
        if (pSource != null && pSource instanceof PSource.PSpecified) {
            byte[] label = ((PSource.PSpecified) pSource).getValue();
            if (label != null && label.length > 0) {
                throw new InvalidAlgorithmParameterException(
                    "OAEP label (PSource) must be empty, custom labels " +
                    "are not supported");
            }
        }

        /* Set OAEP hash type */
        this.oaepHashType = hashNameToWolfCryptType(spec.getDigestAlgorithm());

        /* Set MGF type */
        this.oaepMgf = mgf1SpecToWolfCryptMgf((MGF1ParameterSpec) mgfParams);

        log("set OAEP params: hash=" + spec.getDigestAlgorithm() +
            ", mgf1Hash=" + ((MGF1ParameterSpec) mgfParams).
            getDigestAlgorithm());
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
                else if (cipherMode == CipherMode.WC_CTS) {
                    if (aesCts != null) {
                        aesCts.releaseNativeStruct();
                        aesCts = null;
                    }
                    aesCts = new AesCts();
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

        } else if (mode.equals("CTS")) {

            /* AES supports CTS */
            if (cipherType == CipherType.WC_AES) {
                cipherMode = CipherMode.WC_CTS;
                supported = 1;

                log("set mode to CTS");
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

        } else if (padding.equals("OAEPWithSHA-256AndMGF1Padding") ||
                   padding.equals("OAEPWithSHA256AndMGF1Padding")) {

            if (cipherType == CipherType.WC_RSA) {
                paddingType = PaddingType.WC_OAEP_SHA256;
                initOaepParams();
                supported = 1;

                log("set padding to OAEPWithSHA-256AndMGF1Padding");
            }

        } else if (padding.equals("OAEPWithSHA-1AndMGF1Padding") ||
                   padding.equals("OAEPWithSHA1AndMGF1Padding")) {

            if (cipherType == CipherType.WC_RSA) {
                paddingType = PaddingType.WC_OAEP_SHA1;
                initOaepParamsSha1();
                supported = 1;

                log("set padding to OAEPWithSHA-1AndMGF1Padding");
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

        int outSize = 0;
        int totalSz = inputLen;
        int totalBlocks = 0;

        if (!this.cipherInitialized) {
            throw new IllegalStateException(
                "Cipher has not been initialized yet");
        }

        /* Add buffered data size to input length, calculate total blocks */
        if (isBlockCipher()) {
            if (buffered != null && buffered.length > 0) {
                totalSz = inputLen + buffered.length;
            } else {
                totalSz = inputLen;
            }

            /* For block ciphers that require block boundaries, round
             * to next block size. GCM, CCM, CTR, CTS, and OFB do not require
             * block boundaries. */
            if (cipherMode != CipherMode.WC_GCM &&
                cipherMode != CipherMode.WC_CCM &&
                cipherMode != CipherMode.WC_CTR &&
                cipherMode != CipherMode.WC_CTS &&
                cipherMode != CipherMode.WC_OFB) {
                totalBlocks = totalSz / blockSize;
                totalSz = totalBlocks * blockSize;
            }
        }

        switch (this.cipherType) {
            case WC_AES:
                if (paddingType == PaddingType.WC_NONE) {
                    if (cipherMode == CipherMode.WC_GCM) {
                        /* In AES-GCM mode we append the authentication tag
                         * to the end of ciphertext, When decrypting, output
                         * size will have it taken off. */
                        if (this.direction == OpMode.WC_ENCRYPT) {
                            outSize = totalSz + this.gcmTagLen;
                        }
                        else {
                            outSize = totalSz - this.gcmTagLen;
                        }
                        outSize = Math.max(outSize, 0);
                    }
                    else {
                        /* wolfCrypt expects input to be padded by application
                         * to block size, thus output is same size as input.
                         * If we have buffered data, and that plus inputLen
                         * makes another block, we will have one more block of
                         * data. */
                        outSize = totalSz;
                    }
                }
                else if (paddingType == PaddingType.WC_PKCS5) {
                    outSize = inputLen;
                    if (buffered != null && buffered.length > 0) {
                        outSize += buffered.length;
                    }
                    /* Only add padding size when encrypting. When decrypting,
                     * the output size should not include padding bytes since
                     * they will be stripped off during decryption. */
                    if (this.direction == OpMode.WC_ENCRYPT) {
                        outSize += Aes.getPKCS7PadSize(outSize, Aes.BLOCK_SIZE);
                    }
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
                    outSize = totalSz;
                }
                else if (paddingType == PaddingType.WC_PKCS5) {
                    outSize = inputLen;
                    if (buffered != null && buffered.length > 0) {
                        outSize += buffered.length;
                    }
                    /* Only add padding size when encrypting. When decrypting,
                     * the output size should not include padding bytes since
                     * they will be stripped off during decryption. */
                    if (this.direction == OpMode.WC_ENCRYPT) {
                        outSize += Des3.getPKCS7PadSize(outSize,
                            Des3.BLOCK_SIZE);
                    }
                }
                else {
                    throw new IllegalStateException(
                        "Unsupported padding mode for Cipher Des3");
                }

                break;

            case WC_RSA:
                outSize = this.rsa.getEncryptSize();
                break;
        }

        return outSize;
    }

    @Override
    protected byte[] engineGetIV() {
        return this.iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {

        AlgorithmParameters params = null;

        try {
            switch (this.cipherMode) {
                case WC_GCM:
                case WC_CCM:
                    /* Return parameters only if initialized */
                    if (this.iv != null && this.gcmTagLen > 0) {
                        params = AlgorithmParameters.getInstance("GCM");
                        GCMParameterSpec gcmSpec = new GCMParameterSpec(
                            this.gcmTagLen * 8, this.iv);
                        params.init(gcmSpec);
                    }
                    break;

                case WC_CBC:
                case WC_CTR:
                case WC_OFB:
                    if (this.iv != null) {
                        if (this.cipherType == CipherType.WC_AES) {
                            params = AlgorithmParameters.getInstance("AES");
                        }
                        else if (this.cipherType == CipherType.WC_DES3) {
                            params = AlgorithmParameters.getInstance("DESede");
                        }

                        if (params != null) {
                            IvParameterSpec ivSpec =
                                new IvParameterSpec(this.iv);
                            params.init(ivSpec);
                        }
                    }
                    break;

                /* ECB mode doesn't have parameters to return */
                case WC_ECB:
                    break;
            }

        } catch (NoSuchAlgorithmException |
                 InvalidParameterSpecException e) {
            /* Return null if parameter creation fails */
            params = null;
        }

        return params;
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
                throw new InvalidParameterException(
                    "Cipher opmode must be ENCRYPT_MODE or DECRYPT_MODE");
        }
    }

    private void wolfCryptSetIV(AlgorithmParameterSpec spec,
            SecureRandom random) throws InvalidAlgorithmParameterException {

        /* store AlgorithmParameterSpec for class reset */
        this.storedSpec = spec;

        /* Handle RSA OAEP parameters if provided */
        if (this.cipherType == CipherType.WC_RSA) {
            if (spec != null) {
                if (spec instanceof OAEPParameterSpec) {
                    if (this.paddingType != PaddingType.WC_OAEP_SHA256 &&
                        this.paddingType != PaddingType.WC_OAEP_SHA1) {
                        throw new InvalidAlgorithmParameterException(
                            "OAEPParameterSpec can only be used with " +
                            "OAEP padding modes");
                    }
                    setOaepParams((OAEPParameterSpec) spec);
                } else {
                    throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameterSpec for RSA OAEP must be of " +
                        "type OAEPParameterSpec");
                }
            }
            return;
        }

        /* AES-ECB doesn't need an IV */
        if (this.cipherType == CipherType.WC_AES &&
            this.cipherMode == CipherMode.WC_ECB)
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

                /* wolfSSL requires CRT parameters for RSA private key
                 * operations. Non-CRT keys (created with only modulus and
                 * private exponent) will fail with "mp_exptmod error state"
                 * or similar in the native layer. */
                if (!(key instanceof RSAPrivateCrtKey)) {
                    throw new InvalidKeyException(
                        "wolfSSL requires RSA private keys to include CRT " +
                        "parameters (p, q, dP, dQ, qInv). Keys created from " +
                        "only modulus and exponent are not supported.");
                }

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
                    else if (cipherMode == CipherMode.WC_CTS) {
                        this.aesCts.setKey(encodedKey, iv, AesCts.ENCRYPT_MODE);
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
                    else if (cipherMode == CipherMode.WC_CTS) {
                        this.aesCts.setKey(encodedKey, iv, AesCts.DECRYPT_MODE);
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

        /* Reset buffered data from any previous operation */
        buffered = new byte[0];

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

        AlgorithmParameterSpec spec = null;

        try {

            if (params != null) {
                if (this.cipherType == CipherType.WC_RSA &&
                    (this.paddingType == PaddingType.WC_OAEP_SHA256 ||
                     this.paddingType == PaddingType.WC_OAEP_SHA1)) {
                    spec = params.getParameterSpec(OAEPParameterSpec.class);
                }
                else if (this.cipherMode == CipherMode.WC_GCM ||
                    this.cipherMode == CipherMode.WC_CCM) {
                    spec = params.getParameterSpec(GCMParameterSpec.class);
                }
                else {
                    spec = params.getParameterSpec(IvParameterSpec.class);
                }
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

    /**
     * If a call to update() would be a no-op (or just return byte[0]) for the
     * selected cipher type, mode, and buffered data, return true.
     *
     * This happens in cases like RSA, or AES-GCM/CCM which don't support
     * streaming and buffer all data until doFinal() is called.
     *
     * @param inputSz total size in bytes of data available for processing,
     *        including input data and buffered data.
     *
     * @return true if update() would be a no-op, otherwise false
     */
    private boolean isNoOpUpdate(int inputSz) {

        /* RSA keeps buffered data until final() call */
        if (cipherType == CipherType.WC_RSA) {
            return true;
        }

        /* AES-GCM, AES-CCM, and AES-CTS keep all data buffered until
         * final() call. wolfJCE does not support streaming GCM/CCM yet.
         * CTS requires the entire message for ciphertext stealing. */
        if (cipherType == CipherType.WC_AES &&
            (cipherMode == CipherMode.WC_GCM ||
             cipherMode == CipherMode.WC_CCM ||
             cipherMode == CipherMode.WC_CTS)) {
            return true;
        }

        /* If total data input (plus buffered) is less than block size,
         * update() is a no-op, except for CTR and OFB which are stream
         * ciphers */
        if ((inputSz < blockSize) &&
            (cipherMode != CipherMode.WC_CTR) &&
            (cipherMode != CipherMode.WC_OFB)) {
            return true;
        }

        return false;
    }

    private byte[] wolfCryptUpdate(byte[] input, int inputOffset, int len)
        throws IllegalArgumentException {

        int  blocks    = 0;
        int  bytesToProcess = 0;
        byte[] output  = null;
        byte[] tmpIn   = null;
        byte[] tmpBuf  = null;

        if (input == null || len < 0 || inputOffset < 0) {
            throw new IllegalArgumentException(
                "Null input buffer or len/offset < 0");
        }

        if (input.length < (inputOffset + len)) {
            throw new IllegalArgumentException(
                "Input buffer length smaller than inputOffset + len");
        }

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

        /* Some algos/modes keep data buffered until the doFinal() call, like
         * RSA or AES-GCM/CCM without stream mode compiled natively. Just
         * return an empty byte array in those cases here. */
        if (isNoOpUpdate(len + buffered.length)) {
            return new byte[0];
        }

        /* Calculate blocks and partial non-block size remaining */
        blocks = buffered.length / blockSize;
        bytesToProcess = blocks * blockSize;

        /* CTR and OFB are stream ciphers, process all available data */
        if (cipherMode == CipherMode.WC_CTR ||
            cipherMode == CipherMode.WC_OFB) {
            bytesToProcess = buffered.length;
        }

        /* If PKCS#5/7 padding, and decrypting, hold on to last block for
         * padding check in wolfCryptFinal() */
        else if (paddingType == PaddingType.WC_PKCS5 &&
                 direction == OpMode.WC_DECRYPT &&
                 bytesToProcess > 0) {
            bytesToProcess -= blockSize;
        }

        /* Not enough data to process yet return until more or final */
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

            /* Only CBC/ECB/CTR/OFB mode reaches this point currently,
             * GCM/CCM/CTS cache all data internally above until final call */
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

        /* AES-CTS requires input length >= 16 bytes (RFC 3962/8009).
         * For exactly 16 bytes, CTS reduces to plain CBC, handled in JNI. */
        if (cipherMode == CipherMode.WC_CTS && totalSz < blockSize) {
            throw new IllegalBlockSizeException(
                "AES-CTS requires input length >= " + blockSize +
                " bytes, got " + totalSz + " bytes");
        }

        /* AES-GCM, AES-CCM, AES-CTR, AES-CTS, and AES-OFB do not require
         * block size inputs */
        if (isBlockCipher() &&
            (cipherMode != CipherMode.WC_GCM) &&
            (cipherMode != CipherMode.WC_CCM) &&
            (cipherMode != CipherMode.WC_CTR) &&
            (cipherMode != CipherMode.WC_CTS) &&
            (cipherMode != CipherMode.WC_OFB) &&
            (this.direction == OpMode.WC_DECRYPT ||
            (this.direction == OpMode.WC_ENCRYPT &&
             this.paddingType != PaddingType.WC_PKCS5)) &&
            (totalSz % blockSize != 0)) {
            throw new IllegalBlockSizeException(
                "Input length (" + totalSz + ") not multiple of " +
                blockSize + " bytes. (" + buffered.length +" buffered)");
        }

        /* do final encrypt over totalSz */
        tmpIn = new byte[totalSz];
        if (totalSz > 0) {
            System.arraycopy(buffered, 0, tmpIn, 0, buffered.length);
            if (input != null && len > 0) {
                System.arraycopy(input, inputOffset, tmpIn,
                    buffered.length, len);
            }
        }

        /* add padding if encrypting and PKCS5 padding is used. PKCS#5 padding
         * is treated the same as PKCS#7 padding here, using each algorithm's
         * specific block size. CCM, CTR, CTS, and OFB modes do not use
         * padding */
        if (this.direction == OpMode.WC_ENCRYPT &&
            this.paddingType == PaddingType.WC_PKCS5 &&
            cipherMode != CipherMode.WC_CCM &&
            cipherMode != CipherMode.WC_CTR &&
            cipherMode != CipherMode.WC_CTS &&
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
                        /* Case where input is only the authentication tag,
                         * zero-length plaintext */
                        if (tmpIn.length < this.gcmTagLen) {
                            throw new AEADBadTagException(
                                "Input too short for GCM tag, got " +
                                tmpIn.length + " bytes, need at least " +
                                this.gcmTagLen);
                        }

                        /* Get auth tag from end of ciphertext */
                        byte[] tag = Arrays.copyOfRange(tmpIn,
                                        tmpIn.length - this.gcmTagLen,
                                        tmpIn.length);

                        /* Shrink ciphertext array down to not include tag */
                        tmpIn = Arrays.copyOfRange(tmpIn, 0,
                                    tmpIn.length - this.gcmTagLen);

                        try {
                            tmpOut = this.aesGcm.decrypt(tmpIn, this.iv,
                                tag, this.aadData);

                        } catch (WolfCryptException e) {
                            /* Convert to AEADBadTagException */
                            if (e.getCode() ==
                                WolfCryptError.AES_GCM_AUTH_E.getCode()) {
                                /* Authentication check fail */
                                throw new AEADBadTagException(e.getMessage());
                            }
                            throw e;
                        }
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
                        /* Case where input is only the authentication tag,
                         * zero-length plaintext */
                        if (tmpIn.length < this.gcmTagLen) {
                            throw new AEADBadTagException(
                                "Input too short for CCM tag, got " +
                                tmpIn.length + " bytes, need at least " +
                                this.gcmTagLen);
                        }

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
                else if (cipherMode == CipherMode.WC_CTS) {
                    tmpOut = this.aesCts.update(tmpIn, 0, tmpIn.length);
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
                 * CCM, CTR, CTS, and OFB modes do not use padding */
                if (tmpOut != null && tmpOut.length > 0) {
                    if (this.direction == OpMode.WC_DECRYPT &&
                        this.paddingType == PaddingType.WC_PKCS5 &&
                        cipherMode != CipherMode.WC_CCM &&
                        cipherMode != CipherMode.WC_CTR &&
                        cipherMode != CipherMode.WC_CTS &&
                        cipherMode != CipherMode.WC_OFB) {
                        tmpOut = Aes.unPadPKCS7(tmpOut, Aes.BLOCK_SIZE);
                    }
                }

                break;

            case WC_DES3:
                tmpOut = this.des3.update(tmpIn, 0, tmpIn.length);

                /* truncate */
                tmpOut = Arrays.copyOfRange(tmpOut, 0, tmpIn.length);

                /* strip PKCS#5/PKCS#7 padding if required */
                if (tmpOut != null && tmpOut.length > 0) {
                    if (this.direction == OpMode.WC_DECRYPT &&
                        this.paddingType == PaddingType.WC_PKCS5) {
                        tmpOut = Des3.unPadPKCS7(tmpOut, Des3.BLOCK_SIZE);
                    }
                }

                break;

            case WC_RSA:

                if (this.paddingType == PaddingType.WC_OAEP_SHA256 ||
                    this.paddingType == PaddingType.WC_OAEP_SHA1) {
                    /* OAEP only supports public key encrypt, private decrypt */
                    if (this.direction == OpMode.WC_ENCRYPT) {
                        if (this.rsaKeyType == RsaKeyType.WC_RSA_PRIVATE) {
                            throw new IllegalStateException(
                                "OAEP padding requires public key for " +
                                "encryption");
                        }

                        tmpOut = this.rsa.encryptOaep(tmpIn, this.rng,
                            this.oaepHashType, this.oaepMgf);

                    } else {
                        if (this.rsaKeyType == RsaKeyType.WC_RSA_PUBLIC) {
                            throw new IllegalStateException(
                                "OAEP padding requires private key for " +
                                "decryption");
                        }

                        try {
                            tmpOut = this.rsa.decryptOaep(tmpIn,
                                this.oaepHashType, this.oaepMgf);

                        } catch (WolfCryptException e) {
                            throw new BadPaddingException(
                                "OAEP decryption failed: " + e.getMessage());
                        }
                    }
                } else {
                    /* PKCS#1 v1.5 padding */
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
                /* Create appropriate ParameterSpec with the current IV to avoid
                 * generating a new random IV during reset */
                AlgorithmParameterSpec currentIvSpec;
                if (cipherMode == CipherMode.WC_GCM) {
                    /* For GCM mode, create GCMParameterSpec with current
                     * IV and tag length */
                    currentIvSpec = new GCMParameterSpec(
                        this.gcmTagLen * 8, this.iv.clone());
                } else {
                    /* For other modes, use IvParameterSpec */
                    currentIvSpec = new IvParameterSpec(this.iv.clone());
                }
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

    /**
     * Sanity check output buffer size is large enough for update() call,
     * based on padding and buffered data.
     *
     * @param inputSz size of input data to update()
     * @param outputSz total size of output buffer provided
     *
     * @throws ShortBufferException if output buffer is too small
     */
    private void checkUpdateOutputBufferSize(int inputSz, int outputSz)
        throws ShortBufferException {

        int outSize;

        if (!isNoOpUpdate(inputSz)) {
            outSize = engineGetOutputSize(inputSz);

            /* update() in DECRYPT mode with PKCS5 padding will hold
             * back one block of data for padding check in final() */
            if (direction == OpMode.WC_DECRYPT &&
                paddingType == PaddingType.WC_PKCS5) {
                if (outSize % blockSize == 0) {
                    outSize -= blockSize;
                }
                else {
                    outSize -= (outSize % blockSize);
                }
            }

            if (outputSz < outSize) {
                throw new ShortBufferException(
                    "Output buffer too small, need " + outSize +
                    " bytes, got " + outputSz);
            }
        }
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

        log("update (inputOffset: " + inputOffset + ", inputLen: " +
            inputLen + ", outputOffset: " + outputOffset + ")");

        if (output == null || (output.length < outputOffset)) {
            throw new IllegalArgumentException(
                "output is null or offset past output array sz");
        }

        if (input == null || (inputLen + inputOffset > input.length)) {
            throw new IllegalArgumentException(
                "input is null or inOffset + inputLen past input array size");
        }

        /* Sanitize output buffer size, throws ShortBufferException if needed */
        checkUpdateOutputBufferSize(inputLen, output.length - outputOffset);

        tmpOut = wolfCryptUpdate(input, inputOffset, inputLen);
        if (tmpOut == null) {
            return 0;
        }

        if (output.length - outputOffset < tmpOut.length) {
            throw new ShortBufferException(
                "Output buffer too small, need " + tmpOut.length +
                " bytes, got " + (output.length - outputOffset));
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

        log("final (offset: " + inputOffset + ", len: " + inputLen +
            ", buffered: " + buffered.length + ")");

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

        log("final (inputOffset: " + inputOffset + ", inputLen: " +
            inputLen + ", outputOffset: " + outputOffset + ", buffered: " +
            buffered.length + ")");

        if (output == null || (outputOffset > output.length)) {
            throw new IllegalArgumentException(
                "output is null or offset past output array sz");
        }

        /* SunJCE can save Cipher state so it can throw a more precise
         * ShortBufferException after checking the actual length after
         * stripping padding. But, native wolfCrypt does not support
         * saving/restoring Aes state, so we err on the side of making callers
         * give us up to the next block size of output space */
        if ((output.length - outputOffset) < engineGetOutputSize(inputLen)) {
            throw new ShortBufferException("Output buffer too small, need " +
                engineGetOutputSize(inputLen) + " bytes, got " +
                (output.length - outputOffset));
        }

        tmpOut = wolfCryptFinal(input, inputOffset, inputLen);

        if (output.length - outputOffset < tmpOut.length) {
            throw new ShortBufferException(
                "Output buffer too small, need " + tmpOut.length +
                " bytes, got " + (output.length - outputOffset));
        }

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

            if (this.aesCts != null) {
                this.aesCts.releaseNativeStruct();
                this.aesCts = null;
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
     * Class for AES-CTS with no padding
     */
    public static final class wcAESCTSNoPadding extends WolfCryptCipher {
        /**
         * Create new wcAESCTSNoPadding object
         */
        public wcAESCTSNoPadding() {
            super(CipherType.WC_AES, CipherMode.WC_CTS, PaddingType.WC_NONE);
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

    /**
     * Class for RSA-ECB with OAEP SHA-256 padding
     */
    public static final class wcRSAECBOAEPSHA256Padding
        extends WolfCryptCipher {
        /**
         * Create new wcRSAECBOAEPSHA256Padding object
         */
        public wcRSAECBOAEPSHA256Padding() {
            super(CipherType.WC_RSA, CipherMode.WC_ECB,
                  PaddingType.WC_OAEP_SHA256);
        }
    }

    /**
     * Class for RSA-ECB with OAEP SHA-1 padding
     */
    public static final class wcRSAECBOAEPSHA1Padding
        extends WolfCryptCipher {
        /**
         * Create new wcRSAECBOAEPSHA1Padding object
         */
        public wcRSAECBOAEPSHA1Padding() {
            super(CipherType.WC_RSA, CipherMode.WC_ECB,
                  PaddingType.WC_OAEP_SHA1);
        }
    }
}

