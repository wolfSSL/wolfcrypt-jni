/* WolfCryptCipher.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

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

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Asn;
import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.Des3;
import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Rng;

import com.wolfssl.provider.jce.WolfCryptDebug;

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
        WC_CBC
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

    private Aes  aes  = null;
    private Des3 des3 = null;
    private Rsa  rsa  = null;
    private Rng  rng  = null;

    /* for debug logging */
    private WolfCryptDebug debug;
    private String algString;
    private String algMode;

    /* stash key and IV here for easy lookup */
    private Key storedKey = null;
    private AlgorithmParameterSpec storedSpec = null;
    private byte[] iv = null;

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
                aes = new Aes();
                blockSize = Aes.BLOCK_SIZE;
                break;

            case WC_DES3:
                des3 = new Des3();
                blockSize = Des3.BLOCK_SIZE;
                break;

            case WC_RSA:
                rsa = new Rsa();
                rsa.setRng(this.rng);
                break;
        }

        if (debug.DEBUG) {
            algString = typeToString(cipherType);
            algMode = modeToString(cipherMode);
        }
    }

    @Override
    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException {

        int supported = 0;

        if (mode.equals("ECB")) {

            /* RSA is ECB mode */
            if (cipherType == CipherType.WC_RSA) {
                cipherMode = CipherMode.WC_ECB;
                supported = 1;

                if (debug.DEBUG)
                    log("set mode to ECB");
            }

        } else if (mode.equals("CBC")) {

            /* AES and 3DES support CBC */
            if (cipherType == CipherType.WC_AES ||
                cipherType == CipherType.WC_DES3 ) {
                cipherMode = CipherMode.WC_CBC;
                supported = 1;

                if (debug.DEBUG)
                    log("set mode to CBC");
            }
        }

        if (supported == 0) {
            throw new NoSuchAlgorithmException(
                "Unsupported cipher mode for active algorithm choice");
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

                if (debug.DEBUG)
                    log("set padding to NoPadding");
            }

        } else if (padding.equals("PKCS1Padding")) {

            if (cipherType == CipherType.WC_RSA) {
                paddingType = PaddingType.WC_PKCS1;
                supported = 1;

                if (debug.DEBUG)
                    log("set padding to PKCS1Padding");
            }

        } else if (padding.equals("PKCS5Padding")) {

            if (cipherType == CipherType.WC_AES) {
                paddingType = PaddingType.WC_PKCS5;
                supported = 1;

                if (debug.DEBUG)
                    log("set padding to PKCS5Padding");
            }
        }

        if (supported == 0) {
            throw new NoSuchPaddingException(
                "Unsupported padding type for active algorithm choice");
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

        switch (this.cipherType) {
            case WC_AES:
                if (paddingType == PaddingType.WC_NONE) {
                    /* wolfCrypt expects input to be padded by application to
                     * block size, thus output is same size as input */
                    size = inputLen;
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

        /* RSA doesn't need an IV */
        if (this.cipherType == CipherType.WC_RSA)
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
            if (!(spec instanceof IvParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                    "AlgorithmParameterSpec must be of type IvParameterSpec");
            }

            IvParameterSpec ivSpec = (IvParameterSpec)spec;

            /* IV should be of block size length */
            if (ivSpec.getIV().length != this.blockSize) {
                throw new InvalidAlgorithmParameterException(
                        "Bad IV length (" + ivSpec.getIV().length +
                        "), must be " + blockSize + " bytes long");
            }

            this.iv = ivSpec.getIV();
        }
    }

    private void wolfCryptSetKey(Key key)
        throws InvalidKeyException {

        int ret = 0;
        long[] idx = {0};
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
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        switch (cipherType) {
            case WC_AES:
                if (this.direction == OpMode.WC_ENCRYPT) {
                    this.aes.setKey(encodedKey, iv, Aes.ENCRYPT_MODE);
                } else {
                    this.aes.setKey(encodedKey, iv, Aes.DECRYPT_MODE);
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

        wolfCryptSetDirection(opmode);
        wolfCryptSetIV(spec, random);
        wolfCryptSetKey(key);
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {

        try {

            wolfCryptCipherInit(opmode, key, null, random);

            if (debug.DEBUG)
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

        if (debug.DEBUG)
            log("initialized with key and AlgorithmParameterSpec");
    }

    @Override
    protected void engineInit(int opmode, Key key,
            AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        AlgorithmParameterSpec spec;

        try {

            spec = params.getParameterSpec(IvParameterSpec.class);

            if (debug.DEBUG)
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
        };

        return isBlockCipher;
    }

    /* return 1 if cipher is a block cipher and lenth is a block
     * length multiple, otherwise 0 */
    private int isValidBlockLength(int length) {

        /* skip if not a block cipher */
        if (isBlockCipher() == false)
            return 1;

        if ((length % this.blockSize) != 0)
            return 0;

        return 1;
    }

    private byte[] wolfCryptUpdate(byte[] input, int inputOffset, int len) {

        int  blocks    = 0;
        int  remaining = 0;
        int  bytesToProcess = 0;
        byte[] output  = null;
        byte[] tmpIn   = null;
        byte[] tmpBuf  = null;

        if (input == null || len < 0)
            throw new IllegalArgumentException("Null input buffer or len < 0");

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

        /* keep buffered data if RSA or data is less than block size */
        if (cipherType == CipherType.WC_RSA ||
            buffered.length < blockSize) {
            return new byte[0];
        }

        /* calculate blocks and partial non-block size remaining */
        blocks    = buffered.length / blockSize;
        remaining = buffered.length % blockSize;
        bytesToProcess = blocks * blockSize;

        /* if PKCS#5/7 padding, and decrypting, hold on to last block for
         * padding check in wolfCryptFinal() */
        if (paddingType == PaddingType.WC_PKCS5 &&
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

            case WC_AES:
                output = this.aes.update(tmpIn, 0, tmpIn.length);

                /* truncate */
                output = Arrays.copyOfRange(output, 0, tmpIn.length);

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

        totalSz = buffered.length + len;

        if (isBlockCipher() &&
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
         * specific block size */
        if (this.direction == OpMode.WC_ENCRYPT &&
            this.paddingType == PaddingType.WC_PKCS5) {
            if (this.cipherType == CipherType.WC_AES) {
                tmpIn = Aes.padPKCS7(tmpIn, Aes.BLOCK_SIZE);
            } else if (this.cipherType == CipherType.WC_DES3) {
                tmpIn = Des3.padPKCS7(tmpIn, Des3.BLOCK_SIZE);
            }
        }

        switch (this.cipherType) {

            case WC_AES:
                tmpOut = this.aes.update(tmpIn, 0, tmpIn.length);

                /* truncate */
                tmpOut = Arrays.copyOfRange(tmpOut, 0, tmpIn.length);

                /* strip PKCS#5/PKCS#7 padding if required */
                if (this.direction == OpMode.WC_DECRYPT &&
                    this.paddingType == PaddingType.WC_PKCS5) {
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

            wolfCryptSetIV(storedSpec, null);
            wolfCryptSetKey(storedKey);

        } catch (InvalidKeyException e) {
            throw new RuntimeException(e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e.getMessage());
        }

        return tmpOut;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

        byte output[];

        if (debug.DEBUG)
            log("update (offset: " + inputOffset + ", len: " +
                inputLen + ")");

        output = wolfCryptUpdate(input, inputOffset, inputLen);

        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset)
        throws ShortBufferException {

        byte tmpOut[];

        if (debug.DEBUG)
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
        throws IllegalBlockSizeException, BadPaddingException {

        if (debug.DEBUG)
            log("final (offset: " + inputOffset + ", len: " +
                inputLen + ")");

        return wolfCryptFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset,
            int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {

        byte tmpOut[];

        if (debug.DEBUG)
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
            default:
                return "None";
        }
    }

    private void log(String msg) {
        debug.print("[Cipher, " + algString + "-" + algMode + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.aes != null)
                this.aes.releaseNativeStruct();

            if (this.des3 != null)
                this.des3.releaseNativeStruct();

            if (this.rsa != null)
                this.rsa.releaseNativeStruct();

            if (this.rng != null)
                this.rng.releaseNativeStruct();

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

