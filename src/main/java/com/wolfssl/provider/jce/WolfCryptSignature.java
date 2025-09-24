/* WolfCryptSignature.java
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

import java.security.SignatureSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

import java.math.BigInteger;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.ShortBufferException;

import com.wolfssl.wolfcrypt.Asn;
import com.wolfssl.wolfcrypt.Md5;
import com.wolfssl.wolfcrypt.Sha;
import com.wolfssl.wolfcrypt.Sha224;
import com.wolfssl.wolfcrypt.Sha256;
import com.wolfssl.wolfcrypt.Sha384;
import com.wolfssl.wolfcrypt.Sha512;
import com.wolfssl.wolfcrypt.Sha3;
import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE Signature wrapper
 */
public class WolfCryptSignature extends SignatureSpi {

    enum KeyType {
        WC_RSA,
        WC_ECDSA
    }

    enum DigestType {
        WC_MD5,
        WC_SHA1,
        WC_SHA224,
        WC_SHA256,
        WC_SHA384,
        WC_SHA512,
        WC_SHA3_224,
        WC_SHA3_256,
        WC_SHA3_384,
        WC_SHA3_512
    }

    enum PaddingType {
        WC_PKCS1_V1_5,  /* PKCS#1 v1.5 padding */
        WC_RSA_PSS      /* RSA-PSS padding */
    }

    /* internal hash type sums (from oid_sum.h) - retrieved dynamically */
    private int MD5h = Asn.MD5h;
    private int SHAh = Asn.SHAh;
    private int SHA224h = Asn.SHA224h;
    private int SHA256h = Asn.SHA256h;
    private int SHA384h = Asn.SHA384h;
    private int SHA512h = Asn.SHA512h;
    private int SHA3_224h = Asn.SHA3_224h;
    private int SHA3_256h = Asn.SHA3_256h;
    private int SHA3_384h = Asn.SHA3_384h;
    private int SHA3_512h = Asn.SHA3_512h;


    /* internal key objects */
    private Rsa rsa = null;

    /** Internal Ecc object */
    protected Ecc ecc = null;

    /* internal hash objects */
    private Md5 md5 = null;
    private Sha sha = null;
    private Sha224 sha224 = null;
    private Sha256 sha256 = null;
    private Sha384 sha384 = null;
    private Sha512 sha512 = null;
    private Sha3 sha3 = null;

    private KeyType keyType;        /* active key type, from KeyType */
    private DigestType digestType;  /* active digest type, from DigestType */
    private PaddingType paddingType = PaddingType.WC_PKCS1_V1_5; /* default */
    private int internalHashSum;    /* used for native EncodeSignature */
    private int digestSz;           /* digest size in bytes */

    /* Parameter spec for RSA-PSS */
    private PSSParameterSpec pssParams = null;

    /* for debug logging */
    private String keyString;
    private String digestString;

    /* Class-wide RNG to be used for padding during sign operations */
    private Rng rng = null;
    private final Object rngLock = new Object();

    /* Lock for hash object synchronization */
    private final Object hashLock = new Object();

    /**
     * Create a WolfCryptSignature instance with the specified key type
     * and digest type.
     *
     * @param ktype KeyType to use (WC_RSA or WC_ECDSA)
     * @param dtype DigestType to use (WC_MD5, WC_SHA1, etc.)
     *
     * @throws NoSuchAlgorithmException if the key type or digest type is not
     *         supported
     */
    private WolfCryptSignature(KeyType ktype, DigestType dtype)
        throws NoSuchAlgorithmException {

        this.keyType = ktype;
        this.digestType = dtype;
        this.paddingType = PaddingType.WC_PKCS1_V1_5;

        init(ktype, dtype, this.paddingType);
    }

    /**
     * Create a WolfCryptSignature instance with the specified key type,
     * digest type, and padding type.
     *
     * If the padding type is WC_RSA_PSS, digest object and parameters will be
     * initialized later via engineSetParameter().
     *
     * @param ktype KeyType to use (WC_RSA or WC_ECDSA)
     * @param dtype DigestType to use (WC_MD5, WC_SHA1, etc.)
     * @param ptype PaddingType to use (WC_PKCS1_V1_5 or WC_RSA_PSS)
     *
     * @throws NoSuchAlgorithmException if the key type or digest type is not
     *        supported, or if the padding type is not compatible with the
     *        digest type.
     */
    private WolfCryptSignature(KeyType ktype, DigestType dtype,
        PaddingType ptype) throws NoSuchAlgorithmException {

        this.keyType = ktype;
        this.digestType = dtype;
        this.paddingType = ptype;

        /* For RSASSA-PSS without explicit digest type, delay initialization
         * until parameters are set */
        if (dtype != null) {
            init(ktype, dtype, ptype);
        } else if (ptype == PaddingType.WC_RSA_PSS) {
            /* Init RNG only, hash will be set and initialized via parameters */
            synchronized (rngLock) {
                this.rng = new Rng();
                this.rng.init();
            }
        } else {
            throw new NoSuchAlgorithmException(
                "Digest type cannot be null for non-PSS algorithms");
        }
    }

    private void init(KeyType ktype, DigestType dtype, PaddingType ptype)
        throws NoSuchAlgorithmException {

        if ((ktype != KeyType.WC_RSA) &&
            (ktype != KeyType.WC_ECDSA)) {
            throw new NoSuchAlgorithmException(
                "Signature algorithm key type must be RSA or ECC");
        }

        synchronized (rngLock) {
            if (this.rng == null) {
                this.rng = new Rng();
                this.rng.init();
            }
        }

        /* Release existing hash objects to prevent memory leaks */
        releaseHashObjects();

        /* init hash type */
        switch (dtype) {
            case WC_MD5:
                this.md5 = new Md5();
                this.digestSz = Md5.DIGEST_SIZE;
                this.internalHashSum = MD5h;
                break;

            case WC_SHA1:
                this.sha = new Sha();
                this.digestSz = Sha.DIGEST_SIZE;
                this.internalHashSum = SHAh;
                break;

            case WC_SHA224:
                this.sha224 = new Sha224();
                this.digestSz = Sha224.DIGEST_SIZE;
                this.internalHashSum = SHA224h;
                break;

            case WC_SHA256:
                this.sha256 = new Sha256();
                this.digestSz = Sha256.DIGEST_SIZE;
                this.internalHashSum = SHA256h;
                break;

            case WC_SHA384:
                this.sha384 = new Sha384();
                this.digestSz = Sha384.DIGEST_SIZE;
                this.internalHashSum = SHA384h;
                break;

            case WC_SHA512:
                this.sha512 = new Sha512();
                this.digestSz = Sha512.DIGEST_SIZE;
                this.internalHashSum = SHA512h;
                break;

            case WC_SHA3_224:
                this.sha3 = new Sha3(Sha3.TYPE_SHA3_224);
                this.digestSz = Sha3.DIGEST_SIZE_224;
                this.internalHashSum = SHA3_224h;
                break;

            case WC_SHA3_256:
                this.sha3 = new Sha3(Sha3.TYPE_SHA3_256);
                this.digestSz = Sha3.DIGEST_SIZE_256;
                this.internalHashSum = SHA3_256h;
                break;

            case WC_SHA3_384:
                this.sha3 = new Sha3(Sha3.TYPE_SHA3_384);
                this.digestSz = Sha3.DIGEST_SIZE_384;
                this.internalHashSum = SHA3_384h;
                break;

            case WC_SHA3_512:
                this.sha3 = new Sha3(Sha3.TYPE_SHA3_512);
                this.digestSz = Sha3.DIGEST_SIZE_512;
                this.internalHashSum = SHA3_512h;
                break;

            default:
                throw new NoSuchAlgorithmException(
                    "Unsupported signature algorithm digest type");
        }

        /* Initialize PSS parameters if PSS padding */
        if (ptype == PaddingType.WC_RSA_PSS) {
            String digestAlg = digestTypeToJavaName(dtype);
            MGF1ParameterSpec mgf1Spec = getMGF1SpecForDigest(digestAlg);
            int saltLen = this.digestSz;  /* Use actual hash length */
            this.pssParams = new PSSParameterSpec(
                digestAlg,  /* message digest */
                "MGF1",     /* mask generation function */
                mgf1Spec,   /* MGF parameters */
                saltLen,    /* salt length (hash length) */
                1           /* trailer field (always 1) */
            );
        }

        if (WolfCryptDebug.DEBUG) {
            keyString = keyTypeToString(ktype);
            digestString = digestTypeToString(dtype);
        }
    }

    /**
     * This method is deprecated in SignatureSpi, thus not implemented
     * here in wolfJCE.
     */
    @Deprecated
    @Override
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "wolfJCE does not support Signature.getParameter()");
    }

    private void wolfCryptInitPrivateKey(PrivateKey key, byte[] encodedKey)
        throws InvalidKeyException {

        switch (this.keyType) {

            case WC_RSA:

                /* import private PKCS#8 */
                this.rsa.decodePrivateKeyPKCS8(encodedKey);

                break;

            case WC_ECDSA:

                ECPrivateKey ecPriv = (ECPrivateKey)key;
                this.ecc.importPrivate(ecPriv.getS().toByteArray(), null);

                break;
        }
    }

    private void wolfCryptInitPublicKey(PublicKey key, byte[] encodedKey)
        throws InvalidKeyException {

        switch(this.keyType) {

            case WC_RSA:

                this.rsa.decodePublicKey(encodedKey);

                break;

            case WC_ECDSA:

                this.ecc.publicKeyDecode(encodedKey);

                break;
        }
    }

    @Override
    protected synchronized void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException {

        byte[] encodedKey;

        if (this.keyType == KeyType.WC_RSA &&
                !(privateKey instanceof RSAPrivateKey)) {
            throw new InvalidKeyException("Key is not of type RSAPrivateKey");

        } else if (this.keyType == KeyType.WC_RSA &&
                   privateKey instanceof RSAPrivateKey &&
                   !(privateKey instanceof RSAPrivateCrtKey)) {
            throw new InvalidKeyException(
                "RSA private key must include CRT parameters " +
                "(p, q, dP, dQ, qInv). Keys created from only " +
                "modulus and exponent are not supported by wolfSSL.");

        } else if (this.keyType == KeyType.WC_ECDSA &&
                !(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Key is not of type ECPrivateKey");
        }

        /* If ECDSA key, validate EC private key range. Validating here to
         * match Sun behavior. */
        if ((this.keyType == KeyType.WC_ECDSA) &&
            (privateKey instanceof ECPrivateKey)) {

            ECPrivateKey ecPrivKey = (ECPrivateKey) privateKey;
            BigInteger privateValue = ecPrivKey.getS();
            ECParameterSpec ecParams = ecPrivKey.getParams();

            if (privateValue.signum() <= 0) {
                throw new InvalidKeyException(
                    "EC private key value must be positive");
            }

            BigInteger order = ecParams.getOrder();
            if (privateValue.compareTo(order) >= 0) {
                throw new InvalidKeyException(
                    "EC private key value must be less than curve order");
            }
        }

        /* get encoded key, returns PKCS#8 formatted private key */
        encodedKey = privateKey.getEncoded();
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        /* initialize native struct */
        switch (keyType) {
            case WC_RSA:
                if (this.rsa != null) {
                    this.rsa.releaseNativeStruct();
                }
                this.rsa = new Rsa();
                break;
            case WC_ECDSA:
                if (this.ecc != null) {
                    this.ecc.releaseNativeStruct();
                }
                synchronized (this.rngLock) {
                    this.ecc = new Ecc(this.rng);
                }
                break;
        }

        wolfCryptInitPrivateKey(privateKey, encodedKey);

        /* init hash object if digest type is set */
        if (this.digestType == null) {
            /* For RSASSA-PSS, hash init will happen in engineSetParameter() */
            log("init sign with PrivateKey (hash init deferred for PSS)");
            return;
        }

        synchronized (hashLock) {
            switch (this.digestType) {
                case WC_MD5:
                    this.md5.init();
                    break;

                case WC_SHA1:
                    this.sha.init();
                    break;

                case WC_SHA224:
                    this.sha224.init();
                    break;

                case WC_SHA256:
                    this.sha256.init();
                    break;

                case WC_SHA384:
                    this.sha384.init();
                    break;

                case WC_SHA512:
                    this.sha512.init();
                    break;

                case WC_SHA3_224:
                case WC_SHA3_256:
                case WC_SHA3_384:
                case WC_SHA3_512:
                    this.sha3.init();
                    break;
            }
        }

        log("init sign with PrivateKey");
    }

    @Override
    protected synchronized void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException {

        byte[] encodedKey;

        if (this.keyType == KeyType.WC_RSA &&
                !(publicKey instanceof RSAPublicKey)) {
            throw new InvalidKeyException("Key is not of type RSAPublicKey");

        } else if (this.keyType == KeyType.WC_ECDSA &&
                !(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("Key is not of type ECPublicKey");
        }

        /* get encoded key, returns PKCS#8 formatted private key */
        encodedKey = publicKey.getEncoded();
        if (encodedKey == null)
            throw new InvalidKeyException("Key does not support encoding");

        /* initialize native struct */
        switch (keyType) {
            case WC_RSA:
                if (this.rsa != null) {
                    this.rsa.releaseNativeStruct();
                }
                this.rsa = new Rsa();
                break;
            case WC_ECDSA:
                if (this.ecc != null) {
                    this.ecc.releaseNativeStruct();
                }
                synchronized (this.rngLock) {
                    this.ecc = new Ecc(this.rng);
                }
                break;
        }

        wolfCryptInitPublicKey(publicKey, encodedKey);

        /* init hash object if digest type is set */
        if (this.digestType == null) {
            /* For RSASSA-PSS, hash init will happen in engineSetParameter() */
            log("init verify with PublicKey (hash init deferred for PSS)");
            return;
        }

        synchronized (hashLock) {
            switch (this.digestType) {
                case WC_MD5:
                    this.md5.init();
                    break;

                case WC_SHA1:
                    this.sha.init();
                    break;

                case WC_SHA224:
                    this.sha224.init();
                    break;

                case WC_SHA256:
                    this.sha256.init();
                    break;

                case WC_SHA384:
                    this.sha384.init();
                    break;

                case WC_SHA512:
                    this.sha512.init();
                    break;

                case WC_SHA3_224:
                case WC_SHA3_256:
                case WC_SHA3_384:
                case WC_SHA3_512:
                    this.sha3.init();
                    break;
            }
        }

        log("init verify with PublicKey");
    }

    /**
     * This method is deprecated in SignatureSpi, thus not implemented
     * here in wolfJCE.
     */
    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "wolfJCE does not support Signature.setParameter()");
    }

    @Override
    protected synchronized void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {

        /* For RSA-PSS signatures, parameters are required */
        if (this.paddingType == PaddingType.WC_RSA_PSS) {
            if (!(params instanceof PSSParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                    "Only PSSParameterSpec supported for RSA-PSS");
            }

            PSSParameterSpec pss = (PSSParameterSpec)params;
            validatePSSParameters(pss);
            this.pssParams = pss;

            /* For RSASSA-PSS, (re)initialize digest based on parameters */
            String hashAlg = pss.getDigestAlgorithm();
            DigestType newDigestType = javaNameToDigestType(hashAlg);

            /* Check if digest type has changed or needs initialization */
            if (this.digestType == null || this.digestType != newDigestType) {
                this.digestType = newDigestType;

                try {
                    /* (re)initialize with the new digest type */
                    init(this.keyType, this.digestType, this.paddingType);

                    /* Initialize hash object for existing key if already set */
                    if ((this.rsa != null || this.ecc != null)) {
                        initHashObject();
                    }
                } catch (NoSuchAlgorithmException e) {
                    throw new InvalidAlgorithmParameterException(
                        "Failed to initialize with digest: " + hashAlg, e);
                }
            }
            return;
        }

        /* For non-PSS signatures, allow null parameters (ignore) */
        if (params == null) {
            return;
        }

        if (this.keyType == KeyType.WC_ECDSA &&
            params instanceof ECParameterSpec) {
            /* To match Sun behavior, ECDSA signatures should not store/return
             * parameters, but should accept them without error */
            return;
        }

        /* For other non-PSS signatures, reject any non-null parameters */
        throw new InvalidAlgorithmParameterException(
            "Parameters not supported for " +
            keyTypeToString(this.keyType) + " with PKCS#1 v1.5 padding");
    }

    @Override
    protected synchronized AlgorithmParameters engineGetParameters() {
        if (this.paddingType != PaddingType.WC_RSA_PSS ||
            this.pssParams == null) {
            return null;
        }

        try {
            AlgorithmParameters params =
                AlgorithmParameters.getInstance("RSASSA-PSS");
            params.init(this.pssParams);

            return params;

        } catch (Exception e) {
            return null;
        }
    }

    @Override
    protected synchronized byte[] engineSign() throws SignatureException {

        /* For RSASSA-PSS, ensure parameters have been set */
        if (this.paddingType == PaddingType.WC_RSA_PSS &&
            this.digestType == null) {
            throw new SignatureException(
                "Parameters must be set before signing with RSASSA-PSS");
        }

        int encodedSz = 0;

        byte[] digest    = new byte[this.digestSz];
        byte[] encDigest = new byte[Asn.MAX_ENCODED_SIG_SIZE];
        byte[] signature = new byte[Asn.MAX_ENCODED_SIG_SIZE];

        /* get final digest */
        try {
            synchronized (hashLock) {
                switch (this.digestType) {
                    case WC_MD5:
                        this.md5.digest(digest);
                        break;

                    case WC_SHA1:
                        this.sha.digest(digest);
                        break;

                    case WC_SHA224:
                        this.sha224.digest(digest);
                        break;

                    case WC_SHA256:
                        this.sha256.digest(digest);
                        break;

                    case WC_SHA384:
                        this.sha384.digest(digest);
                        break;

                    case WC_SHA512:
                        this.sha512.digest(digest);
                        break;

                    case WC_SHA3_224:
                    case WC_SHA3_256:
                    case WC_SHA3_384:
                    case WC_SHA3_512:
                        this.sha3.digest(digest);
                        break;
                }
            }
        } catch (ShortBufferException e) {
            throw new SignatureException(e.getMessage());
        }

        /* sign digest */
        switch (this.keyType) {
            case WC_RSA:
                if (this.paddingType == PaddingType.WC_RSA_PSS) {
                    /* RSA-PSS signature */
                    int mgfType = getMgfTypeFromParams();
                    int saltLen = this.pssParams.getSaltLength();

                    /* Convert -1 (default) to digest length */
                    if (saltLen == -1) {
                        saltLen = this.digestSz;
                    }

                    synchronized (rngLock) {
                        signature = this.rsa.rsaPssSign(digest,
                            digestTypeToHashType(this.digestType),
                            mgfType, saltLen, this.rng);
                    }
                } else {
                    /* Existing PKCS#1 v1.5 signature code */
                    encodedSz = (int)Asn.encodeSignature(encDigest, digest,
                                    digest.length, this.internalHashSum);

                    if (encodedSz < 0) {
                        throw new SignatureException(
                            "Failed to DER encode digest during sig gen");
                    }

                    byte[] tmp = new byte[encodedSz];
                    System.arraycopy(encDigest, 0, tmp, 0, encodedSz);
                    synchronized (rngLock) {
                        signature = this.rsa.sign(tmp, this.rng);
                    }
                    zeroArray(tmp);
                }

                break;

            case WC_ECDSA:

                /* Ecc.sign() internally has a rngLock unlike Rsa.sign() */
                signature = this.ecc.sign(digest, this.rng);

                break;

            default:
                throw new SignatureException(
                    "Invalid signature algorithm type");
        }

        if (signature != null) {
            log("generated signature, len: " + signature.length);
        } else {
            log("generated signature was null");
        }

        return signature;
    }

    @Override
    protected synchronized void engineUpdate(byte b) throws SignatureException {

        byte[] tmp = new byte[1];
        tmp[0] = b;

        engineUpdate(tmp, 0, 1);

        log("update with single byte");
    }

    @Override
    protected synchronized void engineUpdate(byte[] b, int off, int len)
        throws SignatureException {

        /* For RSASSA-PSS, ensure parameters have been set */
        if (this.paddingType == PaddingType.WC_RSA_PSS &&
            this.digestType == null) {
            throw new SignatureException(
                "Parameters must be set before updating with RSASSA-PSS");
        }

        synchronized (hashLock) {
            switch (this.digestType) {
                case WC_MD5:
                    this.md5.update(b, off, len);
                    break;

                case WC_SHA1:
                    this.sha.update(b, off, len);
                    break;

                case WC_SHA224:
                    this.sha224.update(b, off, len);
                    break;

                case WC_SHA256:
                    this.sha256.update(b, off, len);
                    break;

                case WC_SHA384:
                    this.sha384.update(b, off, len);
                    break;

                case WC_SHA512:
                    this.sha512.update(b, off, len);
                    break;

                case WC_SHA3_224:
                case WC_SHA3_256:
                case WC_SHA3_384:
                case WC_SHA3_512:
                    this.sha3.update(b, off, len);
                    break;
            }
        }

        log("update, offset: " + off + ", len: " + len);
    }

    @Override
    protected synchronized boolean engineVerify(byte[] sigBytes)
        throws SignatureException {

        /* For RSASSA-PSS, ensure parameters have been set */
        if (this.paddingType == PaddingType.WC_RSA_PSS &&
            this.digestType == null) {
            throw new SignatureException(
                "Parameters must be set before verifying with RSASSA-PSS");
        }

        long   encodedSz = 0;
        boolean verified = true;

        byte[] digest    = new byte[this.digestSz];
        byte[] encDigest = new byte[Asn.MAX_ENCODED_SIG_SIZE];
        byte[] verify    = new byte[Asn.MAX_ENCODED_SIG_SIZE];

        /* get final digest */
        try {
            synchronized (hashLock) {
                switch (this.digestType) {
                    case WC_MD5:
                        this.md5.digest(digest);
                        break;

                    case WC_SHA1:
                        this.sha.digest(digest);
                        break;

                    case WC_SHA224:
                        this.sha224.digest(digest);
                        break;

                    case WC_SHA256:
                        this.sha256.digest(digest);
                        break;

                    case WC_SHA384:
                        this.sha384.digest(digest);
                        break;

                    case WC_SHA512:
                        this.sha512.digest(digest);
                        break;

                    case WC_SHA3_224:
                    case WC_SHA3_256:
                    case WC_SHA3_384:
                    case WC_SHA3_512:
                        this.sha3.digest(digest);
                        break;
                }
            }

        } catch (ShortBufferException e) {
            throw new SignatureException(e.getMessage());
        }

        /* verify digest */
        switch (this.keyType) {
            case WC_RSA:
                if (this.paddingType == PaddingType.WC_RSA_PSS) {
                    /* RSA-PSS verification */
                    int mgfType = getMgfTypeFromParams();
                    int saltLen = this.pssParams.getSaltLength();

                    /* Convert -1 (default) to digest length */
                    if (saltLen == -1) {
                        saltLen = this.digestSz;
                    }

                    try {
                        /* Use rsaPssVerifyWithDigest for pre-computed digest
                         * verification. Pass digest as both data and digest
                         * since we only have the final digest here */
                        verified = this.rsa.rsaPssVerifyWithDigest(
                            sigBytes, digest, digest,
                            digestTypeToHashType(this.digestType), mgfType,
                            saltLen);

                    } catch (WolfCryptException e) {
                        verified = false;
                    }

                } else {
                    /* Existing PKCS#1 v1.5 verification code */
                    encodedSz = Asn.encodeSignature(encDigest, digest,
                                    digest.length, this.internalHashSum);

                    if (encodedSz < 0) {
                        throw new SignatureException(
                            "Failed to DER encode digest during sig verify");
                    }

                    try {
                        verify = this.rsa.verify(sigBytes);
                    } catch (WolfCryptException e) {
                        verified = false;
                    }

                    /* compare expected digest to one unwrapped from verify */
                    if ((encodedSz > encDigest.length) ||
                        (verify.length != encodedSz)) {
                        verified = false;
                    }
                    else {
                        for (int i = 0; i < verify.length; i++) {
                            if (verify[i] != encDigest[i]) {
                                verified = false;
                            }
                        }
                    }
                }

                break;

            case WC_ECDSA:

                try {
                    verified = this.ecc.verify(digest, sigBytes);
                } catch (WolfCryptException we) {
                    verified = false;
                }

                break;
        }

        if (sigBytes != null) {
            log("finished verify of sig len: " + sigBytes.length +
                ", verified: " + verified);
        }

        return verified;
    }

    /**
     * Helper method to zero out a byte array.
     *
     * @param in byte array to zero out
     */
    private void zeroArray(byte[] in) {

        if (in == null)
            return;

        for (int i = 0; i < in.length; i++) {
            in[i] = 0;
        }
    }

    /**
     * Helper method for converting KeyType to String
     *
     * @param type KeyType to convert
     *
     * @return String representation of the key type
     */
    private String keyTypeToString(KeyType type) {
        switch (type) {
            case WC_RSA:
                return "RSA";
            case WC_ECDSA:
                return "ECDSA";
            default:
                return "None";
        }
    }

    /**
     * Helper method for converting DigestType to String
     *
     * @param type DigestType to convert
     *
     * @return String representation of the digest type
     */
    private String digestTypeToString(DigestType type) {
        switch (type) {
            case WC_MD5:
                return "MD5";
            case WC_SHA1:
                return "SHA";
            case WC_SHA224:
                return "SHA224";
            case WC_SHA256:
                return "SHA256";
            case WC_SHA384:
                return "SHA384";
            case WC_SHA512:
                return "SHA512";
            case WC_SHA3_224:
                return "SHA3-224";
            case WC_SHA3_256:
                return "SHA3-256";
            case WC_SHA3_384:
                return "SHA3-384";
            case WC_SHA3_512:
                return "SHA3-512";
            default:
                return "None";
        }
    }

    /**
     * Helper method for converting DigestType to Java name
     *
     * @param dtype DigestType to convert
     *
     * @return String representation of the digest type
     */
    private String digestTypeToJavaName(DigestType dtype) {
        switch (dtype) {
            case WC_SHA1:
                return "SHA-1";
            case WC_SHA224:
                return "SHA-224";
            case WC_SHA256:
                return "SHA-256";
            case WC_SHA384:
                return "SHA-384";
            case WC_SHA512:
                return "SHA-512";
            default:
                throw new IllegalArgumentException(
                    "Unsupported digest for PSS: " + dtype);
        }
    }

    /**
     * Helper method for converting Java digest name to DigestType
     *
     * @param javaName Java digest algorithm name
     *
     * @return DigestType corresponding to the Java name
     */
    private DigestType javaNameToDigestType(String javaName)
        throws InvalidAlgorithmParameterException {
        switch (javaName.toUpperCase()) {
            case "SHA-1":
                return DigestType.WC_SHA1;
            case "SHA-224":
                return DigestType.WC_SHA224;
            case "SHA-256":
                return DigestType.WC_SHA256;
            case "SHA-384":
                return DigestType.WC_SHA384;
            case "SHA-512":
                return DigestType.WC_SHA512;
            default:
                throw new InvalidAlgorithmParameterException(
                    "Unsupported digest algorithm: " + javaName);
        }
    }

    /**
     * Helper method to get MGF1ParameterSpec for a given digest algorithm
     *
     * @param digestAlg Digest algorithm name
     *
     * @return MGF1ParameterSpec corresponding to the digest algorithm
     */
    private MGF1ParameterSpec getMGF1SpecForDigest(String digestAlg) {
        switch (digestAlg) {
            case "SHA-1":
                return MGF1ParameterSpec.SHA1;
            case "SHA-224":
                return MGF1ParameterSpec.SHA224;
            case "SHA-256":
                return MGF1ParameterSpec.SHA256;
            case "SHA-384":
                return MGF1ParameterSpec.SHA384;
            case "SHA-512":
                return MGF1ParameterSpec.SHA512;
            case "SHA-512/224":
                /* MGF1ParameterSpec.SHA512_224 added in Java 11,
                 * fallback for Java 8 */
                try {
                    return (MGF1ParameterSpec) MGF1ParameterSpec.class
                        .getField("SHA512_224").get(null);
                } catch (Exception e) {
                    return new MGF1ParameterSpec("SHA-512/224");
                }
            case "SHA-512/256":
                /* MGF1ParameterSpec.SHA512_256 added in Java 11,
                 * fallback for Java 8 */
                try {
                    return (MGF1ParameterSpec) MGF1ParameterSpec.class
                        .getField("SHA512_256").get(null);
                } catch (Exception e) {
                    return new MGF1ParameterSpec("SHA-512/256");
                }
            default:
                throw new IllegalArgumentException(
                    "Unsupported digest for MGF1: " + digestAlg);
        }
    }

    /**
     * Helper method to get MGF type from PSS parameters
     *
     * @return MGF type constant corresponding to the digest algorithm.
     *         If no parameters are set, defaults to WC_MGF1SHA256.
     */
    private int getMgfTypeFromParams() {

        /* Default MGF type is SHA-256 */
        int ret = Rsa.WC_MGF1SHA256;

        if (pssParams != null) {
            if (pssParams.getMGFParameters() instanceof MGF1ParameterSpec) {
                MGF1ParameterSpec mgf1Spec =
                    (MGF1ParameterSpec)pssParams.getMGFParameters();
                String digestAlg = mgf1Spec.getDigestAlgorithm();
                switch (digestAlg.toUpperCase()) {
                    case "SHA-1":
                        return Rsa.WC_MGF1SHA1;
                    case "SHA-224":
                        return Rsa.WC_MGF1SHA224;
                    case "SHA-256":
                        return Rsa.WC_MGF1SHA256;
                    case "SHA-384":
                        return Rsa.WC_MGF1SHA384;
                    case "SHA-512":
                        return Rsa.WC_MGF1SHA512;
                    case "SHA-512/224":
                        return Rsa.WC_MGF1SHA512_224;
                    case "SHA-512/256":
                        return Rsa.WC_MGF1SHA512_256;
                    default:
                        throw new IllegalArgumentException(
                            "Unsupported MGF1 digest: " + digestAlg);
                }
            }
        }

        return ret;
    }

    /**
     * Validates the PSS parameters are supported by wolfJCE.
     *
     * @param pss PSSParameterSpec to validate
     *
     * @throws InvalidAlgorithmParameterException if the parameters are not
     */
    private void validatePSSParameters(PSSParameterSpec pss)
            throws InvalidAlgorithmParameterException {

        /* Validate hash algorithm */
        String hashAlg = pss.getDigestAlgorithm();
        if (!isDigestSupported(hashAlg)) {
            throw new InvalidAlgorithmParameterException(
                "Hash algorithm not supported: " + hashAlg);
        }

        /* Validate MGF algorithm */
        String mgfAlg = pss.getMGFAlgorithm();
        if (!"MGF1".equalsIgnoreCase(mgfAlg)) {
            throw new InvalidAlgorithmParameterException(
                "Only MGF1 supported, got " + mgfAlg);
        }

        /* Validate salt length is reasonable */
        int saltLen = pss.getSaltLength();
        if (saltLen < -2) {
            throw new InvalidAlgorithmParameterException(
                "Invalid salt length: " + saltLen);
        }

        /* Validate trailer field is 1 */
        if (pss.getTrailerField() != 1) {
            throw new InvalidAlgorithmParameterException(
                "Trailer field must be 1, got " + pss.getTrailerField());
        }
    }

    /**
     * Checks if the given digest algorithm is supported by wolfJCE.
     *
     * @param digestAlg Digest algorithm name
     *
     * @return true if supported, false otherwise
     */
    private boolean isDigestSupported(String digestAlg) {
        switch (digestAlg.toUpperCase()) {
            case "SHA-1":
            case "SHA-224":
            case "SHA-256":
            case "SHA-384":
            case "SHA-512":
            case "SHA-512/224":
            case "SHA-512/256":
                return true;
            default:
                return false;
        }
    }

    /**
     * Release existing hash objects to prevent memory leaks
     */
    private void releaseHashObjects() {
        synchronized (hashLock) {
            if (this.md5 != null) {
                this.md5.releaseNativeStruct();
                this.md5 = null;
            }
            if (this.sha != null) {
                this.sha.releaseNativeStruct();
                this.sha = null;
            }
            if (this.sha224 != null) {
                this.sha224.releaseNativeStruct();
                this.sha224 = null;
            }
            if (this.sha256 != null) {
                this.sha256.releaseNativeStruct();
                this.sha256 = null;
            }
            if (this.sha384 != null) {
                this.sha384.releaseNativeStruct();
                this.sha384 = null;
            }
            if (this.sha512 != null) {
                this.sha512.releaseNativeStruct();
                this.sha512 = null;
            }
            if (this.sha3 != null) {
                this.sha3.releaseNativeStruct();
                this.sha3 = null;
            }
        }
    }

    /**
     * Initialize hash object based on current digest type
     */
    private void initHashObject() {
        synchronized (hashLock) {
            switch (this.digestType) {
                case WC_MD5:
                    this.md5.init();
                    break;
                case WC_SHA1:
                    this.sha.init();
                    break;
                case WC_SHA224:
                    this.sha224.init();
                    break;
                case WC_SHA256:
                    this.sha256.init();
                    break;
                case WC_SHA384:
                    this.sha384.init();
                    break;
                case WC_SHA512:
                    this.sha512.init();
                    break;
                case WC_SHA3_224:
                case WC_SHA3_256:
                case WC_SHA3_384:
                case WC_SHA3_512:
                    this.sha3.init();
                    break;
            }
        }
    }

    /**
     * Converts DigestType to corresponding wolfCrypt hash type.
     *
     * @param dtype DigestType to convert
     *
     * @return wolfCrypt hash type constant
     */
    private long digestTypeToHashType(DigestType dtype) {
        switch (dtype) {
            case WC_MD5:
                return WolfCrypt.WC_HASH_TYPE_MD5;
            case WC_SHA1:
                return WolfCrypt.WC_HASH_TYPE_SHA;
            case WC_SHA224:
                return WolfCrypt.WC_HASH_TYPE_SHA224;
            case WC_SHA256:
                return WolfCrypt.WC_HASH_TYPE_SHA256;
            case WC_SHA384:
                return WolfCrypt.WC_HASH_TYPE_SHA384;
            case WC_SHA512:
                return WolfCrypt.WC_HASH_TYPE_SHA512;
            case WC_SHA3_224:
                return WolfCrypt.WC_HASH_TYPE_SHA3_224;
            case WC_SHA3_256:
                return WolfCrypt.WC_HASH_TYPE_SHA3_256;
            case WC_SHA3_384:
                return WolfCrypt.WC_HASH_TYPE_SHA3_384;
            case WC_SHA3_512:
                return WolfCrypt.WC_HASH_TYPE_SHA3_512;
            default:
                throw new IllegalArgumentException(
                    "Unsupported digest type: " + dtype);
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[" + keyString + "-" + digestString + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            /* free native digest objects */
            releaseHashObjects();

            /* free native key objects */
            if (this.rsa != null)
                this.rsa.releaseNativeStruct();

            if (this.ecc != null)
                this.ecc.releaseNativeStruct();  /* frees internally */

            synchronized (rngLock) {
                if (this.rng != null) {
                    /* release RNG */
                    this.rng.free();
                    this.rng.releaseNativeStruct();
                    this.rng = null;
                }
            }

        } finally {
            super.finalize();
        }
    }

    /**
     * wolfJCE MD5wRSA signature class
     */
    public static final class wcMD5wRSA extends WolfCryptSignature {
        /**
         * Create new wcMD5wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcMD5wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_MD5);
        }
    }

    /**
     * wolfJCE SHA1wRSA signature class
     */
    public static final class wcSHA1wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA1wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA1wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA1);
        }
    }

    /**
     * wolfJCE SHA224wRSA signature class
     */
    public static final class wcSHA224wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA224wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA224wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA224);
        }
    }

    /**
     * wolfJCE SHA256wRSA signature class
     */
    public static final class wcSHA256wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA256wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA256wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA256);
        }
    }

    /**
     * wolfJCE SHA384wRSA signature class
     */
    public static final class wcSHA384wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA384wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA384wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA384);
        }
    }

    /**
     * wolfJCE SHA512wRSA signature class
     */
    public static final class wcSHA512wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA512wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA512wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA512);
        }
    }

    /**
     * wolfJCE SHA3-224wRSA signature class
     */
    public static final class wcSHA3_224wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_224wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_224wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA3_224);
        }
    }

    /**
     * wolfJCE SHA3-256wRSA signature class
     */
    public static final class wcSHA3_256wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_256wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_256wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA3_256);
        }
    }

    /**
     * wolfJCE SHA3-384wRSA signature class
     */
    public static final class wcSHA3_384wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_384wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_384wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA3_384);
        }
    }

    /**
     * wolfJCE SHA3-512wRSA signature class
     */
    public static final class wcSHA3_512wRSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_512wRSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_512wRSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA3_512);
        }
    }

    /**
     * wolfJCE SHA1wECDSA signature class
     */
    public static final class wcSHA1wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA1wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA1wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA1);
        }
    }

    /**
     * wolfJCE SHA224wECDSA signature class
     */
    public static final class wcSHA224wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA224wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA224wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA224);
        }
    }

    /**
     * wolfJCE SHA256wECDSA signature class
     */
    public static final class wcSHA256wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA256wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA256wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA256);
        }
    }

    /**
     * wolfJCE SHA384wECDSA signature class
     */
    public static final class wcSHA384wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA384wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA384wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA384);
        }
    }

    /**
     * wolfJCE SHA512wECDSA signature class
     */
    public static final class wcSHA512wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA512wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA512wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA512);
        }
    }

    /**
     * wolfJCE SHA3-224wECDSA signature class
     */
    public static final class wcSHA3_224wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_224wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_224wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA3_224);
        }
    }

    /**
     * wolfJCE SHA3-256wECDSA signature class
     */
    public static final class wcSHA3_256wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_256wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_256wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA3_256);
        }
    }

    /**
     * wolfJCE SHA3-384wECDSA signature class
     */
    public static final class wcSHA3_384wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_384wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_384wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA3_384);
        }
    }

    /**
     * wolfJCE SHA3-512wECDSA signature class
     */
    public static final class wcSHA3_512wECDSA extends WolfCryptSignature {
        /**
         * Create new wcSHA3_512wECDSA object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_512wECDSA() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA3_512);
        }
    }

    /**
     * wolfJCE RSA-PSS signature class (generic)
     */
    public static final class wcRSAPSS extends WolfCryptSignature {
        /**
         * Create new wcRSAPSS object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcRSAPSS() throws NoSuchAlgorithmException {
            /* No default digest - must be set via parameters */
            super(KeyType.WC_RSA, null, PaddingType.WC_RSA_PSS);
        }
    }

    /**
     * wolfJCE SHA224withRSA/PSS signature class
     */
    public static final class wcSHA224wRSAPSS extends WolfCryptSignature {
        /**
         * Create new wcSHA224wRSAPSS object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA224wRSAPSS() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA224,
                  PaddingType.WC_RSA_PSS);
        }
    }

    /**
     * wolfJCE SHA256withRSA/PSS signature class
     */
    public static final class wcSHA256wRSAPSS extends WolfCryptSignature {
        /**
         * Create new wcSHA256wRSAPSS object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA256wRSAPSS() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA256,
                  PaddingType.WC_RSA_PSS);
        }
    }

    /**
     * wolfJCE SHA384withRSA/PSS signature class
     */
    public static final class wcSHA384wRSAPSS extends WolfCryptSignature {
        /**
         * Create new wcSHA384wRSAPSS object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA384wRSAPSS() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA384,
                  PaddingType.WC_RSA_PSS);
        }
    }

    /**
     * wolfJCE SHA512withRSA/PSS signature class
     */
    public static final class wcSHA512wRSAPSS extends WolfCryptSignature {
        /**
         * Create new wcSHA512wRSAPSS object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA512wRSAPSS() throws NoSuchAlgorithmException {
            super(KeyType.WC_RSA, DigestType.WC_SHA512,
                  PaddingType.WC_RSA_PSS);
        }
    }

    /**
     * Get the component size in bytes for P1363 format based on curve.
     * This is calculated as ceil(curve_bits / 8).
     *
     * @param ecc ECC key to get curve size from
     *
     * @return component size in bytes for P1363 format
     *
     * @throws SignatureException if curve size cannot be determined
     */
    private static int getP1363ComponentSize(Ecc ecc)
        throws SignatureException {

        int componentSize;

        try {
            /* Get curve size in bytes, gives us the component size */
            componentSize = ecc.getCurveSizeByKey();
            if (componentSize <= 0) {
                throw new SignatureException(
                    "Invalid curve size for P1363 format");
            }

            return componentSize;

        } catch (Exception e) {
            throw new SignatureException("Failed to get curve size: " +
                e.getMessage());
        }
    }

    /**
     * Convert DER-encoded signature to P1363 format (r|s).
     *
     * @param derSignature DER-encoded ECDSA signature
     * @param ecc ECC key for determining component size
     *
     * @return P1363 format signature (r|s concatenated)
     *
     * @throws SignatureException if conversion fails
     */
    private static byte[] derToP1363(byte[] derSignature, Ecc ecc)
        throws SignatureException {

        int componentSize;
        int rOffset, rCopyLen;
        int sOffset, sCopyLen;
        byte[] r;
        byte[] s;
        byte[] p1363Signature;

        try {
            /* Extract raw r,s from DER signature via JNI */
            byte[][] rs = ecc.sigToRsRaw(derSignature);
            if (rs == null || rs.length != 2 ||
                rs[0] == null || rs[1] == null) {
                throw new SignatureException(
                    "Failed to extract r,s from DER signature");
            }

            r = rs[0];
            s = rs[1];

            /* Get component size for P1363 format */
            componentSize = getP1363ComponentSize(ecc);

            /* Create P1363 format: r | s with fixed sizes */
            p1363Signature = new byte[componentSize * 2];

            /* Pad r to component size (big-endian, so pad on left) */
            rOffset = Math.max(0, componentSize - r.length);
            rCopyLen = Math.min(r.length, componentSize);
            System.arraycopy(r, Math.max(0, r.length - componentSize),
                p1363Signature, rOffset, rCopyLen);

            /* Pad s to component size (big-endian, so pad on left) */
            sOffset = componentSize + Math.max(0, componentSize - s.length);
            sCopyLen = Math.min(s.length, componentSize);
            System.arraycopy(s, Math.max(0, s.length - componentSize),
                p1363Signature, sOffset, sCopyLen);

            return p1363Signature;

        } catch (Exception e) {
            throw new SignatureException("DER to P1363 conversion failed: " +
                e.getMessage());
        }
    }

    /**
     * Convert P1363 format signature (r|s) to DER-encoded format.
     *
     * @param p1363Signature P1363 format signature
     * @param ecc ECC key for determining component size
     *
     * @return DER-encoded ECDSA signature
     *
     * @throws SignatureException if conversion fails
     */
    private static byte[] p1363ToDer(byte[] p1363Signature, Ecc ecc)
        throws SignatureException {

        int componentSize;
        byte[] r;
        byte[] s;

        try {
            /* Get component size for P1363 format */
            componentSize = getP1363ComponentSize(ecc);

            /* Validate P1363 signature size */
            if (p1363Signature.length != componentSize * 2) {
                throw new SignatureException(
                    "Invalid P1363 signature size: expected " +
                    (componentSize * 2) + ", got " + p1363Signature.length);
            }

            /* Extract r and s components */
            r = new byte[componentSize];
            s = new byte[componentSize];

            System.arraycopy(p1363Signature, 0, r, 0, componentSize);
            System.arraycopy(p1363Signature, componentSize, s, 0,
                componentSize);

            /* Create DER signature from raw r,s */
            return ecc.rsRawToSig(r, s);

        } catch (Exception e) {
            throw new SignatureException("P1363 to DER conversion failed: " +
                e.getMessage());
        }
    }

    /**
     * wolfJCE SHA256withECDSAinP1363Format signature class
     */
    public static final class wcSHA256wECDSAP1363 extends WolfCryptSignature {
        /**
         * Create new wcSHA256wECDSAP1363 object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA256wECDSAP1363() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA256);
        }

        /**
         * Override engineSign to return P1363 format signature
         */
        @Override
        protected synchronized byte[] engineSign()
            throws SignatureException {

            /* Get DER signature from parent class */
            byte[] derSignature = super.engineSign();
            if (derSignature == null) {
                throw new SignatureException(
                    "Failed to generate DER signature");
            }

            /* Convert DER to P1363 format */
            return derToP1363(derSignature, this.ecc);
        }

        /**
         * Override engineVerify to handle P1363 format signature
         */
        @Override
        protected synchronized boolean engineVerify(byte[] signature)
            throws SignatureException {

            if (signature == null) {
                return false;
            }

            /* Convert P1363 to DER format */
            byte[] derSignature = p1363ToDer(signature, this.ecc);

            /* Verify using parent class with DER signature */
            return super.engineVerify(derSignature);
        }
    }

    /**
     * wolfJCE SHA384withECDSAinP1363Format signature class
     */
    public static final class wcSHA384wECDSAP1363 extends WolfCryptSignature {
        /**
         * Create new wcSHA384wECDSAP1363 object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA384wECDSAP1363() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA384);
        }

        /**
         * Override engineSign to return P1363 format signature
         */
        @Override
        protected synchronized byte[] engineSign()
            throws SignatureException {

            /* Get DER signature from parent class */
            byte[] derSignature = super.engineSign();
            if (derSignature == null) {
                throw new SignatureException(
                    "Failed to generate DER signature");
            }

            /* Convert DER to P1363 format */
            return derToP1363(derSignature, this.ecc);
        }

        /**
         * Override engineVerify to handle P1363 format signature
         */
        @Override
        protected synchronized boolean engineVerify(byte[] signature)
            throws SignatureException {

            if (signature == null) {
                return false;
            }

            /* Convert P1363 to DER format */
            byte[] derSignature = p1363ToDer(signature, this.ecc);

            /* Verify using parent class with DER signature */
            return super.engineVerify(derSignature);
        }
    }

    /**
     * wolfJCE SHA3-256withECDSAinP1363Format signature class
     */
    public static final class wcSHA3_256wECDSAP1363 extends WolfCryptSignature {
        /**
         * Create new wcSHA3_256wECDSAP1363 object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_256wECDSAP1363() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA3_256);
        }

        /**
         * Override engineSign to return P1363 format signature
         */
        @Override
        protected synchronized byte[] engineSign()
            throws SignatureException {

            /* Get DER signature from parent class */
            byte[] derSignature = super.engineSign();
            if (derSignature == null) {
                throw new SignatureException(
                    "Failed to generate DER signature");
            }

            /* Convert DER to P1363 format */
            return derToP1363(derSignature, this.ecc);
        }

        /**
         * Override engineVerify to handle P1363 format signature
         */
        @Override
        protected synchronized boolean engineVerify(byte[] signature)
            throws SignatureException {

            if (signature == null) {
                return false;
            }

            /* Convert P1363 to DER format */
            byte[] derSignature = p1363ToDer(signature, this.ecc);

            /* Verify using parent class with DER signature */
            return super.engineVerify(derSignature);
        }
    }

    /**
     * wolfJCE SHA3-384withECDSAinP1363Format signature class
     */
    public static final class wcSHA3_384wECDSAP1363 extends WolfCryptSignature {
        /**
         * Create new wcSHA3_384wECDSAP1363 object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_384wECDSAP1363() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA3_384);
        }

        /**
         * Override engineSign to return P1363 format signature
         */
        @Override
        protected synchronized byte[] engineSign()
            throws SignatureException {

            /* Get DER signature from parent class */
            byte[] derSignature = super.engineSign();
            if (derSignature == null) {
                throw new SignatureException(
                    "Failed to generate DER signature");
            }

            /* Convert DER to P1363 format */
            return derToP1363(derSignature, this.ecc);
        }

        /**
         * Override engineVerify to handle P1363 format signature
         */
        @Override
        protected synchronized boolean engineVerify(byte[] signature)
            throws SignatureException {

            if (signature == null) {
                return false;
            }

            /* Convert P1363 to DER format */
            byte[] derSignature = p1363ToDer(signature, this.ecc);

            /* Verify using parent class with DER signature */
            return super.engineVerify(derSignature);
        }
    }

    /**
     * wolfJCE SHA3-512withECDSAinP1363Format signature class
     */
    public static final class wcSHA3_512wECDSAP1363 extends WolfCryptSignature {
        /**
         * Create new wcSHA3_512wECDSAP1363 object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA3_512wECDSAP1363() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA3_512);
        }

        /**
         * Override engineSign to return P1363 format signature
         */
        @Override
        protected synchronized byte[] engineSign()
            throws SignatureException {

            /* Get DER signature from parent class */
            byte[] derSignature = super.engineSign();
            if (derSignature == null) {
                throw new SignatureException(
                    "Failed to generate DER signature");
            }

            /* Convert DER to P1363 format */
            return derToP1363(derSignature, this.ecc);
        }

        /**
         * Override engineVerify to handle P1363 format signature
         */
        @Override
        protected synchronized boolean engineVerify(byte[] signature)
            throws SignatureException {

            if (signature == null) {
                return false;
            }

            /* Convert P1363 to DER format */
            byte[] derSignature = p1363ToDer(signature, this.ecc);

            /* Verify using parent class with DER signature */
            return super.engineVerify(derSignature);
        }
    }

    /**
     * wolfJCE SHA512withECDSAinP1363Format signature class
     */
    public static final class wcSHA512wECDSAP1363 extends WolfCryptSignature {
        /**
         * Create new wcSHA512wECDSAP1363 object
         *
         * @throws NoSuchAlgorithmException if signature type is not
         *         available in native wolfCrypt library
         */
        public wcSHA512wECDSAP1363() throws NoSuchAlgorithmException {
            super(KeyType.WC_ECDSA, DigestType.WC_SHA512);
        }

        /**
         * Override engineSign to return P1363 format signature
         */
        @Override
        protected synchronized byte[] engineSign()
            throws SignatureException {

            /* Get DER signature from parent class */
            byte[] derSignature = super.engineSign();
            if (derSignature == null) {
                throw new SignatureException(
                    "Failed to generate DER signature");
            }

            /* Convert DER to P1363 format */
            return derToP1363(derSignature, this.ecc);
        }

        /**
         * Override engineVerify to handle P1363 format signature
         */
        @Override
        protected synchronized boolean engineVerify(byte[] signature)
            throws SignatureException {

            if (signature == null) {
                return false;
            }

            /* Convert P1363 to DER format */
            byte[] derSignature = p1363ToDer(signature, this.ecc);

            /* Verify using parent class with DER signature */
            return super.engineVerify(derSignature);
        }
    }
}

