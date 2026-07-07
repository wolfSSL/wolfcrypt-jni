/* WolfCryptKeyPairGenerator.java
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

import java.math.BigInteger;

import java.security.KeyPairGeneratorSpi;
import java.security.KeyPair;
import java.security.InvalidParameterException;
import java.security.InvalidAlgorithmParameterException;

import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.MlKem;
import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE KeyPairGenerator wrapper class
 */
public class WolfCryptKeyPairGenerator extends KeyPairGeneratorSpi {

    enum KeyType {
        WC_RSA,
        WC_RSA_PSS,
        WC_ECC,
        WC_DH,
        WC_ML_DSA,
        WC_ML_KEM,
        WC_SLH_DSA
    }

    private KeyType type = null;

    private String curve = null;
    private int keysize = 0;
    private long publicExponent = 0;

    private byte[] dhP = null;
    private byte[] dhG = null;

    /** Flag for "no PQC parameter set" in pqcParam and pqcLockedParam.
     * Must be negative, 0 reserved for SLH-DSA-SHAKE-128s. */
    private static final int PQC_PARAM_UNSET = -1;

    /**
     * PQC parameter set for WC_ML_DSA, WC_ML_KEM, and WC_SLH_DSA generators.
     * Interpreted by this.type: an MlDsa.ML_DSA_* level, MlKem.ML_KEM_* level,
     * or SlhDsa.SLH_DSA_* parameter set. Set to the per-family default in
     * constructor. */
    private int pqcParam = PQC_PARAM_UNSET;

    /**
     * For per-parameter-set PQC subclasses wcKeyPairGenMlDsa{44,65,87},
     * wcKeyPairGenMlKem{512,768,1024}, wcKeyPairGenSlhDsa*, the parameter set
     * is fixed and engineInitialize(AlgorithmParameterSpec) must reject
     * mismatching specs. PQC_PARAM_UNSET means the generic alias (any param
     * set via spec).
     */
    private int pqcLockedParam = PQC_PARAM_UNSET;

    /**
     * True when the PQC parameter set was explicitly chosen, either by a
     * per-set subclass or an engineInitialize(AlgorithmParameterSpec) call.
     * When false, the generic generator is using its per-family default.
     */
    private boolean pqcParamExplicit = false;

    private Rng rng = null;

    /* Lock around Rng access */
    private final Object rngLock = new Object();

    /* for debug logging */
    private String algString;

    private WolfCryptKeyPairGenerator(KeyType type) {
        this(type, PQC_PARAM_UNSET);
    }

    /**
     * Create new WolfCryptKeyPairGenerator, optionally locking the PQC param
     * set for the per-parameter-set subclasses (wcKeyPairGenMlDsa{44,65,87},
     * wcKeyPairGenMlKem{512,768,1024}, and wcKeyPairGenSlhDsa*).
     *
     * @param type key type to generate
     * @param lockedParam fixed PQC parameter set for per-set aliases, or
     *        PQC_PARAM_UNSET for the generic alias (any parameter set via
     *        spec). Ignored for non-PQC key types.
     */
    private WolfCryptKeyPairGenerator(KeyType type, int lockedParam) {

        this.type = type;

        /* Set default parameters for RSA key generation */
        if (type == KeyType.WC_RSA || type == KeyType.WC_RSA_PSS) {
            this.keysize = 2048;  /* Default RSA key size */
            this.publicExponent = Rsa.getDefaultRsaExponent();
        }

        /* Set default parameters for ECC key generation */
        if (type == KeyType.WC_ECC) {
            /* Default to 256-bit ECC */
            this.keysize = 32;
        }

        /* Set default parameters for DH key generation.
         * Try FFDHE 3072 first (matches SunJCE default), but fall back
         * to FFDHE 2048 if 3072 is not available in the wolfSSL build. */
        if (type == KeyType.WC_DH) {
            try {
                /* Try FFDHE 3072 first */
                byte[][] params = Dh.getNamedDhParams(Dh.WC_FFDHE_3072);
                if (params != null && params.length == 2 &&
                    params[0] != null && params[0].length > 0) {
                    this.dhP = params[0];
                    this.dhG = params[1];
                }
                else {
                    /* Fall back to FFDHE 2048 if 3072 not available */
                    params = Dh.getNamedDhParams(Dh.WC_FFDHE_2048);
                    if (params != null && params.length == 2 &&
                        params[0] != null && params[0].length > 0) {
                        this.dhP = params[0];
                        this.dhG = params[1];
                    }
                }
            }
            catch (Exception e) {
                /* Not fatal if default param initialization. User can still
                 * initialize() before generateKeyPair() */
            }
        }

        /* Set defaults for PQC key generation (ML-DSA, ML-KEM, SLH-DSA).
         * Per-set subclasses pass their fixed parameter set in. Generic
         * aliases get the per-family default. */
        if (type == KeyType.WC_ML_DSA || type == KeyType.WC_ML_KEM ||
            type == KeyType.WC_SLH_DSA) {

            this.pqcLockedParam = lockedParam;
            if (lockedParam != PQC_PARAM_UNSET) {
                this.pqcParam = lockedParam;
                this.pqcParamExplicit = true;
            }
            else {
                switch (type) {
                    case WC_ML_DSA:
                        this.pqcParam = MlDsa.ML_DSA_65;
                        break;
                    case WC_ML_KEM:
                        this.pqcParam = MlKem.ML_KEM_768;
                        break;
                    default:
                        this.pqcParam = SlhDsa.SLH_DSA_SHA2_128F;
                        break;
                }
                this.pqcParamExplicit = false;
            }
        }

        /* Initialize RNG for default key generation if needed. */
        if (type == KeyType.WC_RSA || type == KeyType.WC_RSA_PSS ||
            type == KeyType.WC_ECC || type == KeyType.WC_DH ||
            type == KeyType.WC_ML_DSA || type == KeyType.WC_ML_KEM ||
            type == KeyType.WC_SLH_DSA) {

            synchronized (rngLock) {
                if (this.rng == null) {
                    this.rng = new Rng();
                    this.rng.init();
                }
            }
        }

        if (WolfCryptDebug.DEBUG) {
            algString = typeToString(type);
        }
    }

    @Override
    public synchronized void initialize(int keysize, SecureRandom random) {

        if (type == KeyType.WC_ML_DSA || type == KeyType.WC_ML_KEM ||
            type == KeyType.WC_SLH_DSA) {
            /* PQC parameter sets are selected by a named parameter spec, not
             * integer key size. Callers must supply a NamedParameterSpec or
             * WolfPQCParameterSpec via initialize(AlgorithmParameterSpec), or
             * use the parameter-set-specific KeyPairGenerator name. Matches
             * JDK 24 / JEP 497 behavior. */
            throw new InvalidParameterException(
                typeToString(this.type) + " does not accept integer key " +
                "sizes: use initialize(AlgorithmParameterSpec) with a " +
                "NamedParameterSpec or WolfPQCParameterSpec instead.");
        }

        if (type == KeyType.WC_DH) {
            int namedGroup = -1;

            /* Map key size (in bits) to FFDHE named group.
             * Only standard FFDHE sizes are supported (2048, 3072, 4096,
             * 6144, 8192). Throw InvalidParameterException for unsupported
             * sizes, matching SunJCE behavior. */
            if (keysize == 2048) {
                namedGroup = Dh.WC_FFDHE_2048;
            }
            else if (keysize == 3072) {
                namedGroup = Dh.WC_FFDHE_3072;
            }
            else if (keysize == 4096) {
                namedGroup = Dh.WC_FFDHE_4096;
            }
            else if (keysize == 6144) {
                namedGroup = Dh.WC_FFDHE_6144;
            }
            else if (keysize == 8192) {
                namedGroup = Dh.WC_FFDHE_8192;
            }
            else {
                throw new InvalidParameterException(
                    "DH key size must be 2048, 3072, 4096, 6144, or 8192. " +
                    "Unsupported size: " + keysize);
            }

            try {
                /* Get DH parameters for named group. If this FFDHE group
                 * is not compiled into wolfSSL, throw an exception. */
                byte[][] params = Dh.getNamedDhParams(namedGroup);
                if (params != null && params.length == 2 &&
                    params[0] != null && params[0].length > 0) {
                    this.dhP = params[0];
                    this.dhG = params[1];
                }
                else {
                    throw new InvalidParameterException(
                        "FFDHE " + keysize + "-bit group not available in " +
                        "native wolfSSL library. Only FFDHE groups compiled " +
                        "into wolfSSL can be used.");
                }
            }
            catch (InvalidParameterException e) {
                throw e;
            }
            catch (Exception e) {
                throw new RuntimeException(
                    "Failed to initialize DH parameters: " + e.getMessage());
            }

            synchronized (rngLock) {
                if (this.rng == null) {
                    this.rng = new Rng();
                    this.rng.init();
                }
            }

            log("init with DH keysize: " + keysize +
                " (using FFDHE group " + namedGroup + ")");

            return;
        }

        if (type == KeyType.WC_ECC) {
            /* Validate EC key size and map to standard NIST curve.
             * Only standard key sizes are supported (192, 224, 256, 384, 521)
             * which matches SunEC behavior. For non-NIST curves use
             * ECGenParameterSpec explicitly via
             * initialize(AlgorithmParameterSpec). */

            int curveSize = -1;
            String curveName = null;

            if (keysize != 192 && keysize != 224 && keysize != 256 &&
                keysize != 384 && keysize != 521) {
                throw new InvalidParameterException(
                    "EC key size must be 192, 224, 256, 384, or 521. " +
                    "Unsupported size: " + keysize);
            }

            /* Map key size to NIST curve name (matching SunEC behavior) */
            switch (keysize) {
                case 192:
                    curveName = "secp192r1";
                    break;
                case 224:
                    curveName = "secp224r1";
                    break;
                case 256:
                    curveName = "secp256r1";
                    break;
                case 384:
                    curveName = "secp384r1";
                    break;
                case 521:
                    curveName = "secp521r1";
                    break;
            }

            /* Verify the curve is available in native wolfSSL library */
            try {
                curveSize = Ecc.getCurveSizeFromName(curveName);
            } catch (WolfCryptException e) {
                throw new InvalidParameterException("EC curve " + curveName +
                    " for key size " + keysize +
                    " not available in native wolfSSL library: " +
                    e.getMessage());
            }

            if (curveSize < 0) {
                throw new InvalidParameterException("EC curve " + curveName +
                    " for key size " + keysize +
                    " not available in native wolfSSL library");
            }

            /* Store the curve name and size */
            this.curve = curveName;
            this.keysize = curveSize;

            log("init with keysize " + keysize + ", using curve: " +
                curveName);

        } else {
            this.keysize = keysize;
        }

        if (type == KeyType.WC_RSA || type == KeyType.WC_RSA_PSS) {

            /* Sanity check on key size */
            if (keysize < Rsa.RSA_MIN_SIZE) {
                throw new InvalidParameterException(
                    "RSA key size too small, min is " +
                    Rsa.RSA_MIN_SIZE);
            }

            /* Set default RSA exponent for wolfSSL */
            this.publicExponent = Rsa.getDefaultRsaExponent();
        }

        synchronized (rngLock) {
            if (this.rng == null) {
                this.rng = new Rng();
                this.rng.init();
            }
        }

        log("init with keysize: " + keysize);
    }

    @Override
    public synchronized void initialize(AlgorithmParameterSpec params,
        SecureRandom random) throws InvalidAlgorithmParameterException {

        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameterSpec must not be null");
        }

        synchronized (rngLock) {
            if (this.rng == null) {
                this.rng = new Rng();
                this.rng.init();
            }
        }

        switch (type) {

            case WC_RSA:
            case WC_RSA_PSS:

                if (!(params instanceof RSAKeyGenParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "params must be of type RSAKeyGenParameterSpec");
                }

                RSAKeyGenParameterSpec rsaSpec = (RSAKeyGenParameterSpec)params;
                this.keysize = rsaSpec.getKeysize();

                /* Exponent should be larger than 1 and odd */
                long exp = rsaSpec.getPublicExponent().longValue();
                if ((exp <= 1) || (exp % 2 == 0)) {
                    throw new InvalidAlgorithmParameterException(
                        "RSA public exponent must be positive and odd" );
                }
                this.publicExponent = exp;

                /* Double check longValue() converted correctly. Some platforms
                 * do not have longValueExact() */
                if (!BigInteger.valueOf(this.publicExponent).equals(
                        rsaSpec.getPublicExponent())) {
                    throw new InvalidAlgorithmParameterException(
                        "RSA public exponent value larger than long");
                }

                log("init with RSA spec, keysize = " + keysize +
                    ", public exponent = " + publicExponent);

                break;

            case WC_ECC:

                int curvesize;

                if (!(params instanceof ECGenParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "params must be of type ECCGenParameterSpec");
                }

                ECGenParameterSpec eccSpec = (ECGenParameterSpec)params;
                String curveName = eccSpec.getName();

                curvesize = Ecc.getCurveSizeFromName(curveName);
                if (curvesize < 0) {
                    throw new InvalidAlgorithmParameterException(
                        "Unsupported ECC curve in native wolfCrypt library");
                }

                this.curve = curveName;
                this.keysize = curvesize;

                log("init with spec, curve: " + curveName +
                    ", keysize: " + curvesize);

                break;

            case WC_DH:

                if (!(params instanceof DHParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "params must be of type DHParameterSpec");
                }

                DHParameterSpec dhSpec = (DHParameterSpec)params;
                this.dhP = dhSpec.getP().toByteArray();
                this.dhG = dhSpec.getG().toByteArray();

                if (dhP == null || dhG == null) {
                    throw new InvalidAlgorithmParameterException(
                        "Invalid parameters, either p or g is null");
                }

                log("init with spec, prime len: " + this.dhP.length);

                break;

            case WC_ML_DSA:
            case WC_ML_KEM:
            case WC_SLH_DSA:

                String algName = typeToString(this.type);
                int newParam;
                String paramName = null;

                /* Fall back to our AlgorithmParameterSpec subtype for
                 * JDK 8-10. */
                if (params instanceof WolfPQCParameterSpec) {
                    paramName = ((WolfPQCParameterSpec) params).getName();
                }
                /* JDK 11+ uses standard NamedParameterSpec via reflection. */
                else {
                    paramName =
                        WolfPQCJdkCompat.namedParameterSpecGetName(params);
                }

                if (paramName == null) {
                    throw new InvalidAlgorithmParameterException(
                        algName + " params must be a NamedParameterSpec " +
                        "(JDK 11+) or WolfPQCParameterSpec (JDK 8-10), got: " +
                        params.getClass().getName());
                }

                try {
                    newParam = pqcNameToParam(paramName);
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidAlgorithmParameterException(
                        "Unrecognized " + algName + " parameter set: " +
                        paramName);
                }

                /* Per-parameter-set subclasses reject specs that don't
                 * match their locked parameter set. */
                if ((this.pqcLockedParam != PQC_PARAM_UNSET) &&
                    (newParam != this.pqcLockedParam)) {

                    throw new InvalidAlgorithmParameterException(
                        "Spec '" + paramName + "' does not match the " +
                        "fixed parameter set for this KeyPairGenerator");
                }

                this.pqcParam = newParam;
                this.pqcParamExplicit = true;
                log("init with " + algName + " spec: " + paramName);

                break;

            default:
                throw new RuntimeException(
                    "Unsupported algorithm for key generation");
        }
    }

    @Override
    public synchronized KeyPair generateKeyPair() {

        KeyPair pair = null;

        byte[] privDer = null;
        byte[] pubDer  = null;

        KeySpec privSpec = null;
        KeySpec pubSpec  = null;

        final int MAX_KEYGEN_RETRIES = 5;
        int retryCount = 0;
        WolfCryptException lastPrimeGenException = null;


        switch (this.type) {

            case WC_RSA:
            case WC_RSA_PSS:

                if (keysize == 0) {
                    throw new RuntimeException(
                        "keysize is 0, please set before generating key");
                }

                RSAPrivateKey rsaPriv = null;
                RSAPublicKey  rsaPub  = null;

                /* Retry loop for RSA key generation. Native wolfCrypt may
                 * return PRIME_GEN_E (-251) if it fails to find a suitable
                 * prime after the NIST FIPS 186-4 mandated number of attempts.
                 * We retry a few times in that error case before giving up. */
                while (retryCount < MAX_KEYGEN_RETRIES) {
                    Rsa rsa = new Rsa();

                    try {
                        synchronized (rngLock) {
                            rsa.makeKey(this.keysize, this.publicExponent,
                                this.rng);
                        }

                        /* private key */
                        privDer = rsa.privateKeyEncodePKCS8();
                        if (privDer == null) {
                            throw new RuntimeException(
                                "Unable to get RSA private key DER");
                        }
                        privSpec = new PKCS8EncodedKeySpec(privDer);

                        /* public key */
                        pubDer = rsa.exportPublicDer();
                        if (pubDer == null) {
                            throw new RuntimeException(
                                "Unable to get RSA public key DER");
                        }
                        pubSpec = new X509EncodedKeySpec(pubDer);

                        /* Prefer wolfJCE KeyFactory by name to avoid a
                         * higher priority Provider that may strip RSA CRT
                         * params (incompatible with WolfCryptSignature). Fall
                         * back to default lookup in builds where wolfJCE does
                         * not register KeyFactory.RSA (!WOLFSSL_PUBLIC_MP). */
                        KeyFactory kf =
                            WolfCryptUtil.getKeyFactoryPreferWolfJCE("RSA");
                        rsaPriv = (RSAPrivateKey)kf.generatePrivate(privSpec);
                        rsaPub  = (RSAPublicKey)kf.generatePublic(pubSpec);

                        if (this.type == KeyType.WC_RSA_PSS) {
                            /* Try to use RSASSA-PSS KeyFactory if available.
                             * wolfJCE does not currently register one, so
                             * this resolves through Provider priority order.
                             * Not all platforms support it (e.g. Android). */
                            try {
                                /* Get key specs to generate PSS keys */
                                RSAPrivateCrtKeySpec privCrtSpec =
                                    kf.getKeySpec(rsaPriv,
                                        RSAPrivateCrtKeySpec.class);
                                RSAPublicKeySpec pubKeySpec =
                                    kf.getKeySpec(rsaPub,
                                        RSAPublicKeySpec.class);

                                /* Use RSASSA-PSS KeyFactory */
                                KeyFactory pssKf =
                                    KeyFactory.getInstance("RSASSA-PSS");
                                RSAPrivateKey altPriv = (RSAPrivateKey)pssKf
                                    .generatePrivate(privCrtSpec);
                                RSAPublicKey altPub = (RSAPublicKey)pssKf
                                    .generatePublic(pubKeySpec);

                                /* Only adopt PSS KeyFactory output if it
                                 * preserves CRT params. */
                                if (altPriv instanceof RSAPrivateCrtKey) {
                                    rsaPriv = altPriv;
                                    rsaPub  = altPub;
                                }
                            } catch (NoSuchAlgorithmException |
                                     InvalidKeySpecException |
                                     ClassCastException e) {
                                /* RSASSA-PSS KeyFactory not available on this
                                 * platform, use regular RSA keys which are
                                 * still valid for PSS operations */
                            }
                        }

                        pair = new KeyPair(rsaPub, rsaPriv);

                        /* Success, exit retry loop */
                        break;

                    } catch (WolfCryptException e) {
                        /* Only retry on PRIME_GEN_E error */
                        if (e.getError() == WolfCryptError.PRIME_GEN_E) {
                            lastPrimeGenException = e;
                            retryCount++;
                            log("RSA key generation failed to find prime, " +
                                "retry " + retryCount + "/" +
                                MAX_KEYGEN_RETRIES);
                        }
                        else {
                            throw new RuntimeException(e);
                        }

                    } catch (Exception e) {
                        throw new RuntimeException(e);

                    } finally {
                        /* Always clean up */
                        zeroArray(privDer);
                        zeroArray(pubDer);
                        rsa.releaseNativeStruct();
                    }
                }

                /* Check if we exhausted all retries */
                if (pair == null) {
                    throw new RuntimeException(
                        "RSA key generation failed after " +
                        MAX_KEYGEN_RETRIES +
                        " attempts due to prime generation failure",
                        lastPrimeGenException);
                }

                log("generated " +
                    (this.type == KeyType.WC_RSA_PSS ? "RSASSA-PSS" : "RSA") +
                    " KeyPair");

                break;

            case WC_ECC:

                if (keysize == 0) {
                    throw new RuntimeException(
                        "Keysize is 0, please set before generating key");
                }

                ECPrivateKey eccPriv = null;
                ECPublicKey  eccPub  = null;
                Ecc ecc = null;

                /* synchronize entire key generation and encoding to prevent
                 * multiple threads from mixing up keys during generation */
                synchronized (rngLock) {
                    ecc = new Ecc(this.rng);

                    log("generating ECC key on curve: " +
                        (this.curve == null ? "default" : this.curve) +
                        ", keysize: " + this.keysize);

                    if (this.curve == null) {
                        ecc.makeKey(this.rng, this.keysize);
                    } else {
                        ecc.makeKeyOnCurve(this.rng, this.keysize, this.curve);
                    }

                    /* private key */
                    privDer = ecc.privateKeyEncodePKCS8();
                    if (privDer == null) {
                        throw new RuntimeException(
                            "Unable to get ECC private key DER");
                    }
                    privSpec = new PKCS8EncodedKeySpec(privDer);

                    /* public key */
                    pubDer = ecc.publicKeyEncode();
                    if (pubDer == null) {
                        throw new RuntimeException(
                            "Unable to get ECC public key DER");
                    }
                    pubSpec = new X509EncodedKeySpec(pubDer);

                    zeroArray(privDer);
                    zeroArray(pubDer);
                    ecc.releaseNativeStruct();

                    try {
                        KeyFactory kf =
                            WolfCryptUtil.getKeyFactoryPreferWolfJCE("EC");

                        eccPriv  = (ECPrivateKey)kf.generatePrivate(privSpec);
                        eccPub   = (ECPublicKey)kf.generatePublic(pubSpec);

                        pair = new KeyPair(eccPub, eccPriv);

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }

                log("generated ECC KeyPair");

                break;

            case WC_DH:

                DHPrivateKey dhPriv = null;
                DHPublicKey  dhPub  = null;

                if (dhP == null || dhG == null) {
                    throw new RuntimeException("No DH parameters available");
                }

                Dh dh = new Dh();

                /* load params */
                dh.setParams(dhP, dhG);

                /* make key */
                synchronized (rngLock) {
                    dh.makeKey(this.rng);
                }

                privSpec = new DHPrivateKeySpec(
                    new BigInteger(1, dh.getPrivateKey()),
                    new BigInteger(1, dhP),
                    new BigInteger(1, dhG));

                pubSpec = new DHPublicKeySpec(
                    new BigInteger(1, dh.getPublicKey()),
                    new BigInteger(1, dhP),
                    new BigInteger(1, dhG));

                dh.releaseNativeStruct();

                try {
                    KeyFactory kf =
                        WolfCryptUtil.getKeyFactoryPreferWolfJCE("DH");

                    dhPriv  = (DHPrivateKey)kf.generatePrivate(privSpec);
                    dhPub   = (DHPublicKey)kf.generatePublic(pubSpec);

                    pair = new KeyPair(dhPub, dhPriv);

                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage());
                }

                log("generated DH KeyPair");

                break;

            case WC_ML_DSA:

                if (this.pqcParam == PQC_PARAM_UNSET) {
                    throw new RuntimeException(
                        "ML-DSA level not set, call initialize() first");
                }

                MlDsa mlDsa = null;
                byte[] mlDsaPubDer = null;
                byte[] mlDsaPrivDer = null;

                try {
                    mlDsa = new MlDsa(this.pqcParam);

                    synchronized (rngLock) {
                        mlDsa.makeKey(this.rng);
                    }

                    mlDsaPubDer = mlDsa.exportPublicKeyDer(true);
                    mlDsaPrivDer = mlDsa.exportPrivateKeyDer();

                    WolfCryptMlDsaPublicKey mlDsaPub =
                        new WolfCryptMlDsaPublicKey(mlDsaPubDer,
                            this.pqcParam);
                    WolfCryptMlDsaPrivateKey mlDsaPriv =
                        new WolfCryptMlDsaPrivateKey(mlDsaPrivDer,
                            this.pqcParam);

                    pair = new KeyPair(mlDsaPub, mlDsaPriv);

                }
                catch (WolfCryptException e) {
                    throw new RuntimeException(e);
                }
                finally {
                    zeroArray(mlDsaPubDer);
                    zeroArray(mlDsaPrivDer);
                    if (mlDsa != null) {
                        mlDsa.releaseNativeStruct();
                    }
                }

                log("generated ML-DSA KeyPair, level " + this.pqcParam);

                break;

            case WC_SLH_DSA:

                if (this.pqcParam == PQC_PARAM_UNSET) {
                    throw new RuntimeException(
                        "SLH-DSA param set not set, call initialize() first");
                }

                /* For generic generator, fall back from default to a param set
                 * compiled into native wolfSSL, so getInstance("SLH-DSA") works
                 * on varied build configs. */
                int slhDsaGenParam = this.pqcParam;
                if (!this.pqcParamExplicit) {
                    slhDsaGenParam = resolveDefaultSlhDsaParam();
                }

                SlhDsa slhDsa = null;
                byte[] slhDsaPubDer = null;
                byte[] slhDsaPrivDer = null;

                try {
                    slhDsa = new SlhDsa(slhDsaGenParam);

                    synchronized (rngLock) {
                        slhDsa.makeKey(this.rng);
                    }

                    slhDsaPubDer = slhDsa.exportPublicKeyDer(true);
                    slhDsaPrivDer = slhDsa.exportPrivateKeyDer();

                    WolfCryptSlhDsaPublicKey slhDsaPub =
                        new WolfCryptSlhDsaPublicKey(slhDsaPubDer,
                            slhDsaGenParam);
                    WolfCryptSlhDsaPrivateKey slhDsaPriv =
                        new WolfCryptSlhDsaPrivateKey(slhDsaPrivDer,
                            slhDsaGenParam);

                    pair = new KeyPair(slhDsaPub, slhDsaPriv);

                }
                catch (WolfCryptException e) {
                    throw new RuntimeException(e);
                }
                finally {
                    zeroArray(slhDsaPubDer);
                    zeroArray(slhDsaPrivDer);
                    if (slhDsa != null) {
                        slhDsa.releaseNativeStruct();
                    }
                }

                log("generated SLH-DSA KeyPair, param " + slhDsaGenParam);

                break;

            case WC_ML_KEM:

                MlKem mlkem = null;
                byte[] mlkemSeed = null;
                byte[] mlkemPub  = null;
                byte[] mlkemPriv = null;

                try {
                    /* Generate the FIPS 203 seed and derive the key
                     * deterministically, so the seed is retained for the
                     * seed and both PKCS#8 output forms (controlled by the
                     * jdk.mlkem.pkcs8.encoding property). */
                    synchronized (rngLock) {
                        mlkemSeed =
                            this.rng.generateBlock(MlKem.ML_KEM_SEED_SIZE);
                    }

                    mlkem = new MlKem(this.pqcParam);
                    mlkem.makeKeyFromSeed(mlkemSeed);

                    mlkemPub  = mlkem.exportPublic();
                    mlkemPriv = mlkem.exportPrivate();

                    WolfCryptMlKemPublicKey mlkemPubKey =
                        new WolfCryptMlKemPublicKey(this.pqcParam, mlkemPub);
                    WolfCryptMlKemPrivateKey mlkemPrivKey =
                        new WolfCryptMlKemPrivateKey(this.pqcParam, mlkemPriv,
                            mlkemSeed);

                    pair = new KeyPair(mlkemPubKey, mlkemPrivKey);

                }
                catch (WolfCryptException e) {
                    throw new RuntimeException(e);
                }
                finally {
                    zeroArray(mlkemSeed);
                    zeroArray(mlkemPriv);
                    if (mlkem != null) {
                        mlkem.releaseNativeStruct();
                    }
                }

                log("generated ML-KEM KeyPair, level " + this.pqcParam);

                break;

            default:
                throw new RuntimeException(
                    "Unsupported algorithm for key generation: " + this.type);
        }

        return pair;
    }

    /*
     * Resolve a PQC parameter-set name to its native value for this
     * generator's key type: an MlDsa.ML_DSA_* level, an MlKem.ML_KEM_*
     * level, or an SlhDsa.SLH_DSA_* parameter set.
     *
     * Throws IllegalArgumentException if the name is not a valid parameter
     * set name for this key type.
     */
    private int pqcNameToParam(String name) {
        switch (this.type) {
            case WC_ML_DSA:
                return WolfPQCJdkCompat.paramNameToLevel(name);
            case WC_ML_KEM:
                return WolfPQCJdkCompat.mlkemParamNameToLevel(name);
            default:
                return WolfPQCJdkCompat.slhDsaNameToParam(name);
        }
    }

    private String typeToString(KeyType type) {
        switch (type) {
            case WC_RSA:
                return "RSA";
            case WC_RSA_PSS:
                return "RSASSA-PSS";
            case WC_ECC:
                return "ECC";
            case WC_DH:
                return "DH";
            case WC_ML_DSA:
                return "ML-DSA";
            case WC_ML_KEM:
                return "ML-KEM";
            case WC_SLH_DSA:
                return "SLH-DSA";
            default:
                return "None";
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[" + algString + "] " + msg);
    }

    @SuppressWarnings({"deprecation", "removal"})
    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            synchronized (rngLock) {
                if (this.rng != null) {
                    this.rng.free();
                    this.rng.releaseNativeStruct();
                }
            }
        } finally {
            super.finalize();
        }
    }

    private void zeroArray(byte[] in) {

        if (in == null)
            return;

        for (int i = 0; i < in.length; i++) {
            in[i] = 0;
        }
    }

    /**
     * wolfCrypt RSA key pair generator class
     */
    public static final class wcKeyPairGenRSA
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenRSA object
         */
        public wcKeyPairGenRSA() {
            super(KeyType.WC_RSA);
        }
    }

    /**
     * wolfCrypt RSASSA-PSS key pair generator class
     */
    public static final class wcKeyPairGenRSAPSS
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenRSAPSS object
         */
        public wcKeyPairGenRSAPSS() {
            super(KeyType.WC_RSA_PSS);
        }
    }

    /**
     * wolfCrypt ECC key pair generator class
     */
    public static final class wcKeyPairGenECC
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenECC object
         */
        public wcKeyPairGenECC() {
            super(KeyType.WC_ECC);
        }
    }

    /**
     * wolfCrypt DH key pair generator class
     */
    public static final class wcKeyPairGenDH
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenDH object
         */
        public wcKeyPairGenDH() {
            super(KeyType.WC_DH);
        }
    }

    /**
     * wolfCrypt ML-DSA (FIPS 204) generic key pair generator. Accepts any
     * of the three ML-DSA parameter sets via
     * {@code initialize(NamedParameterSpec)} or
     * {@code initialize(WolfPQCParameterSpec)}. Defaults to ML-DSA-65 to
     * match JDK 24 / JEP 497 behavior.
     */
    public static final class wcKeyPairGenMlDsa
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlDsa object
         */
        public wcKeyPairGenMlDsa() {
            super(KeyType.WC_ML_DSA);
        }
    }

    /**
     * wolfCrypt ML-DSA-44 key pair generator.
     */
    public static final class wcKeyPairGenMlDsa44
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlDsa44 object
         */
        public wcKeyPairGenMlDsa44() {
            super(KeyType.WC_ML_DSA, MlDsa.ML_DSA_44);
        }
    }

    /**
     * wolfCrypt ML-DSA-65 key pair generator.
     */
    public static final class wcKeyPairGenMlDsa65
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlDsa65 object
         */
        public wcKeyPairGenMlDsa65() {
            super(KeyType.WC_ML_DSA, MlDsa.ML_DSA_65);
        }
    }

    /**
     * wolfCrypt ML-DSA-87 key pair generator.
     */
    public static final class wcKeyPairGenMlDsa87
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlDsa87 object
         */
        public wcKeyPairGenMlDsa87() {
            super(KeyType.WC_ML_DSA, MlDsa.ML_DSA_87);
        }
    }

    /* Cached resolveDefaultSlhDsaParam() result. The parameter sets compiled
     * into the loaded native library cannot change at runtime, so probe native
     * availability only once. -1 means unresolved. */
    private static volatile int defaultSlhDsaParam = -1;

    /**
     * Resolve the generic generator default SLH-DSA parameter set to one
     * compiled into native wolfSSL. Prefers SLH-DSA-SHA2-128f, then falls back
     * through the remaining sets so getInstance("SLH-DSA") works on varied
     * native builds. The result is cached after the first probe.
     *
     * @return the first compiled-in parameter set from the preference order,
     *         or SLH-DSA-SHA2-128f if none could be probed.
     */
    private static int resolveDefaultSlhDsaParam() {

        int resolved = defaultSlhDsaParam;
        if (resolved >= 0) {
            return resolved;
        }

        int[] preference = {
            SlhDsa.SLH_DSA_SHA2_128F, SlhDsa.SLH_DSA_SHAKE_128F,
            SlhDsa.SLH_DSA_SHA2_128S, SlhDsa.SLH_DSA_SHAKE_128S,
            SlhDsa.SLH_DSA_SHA2_192F, SlhDsa.SLH_DSA_SHAKE_192F,
            SlhDsa.SLH_DSA_SHA2_192S, SlhDsa.SLH_DSA_SHAKE_192S,
            SlhDsa.SLH_DSA_SHA2_256F, SlhDsa.SLH_DSA_SHAKE_256F,
            SlhDsa.SLH_DSA_SHA2_256S, SlhDsa.SLH_DSA_SHAKE_256S
        };

        resolved = SlhDsa.SLH_DSA_SHA2_128F;
        for (int param : preference) {
            if (slhDsaParamAvailable(param)) {
                resolved = param;
                break;
            }
        }

        defaultSlhDsaParam = resolved;
        return resolved;
    }

    /**
     * Check whether an SLH-DSA parameter set is compiled into native wolfSSL.
     * Performs a native init (via publicKeySize) without generating a key.
     *
     * @param param SLH-DSA parameter set (0-11)
     *
     * @return true if the parameter set is available, false otherwise
     */
    private static boolean slhDsaParamAvailable(int param) {

        try {
            SlhDsa key = new SlhDsa(param);
            try {
                key.publicKeySize();
                return true;
            }
            finally {
                key.releaseNativeStruct();
            }
        }
        catch (WolfCryptException e) {
            return false;
        }
    }

    /**
     * wolfCrypt SLH-DSA key pair generator (generic). The parameter set is
     * selectable via {@code initialize(NamedParameterSpec)} or
     * {@code initialize(WolfPQCParameterSpec)}. Defaults to SLH-DSA-SHA2-128f,
     * falling back to a compiled-in set on partial native builds.
     */
    public static final class wcKeyPairGenSlhDsa
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsa object */
        public wcKeyPairGenSlhDsa() {
            super(KeyType.WC_SLH_DSA, PQC_PARAM_UNSET);
        }
    }

    /** wolfCrypt SLH-DSA-SHAKE-128s key pair generator. */
    public static final class wcKeyPairGenSlhDsaShake_128s
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaShake_128s object */
        public wcKeyPairGenSlhDsaShake_128s() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHAKE_128S);
        }
    }

    /** wolfCrypt SLH-DSA-SHAKE-128f key pair generator. */
    public static final class wcKeyPairGenSlhDsaShake_128f
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaShake_128f object */
        public wcKeyPairGenSlhDsaShake_128f() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHAKE_128F);
        }
    }

    /** wolfCrypt SLH-DSA-SHAKE-192s key pair generator. */
    public static final class wcKeyPairGenSlhDsaShake_192s
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaShake_192s object */
        public wcKeyPairGenSlhDsaShake_192s() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHAKE_192S);
        }
    }

    /** wolfCrypt SLH-DSA-SHAKE-192f key pair generator. */
    public static final class wcKeyPairGenSlhDsaShake_192f
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaShake_192f object */
        public wcKeyPairGenSlhDsaShake_192f() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHAKE_192F);
        }
    }

    /** wolfCrypt SLH-DSA-SHAKE-256s key pair generator. */
    public static final class wcKeyPairGenSlhDsaShake_256s
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaShake_256s object */
        public wcKeyPairGenSlhDsaShake_256s() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHAKE_256S);
        }
    }

    /** wolfCrypt SLH-DSA-SHAKE-256f key pair generator. */
    public static final class wcKeyPairGenSlhDsaShake_256f
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaShake_256f object */
        public wcKeyPairGenSlhDsaShake_256f() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHAKE_256F);
        }
    }

    /** wolfCrypt SLH-DSA-SHA2-128s key pair generator. */
    public static final class wcKeyPairGenSlhDsaSha2_128s
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaSha2_128s object */
        public wcKeyPairGenSlhDsaSha2_128s() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHA2_128S);
        }
    }

    /** wolfCrypt SLH-DSA-SHA2-128f key pair generator. */
    public static final class wcKeyPairGenSlhDsaSha2_128f
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaSha2_128f object */
        public wcKeyPairGenSlhDsaSha2_128f() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHA2_128F);
        }
    }

    /** wolfCrypt SLH-DSA-SHA2-192s key pair generator. */
    public static final class wcKeyPairGenSlhDsaSha2_192s
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaSha2_192s object */
        public wcKeyPairGenSlhDsaSha2_192s() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHA2_192S);
        }
    }

    /** wolfCrypt SLH-DSA-SHA2-192f key pair generator. */
    public static final class wcKeyPairGenSlhDsaSha2_192f
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaSha2_192f object */
        public wcKeyPairGenSlhDsaSha2_192f() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHA2_192F);
        }
    }

    /** wolfCrypt SLH-DSA-SHA2-256s key pair generator. */
    public static final class wcKeyPairGenSlhDsaSha2_256s
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaSha2_256s object */
        public wcKeyPairGenSlhDsaSha2_256s() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHA2_256S);
        }
    }

    /** wolfCrypt SLH-DSA-SHA2-256f key pair generator. */
    public static final class wcKeyPairGenSlhDsaSha2_256f
        extends WolfCryptKeyPairGenerator {
        /** Create new wcKeyPairGenSlhDsaSha2_256f object */
        public wcKeyPairGenSlhDsaSha2_256f() {
            super(KeyType.WC_SLH_DSA, SlhDsa.SLH_DSA_SHA2_256F);
        }
    }

    /**
     * wolfCrypt ML-KEM (FIPS 203) generic key pair generator. Accepts any of
     * the three ML-KEM parameter sets via
     * {@code initialize(NamedParameterSpec)} or
     * {@code initialize(WolfPQCParameterSpec)}. Defaults to ML-KEM-768 so we
     * match the JDK reference implementation default.
     */
    public static final class wcKeyPairGenMlKem
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlKem object
         */
        public wcKeyPairGenMlKem() {
            super(KeyType.WC_ML_KEM);
        }
    }

    /**
     * wolfCrypt ML-KEM-512 key pair generator.
     */
    public static final class wcKeyPairGenMlKem512
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlKem512 object
         */
        public wcKeyPairGenMlKem512() {
            super(KeyType.WC_ML_KEM, MlKem.ML_KEM_512);
        }
    }

    /**
     * wolfCrypt ML-KEM-768 key pair generator.
     */
    public static final class wcKeyPairGenMlKem768
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlKem768 object
         */
        public wcKeyPairGenMlKem768() {
            super(KeyType.WC_ML_KEM, MlKem.ML_KEM_768);
        }
    }

    /**
     * wolfCrypt ML-KEM-1024 key pair generator.
     */
    public static final class wcKeyPairGenMlKem1024
        extends WolfCryptKeyPairGenerator {
        /**
         * Create new wcKeyPairGenMlKem1024 object
         */
        public wcKeyPairGenMlKem1024() {
            super(KeyType.WC_ML_KEM, MlKem.ML_KEM_1024);
        }
    }
}

