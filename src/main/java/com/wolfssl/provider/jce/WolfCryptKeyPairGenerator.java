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
        WC_DH
    }

    private KeyType type = null;

    private String curve = null;
    private int keysize = 0;
    private long publicExponent = 0;

    private byte[] dhP = null;
    private byte[] dhG = null;

    private Rng rng = null;

    /* Lock around Rng access */
    private final Object rngLock = new Object();

    /* for debug logging */
    private String algString;

    private WolfCryptKeyPairGenerator(KeyType type) {

        this.type = type;

        /* Set default parameters for RSA key generation */
        if (type == KeyType.WC_RSA || type == KeyType.WC_RSA_PSS) {
            this.keysize = 2048;  /* Default RSA key size */
            this.publicExponent = Rsa.getDefaultRsaExponent();

            /* Initialize RNG for default key generation */
            synchronized (rngLock) {
                if (this.rng == null) {
                    this.rng = new Rng();
                    this.rng.init();
                }
            }
        }

        /* Set default parameters for ECC key generation */
        if (type == KeyType.WC_ECC) {
            /* Default to 256-bit ECC */
            this.keysize = 32;

            /* Initialize RNG for default key generation */
            synchronized (rngLock) {
                if (this.rng == null) {
                    this.rng = new Rng();
                    this.rng.init();
                }
            }
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

            /* Initialize RNG for default key generation */
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

                if (this.dhP != null) {
                    log("init with spec, prime len: " + this.dhP.length);
                }

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

                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        rsaPriv = (RSAPrivateKey)kf.generatePrivate(privSpec);
                        rsaPub  = (RSAPublicKey)kf.generatePublic(pubSpec);

                        if (this.type == KeyType.WC_RSA_PSS) {
                            /* Try to use RSASSA-PSS KeyFactory if available.
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
                                rsaPriv = (RSAPrivateKey)pssKf
                                    .generatePrivate(privCrtSpec);
                                rsaPub  = (RSAPublicKey)pssKf
                                    .generatePublic(pubKeySpec);
                            } catch (NoSuchAlgorithmException e) {
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
                        KeyFactory kf = KeyFactory.getInstance("EC");

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
                    KeyFactory kf = KeyFactory.getInstance("DH");

                    dhPriv  = (DHPrivateKey)kf.generatePrivate(privSpec);
                    dhPub   = (DHPublicKey)kf.generatePublic(pubSpec);

                    pair = new KeyPair(dhPub, dhPriv);

                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage());
                }

                log("generated DH KeyPair");

                break;

            default:
                throw new RuntimeException(
                    "Unsupported algorithm for key generation: " + this.type);
        }

        return pair;
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
}

