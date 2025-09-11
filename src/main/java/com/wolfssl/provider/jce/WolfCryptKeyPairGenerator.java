/* WolfCryptKeyPairGenerator.java
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

import java.math.BigInteger;

import java.security.KeyPairGeneratorSpi;
import java.security.KeyPair;
import java.security.InvalidAlgorithmParameterException;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
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

/**
 * wolfCrypt JCE KeyPairGenerator wrapper class
 */
public class WolfCryptKeyPairGenerator extends KeyPairGeneratorSpi {

    enum KeyType {
        WC_RSA,
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
        if (type == KeyType.WC_RSA) {
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

        if (WolfCryptDebug.DEBUG) {
            algString = typeToString(type);
        }
    }

    @Override
    public synchronized void initialize(int keysize, SecureRandom random) {

        if (type == KeyType.WC_DH) {
            throw new RuntimeException(
                "wolfJCE requires users to explicitly set DH parameters, " +
                "please call initialize() with DHParameterSpec");
        }

        if (type == KeyType.WC_ECC) {
            /* ECC keysize from Java is bits, but wolfSSL expects bytes */
            this.keysize = (keysize + 7) / 8;
        } else {
            this.keysize = keysize;
        }

        if (type == KeyType.WC_RSA) {
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


        switch (this.type) {

            case WC_RSA:

                if (keysize == 0) {
                    throw new RuntimeException(
                        "keysize is 0, please set before generating key");
                }

                RSAPrivateKey rsaPriv = null;
                RSAPublicKey  rsaPub  = null;

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

                    zeroArray(privDer);
                    zeroArray(pubDer);
                    rsa.releaseNativeStruct();

                    KeyFactory kf = KeyFactory.getInstance("RSA");

                    rsaPriv = (RSAPrivateKey)kf.generatePrivate(privSpec);
                    rsaPub  = (RSAPublicKey)kf.generatePublic(pubSpec);

                    pair = new KeyPair(rsaPub, rsaPriv);

                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                log("generated RSA KeyPair");

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
                    throw new RuntimeException(
                        "No DH parameters set, wolfJCE requires users to " +
                        "set through KeyPairGenerator.initialize()");
                }

                Dh dh = new Dh();

                /* load params */
                dh.setParams(dhP, dhG);

                /* make key */
                synchronized (rngLock) {
                    dh.makeKey(this.rng);
                }

                privSpec = new DHPrivateKeySpec(
                                new BigInteger(dh.getPrivateKey()),
                                new BigInteger(dhP),
                                new BigInteger(dhG));

                pubSpec = new DHPublicKeySpec(
                                new BigInteger(dh.getPublicKey()),
                                new BigInteger(dhP),
                                new BigInteger(dhG));

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

