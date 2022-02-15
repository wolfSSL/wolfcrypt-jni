/* WolfCryptKeyPairGenerator.java
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

import java.math.BigInteger;

import java.security.KeyPairGeneratorSpi;
import java.security.KeyPair;
import java.security.InvalidAlgorithmParameterException;

import java.security.SecureRandom;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.Rng;

import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfCrypt JCE KeyPairGenerator wrapper class
 */
public class WolfCryptKeyPairGenerator extends KeyPairGeneratorSpi {

    enum KeyType {
        WC_ECC,
        WC_DH
    }

    private KeyType type = null;

    private String curve = null;
    private int keysize = 0;

    private byte[] dhP = null;
    private byte[] dhG = null;

    private Rng rng = null;

    /* for debug logging */
    private WolfCryptDebug debug;
    private String algString;

    private WolfCryptKeyPairGenerator(KeyType type) {

        this.type = type;

        rng = new Rng();
        rng.init();

        if (debug.DEBUG)
            algString = typeToString(type);
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {

        if (type == KeyType.WC_DH) {
            throw new RuntimeException(
                "wolfJCE requires users to explicitly set DH parameters, " +
                "please call initialize() with DHParameterSpec");
        }

        this.keysize = keysize;

        if (debug.DEBUG)
            log("init with keysize: " + keysize);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidAlgorithmParameterException {

        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameterSpec must not be null");
        }

        switch (type) {

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

                if (debug.DEBUG)
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

                if ((this.dhP != null) && debug.DEBUG)
                    log("init with spec, prime len: " + this.dhP.length);

                break;

            default:
                throw new RuntimeException(
                    "Unsupported algorithm for key generation");
        }
    }

    @Override
    public KeyPair generateKeyPair() {

        KeyPair pair = null;

        byte[] privDer = null;
        byte[] pubDer  = null;

        KeySpec privSpec = null;
        KeySpec pubSpec  = null;


        switch (this.type) {

            case WC_ECC:

                if (keysize == 0) {
                    throw new RuntimeException(
                        "Keysize is 0, please set before generating key");
                }

                ECPrivateKey eccPriv = null;
                ECPublicKey  eccPub  = null;

                Ecc ecc = new Ecc();

                if (this.curve == null) {
                    ecc.makeKey(rng, this.keysize);
                } else {
                    ecc.makeKeyOnCurve(rng, this.keysize, this.curve);
                }

                /* private key */
                privDer = ecc.privateKeyEncodePKCS8();
                privSpec = new PKCS8EncodedKeySpec(privDer);

                /* public key */
                pubDer = ecc.publicKeyEncode();
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
                    throw new RuntimeException(e.getMessage());
                }

                if (debug.DEBUG)
                    log("generated KeyPair");

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
                dh.makeKey(rng);

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

                if (debug.DEBUG)
                    log("generated KeyPair");

                break;

            default:
                throw new RuntimeException(
                    "Unsupported algorithm for key generation");
        }

        return pair;
    }

    private String typeToString(KeyType type) {
        switch (type) {
            case WC_ECC:
                return "ECC";
            case WC_DH:
                return "DH";
            default:
                return "None";
        }
    }

    private void log(String msg) {
        debug.print("[KeyPairGenerator, " + algString + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {
            if (this.rng != null) {
                rng.free();
                rng.releaseNativeStruct();
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

