/* WolfCryptKeyAgreement.java
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
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidParameterException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.Ecc;

import com.wolfssl.provider.jce.WolfCryptDebug;

/**
 * wolfCrypt JCE Key Agreement wrapper
 */
public class WolfCryptKeyAgreement extends KeyAgreementSpi {

    enum KeyAgreeType {
        WC_DH,
        WC_ECDH
    }

    enum EngineState {
        WC_UNINITIALIZED,
        WC_INIT_DONE,
        WC_PRIVKEY_DONE,
        WC_PUBKEY_DONE
    }

    private Dh dh = null;
    private Ecc ecPublic  = null;
    private Ecc ecPrivate = null;

    private int primeLen  = 0;
    private int curveSize = 0;
    private String curveName = null;

    private KeyAgreeType type;
    private EngineState state = EngineState.WC_UNINITIALIZED;
    private String algString;

    private WolfCryptKeyAgreement(KeyAgreeType type) {

        this.type = type;

        switch (type) {

            case WC_DH:
                dh = new Dh();
                break;

            case WC_ECDH:
                ecPublic  = new Ecc();
                ecPrivate = new Ecc();
                break;
        };

        if (WolfCryptDebug.DEBUG) {
            algString = typeToString(type);
        }

        this.state = EngineState.WC_INIT_DONE;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
        throws InvalidKeyException, IllegalStateException {

        byte[] pubKey = null;

        log("engineDoPhase, lastPhase: " + lastPhase);

        if (this.state != EngineState.WC_PRIVKEY_DONE)
            throw new IllegalStateException(
                "KeyAgreement object must be initialized with " +
                "private key before calling doPhase");

        if (lastPhase == false) {
            throw new IllegalStateException(
                "wolfJCE KeyAgreement currently only supports "  +
                "two parties and thus one single doPhase call. " +
                "lastPhase must be set to true.");
        }

        switch (this.type) {
            case WC_DH:
                if (!(key instanceof DHPublicKey)) {
                    throw new InvalidKeyException(
                        "Key must be of type DHPublicKey");
                }

                pubKey = ((DHPublicKey)key).getY().toByteArray();
                if (pubKey == null) {
                    throw new InvalidKeyException(
                        "Failed to get DH public key from Key object");
                }

                this.dh.setPublicKey(pubKey);

                break;

            case WC_ECDH:
                if (!(key instanceof ECPublicKey)) {
                    throw new InvalidKeyException(
                        "Key must be of type ECPublicKey");
                }

                pubKey = key.getEncoded();
                if (pubKey == null) {
                    throw new InvalidKeyException(
                        "Failed to get ECC public key from Key object");
                }

                this.ecPublic.publicKeyDecode(pubKey);

                break;
        };

        zeroArray(pubKey);
        this.state = EngineState.WC_PUBKEY_DONE;

        return null;
    }

    @Override
    protected byte[] engineGenerateSecret()
        throws IllegalStateException {

        int len       = 0;
        int secretLen = 0;

        byte tmp[]    = null;
        byte secret[] = null;

        try {

            switch (this.type) {
                case WC_DH:
                    tmp = new byte[this.primeLen];
                    break;
                case WC_ECDH:
                    secretLen = this.curveSize;
                    tmp = new byte[secretLen];
                    break;
            }

            len = engineGenerateSecret(tmp, 0);

            log("generated secret, len: " + len);

            /* may need to truncate */
            secret = new byte[len];
            System.arraycopy(tmp, 0, secret, 0, len);

            /* DH shared secrets can vary in length depending on if they are
             * padded or not at the beginning with zero bytes to make a total
             * output size matching the prime length.
             *
             * Native wolfCrypt does not prepend zero bytes to DH shared
             * secrets, following RFC 5246 (8.1.2) which instructs to strip
             * leading zero bytes.
             *
             * Sun KeyAgreement DH implementations as of after Java 8
             * prepend zero bytes if total length is not equal to prime length.
             * This was changed with OpenJDK bug fix JDK-7146728.
             *
             * BouncyCastle also behaves the same way, prepending zero bytes
             * if total secret size is not prime length. This follows
             * RFC 2631 (2.1.2).
             *
             * To match Sun and BC behavior, we will follow the same here if
             * running on a Java version later than Java 8.
             */
            if (this.type == KeyAgreeType.WC_DH) {
                tmp = new byte[this.primeLen];
                Arrays.fill(tmp, (byte)0);
                System.arraycopy(secret, 0, tmp,
                    tmp.length - secret.length, secret.length);
                secret = tmp.clone();
            }

        } catch (ShortBufferException e) {
            zeroArray(tmp);
            zeroArray(secret);
            throw new RuntimeException(
                "Buffer error when generating shared secret, " +
                "input buffer too small");
        }

        zeroArray(tmp);

        return secret;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
        throws IllegalStateException, ShortBufferException {

        int  ret   = 0;
        byte tmp[] = null;
        long sz[]  = null;

        if (this.state != EngineState.WC_PUBKEY_DONE)
            throw new IllegalStateException(
                "KeyAgreement object must be initialized with init() " +
                "and doPhase() before generating a shared secret");

        if (sharedSecret == null) {
            throw new ShortBufferException("Input buffer is null");
        }

        switch (this.type) {
            case WC_DH:

                if ((sharedSecret.length - offset) < this.primeLen) {
                    throw new ShortBufferException(
                        "Input buffer too small when generating " +
                        "shared secret");
                }

                /* public key has been stored inside this.dh already */
                tmp = this.dh.makeSharedSecret();
                if (tmp == null) {
                    throw new RuntimeException("Error when creating DH " +
                            "shared secret");
                }

                if ((sharedSecret.length - offset) < tmp.length) {
                    zeroArray(tmp);
                    throw new ShortBufferException(
                        "Output buffer too small when generating " +
                        "DH shared secret");
                }

                /* copy array back to output offset */
                System.arraycopy(tmp, 0, sharedSecret, offset, tmp.length);

                /* reset state, using same private info and alg params */
                this.state = EngineState.WC_PRIVKEY_DONE;

                break;

            case WC_ECDH:

                tmp = this.ecPrivate.makeSharedSecret(this.ecPublic);
                if (tmp == null) {
                    throw new RuntimeException("Error when creating ECDH " +
                            "shared secret");
                }

                if ((sharedSecret.length - offset) < tmp.length) {
                    zeroArray(tmp);
                    throw new ShortBufferException(
                        "Output buffer too small when generating " +
                        "ECDH shared secret");
                }

                /* copy array back to output ofset */
                System.arraycopy(tmp, 0, sharedSecret, offset, tmp.length);

                /* reset state, using same private info and alg params */
                byte[] priv = this.ecPrivate.exportPrivate();
                if (priv == null) {
                    throw new RuntimeException("Error reseting native " +
                            "wolfCrypt state during ECDH operation");
                }

                this.ecPublic.releaseNativeStruct();
                this.ecPublic = new Ecc();
                this.ecPrivate.releaseNativeStruct();
                this.ecPrivate = new Ecc();
                this.ecPrivate.importPrivateOnCurve(priv, null, this.curveName);
                zeroArray(priv);

                this.state = EngineState.WC_PRIVKEY_DONE;

                break;
        };

        if (tmp != null) {

            log("generated secret, len: " + tmp.length);

            zeroArray(tmp);
            return tmp.length;
        }

        return 0;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
        throws IllegalStateException, NoSuchAlgorithmException,
               InvalidKeyException {

        byte secret[] = engineGenerateSecret();

        log("generating SecretKey for " + algorithm);

        if (algorithm.equals("DES")) {
            return (SecretKey)new DESKeySpec(secret);

        } else if (algorithm.equals("DESede")) {
            return (SecretKey)new DESedeKeySpec(secret);

        } else {
            /* AES and default */
            return new SecretKeySpec(secret, algorithm);
        }
    }

    /**
     * Imports DH parameters into wolfCrypt DH key struct.
     */
    private void wcInitDHParams(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        int ret = 0;
        byte paramP[] = null;
        byte paramG[] = null;
        byte dhPriv[] = null;
        DHPrivateKey dhKey = null;

        if (!(key instanceof DHPrivateKey)) {
            throw new InvalidKeyException(
                "Key must be of type DHPrivateKey");
        }
        dhKey = (DHPrivateKey)key;

        /* try to extract {p,g} from AlgorithmParameterSpec if given */
        if (params != null) {

            if (!(params instanceof DHParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                    "AlgorithmParameterSpec is not of type DHParameterSpec");
            }

            paramP = ((DHParameterSpec)params).getP().toByteArray();
            paramG = ((DHParameterSpec)params).getG().toByteArray();

            if (paramP != null && paramG != null) {

                this.dh.setParams(paramP, paramG);

                primeLen = paramP.length;

                /* prime may have leading zero */
                if (paramP[0] == 0x00) {
                    primeLen--;
                }

                return;

            } else {
                throw new InvalidParameterException(
                    "AlgorithmParameterSpec does not include required " +
                    "DH parameters (P,G)");
            }
        }

        /* try to import params from key */
        paramP = dhKey.getParams().getP().toByteArray();
        paramG = dhKey.getParams().getG().toByteArray();

        if (paramP == null || paramG == null) {
            throw new InvalidKeyException(
                "Key must include DH parameters when not called " +
                "with explicit AlgorithmParameterSpec");
        }

        this.dh.setParams(paramP, paramG);

        primeLen = paramP.length;

        /* prime may have leading zero */
        if (paramP[0] == 0x00) {
            primeLen--;
        }

        /* import private key */
        dhPriv = dhKey.getX().toByteArray();
        if (dhPriv == null) {
            throw new InvalidKeyException(
                "Unable to get DH private key from Key object");
        }

        this.dh.setPrivateKey(dhPriv);
        zeroArray(dhPriv);

        return;
    }

    private void getCurveFromSpec(AlgorithmParameterSpec spec)
        throws InvalidAlgorithmParameterException {

        int fieldSz = 0;

        if (spec instanceof ECGenParameterSpec) {

            ECGenParameterSpec gs = (ECGenParameterSpec)spec;

            /* only have curve name available in spec */
            this.curveName = gs.getName();

            /* look up curve size */
            this.curveSize = Ecc.getCurveSizeFromName(this.curveName);
            log("curveName: " + curveName + ", curveSize: " + curveSize);

        } else if (spec instanceof ECParameterSpec) {

            ECParameterSpec espec = (ECParameterSpec)spec;

            this.curveName = Ecc.getCurveName(espec);
            this.curveSize = Ecc.getCurveSizeFromName(this.curveName);
            log("curveName: " + curveName + ", curveSize: " + curveSize);

        } else {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameterSpec is not of type " +
                "ECParameterSpec or ECGenParameterSpec");
        }
    }

    private void wcInitECDHParams(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        ECPrivateKey ecKey;

        if (!(key instanceof ECPrivateKey)) {
            throw new InvalidKeyException(
                "Key must be of type ECPrivateKey");
        }
        ecKey = (ECPrivateKey)key;

        if (params != null) {
            /* try to extract curve info from AlgorithmParameterSpec */
            getCurveFromSpec(params);

        } else {
            /* otherwise, try to import params from key */
            ECParameterSpec spec = ecKey.getParams();
            getCurveFromSpec(spec);
        }

        /* import private */
        if (this.curveName == null) {
            throw new InvalidAlgorithmParameterException(
                "ECC curve is null, please check algorithm parameters");
        }
        this.ecPrivate.importPrivateOnCurve(ecKey.getS().toByteArray(),
                null, this.curveName);
    }

    /**
     * Imports DH or ECDH parameters into key structure.
     *
     * NOTE: Currently ignores SecureRandom argument. wolfCrypt
     * seeds itself internally.
     */
    private void wcKeyAgreementInit(Key key,
            AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        switch (this.type) {
            case WC_DH:
                wcInitDHParams(key, params);
                break;

            case WC_ECDH:
                wcInitECDHParams(key, params);
                break;
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params,
            SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        log("initialized with key and AlgorithmParameterSpec");

        wcKeyAgreementInit(key, params, random);

        this.state = EngineState.WC_PRIVKEY_DONE;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random)
        throws InvalidKeyException {

        try {
            log("initialized with key");

            wcKeyAgreementInit(key, null, random);

        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }

        this.state = EngineState.WC_PRIVKEY_DONE;
    }

    private void zeroArray(byte[] in) {

        if (in == null)
            return;

        for (int i = 0; i < in.length; i++) {
            in[i] = 0;
        }
    }

    private String typeToString(KeyAgreeType type) {
        switch (type) {
            case WC_DH:
                return "DH";
            case WC_ECDH:
                return "ECDH";
            default:
                return "None";
        }
    }

    private void log(String msg) {
        WolfCryptDebug.print("[KeyAgreement, " + algString + "] " + msg);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        try {

            switch (this.type) {
                case WC_DH:
                    if (this.dh != null)
                        this.dh.releaseNativeStruct();
                    break;

                case WC_ECDH:
                    if (this.ecPublic != null)
                        this.ecPublic.releaseNativeStruct();

                    if (this.ecPrivate != null)
                        this.ecPrivate.releaseNativeStruct();
                    break;
            }

        } finally {
            super.finalize();
        }
    }

    /**
     * wolfJCE DH class
     */
    public static final class wcDH extends WolfCryptKeyAgreement {
        /**
         * Create new wcDH object
         */
        public wcDH() {
            super(KeyAgreeType.WC_DH);
        }
    }

    /**
     * wolfJCE ECDH class
     */
    public static final class wcECDH extends WolfCryptKeyAgreement {
        /**
         * Create new wcECDH object
         */
        public wcECDH() {
            super(KeyAgreeType.WC_ECDH);
        }
    }
}

