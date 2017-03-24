/* WolfCryptKeyAgreement.java
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidParameterException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.Ecc;

/**
 * wolfCrypt JCE Key Agreement wrapper
 *
 * @author wolfSSL
 * @version 1.0, March 2017
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

    private int  primeLen  = 0;
    private int  fieldSize = 0;

    private KeyAgreeType type;
    private EngineState state = EngineState.WC_UNINITIALIZED;

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

        this.state = EngineState.WC_INIT_DONE;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
        throws InvalidKeyException, IllegalStateException {

        byte[] pubKey = null;

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
                    secretLen = (int)Math.ceil(this.fieldSize / 8.0);
                    tmp = new byte[secretLen];
                    break;
            }

            len = engineGenerateSecret(tmp, 0);

            /* may need to truncate */
            secret = new byte[len];
            System.arraycopy(tmp, 0, secret, 0, len);

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

        int ret    = 0;
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

                tmp = this.dh.makeSharedSecret(this.dh);
                
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
                this.ecPrivate.importPrivate(priv, null);
                zeroArray(priv);

                this.state = EngineState.WC_PRIVKEY_DONE;

                break;
        };

        if (tmp != null) {
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
        DHPrivateKey dhKey  = null;

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

    private void wcInitECDHParams(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        int fieldSz = 0;
        ECPrivateKey ecKey;

        if (!(key instanceof ECPrivateKey)) {
            throw new InvalidKeyException(
                "Key must be of type ECPrivateKey");
        }
        ecKey = (ECPrivateKey)key;

        /* try to extract field size from AlgorithmParameterSpec if given */
        if (params != null) {

            if (!(params instanceof ECParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                    "AlgorithmParameterSpec is not of type ECParameterSpec");
            }

            fieldSz =
                ((ECParameterSpec)params).getCurve().getField().getFieldSize();

            if (fieldSz != 0) {
                this.fieldSize = fieldSz;

            } else {
                throw new InvalidParameterException(
                    "AlgorithmParameterSpec does not include required " +
                    "ECC curve field size");
            }
        }

        /* try to import params from key */
        fieldSz = ecKey.getParams().getCurve().getField().getFieldSize();

        if (fieldSz != 0) {
            this.fieldSize = fieldSz;

        } else {
            throw new InvalidKeyException(
                "Key must include ECC curve parameters when not called " +
                "with explicit AlgorithmParameterSpec");
        }

        /* import private */
        ecKey = (ECPrivateKey)key;
        this.ecPrivate.importPrivate(ecKey.getS().toByteArray(), null);
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

        wcKeyAgreementInit(key, params, random);

        this.state = EngineState.WC_PRIVKEY_DONE;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random)
        throws InvalidKeyException {

        try {
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

    @Override
    protected void finalize() throws Throwable {
        try {

            switch (this.type) {
                case WC_DH:
                    this.dh.releaseNativeStruct();
                    break;

                case WC_ECDH:
                    this.ecPublic.releaseNativeStruct();
                    this.ecPrivate.releaseNativeStruct();
                    break;
            }

        } finally {
            super.finalize();
        }
    }

    public static final class wcDH extends WolfCryptKeyAgreement {
        public wcDH() {
            super(KeyAgreeType.WC_DH);
        }
    }

    public static final class wcECDH extends WolfCryptKeyAgreement {
        public wcECDH() {
            super(KeyAgreeType.WC_ECDH);
        }
    }
}

