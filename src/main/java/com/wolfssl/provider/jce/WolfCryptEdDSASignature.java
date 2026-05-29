/* WolfCryptEdDSASignature.java
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

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE SignatureSpi implementation for Ed25519 (EdDSA).
 *
 * Ed25519 accumulates the entire message internally — there is no separate
 * digest object. The algorithm is identified by the JCA name "Ed25519"
 * (also accessible as "EdDSA" for signature objects).
 *
 * Usage:
 *   Signature sig = Signature.getInstance("Ed25519");
 *   sig.initSign(privateKey);
 *   sig.update(message);
 *   byte[] signature = sig.sign();
 */
public class WolfCryptEdDSASignature extends SignatureSpi {

    /** Buffered message bytes accumulated via update(). */
    private final ByteArrayOutputStream msgBuf = new ByteArrayOutputStream();

    /** Native Ed25519 key object. */
    private Ed25519 ed = null;

    /** True when initialized for signing, false for verification. */
    private boolean signingMode = false;

    /** Lock around ed and signingMode. */
    private final Object keyLock = new Object();

    @Override
    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException {

        if (!(privateKey instanceof WolfCryptEdDSAPrivateKey)) {
            throw new InvalidKeyException(
                "Key must be a WolfCryptEdDSAPrivateKey; got: " +
                privateKey.getClass().getName());
        }

        WolfCryptEdDSAPrivateKey edKey = (WolfCryptEdDSAPrivateKey) privateKey;
        byte[] seed = edKey.getRawSeed();
        if (seed == null) {
            throw new InvalidKeyException("Key has been destroyed");
        }

        synchronized (keyLock) {
            releaseKey();
            try {
                ed = new Ed25519();
                ed.importPrivateOnly(seed);
            } catch (WolfCryptException e) {
                releaseKey();
                throw new InvalidKeyException(
                    "Failed to import Ed25519 private key: " + e.getMessage(),
                    e);
            } finally {
                Arrays.fill(seed, (byte) 0);
            }
            signingMode = true;
        }

        msgBuf.reset();

        log("initialized for signing");
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException {

        if (!(publicKey instanceof WolfCryptEdDSAPublicKey)) {
            throw new InvalidKeyException(
                "Key must be a WolfCryptEdDSAPublicKey; got: " +
                publicKey.getClass().getName());
        }

        WolfCryptEdDSAPublicKey edKey = (WolfCryptEdDSAPublicKey) publicKey;
        byte[] pub = edKey.getRawPublicKey();
        if (pub == null) {
            throw new InvalidKeyException("Key has been destroyed");
        }

        synchronized (keyLock) {
            releaseKey();
            try {
                ed = new Ed25519();
                ed.importPublic(pub);
            } catch (WolfCryptException e) {
                releaseKey();
                throw new InvalidKeyException(
                    "Failed to import Ed25519 public key: " + e.getMessage(),
                    e);
            }
            signingMode = false;
        }

        msgBuf.reset();

        log("initialized for verification");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        msgBuf.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException {
        msgBuf.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        synchronized (keyLock) {
            if (ed == null || !signingMode) {
                throw new SignatureException(
                    "Signature not initialized for signing");
            }

            byte[] msg = msgBuf.toByteArray();
            msgBuf.reset();

            try {
                byte[] sig = ed.sign_msg(msg);
                log("signed " + msg.length + " bytes, signature length: " +
                    (sig != null ? sig.length : 0));
                return sig;
            } catch (WolfCryptException e) {
                throw new SignatureException(
                    "Ed25519 sign failed: " + e.getMessage(), e);
            }
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        synchronized (keyLock) {
            if (ed == null || signingMode) {
                throw new SignatureException(
                    "Signature not initialized for verification");
            }

            byte[] msg = msgBuf.toByteArray();
            msgBuf.reset();

            try {
                boolean result = ed.verify_msg(msg, sigBytes);
                log("verified " + msg.length + " bytes: " + result);
                return result;
            } catch (WolfCryptException e) {
                /* wolfSSL throws on verification failure in some builds;
                 * treat as false rather than propagating the exception. */
                log("verify_msg threw (treating as false): " + e.getMessage());
                return false;
            }
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
            "Ed25519 signature does not accept algorithm parameters");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {
        throw new InvalidParameterException(
            "Ed25519 signature does not accept parameters");
    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {
        return null;
    }

    @SuppressWarnings({"deprecation", "removal"})
    @Override
    protected void finalize() throws Throwable {
        try {
            releaseKey();
        } finally {
            super.finalize();
        }
    }

    private void releaseKey() {
        if (ed != null) {
            ed.releaseNativeStruct();
            ed = null;
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[WolfCryptEdDSASignature] " + msg);
    }
}
