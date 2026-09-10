/* WolfCryptEdDSASignature.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import com.wolfssl.wolfcrypt.Ed25519;
import com.wolfssl.wolfcrypt.Ed448;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE EdDSA (Ed25519 / Ed448, RFC 8032) signature provider.
 *
 * <p>EdDSA signs the whole message (twice, internally). This class
 * buffers the message in a ByteArrayOutputStream during engineUpdate and
 * consumes it on engineSign / engineVerify. Native streaming verify is not
 * usable here, it needs the signature before the message and SignatureSpi
 * supplies it last.</p>
 *
 * <p>Signature variant follows the JDK EdDSAParameterSpec semantics: with
 * no parameters set the pure variant is used. If a context is present
 * (even empty), this selects Ed25519ctx for Ed25519 and is passed to Ed448.
 * Setting 'prehash = true' selects Ed25519ph / Ed448ph. Parameters are set
 * with WolfCryptEdDSAParameterSpec, the JDK EdDSAParameterSpec (JDK 15+), or
 * WolfCryptContextParameterSpec (context only). Note that
 * WolfCryptContextParameterSpec always carries a context (an empty one when
 * built with null) and leaves prehash as previously set, so with prehash
 * off it selects Ed25519ctx. Use WolfCryptEdDSAParameterSpec(false) for
 * pure Ed25519.</p>
 *
 * <p>Nested classes restrict the accepted curve: wcEd25519, wcEd448, or the
 * generic wcEdDSA, which takes the curve from the key.</p>
 */
public abstract class WolfCryptEdDSASignature extends SignatureSpi {

    /** Curve this Signature is locked to, or null for any */
    private final WolfCryptEdDSACurve lockedCurve;

    /** Curve of the key loaded by the last init, null before init */
    private WolfCryptEdDSACurve curve = null;

    /** Native key (one of the two is non-null after init) */
    private Ed25519 key25519 = null;
    private Ed448 key448 = null;

    /** True when initialized for sign, false for verify */
    private boolean signing = false;

    /** Pre-hash variant selected */
    private boolean prehash = false;

    /** Context bytes, null when absent */
    private byte[] context = null;

    /* Max size for backing array used by reset, larger buffers are
     * reallocated */
    private static final int BUFFER_RETAIN_MAX = 1024 * 1024;

    /** Buffered message bytes */
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /** True once update() has been called for the current operation */
    private boolean updated = false;

    /**
     * Create new WolfCryptEdDSASignature with optional locked curve.
     *
     * @param lockedCurve curve to require, or null for any
     */
    WolfCryptEdDSASignature(WolfCryptEdDSACurve lockedCurve) {
        this.lockedCurve = lockedCurve;
    }

    /**
     * Generic EdDSA Signature, accepts Ed25519 and Ed448 keys.
     */
    public static final class wcEdDSA extends WolfCryptEdDSASignature {
        /** Default constructor. */
        public wcEdDSA() {
            super(null);
        }
    }

    /** Ed25519 only Signature */
    public static final class wcEd25519 extends WolfCryptEdDSASignature {
        /** Default constructor. */
        public wcEd25519() {
            super(WolfCryptEdDSACurve.ED25519);
        }
    }

    /** Ed448 only Signature */
    public static final class wcEd448 extends WolfCryptEdDSASignature {
        /** Default constructor. */
        public wcEd448() {
            super(WolfCryptEdDSACurve.ED448);
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[EdDSA Signature] " + msg);
    }

    /**
     * Release native key loaded by the previous init, if any.
     */
    private void releaseKey() {
        if (this.key25519 != null) {
            this.key25519.releaseNativeStruct();
            this.key25519 = null;
        }
        if (this.key448 != null) {
            this.key448.releaseNativeStruct();
            this.key448 = null;
        }
        this.curve = null;
    }

    /**
     * Clear the message buffer. Reallocate it when the prior message was
     * large so the high water mark backing array is not kept for the life of
     * this Signature object.
     */
    private void resetBuffer() {
        if (this.buffer.size() > BUFFER_RETAIN_MAX) {
            this.buffer = new ByteArrayOutputStream();
        }
        else {
            this.buffer.reset();
        }
        this.updated = false;
    }

    private void checkCurveMatchesLocked(WolfCryptEdDSACurve keyCurve)
        throws InvalidKeyException {

        if (this.lockedCurve != null && keyCurve != this.lockedCurve) {
            throw new InvalidKeyException(
                "Key curve does not match Signature: expected " +
                this.lockedCurve.getJcaName() + ", got " +
                keyCurve.getJcaName());
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException {

        byte[] raw;
        WolfCryptEdDSAPublicKey pub;

        /* Drop previous key first. A failed init must leave the object
         * uninitialized rather than keyed with the old key */
        releaseKey();
        resetBuffer();

        /* Public key holds no secrets, temporary wolfJCE copy of a foreign
         * key is left to the garbage collector */
        pub = WolfCryptEdDSAKeyFactory.toWolfPublicKey(publicKey);
        checkCurveMatchesLocked(pub.curve());

        raw = pub.getRawPublicKey();
        if (raw == null) {
            throw new InvalidKeyException("PublicKey has been destroyed");
        }

        try {
            if (pub.curve() == WolfCryptEdDSACurve.ED25519) {
                Ed25519 k = new Ed25519();
                try {
                    /* untrusted import validates the point */
                    k.importPublicEx(raw, false);
                    this.key25519 = k;
                    k = null;
                }
                finally {
                    if (k != null) {
                        k.releaseNativeStruct();
                    }
                }
            }
            else {
                Ed448 k = new Ed448();
                try {
                    k.importPublicEx(raw, false);
                    this.key448 = k;
                    k = null;
                }
                finally {
                    if (k != null) {
                        k.releaseNativeStruct();
                    }
                }
            }
        }
        catch (WolfCryptException | IllegalStateException e) {
            throw new InvalidKeyException(
                "Failed to import EdDSA public key: " + e.getMessage(), e);
        }

        this.curve = pub.curve();
        this.signing = false;

        log("init verify with " + this.curve.getJcaName() + " key");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException {

        byte[] rawPriv;
        byte[] rawPub;
        WolfCryptEdDSAPrivateKey priv;

        /* Drop previous key first. A failed init must leave the object
         * uninitialized rather than keyed with the old key */
        releaseKey();
        resetBuffer();

        priv = WolfCryptEdDSAKeyFactory.toWolfPrivateKey(privateKey);
        /* A foreign key was decoded into a new wolfJCE key that holds its
         * own copy of the raw private key. Destroy that copy once the native
         * key is loaded. */
        boolean temp = (priv != privateKey);
        try {
            checkCurveMatchesLocked(priv.curve());
        }
        catch (InvalidKeyException e) {
            if (temp) {
                priv.destroy();
            }
            throw e;
        }

        rawPriv = priv.getRawPrivateKey();
        rawPub = priv.getRawPublicKey();
        if (rawPriv == null || rawPub == null) {
            WolfCryptEdDSACurve.zero(rawPriv);
            if (temp) {
                priv.destroy();
            }
            throw new InvalidKeyException("PrivateKey has been destroyed");
        }

        try {
            if (priv.curve() == WolfCryptEdDSACurve.ED25519) {
                Ed25519 k = new Ed25519();
                try {
                    /* untrusted import proves pub matches priv */
                    k.importPrivateEx(rawPriv, rawPub, false);
                    this.key25519 = k;
                    k = null;
                }
                finally {
                    if (k != null) {
                        k.releaseNativeStruct();
                    }
                }
            }
            else {
                Ed448 k = new Ed448();
                try {
                    k.importPrivateEx(rawPriv, rawPub, false);
                    this.key448 = k;
                    k = null;
                }
                finally {
                    if (k != null) {
                        k.releaseNativeStruct();
                    }
                }
            }
        }
        catch (WolfCryptException | IllegalStateException e) {
            throw new InvalidKeyException(
                "Failed to import EdDSA private key: " + e.getMessage(), e);
        }
        finally {
            WolfCryptEdDSACurve.zero(rawPriv);
            if (temp) {
                priv.destroy();
            }
        }

        this.curve = priv.curve();
        this.signing = true;

        log("init sign with " + this.curve.getJcaName() + " key");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {

        if (this.curve == null) {
            throw new SignatureException("Signature not initialized");
        }

        this.updated = true;
        this.buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException {

        if (this.curve == null) {
            throw new SignatureException("Signature not initialized");
        }

        if (b == null || off < 0 || len < 0 || len > b.length - off) {
            throw new SignatureException("Invalid update arguments");
        }

        this.updated = true;
        this.buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {

        if (this.curve == null || !this.signing) {
            throw new SignatureException(
                "Signature not initialized for signing");
        }

        try {
            byte[] msg = this.buffer.toByteArray();

            if (this.curve == WolfCryptEdDSACurve.ED25519) {
                if (this.prehash) {
                    return this.key25519.signPh(msg, this.context);
                }
                if (this.context != null) {
                    return this.key25519.signCtx(msg, this.context);
                }
                return this.key25519.sign(msg);
            }

            if (this.prehash) {
                return this.key448.signPh(msg, this.context);
            }

            return this.key448.sign(msg, this.context);
        }
        catch (WolfCryptException | IllegalStateException |
               IllegalArgumentException e) {
            throw new SignatureException("EdDSA sign failed: " +
                e.getMessage(), e);
        }
        finally {
            resetBuffer();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException {

        if (this.curve == null || this.signing) {
            throw new SignatureException(
                "Signature not initialized for verification");
        }

        if (sigBytes == null) {
            throw new SignatureException("Signature bytes are null");
        }

        try {
            byte[] msg = this.buffer.toByteArray();

            /* wrong-length signatures return false from the wrapper */
            if (this.curve == WolfCryptEdDSACurve.ED25519) {
                if (this.prehash) {
                    return this.key25519.verifyPh(sigBytes, msg, this.context);
                }
                if (this.context != null) {
                    return this.key25519.verifyCtx(sigBytes, msg, this.context);
                }
                return this.key25519.verify(sigBytes, msg);
            }

            if (this.prehash) {
                return this.key448.verifyPh(sigBytes, msg, this.context);
            }

            return this.key448.verify(sigBytes, msg, this.context);
        }
        catch (WolfCryptException | IllegalStateException |
               IllegalArgumentException e) {
            throw new SignatureException("EdDSA verify failed: " +
                e.getMessage(), e);
        }
        finally {
            resetBuffer();
        }
    }

    /**
     * Select the signature variant.
     *
     * Accepts WolfCryptEdDSAParameterSpec, the JDK 15+
     * java.security.spec.EdDSAParameterSpec, or WolfCryptContextParameterSpec.
     * May be called before or after init, but not after data update().
     *
     * @param params parameter spec
     *
     * @throws InvalidAlgorithmParameterException if the spec type is not
     *         supported, the context exceeds 255 bytes, or data has already
     *         been buffered
     */
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {

        boolean newPrehash;
        byte[] newContext;

        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameterSpec is null");
        }

        if (this.updated) {
            throw new InvalidAlgorithmParameterException(
                "Cannot set parameters after update()");
        }

        if (params instanceof WolfCryptEdDSAParameterSpec) {
            WolfCryptEdDSAParameterSpec spec =
                (WolfCryptEdDSAParameterSpec) params;
            newPrehash = spec.isPrehash();
            newContext = spec.getContext();
        }
        else if (params instanceof WolfCryptContextParameterSpec) {
            newPrehash = this.prehash;
            newContext = ((WolfCryptContextParameterSpec) params).getContext();
        }
        else if (WolfEdECJdkCompat.isEdDSAParameterSpec(params)) {
            try {
                newPrehash =
                    WolfEdECJdkCompat.edDSAParameterSpecIsPrehash(params);
                newContext =
                    WolfEdECJdkCompat.edDSAParameterSpecGetContext(params);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidAlgorithmParameterException(e.getMessage(),
                    e);
            }
        }
        else {
            throw new InvalidAlgorithmParameterException(
                "Unsupported AlgorithmParameterSpec: " +
                params.getClass().getName() + " (expected " +
                "WolfCryptEdDSAParameterSpec, EdDSAParameterSpec or " +
                "WolfCryptContextParameterSpec)");
        }

        if (newContext != null &&
            newContext.length > WolfCryptEdDSAParameterSpec.MAX_CONTEXT_LEN) {
            throw new InvalidAlgorithmParameterException(
                "Context length exceeds " +
                WolfCryptEdDSAParameterSpec.MAX_CONTEXT_LEN + " bytes");
        }

        this.prehash = newPrehash;
        this.context = newContext;

        log("set parameters: prehash=" + newPrehash + ", context=" +
            ((newContext == null) ? "absent" : newContext.length + " bytes"));
    }

    /**
     * Always returns null. EdDSA has no encoded algorithm parameters (RFC
     * 8410), wolfJCE registers no EdDSA AlgorithmParameters service, so
     * prehash and context set through engineSetParameter() are not reported
     * here. Configure a verifier with the same AlgorithmParameterSpec that was
     * given to the signer.
     *
     * @return null
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    /**
     * Set a named parameter. Not supported, EdDSA parameters are set through
     * an AlgorithmParameterSpec.
     *
     * @param param parameter name
     * @param value parameter value
     *
     * @throws InvalidParameterException always
     *
     * @deprecated unsupported, use
     *             {@link #engineSetParameter(AlgorithmParameterSpec)}
     */
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "Use setParameter(AlgorithmParameterSpec)");
    }

    /**
     * Get a named parameter. Not supported, EdDSA does not expose named params.
     *
     * @param param parameter name
     *
     * @return never returns normally
     *
     * @throws InvalidParameterException always
     *
     * @deprecated unsupported
     */
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "EdDSA does not expose named parameters");
    }
}
