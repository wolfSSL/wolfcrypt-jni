/* WolfCryptMlDsaSignature.java
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
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE ML-DSA (FIPS 204) signature provider.
 *
 * <p>ML-DSA is a one-shot signature scheme; this implementation buffers
 * the message in a {@link ByteArrayOutputStream} during
 * {@code engineUpdate} and consumes it on {@code engineSign} /
 * {@code engineVerify} with an empty FIPS 204 context (matching JDK 24
 * JEP 497 semantics).</p>
 *
 * <p>Inner classes restrict the accepted key parameter set:
 * {@link wcMlDsa44}, {@link wcMlDsa65}, {@link wcMlDsa87}, or the
 * generic {@link wcMlDsa} which accepts any ML-DSA level.</p>
 */
public abstract class WolfCryptMlDsaSignature extends SignatureSpi {

    /** Required ML-DSA level for this Signature instance, or
     * {@link MlDsa#ML_DSA_44}/{@code _65}/{@code _87}. Generic
     * implementation uses 0 ("any"). */
    private final int requiredLevel;

    /** Native ML-DSA wrapper (one per init). */
    private MlDsa key = null;

    /** Set true when initialized for sign, false for verify. Undefined
     * before first init call. */
    private boolean signing = false;

    /** Reset keeps the backing array up to this size, larger buffers
     * are reallocated so long-lived (cached/pooled) Signature objects
     * do not pin one large message's worth of memory indefinitely. */
    private static final int BUFFER_RETAIN_MAX = 1024 * 1024;

    /** Buffered message bytes (ML-DSA signs/verifies the whole message,
     * not a streaming hash). */
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /** Lazily-initialized RNG used for sign operations. */
    private Rng rng = null;

    /**
     * Construct with the required ML-DSA level. {@code 0} means "any
     * level" -- used by the generic {@link wcMlDsa} alias.
     *
     * @param requiredLevel 0, 2, 3, or 5
     */
    protected WolfCryptMlDsaSignature(int requiredLevel) {
        this.requiredLevel = requiredLevel;
    }

    /**
     * Generic ML-DSA Signature, accepts keys of any parameter set.
     */
    public static final class wcMlDsa extends WolfCryptMlDsaSignature {
        /** Default constructor. */
        public wcMlDsa() {
            super(0);
        }
    }

    /** ML-DSA-44 only. */
    public static final class wcMlDsa44 extends WolfCryptMlDsaSignature {
        /** Default constructor. */
        public wcMlDsa44() {
            super(MlDsa.ML_DSA_44);
        }
    }

    /** ML-DSA-65 only. */
    public static final class wcMlDsa65 extends WolfCryptMlDsaSignature {
        /** Default constructor. */
        public wcMlDsa65() {
            super(MlDsa.ML_DSA_65);
        }
    }

    /** ML-DSA-87 only. */
    public static final class wcMlDsa87 extends WolfCryptMlDsaSignature {
        /** Default constructor. */
        public wcMlDsa87() {
            super(MlDsa.ML_DSA_87);
        }
    }

    /**
     * Release any previously-loaded native key (subsequent init resets
     * state). Buffer is cleared on every init.
     */
    private void releaseKey() {
        if (this.key != null) {
            this.key.releaseNativeStruct();
            this.key = null;
        }
    }

    private void resetForInit() {
        releaseKey();
        resetBuffer();
    }

    /**
     * Clear the message buffer, reallocating when the prior message was
     * large so the high-water-mark backing array is not retained for
     * the life of this Signature object.
     */
    private void resetBuffer() {
        if (this.buffer.size() > BUFFER_RETAIN_MAX) {
            this.buffer = new ByteArrayOutputStream();
        }
        else {
            this.buffer.reset();
        }
    }

    private MlDsa importPublicKeyForVerify(PublicKey pub)
        throws InvalidKeyException {

        /* Native wolfJCE public key, level already known. */
        if (pub instanceof WolfCryptMlDsaPublicKey) {
            WolfCryptMlDsaPublicKey wp = (WolfCryptMlDsaPublicKey) pub;
            int level = wp.getLevel();
            checkLevelMatchesRequired(level);
            return importKeyDer(wp.getEncoded(), level, true,
                "Failed to import ML-DSA public key");
        }

        /* Foreign key, must be X.509 SPKI form. */
        if (!"X.509".equalsIgnoreCase(pub.getFormat())) {
            throw new InvalidKeyException(
                "Unsupported PublicKey format for ML-DSA: " +
                pub.getFormat());
        }

        byte[] der = pub.getEncoded();
        if (der == null || der.length == 0) {
            throw new InvalidKeyException(
                "Cannot extract X.509 SPKI from PublicKey");
        }

        return importKeyDer(der, 0, true,
            "Not a recognized ML-DSA X.509 SPKI key");
    }

    private MlDsa importPrivateKeyForSign(PrivateKey priv)
        throws InvalidKeyException {

        /* Native wolfJCE private key, level already known. */
        if (priv instanceof WolfCryptMlDsaPrivateKey) {
            WolfCryptMlDsaPrivateKey wp = (WolfCryptMlDsaPrivateKey) priv;
            int level = wp.getLevel();
            checkLevelMatchesRequired(level);
            return importKeyDer(wp.getEncoded(), level, false,
                "Failed to import ML-DSA private key");
        }

        if (!"PKCS#8".equalsIgnoreCase(priv.getFormat())) {
            throw new InvalidKeyException(
                "Unsupported PrivateKey format for ML-DSA: " +
                priv.getFormat());
        }

        byte[] der = priv.getEncoded();
        if (der == null || der.length == 0) {
            throw new InvalidKeyException(
                "Cannot extract PKCS#8 from PrivateKey");
        }

        return importKeyDer(der, 0, false,
            "Not a recognized ML-DSA PKCS#8 key");
    }

    /**
     * Import key DER into a new native MlDsa object, releasing the
     * native struct before throwing on any failure.
     *
     * When level is 0 the level is auto-detected by the native import
     * (with explicit per-level fallback for pre-PR-10310 native wolfSSL)
     * and checked against requiredLevel after import. A single native decode
     * is performed on auto-detect capable native.
     *
     * @param der key DER, X.509 SPKI if isPublic, otherwise PKCS#8
     * @param level known level, or 0 to auto-detect from DER
     * @param isPublic true for public key import, false for private
     * @param errMsg InvalidKeyException message on import failure
     *
     * @return new MlDsa object holding the imported key, caller owns the
     *         native struct
     *
     * @throws InvalidKeyException if the DER cannot be imported or the
     *         level does not match a parameter-set specific Signature
     */
    private MlDsa importKeyDer(byte[] der, int level, boolean isPublic,
        String errMsg) throws InvalidKeyException {

        MlDsa k = null;

        try {
            if (level != 0) {
                k = new MlDsa(level);
                importDer(k, der, isPublic);
            }
            else {
                try {
                    /* Level auto-detected from DER */
                    k = new MlDsa();
                    importDer(k, der, isPublic);
                }
                catch (WolfCryptException e) {
                    /* Older native wolfSSL without auto-detect, derive
                     * the level explicitly (tries each FIPS 204 level
                     * internally), then import with that level. */
                    if (k != null) {
                        k.releaseNativeStruct();
                        k = null;
                    }
                    int lvl = isPublic ?
                        MlDsa.parseAndValidateMlDsaPublicKeyDer(der) :
                        MlDsa.parseAndValidateMlDsaPrivateKeyDer(der);
                    k = new MlDsa(lvl);
                    importDer(k, der, isPublic);
                }
                checkLevelMatchesRequired(k.getLevel());
            }

            return k;
        }
        catch (WolfCryptException | InvalidKeyException e) {
            if (k != null) {
                k.releaseNativeStruct();
            }
            if (e instanceof InvalidKeyException) {
                throw (InvalidKeyException)e;
            }
            throw new InvalidKeyException(errMsg, e);
        }
    }

    /* Run the native public or private DER import on key object */
    private static void importDer(MlDsa k, byte[] der, boolean isPublic) {

        if (isPublic) {
            k.importPublicKeyDer(der);
        }
        else {
            k.importPrivateKeyDer(der);
        }
    }

    private void checkLevelMatchesRequired(int keyLevel)
        throws InvalidKeyException {

        if (this.requiredLevel == 0) {
            return; /* generic wcMlDsa: any level OK */
        }
        if (keyLevel != this.requiredLevel) {
            throw new InvalidKeyException(
                "Key parameter set does not match Signature: " +
                "expected level " + this.requiredLevel +
                ", got level " + keyLevel);
        }
    }

    private Rng getOrInitRng() {
        if (this.rng == null) {
            this.rng = new Rng();
            this.rng.init();
        }
        return this.rng;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException {

        if (publicKey == null) {
            throw new InvalidKeyException("PublicKey is null");
        }

        resetForInit();
        this.key = importPublicKeyForVerify(publicKey);
        this.signing = false;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException {

        if (privateKey == null) {
            throw new InvalidKeyException("PrivateKey is null");
        }

        resetForInit();
        this.key = importPrivateKeyForSign(privateKey);
        this.signing = true;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {

        if (this.key == null) {
            throw new SignatureException("Signature not initialized");
        }

        this.buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException {

        if (this.key == null) {
            throw new SignatureException("Signature not initialized");
        }

        if (b == null || off < 0 || len < 0 || len > b.length - off) {
            throw new SignatureException("Invalid update arguments");
        }

        this.buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {

        if (this.key == null || !this.signing) {
            throw new SignatureException(
                "Signature not initialized for signing");
        }

        try {
            byte[] msg = this.buffer.toByteArray();
            byte[] sig = this.key.sign(msg, getOrInitRng());
            return sig;
        }
        catch (WolfCryptException e) {
            throw new SignatureException("ML-DSA sign failed", e);
        }
        finally {
            resetBuffer();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException {

        if (this.key == null || this.signing) {
            throw new SignatureException(
                "Signature not initialized for verification");
        }
        if (sigBytes == null) {
            throw new SignatureException("Signature bytes are null");
        }

        try {
            byte[] msg = this.buffer.toByteArray();
            boolean ok = this.key.verify(sigBytes, msg);
            return ok;
        }
        catch (WolfCryptException e) {
            throw new SignatureException("ML-DSA verify failed", e);
        }
        finally {
            resetBuffer();
        }
    }

    /**
     * @deprecated unsupported; ML-DSA has no streaming/algorithm
     *             parameters in the JCE-24 model.
     */
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {
        throw new InvalidParameterException(
            "ML-DSA does not accept algorithm parameters");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws java.security.InvalidAlgorithmParameterException {
        throw new java.security.InvalidAlgorithmParameterException(
            "ML-DSA does not accept algorithm parameters");
    }

    /**
     * @deprecated unsupported.
     */
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {
        throw new InvalidParameterException(
            "ML-DSA does not accept algorithm parameters");
    }
}
