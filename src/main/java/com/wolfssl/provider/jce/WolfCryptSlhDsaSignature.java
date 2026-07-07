/* WolfCryptSlhDsaSignature.java
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE SLH-DSA (FIPS 205) signature provider.
 *
 * <p>SLH-DSA is a one-shot signature scheme. This implementation buffers the
 * message in a {@link ByteArrayOutputStream} during {@code engineUpdate} and
 * consumes it on {@code engineSign} / {@code engineVerify}. This applies to
 * the HashSLH-DSA (pre-hash) services as well: the full message is buffered
 * and pre-hashed natively in one shot, so peak memory is proportional to
 * message size. Incremental pre-hashing during update is a possible future
 * enhancement for large-message use cases.</p>
 *
 * <p>An optional FIPS 205 context string (0..255 bytes, empty by default) can
 * be set via {@code engineSetParameter(AlgorithmParameterSpec)} with a
 * {@link WolfCryptContextParameterSpec}. The context persists across init
 * calls until replaced. To reset, set a spec created with a null or empty
 * context. The signer and verifier must agree on the same context otherwise
 * verification fails.</p>
 *
 * <p>Inner classes restrict the accepted key parameter set; the generic
 * {@link wcSlhDsa} accepts any SLH-DSA parameter set.</p>
 */
public abstract class WolfCryptSlhDsaSignature extends SignatureSpi {

    /** No required parameter set, accept any. */
    private static final int PARAM_ANY = -1;

    /** Required SLH-DSA parameter set for this Signature instance, one of
     * {@code SlhDsa.SLH_DSA_*} (0-11), or {@link #PARAM_ANY} for the generic
     * implementation. */
    private final int requiredParam;

    /** True for the HashSLH-DSA (pre-hash) services, false for pure SLH-DSA.
     * When true the message is pre-hashed natively per FIPS 205 Section
     * 10.2.2 before signing/verifying. */
    private final boolean preHash;

    /** Native SLH-DSA wrapper (one per init). */
    private SlhDsa key = null;

    /** Set true when initialized for sign, false for verify. Undefined
     * before first init call. */
    private boolean signing = false;

    /** FIPS 205 context string. Empty by default. Persists across init so it
     * may be set via setParameter() before or after initSign/initVerify. */
    private byte[] context = new byte[0];

    /** Reset keeps the backing array up to this size, larger buffers are
     * reallocated so long-lived (cached/pooled) Signature objects do not pin
     * one large message's worth of memory indefinitely. */
    private static final int BUFFER_RETAIN_MAX = 1024 * 1024;

    /** Buffered message bytes (SLH-DSA signs/verifies the whole message, not
     * a streaming hash). */
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /** Lazily-initialized RNG used for sign operations. */
    private Rng rng = null;

    /**
     * Construct with the required SLH-DSA parameter set. {@link #PARAM_ANY}
     * means "any parameter set", used by the generic {@link wcSlhDsa} alias.
     *
     * @param requiredParam {@link #PARAM_ANY} or a {@code SlhDsa.SLH_DSA_*}
     */
    protected WolfCryptSlhDsaSignature(int requiredParam) {
        this(requiredParam, false);
    }

    /**
     * Construct with the required SLH-DSA parameter set and pre-hash mode.
     *
     * @param requiredParam {@link #PARAM_ANY} or a {@code SlhDsa.SLH_DSA_*}
     * @param preHash true for HashSLH-DSA (pre-hash), false for pure SLH-DSA
     */
    protected WolfCryptSlhDsaSignature(int requiredParam, boolean preHash) {
        this.requiredParam = requiredParam;
        this.preHash = preHash;
    }

    /** Generic SLH-DSA Signature, accepts keys of any parameter set. */
    public static final class wcSlhDsa extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsa() {
            super(PARAM_ANY);
        }
    }

    /** SLH-DSA-SHAKE-128s only. */
    public static final class wcSlhDsaShake_128s
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaShake_128s() {
            super(SlhDsa.SLH_DSA_SHAKE_128S);
        }
    }

    /** SLH-DSA-SHAKE-128f only. */
    public static final class wcSlhDsaShake_128f
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaShake_128f() {
            super(SlhDsa.SLH_DSA_SHAKE_128F);
        }
    }

    /** SLH-DSA-SHAKE-192s only. */
    public static final class wcSlhDsaShake_192s
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaShake_192s() {
            super(SlhDsa.SLH_DSA_SHAKE_192S);
        }
    }

    /** SLH-DSA-SHAKE-192f only. */
    public static final class wcSlhDsaShake_192f
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaShake_192f() {
            super(SlhDsa.SLH_DSA_SHAKE_192F);
        }
    }

    /** SLH-DSA-SHAKE-256s only. */
    public static final class wcSlhDsaShake_256s
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaShake_256s() {
            super(SlhDsa.SLH_DSA_SHAKE_256S);
        }
    }

    /** SLH-DSA-SHAKE-256f only. */
    public static final class wcSlhDsaShake_256f
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaShake_256f() {
            super(SlhDsa.SLH_DSA_SHAKE_256F);
        }
    }

    /** SLH-DSA-SHA2-128s only. */
    public static final class wcSlhDsaSha2_128s
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaSha2_128s() {
            super(SlhDsa.SLH_DSA_SHA2_128S);
        }
    }

    /** SLH-DSA-SHA2-128f only. */
    public static final class wcSlhDsaSha2_128f
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaSha2_128f() {
            super(SlhDsa.SLH_DSA_SHA2_128F);
        }
    }

    /** SLH-DSA-SHA2-192s only. */
    public static final class wcSlhDsaSha2_192s
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaSha2_192s() {
            super(SlhDsa.SLH_DSA_SHA2_192S);
        }
    }

    /** SLH-DSA-SHA2-192f only. */
    public static final class wcSlhDsaSha2_192f
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaSha2_192f() {
            super(SlhDsa.SLH_DSA_SHA2_192F);
        }
    }

    /** SLH-DSA-SHA2-256s only. */
    public static final class wcSlhDsaSha2_256s
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaSha2_256s() {
            super(SlhDsa.SLH_DSA_SHA2_256S);
        }
    }

    /** SLH-DSA-SHA2-256f only. */
    public static final class wcSlhDsaSha2_256f
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcSlhDsaSha2_256f() {
            super(SlhDsa.SLH_DSA_SHA2_256F);
        }
    }

    /** Generic HashSLH-DSA (pre-hash) Signature, accepts any parameter set. */
    public static final class wcHashSlhDsa extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsa() {
            super(PARAM_ANY, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHA2-128s-WITH-SHA256 only. */
    public static final class wcHashSlhDsaSha2_128sWithSha256
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaSha2_128sWithSha256() {
            super(SlhDsa.SLH_DSA_SHA2_128S, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHA2-128f-WITH-SHA256 only. */
    public static final class wcHashSlhDsaSha2_128fWithSha256
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaSha2_128fWithSha256() {
            super(SlhDsa.SLH_DSA_SHA2_128F, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHA2-192s-WITH-SHA512 only. */
    public static final class wcHashSlhDsaSha2_192sWithSha512
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaSha2_192sWithSha512() {
            super(SlhDsa.SLH_DSA_SHA2_192S, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHA2-192f-WITH-SHA512 only. */
    public static final class wcHashSlhDsaSha2_192fWithSha512
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaSha2_192fWithSha512() {
            super(SlhDsa.SLH_DSA_SHA2_192F, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHA2-256s-WITH-SHA512 only. */
    public static final class wcHashSlhDsaSha2_256sWithSha512
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaSha2_256sWithSha512() {
            super(SlhDsa.SLH_DSA_SHA2_256S, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHA2-256f-WITH-SHA512 only. */
    public static final class wcHashSlhDsaSha2_256fWithSha512
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaSha2_256fWithSha512() {
            super(SlhDsa.SLH_DSA_SHA2_256F, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHAKE-128s-WITH-SHAKE128 only. */
    public static final class wcHashSlhDsaShake_128sWithShake128
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaShake_128sWithShake128() {
            super(SlhDsa.SLH_DSA_SHAKE_128S, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHAKE-128f-WITH-SHAKE128 only. */
    public static final class wcHashSlhDsaShake_128fWithShake128
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaShake_128fWithShake128() {
            super(SlhDsa.SLH_DSA_SHAKE_128F, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHAKE-192s-WITH-SHAKE256 only. */
    public static final class wcHashSlhDsaShake_192sWithShake256
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaShake_192sWithShake256() {
            super(SlhDsa.SLH_DSA_SHAKE_192S, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHAKE-192f-WITH-SHAKE256 only. */
    public static final class wcHashSlhDsaShake_192fWithShake256
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaShake_192fWithShake256() {
            super(SlhDsa.SLH_DSA_SHAKE_192F, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHAKE-256s-WITH-SHAKE256 only. */
    public static final class wcHashSlhDsaShake_256sWithShake256
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaShake_256sWithShake256() {
            super(SlhDsa.SLH_DSA_SHAKE_256S, true);
        }
    }

    /** HashSLH-DSA SLH-DSA-SHAKE-256f-WITH-SHAKE256 only. */
    public static final class wcHashSlhDsaShake_256fWithShake256
        extends WolfCryptSlhDsaSignature {
        /** Default constructor. */
        public wcHashSlhDsaShake_256fWithShake256() {
            super(SlhDsa.SLH_DSA_SHAKE_256F, true);
        }
    }

    /**
     * Release any previously-loaded native key (subsequent init resets state).
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
     * Clear the message buffer, reallocating when the prior message was large
     * so the high-water-mark backing array is not retained for the life of
     * this Signature object.
     */
    private void resetBuffer() {
        if (this.buffer.size() > BUFFER_RETAIN_MAX) {
            this.buffer = new ByteArrayOutputStream();
        }
        else {
            this.buffer.reset();
        }
    }

    private SlhDsa importPublicKeyForVerify(PublicKey pub)
        throws InvalidKeyException {

        /* Native wolfJCE public key, parameter set already known. */
        if (pub instanceof WolfCryptSlhDsaPublicKey) {
            WolfCryptSlhDsaPublicKey wp = (WolfCryptSlhDsaPublicKey) pub;
            int param = wp.getParam();

            checkParamMatchesRequired(param);

            return importKeyDer(wp.getEncoded(), param, true,
                "Failed to import SLH-DSA public key");
        }

        /* Foreign key, must be X.509 SPKI form. */
        if (!"X.509".equalsIgnoreCase(pub.getFormat())) {
            throw new InvalidKeyException(
                "Unsupported PublicKey format for SLH-DSA: " +
                pub.getFormat());
        }

        byte[] der = pub.getEncoded();
        if (der == null || der.length == 0) {
            throw new InvalidKeyException(
                "Cannot extract X.509 SPKI from PublicKey");
        }

        /* Remove NULL AlgorithmIdentifier (JDK re-encoding) if present */
        der = WolfCryptSpkiUtil.stripNullAlgIdParams(der);

        return importKeyDer(der, PARAM_ANY, true,
            "Not a recognized SLH-DSA X.509 SPKI key");
    }

    private SlhDsa importPrivateKeyForSign(PrivateKey priv)
        throws InvalidKeyException {

        /* Native wolfJCE private key, parameter set already known. */
        if (priv instanceof WolfCryptSlhDsaPrivateKey) {
            WolfCryptSlhDsaPrivateKey wp = (WolfCryptSlhDsaPrivateKey) priv;
            int param = wp.getParam();

            checkParamMatchesRequired(param);

            return importKeyDer(wp.getEncoded(), param, false,
                "Failed to import SLH-DSA private key");
        }

        if (!"PKCS#8".equalsIgnoreCase(priv.getFormat())) {
            throw new InvalidKeyException(
                "Unsupported PrivateKey format for SLH-DSA: " +
                priv.getFormat());
        }

        byte[] der = priv.getEncoded();
        if (der == null || der.length == 0) {
            throw new InvalidKeyException(
                "Cannot extract PKCS#8 from PrivateKey");
        }

        return importKeyDer(der, PARAM_ANY, false,
            "Not a recognized SLH-DSA PKCS#8 key");
    }

    /**
     * Import key DER into a new native SlhDsa object, releasing the native
     * struct before throwing on any failure.
     *
     * When param is PARAM_ANY the parameter set is detected by wolfSSL
     * from DER AlgorithmIdentifier OID and checked against requiredParam
     * after import.
     *
     * @param der key DER, X.509 SPKI if isPublic, otherwise PKCS#8
     * @param param known parameter set, or {@link #PARAM_ANY} to detect
     * @param isPublic true for public key import, false for private
     * @param errMsg InvalidKeyException message on import failure
     *
     * @return new SlhDsa object holding the imported key, caller owns the
     *         native struct
     *
     * @throws InvalidKeyException if the DER cannot be imported or the
     *         parameter set does not match a parameter-set specific Signature
     */
    private SlhDsa importKeyDer(byte[] der, int param, boolean isPublic,
        String errMsg) throws InvalidKeyException {

        SlhDsa k = null;

        try {
            if (param != PARAM_ANY) {
                k = new SlhDsa(param);
                importDer(k, der, isPublic);
            }
            else {
                /* Parameter set detected by wolfSSL from DER AlgoID OID */
                k = new SlhDsa();
                importDer(k, der, isPublic);
                checkParamMatchesRequired(k.getParam());
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
    private static void importDer(SlhDsa k, byte[] der, boolean isPublic) {

        if (isPublic) {
            k.importPublicKeyDer(der);
        }
        else {
            k.importPrivateKeyDer(der);
        }
    }

    private void checkParamMatchesRequired(int keyParam)
        throws InvalidKeyException {

        if (this.requiredParam == PARAM_ANY) {
            return; /* generic wcSlhDsa: any parameter set OK */
        }

        if (keyParam != this.requiredParam) {
            throw new InvalidKeyException(
                "Key parameter set does not match Signature: expected " +
                WolfPQCJdkCompat.slhDsaParamToName(this.requiredParam) +
                ", got " + WolfPQCJdkCompat.slhDsaParamToName(keyParam));
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

        /* Use subtraction form so a large off/len pair cannot overflow
         * int and slip past the bounds check */
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

            if (this.preHash) {
                return this.key.signPreHash(msg, this.context,
                    getOrInitRng());
            }

            return this.key.sign(msg, this.context, getOrInitRng());
        }
        catch (WolfCryptException e) {
            throw new SignatureException("SLH-DSA sign failed", e);
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

            if (this.preHash) {
                return this.key.verifyPreHash(sigBytes, msg, this.context);
            }

            return this.key.verify(sigBytes, msg, this.context);
        }
        catch (WolfCryptException e) {
            throw new SignatureException("SLH-DSA verify failed", e);
        }
        finally {
            resetBuffer();
        }
    }

    /**
     * @deprecated unsupported. Use
     *             {@code engineSetParameter(AlgorithmParameterSpec)} with a
     *             {@link WolfCryptContextParameterSpec} to set a context.
     */
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "Use setParameter(AlgorithmParameterSpec) with a " +
            "WolfCryptContextParameterSpec to set an SLH-DSA context");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {

        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameterSpec cannot be null, use a " +
                "WolfCryptContextParameterSpec to set or reset the " +
                "SLH-DSA context");
        }

        if (params instanceof WolfCryptContextParameterSpec) {
            this.context = ((WolfCryptContextParameterSpec) params)
                .getContext();
            return;
        }

        throw new InvalidAlgorithmParameterException(
            "SLH-DSA only accepts WolfCryptContextParameterSpec, got: " +
            params.getClass().getName());
    }

    /**
     * @deprecated unsupported.
     */
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "SLH-DSA does not support getParameter(String)");
    }
}
