/* WolfCryptLmsSignature.java
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

import com.wolfssl.wolfcrypt.Lms;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE LMS/HSS (RFC 8554) Signature provider, registered under both
 * {@code "LMS"} and {@code "HSS/LMS"} names (and the HSS/LMS OID).
 *
 * <p>This is a <b>verify-only</b> provider, matching the JDK SUN provider:
 * {@code initVerify} / {@code verify} check signatures, while {@code initSign}
 * throws {@link InvalidKeyException}. Stateful hash-based signing belongs in
 * hardware (NIST SP 800-208), so wolfJCE does not generate keys or sign.</p>
 *
 * <p>LMS verifies a whole message (not a streaming hash), {@code engineUpdate}
 * buffers it.</p>
 */
public final class WolfCryptLmsSignature extends SignatureSpi {

    /** Native verify key (owned), non-null when initialized for verify. */
    private Lms verifyKey = null;

    /** Reset keeps the backing array up to this size, larger buffers are
     * reallocated so pooled Signature objects do not pin large buffers. */
    private static final int BUFFER_RETAIN_MAX = 1024 * 1024;

    /** Buffered message bytes (LMS verifies the whole message). */
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /**
     * Create a new wolfJCE LMS/HSS verify-only Signature object.
     */
    public WolfCryptLmsSignature() {
    }

    private void releaseKeys() {
        if (this.verifyKey != null) {
            this.verifyKey.releaseNativeStruct();
            this.verifyKey = null;
        }
    }

    private void resetForInit() {
        releaseKeys();
        resetBuffer();
    }

    private void resetBuffer() {
        if (this.buffer.size() > BUFFER_RETAIN_MAX) {
            this.buffer = new ByteArrayOutputStream();
        }
        else {
            this.buffer.reset();
        }
    }

    private Lms importPublicKeyForVerify(PublicKey pub)
        throws InvalidKeyException {

        byte[] der;
        byte[] rawPub;
        Lms k = null;

        if (pub instanceof WolfCryptLmsPublicKey) {
            rawPub = ((WolfCryptLmsPublicKey) pub).getRawPublicKey();
            if (rawPub == null) {
                throw new InvalidKeyException("LMS public key destroyed");
            }
        }
        else {
            if (!"X.509".equalsIgnoreCase(pub.getFormat())) {
                throw new InvalidKeyException(
                    "Unsupported PublicKey format for LMS: " + pub.getFormat());
            }

            der = pub.getEncoded();
            if (der == null || der.length == 0) {
                throw new InvalidKeyException(
                    "Cannot extract X.509 SPKI from PublicKey");
            }

            try {
                rawPub = WolfCryptLmsUtil.parsePublicKeyDer(der);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException(
                    "Not a recognized LMS X.509 SPKI: " + e.getMessage(), e);
            }
        }

        try {
            k = new Lms();
            k.importPublicRaw(rawPub);
            return k;
        }
        catch (WolfCryptException e) {
            if (k != null) {
                k.releaseNativeStruct();
            }
            throw new InvalidKeyException(
                "Failed to import LMS public key: " + e.getMessage(), e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException {

        if (publicKey == null) {
            throw new InvalidKeyException("PublicKey is null");
        }

        resetForInit();

        this.verifyKey = importPublicKeyForVerify(publicKey);
    }

    /**
     * Signing is not supported: wolfJCE provides verify-only LMS/HSS, matching
     * the JDK SUN provider. Stateful hash-based signing belongs in hardware
     * (NIST SP 800-208).
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException {

        throw new InvalidKeyException(
            "LMS/HSS signing is not supported (verify-only)");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {

        if (this.verifyKey == null) {
            throw new SignatureException("Signature not initialized");
        }

        this.buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException {

        if (this.verifyKey == null) {
            throw new SignatureException("Signature not initialized");
        }

        if ((b == null) || (off < 0) || (len < 0) || (off > b.length - len)) {
            throw new SignatureException("Invalid update arguments");
        }

        this.buffer.write(b, off, len);
    }

    /**
     * Signing is not supported (verify-only). See {@link #engineInitSign}.
     */
    @Override
    protected byte[] engineSign() throws SignatureException {

        throw new SignatureException(
            "LMS/HSS signing is not supported (verify-only)");
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException {

        if (this.verifyKey == null) {
            throw new SignatureException(
                "Signature not initialized for verification");
        }

        if (sigBytes == null) {
            throw new SignatureException("Signature bytes are null");
        }

        try {
            return this.verifyKey.verify(sigBytes, this.buffer.toByteArray());
        }
        catch (WolfCryptException e) {
            throw new SignatureException("LMS verify failed", e);
        }
        finally {
            resetBuffer();
        }
    }

    /**
     * @deprecated unsupported, LMS takes no per-signature parameters.
     */
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "LMS does not accept algorithm parameters");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {

        throw new InvalidAlgorithmParameterException(
            "LMS does not accept algorithm parameters");
    }

    /**
     * @deprecated unsupported.
     */
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
        throws InvalidParameterException {

        throw new InvalidParameterException(
            "LMS does not accept algorithm parameters");
    }
}
