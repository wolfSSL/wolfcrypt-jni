/* WolfCryptAesParameters.java
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

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;

import com.wolfssl.wolfcrypt.Aes;
import com.wolfssl.wolfcrypt.AesKeyWrap;

/**
 * wolfCrypt JCE AlgorithmParametersSpi implementation for AES parameters.
 *
 * Holds an AES IV encoded as an ASN.1 OCTET STRING. The IV is 16 bytes for
 * block cipher modes (CBC, CTR, OFB) and 8 bytes for AES Key Wrap (RFC 3394).
 */
public class WolfCryptAesParameters extends AlgorithmParametersSpi {

    private IvParameterSpec ivSpec;

    /**
     * Check if an IV length is valid for AES parameters.
     *
     * @param len IV length in bytes
     *
     * @return true if len is the AES block size (16) or the AES Key Wrap
     *         IV size (8), otherwise false
     */
    private static boolean isValidIvLength(int len) {

        if (len == Aes.BLOCK_SIZE || len == AesKeyWrap.IV_SIZE) {
            return true;
        }

        return false;
    }

    /**
     * Create new WolfCryptAesParameters object
     */
    public WolfCryptAesParameters() {
        /* Set when initialized */
        this.ivSpec = null;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {

        /* Prevent double initialization */
        if (this.ivSpec != null) {
            throw new InvalidParameterSpecException(
                "AlgorithmParameters already initialized");
        }

        if (!(paramSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException(
                "Only IvParameterSpec supported");
        }

        IvParameterSpec spec = (IvParameterSpec) paramSpec;

        /* Validate AES IV parameters */
        if (spec.getIV() == null || spec.getIV().length == 0) {
            throw new InvalidParameterSpecException(
                "AES IV cannot be null or empty");
        }

        /* AES block size is 16 bytes, AES Key Wrap IV is 8 bytes */
        if (!isValidIvLength(spec.getIV().length)) {
            throw new InvalidParameterSpecException(
                "AES IV must be " + Aes.BLOCK_SIZE + " bytes (or " +
                AesKeyWrap.IV_SIZE + " bytes for AES Key Wrap), got: " +
                spec.getIV().length);
        }

        /* Clone the IV to prevent external modification */
        this.ivSpec = new IvParameterSpec(spec.getIV().clone());
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException {

        /* Prevent double initialization */
        if (this.ivSpec != null) {
            throw new IOException(
                "AlgorithmParameters already initialized");
        }

        if (params == null) {
            throw new NullPointerException("params must not be null");
        }

        if (params.length == 0) {
            throw new IOException("AES parameters cannot be empty");
        }

        /* AES IV parameters are encoded as ASN.1 OCTET STRING:
         * tag (0x04) + length + IV bytes */
        if (params.length != Aes.BLOCK_SIZE + 2 &&
            params.length != AesKeyWrap.IV_SIZE + 2) {
            throw new IOException(
                "Invalid AES parameter encoding length: " + params.length);
        }

        /* Verify OCTET STRING tag */
        if (params[0] != 0x04) {
            throw new IOException(
                "DER input not an octet string");
        }

        /* Verify encoded length matches the buffer and is 16 or 8 */
        int ivLen = params[1] & 0xFF;
        if (ivLen != (params.length - 2) || !isValidIvLength(ivLen)) {
            throw new IOException(
                "Invalid AES IV length in encoding: " + ivLen);
        }

        /* Extract IV bytes (skip tag and length) */
        byte[] iv = new byte[ivLen];
        System.arraycopy(params, 2, iv, 0, ivLen);

        this.ivSpec = new IvParameterSpec(iv);
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException {

        if (format != null && !format.equalsIgnoreCase("ASN.1") &&
            !format.equalsIgnoreCase("DER")) {
            throw new IOException("Unsupported format: " + format +
                ", only ASN.1 and DER supported");
        }

        engineInit(params);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(
            Class<T> paramSpec) throws InvalidParameterSpecException {

        if (this.ivSpec == null) {
            throw new InvalidParameterSpecException(
                "AES parameters not initialized");
        }

        if (paramSpec == null) {
            throw new InvalidParameterSpecException(
                "Parameter spec class cannot be null");
        }

        if (paramSpec == IvParameterSpec.class ||
            paramSpec == AlgorithmParameterSpec.class) {
            /* Return a copy to prevent external modification */
            return (T) new IvParameterSpec(this.ivSpec.getIV().clone());
        }

        throw new InvalidParameterSpecException(
            "Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {

        byte[] iv;
        byte[] encoded;

        if (this.ivSpec == null) {
            throw new IOException("AES parameters not initialized");
        }

        iv = this.ivSpec.getIV();
        if (iv == null || !isValidIvLength(iv.length)) {
            throw new IOException("Invalid AES IV for encoding");
        }

        /* Encode as OCTET STRING: tag (0x04) + len (0x10 or 0x08) + IV */
        encoded = new byte[iv.length + 2];
        encoded[0] = 0x04; /* OCTET STRING */
        encoded[1] = (byte)iv.length; /* length = 16, or 8 for Key Wrap */
        System.arraycopy(iv, 0, encoded, 2, iv.length);

        return encoded;
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {

        if (format != null && !format.equalsIgnoreCase("ASN.1") &&
            !format.equalsIgnoreCase("DER")) {
            throw new IOException("Unsupported format: " + format +
                ", only ASN.1 and DER supported");
        }

        return engineGetEncoded();
    }

    @Override
    protected String engineToString() {
        if (this.ivSpec == null) {
            return "WolfCryptAesParameters[uninitialized]";
        }

        return "WolfCryptAesParameters[" +
               "ivLen=" + (this.ivSpec.getIV() != null ?
                           this.ivSpec.getIV().length : 0) +
               "]";
    }

    @Override
    public String toString() {
        return engineToString();
    }
}

