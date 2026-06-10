/* WolfCryptAesParameters.java
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

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;

import com.wolfssl.wolfcrypt.Aes;

/**
 * wolfCrypt JCE AlgorithmParametersSpi implementation for AES parameters
 */
public class WolfCryptAesParameters extends AlgorithmParametersSpi {

    private IvParameterSpec ivSpec;

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

        /* AES block size is 16 bytes, IV should match */
        if (spec.getIV().length != Aes.BLOCK_SIZE) {
            throw new InvalidParameterSpecException(
                "AES IV must be 16 bytes, got: " + spec.getIV().length);
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
         * tag (0x04) + length + IV bytes
         * Expected: 04 10 [16 IV bytes] = 18 bytes */
        if (params.length != Aes.BLOCK_SIZE + 2) {
            throw new IOException(
                "Invalid AES parameter encoding length: " + params.length);
        }

        /* Verify OCTET STRING tag */
        if (params[0] != 0x04) {
            throw new IOException(
                "DER input not an octet string");
        }

        /* Verify length is 16 (0x10) */
        if (params[1] != 0x10) {
            throw new IOException(
                "Invalid AES IV length in encoding: " + params[1]);
        }

        /* Extract IV bytes (skip tag and length) */
        byte[] iv = new byte[Aes.BLOCK_SIZE];
        System.arraycopy(params, 2, iv, 0, Aes.BLOCK_SIZE);

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
        if (iv == null || iv.length != Aes.BLOCK_SIZE) {
            throw new IOException("Invalid AES IV for encoding");
        }

        /* Encode as OCTET STRING: tag (0x04) + len (0x10) + IV */
        encoded = new byte[18];
        encoded[0] = 0x04; /* OCTET STRING */
        encoded[1] = 0x10; /* length = 16 */
        System.arraycopy(iv, 0, encoded, 2, Aes.BLOCK_SIZE);

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

