/* WolfCryptAesParameters.java
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

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;

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
        if (spec.getIV().length != 16) {
            throw new InvalidParameterSpecException(
                "AES IV must be 16 bytes, got: " + spec.getIV().length);
        }

        /* Clone the IV to prevent external modification */
        this.ivSpec = new IvParameterSpec(spec.getIV().clone());
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException {

        throw new IOException("Encoded AES parameters not supported");
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException {

        throw new IOException("Encoded AES parameters not supported");
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
        throw new IOException("Encoded AES parameters not supported");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Encoded AES parameters not supported");
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

