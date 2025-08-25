/* WolfCryptGcmParameters.java
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
import javax.crypto.spec.GCMParameterSpec;

/**
 * wolfCrypt JCE AlgorithmParametersSpi implementation for AES-GCM parameters
 */
public class WolfCryptGcmParameters extends AlgorithmParametersSpi {

    private GCMParameterSpec gcmSpec;

    /**
     * Create new WolfCryptGcmParameters object
     */
    public WolfCryptGcmParameters() {
        /* Set when initialized */
        this.gcmSpec = null;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {

        if (!(paramSpec instanceof GCMParameterSpec)) {
            throw new InvalidParameterSpecException(
                "Only GCMParameterSpec supported");
        }

        GCMParameterSpec spec = (GCMParameterSpec) paramSpec;

        /* Validate parameters */
        if (spec.getIV() == null || spec.getIV().length == 0) {
            throw new InvalidParameterSpecException(
                "GCM IV cannot be null or empty");
        }

        if (spec.getTLen() <= 0) {
            throw new InvalidParameterSpecException(
                "GCM tag length must be positive");
        }

        /* Clone the IV to prevent external modification */
        this.gcmSpec = new GCMParameterSpec(
            spec.getTLen(), spec.getIV().clone());
    }

    @Override
    protected void engineInit(byte[] params)
        throws IOException {

        throw new IOException("Encoded GCM parameters not supported");
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException {

        throw new IOException("Encoded GCM parameters not supported");
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(
            Class<T> paramSpec) throws InvalidParameterSpecException {

        if (this.gcmSpec == null) {
            throw new InvalidParameterSpecException(
                "GCM parameters not initialized");
        }

        if (paramSpec == null) {
            throw new InvalidParameterSpecException(
                "Parameter spec class cannot be null");
        }

        if (paramSpec == GCMParameterSpec.class ||
            paramSpec == AlgorithmParameterSpec.class) {
            /* Return a copy to prevent external modification */
            return (T) new GCMParameterSpec(
                this.gcmSpec.getTLen(), this.gcmSpec.getIV().clone());
        }

        throw new InvalidParameterSpecException(
            "Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException("Encoded GCM parameters not supported");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Encoded GCM parameters not supported");
    }

    @Override
    protected String engineToString() {
        if (this.gcmSpec == null) {
            return "WolfCryptGcmParameters[uninitialized]";
        }

        return "WolfCryptGcmParameters[" +
               "tagLen=" + this.gcmSpec.getTLen() +
               ", ivLen=" + (this.gcmSpec.getIV() != null ?
                             this.gcmSpec.getIV().length : 0) +
               "]";
    }
}

