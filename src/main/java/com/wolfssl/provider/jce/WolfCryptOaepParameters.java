/* WolfCryptOaepParameters.java
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
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * wolfCrypt JCE AlgorithmParametersSpi implementation for RSA-OAEP parameters
 */
public class WolfCryptOaepParameters extends AlgorithmParametersSpi {

    private OAEPParameterSpec oaepSpec;

    public WolfCryptOaepParameters() {
        this.oaepSpec = OAEPParameterSpec.DEFAULT;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {

        if (!(paramSpec instanceof OAEPParameterSpec)) {
            throw new InvalidParameterSpecException(
                "Only OAEPParameterSpec supported");
        }

        OAEPParameterSpec spec = (OAEPParameterSpec) paramSpec;

        if (!"MGF1".equals(spec.getMGFAlgorithm())) {
            throw new InvalidParameterSpecException(
                "Only MGF1 supported for OAEP, got: " +
                spec.getMGFAlgorithm());
        }

        AlgorithmParameterSpec mgfParams = spec.getMGFParameters();
        if (!(mgfParams instanceof MGF1ParameterSpec)) {
            throw new InvalidParameterSpecException(
                "MGF parameters must be MGF1ParameterSpec");
        }

        String mgfDigest = ((MGF1ParameterSpec) mgfParams).getDigestAlgorithm();
        if (!isDigestSupported(mgfDigest)) {
            throw new InvalidParameterSpecException(
                "Unsupported MGF digest: " + mgfDigest);
        }

        PSource pSource = spec.getPSource();
        if (pSource != null && pSource instanceof PSource.PSpecified) {
            byte[] label = ((PSource.PSpecified) pSource).getValue();
            if (label != null && label.length > 0) {
                throw new InvalidParameterSpecException(
                    "OAEP label (PSource) must be empty");
            }
        }

        this.oaepSpec = spec;
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        throw new IOException("Encoded OAEP parameters not supported");
    }

    @Override
    protected void engineInit(byte[] params, String format)
            throws IOException {
        throw new IOException("Encoded OAEP parameters not supported");
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(
            Class<T> paramSpec) throws InvalidParameterSpecException {

        if (this.oaepSpec == null) {
            throw new InvalidParameterSpecException(
                "OAEP parameters not initialized");
        }

        if (paramSpec == null) {
            throw new InvalidParameterSpecException(
                "Parameter spec class cannot be null");
        }

        if (paramSpec == OAEPParameterSpec.class ||
            paramSpec == AlgorithmParameterSpec.class) {
            return (T) this.oaepSpec;
        }

        throw new InvalidParameterSpecException(
            "Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new IOException("Encoded OAEP parameters not supported");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new IOException("Encoded OAEP parameters not supported");
    }

    @Override
    protected String engineToString() {
        if (this.oaepSpec == null) {
            return "WolfCryptOaepParameters[uninitialized]";
        }

        return "WolfCryptOaepParameters[" +
               "digest=" + this.oaepSpec.getDigestAlgorithm() +
               ", mgf=" + this.oaepSpec.getMGFAlgorithm() + "]";
    }

    private boolean isDigestSupported(String digestAlg) {
        switch (digestAlg.toUpperCase()) {
            case "SHA-1":
            case "SHA-224":
            case "SHA-256":
            case "SHA-384":
            case "SHA-512":
            case "SHA-512/224":
            case "SHA-512/256":
                return true;
            default:
                return false;
        }
    }
}
