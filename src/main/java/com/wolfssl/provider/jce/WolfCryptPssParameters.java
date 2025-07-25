/* WolfCryptPssParameters.java
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
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import com.wolfssl.wolfcrypt.Rsa;

/**
 * wolfCrypt JCE AlgorithmParametersSpi implementation for RSA-PSS parameters
 */
public class WolfCryptPssParameters extends AlgorithmParametersSpi {

    private PSSParameterSpec pssSpec;

    /**
     * Create new WolfCryptPssParameters object
     */
    public WolfCryptPssParameters() {
        /* Default PSS parameters with SHA-256 */
        this.pssSpec = new PSSParameterSpec(
            "SHA-256",                       /* message digest */
            "MGF1",                          /* mask generation function */
            MGF1ParameterSpec.SHA256,        /* MGF parameters */
            Rsa.RSA_PSS_SALT_LEN_DEFAULT,    /* salt length (hash length) */
            1                                /* trailer field (always 1) */
        );
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {

        if (!(paramSpec instanceof PSSParameterSpec)) {
            throw new InvalidParameterSpecException(
                "Only PSSParameterSpec supported");
        }

        PSSParameterSpec pss = (PSSParameterSpec)paramSpec;
        validatePSSParameters(pss);
        this.pssSpec = pss;
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        /* ASN.1 DER decoding would be implemented here */
        throw new IOException("DER encoding/decoding not yet implemented");
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        if (!"ASN.1".equalsIgnoreCase(format)) {
            throw new IOException("Only ASN.1 format supported");
        }
        engineInit(params);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(
            Class<T> paramSpec) throws InvalidParameterSpecException {

        if (paramSpec == null) {
            throw new InvalidParameterSpecException(
                "Parameter spec cannot be null");
        }

        if (paramSpec.isAssignableFrom(PSSParameterSpec.class)) {
            return paramSpec.cast(this.pssSpec);
        }

        throw new InvalidParameterSpecException(
            "Unsupported parameter spec: " + paramSpec.getName());
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        /* ASN.1 DER encoding would be implemented here */
        throw new IOException("DER encoding/decoding not yet implemented");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (!"ASN.1".equalsIgnoreCase(format)) {
            throw new IOException("Only ASN.1 format supported");
        }
        return engineGetEncoded();
    }

    @Override
    protected String engineToString() {
        if (pssSpec == null) {
            return "PSS Parameters: null";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("PSS Parameters:\n");
        sb.append("  Message Digest: ").append(pssSpec.getDigestAlgorithm())
            .append("\n");
        sb.append("  MGF Algorithm: ").append(pssSpec.getMGFAlgorithm())
            .append("\n");

        if (pssSpec.getMGFParameters() instanceof MGF1ParameterSpec) {
            MGF1ParameterSpec mgf1 =
                (MGF1ParameterSpec)pssSpec.getMGFParameters();
            sb.append("  MGF Digest: ").append(mgf1.getDigestAlgorithm())
                .append("\n");
        }

        sb.append("  Salt Length: ").append(pssSpec.getSaltLength())
            .append("\n");
        sb.append("  Trailer Field: ").append(pssSpec.getTrailerField())
            .append("\n");

        return sb.toString();
    }

    /**
     * Helper method to validate PSS parameters.
     *
     * @param pss The PSSParameterSpec to validate
     *
     * @throws InvalidParameterSpecException if any parameter is invalid
     */
    private void validatePSSParameters(PSSParameterSpec pss)
            throws InvalidParameterSpecException {

        /* Validate digest algorithm */
        String digestAlg = pss.getDigestAlgorithm();
        if (!isDigestSupported(digestAlg)) {
            throw new InvalidParameterSpecException(
                "Unsupported digest algorithm: " + digestAlg);
        }

        /* Validate MGF algorithm */
        String mgfAlg = pss.getMGFAlgorithm();
        if (!"MGF1".equalsIgnoreCase(mgfAlg)) {
            throw new InvalidParameterSpecException(
                "Only MGF1 supported, got " + mgfAlg);
        }

        /* Validate MGF parameters */
        if (pss.getMGFParameters() instanceof MGF1ParameterSpec) {
            MGF1ParameterSpec mgf1Spec =
                (MGF1ParameterSpec)pss.getMGFParameters();
            String mgfDigest = mgf1Spec.getDigestAlgorithm();

            if (!isDigestSupported(mgfDigest)) {
                throw new InvalidParameterSpecException(
                    "Unsupported MGF digest: " + mgfDigest);
            }
        }

        /* Validate salt length */
        int saltLen = pss.getSaltLength();
        if (saltLen < -2) {
            throw new InvalidParameterSpecException(
                "Invalid salt length: " + saltLen);
        }

        /* Validate trailer field */
        if (pss.getTrailerField() != 1) {
            throw new InvalidParameterSpecException(
                "Trailer field must be 1, got " + pss.getTrailerField());
        }
    }

    /**
     * Helper method to check if the given digest algorithm is supported.
     *
     * @param digestAlg The digest algorithm name
     *
     * @return true if supported, false otherwise
     */
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
