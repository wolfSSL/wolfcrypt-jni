/* WolfCryptPssParameters.java
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
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import com.wolfssl.wolfcrypt.Rsa;
import com.wolfssl.wolfcrypt.Sha256;

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
            Sha256.DIGEST_SIZE,              /* salt length */
            1                                /* trailer field (always 1) */
        );
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException {

        PSSParameterSpec pss;

        if (!(paramSpec instanceof PSSParameterSpec)) {
            throw new InvalidParameterSpecException(
                "Only PSSParameterSpec supported");
        }

        pss = (PSSParameterSpec)paramSpec;
        validatePSSParameters(pss);
        this.pssSpec = pss;
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        if (params == null || params.length == 0) {
            throw new IOException("Parameters cannot be null or empty");
        }

        try {
            this.pssSpec = decodePssParameters(params);
            validatePSSParameters(this.pssSpec);
        } catch (InvalidParameterSpecException e) {
            throw new IOException(
                "Failed to decode PSS parameters: " + e.getMessage(), e);
        }
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
        if (this.pssSpec == null) {
            throw new IOException("PSS parameters not initialized");
        }

        return encodePssParameters(this.pssSpec);
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


    /**
     * Encode PSS parameters to DER format (RFC 4055).
     *
     * @param spec The PSSParameterSpec to encode
     *
     * @return DER-encoded PSS parameters
     *
     * @throws IOException if encoding fails
     */
    private byte[] encodePssParameters(PSSParameterSpec spec)
        throws IOException {

        int saltLen, trailer;
        String digestAlg, mgfDigest;
        ByteArrayOutputStream seq = new ByteArrayOutputStream();
        MGF1ParameterSpec mgf1Spec;
        byte[] seqBytes;

        /* Get hash algorithm name */
        digestAlg = spec.getDigestAlgorithm();
        saltLen = spec.getSaltLength();
        trailer = spec.getTrailerField();

        /* Get MGF digest algorithm from MGF1ParameterSpec.
         * Per RFC 4055, MGF1 is the only supported MGF algorithm. */
        if (!(spec.getMGFParameters() instanceof MGF1ParameterSpec)) {
            throw new IOException(
                "MGF parameters must be MGF1ParameterSpec");
        }

        mgf1Spec = (MGF1ParameterSpec) spec.getMGFParameters();
        mgfDigest = mgf1Spec.getDigestAlgorithm();

        /* Encode hashAlgorithm [0] if not default (SHA-1). If default,
         * we omit from encoding. */
        if (!digestAlg.equalsIgnoreCase("SHA-1")) {
            byte[] hashAlgId = encodeAlgorithmIdentifier(digestAlg);
            seq.write(WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_0);
            seq.write(WolfCryptASN1Util.encodeDERLength(hashAlgId.length));
            seq.write(hashAlgId);
        }

        /* Encode maskGenAlgorithm [1] if not default (mgf1SHA1). If default,
         * we omit from encoding. */
        if (!mgfDigest.equalsIgnoreCase("SHA-1")) {
            byte[] mgfHashAlgId = encodeAlgorithmIdentifier(mgfDigest);
            byte[] mgfAlgId = encodeMGF1AlgorithmIdentifier(mgfHashAlgId);
            seq.write(WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_1);
            seq.write(WolfCryptASN1Util.encodeDERLength(mgfAlgId.length));
            seq.write(mgfAlgId);
        }

        /* Encode saltLength [2] if not default (20) */
        if (saltLen != 20) {
            byte[] saltLenBytes = WolfCryptASN1Util.encodeDERInteger(saltLen);
            seq.write(WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_2);
            seq.write(WolfCryptASN1Util.encodeDERLength(saltLenBytes.length));
            seq.write(saltLenBytes);
        }

        /* Encode trailerField [3] if not default (1) */
        if (trailer != 1) {
            byte[] trailerBytes = WolfCryptASN1Util.encodeDERInteger(trailer);
            seq.write(WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_3);
            seq.write(WolfCryptASN1Util.encodeDERLength(trailerBytes.length));
            seq.write(trailerBytes);
        }

        /* Wrap in SEQUENCE */
        seqBytes = seq.toByteArray();

        return WolfCryptASN1Util.encodeDERSequence(seqBytes);
    }

    /**
     * Decode DER-encoded PSS parameters (RFC 4055).
     *
     * @param params DER-encoded PSS parameters
     *
     * @return Decoded PSSParameterSpec
     *
     * @throws IOException if decoding fails
     */
    private PSSParameterSpec decodePssParameters(byte[] params)
        throws IOException {

        int idx = 0, seqLen = 0;
        int[] lenInfo;

        /* Defaults, per RFC 4055 */
        String digestAlg = "SHA-1";
        String mgfDigest = "SHA-1";
        int saltLen = 20;
        int trailer = 1;

        if (params == null || params.length < 2) {
            throw new IOException("Invalid PSS parameters: too short");
        }

        /* Check SEQUENCE tag */
        if (params[idx++] != WolfCryptASN1Util.ASN1_SEQUENCE) {
            throw new IOException(
                "Invalid PSS parameters: expected SEQUENCE");
        }

        /* Get SEQUENCE length */
        lenInfo = WolfCryptASN1Util.decodeDERLengthWithOffset(params, idx);
        seqLen = lenInfo[0];
        idx = lenInfo[1];

        if (idx + seqLen != params.length) {
            throw new IOException(
                "Invalid PSS parameters: incorrect length");
        }

        /* Parse optional fields */
        while (idx < params.length) {
            byte tag = params[idx++];

            /* Get field length */
            lenInfo =
                WolfCryptASN1Util.decodeDERLengthWithOffset(params, idx);
            int fieldLen = lenInfo[0];
            idx = lenInfo[1];

            if (idx + fieldLen > params.length) {
                throw new IOException(
                    "Invalid PSS parameters: field extends beyond data");
            }

            byte[] fieldData = new byte[fieldLen];
            System.arraycopy(params, idx, fieldData, 0, fieldLen);
            idx += fieldLen;

            if (tag == WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_0) {
                /* hashAlgorithm [0] */
                digestAlg = decodeAlgorithmIdentifier(fieldData);
            }
            else if (tag == WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_1) {
                /* maskGenAlgorithm [1] */
                mgfDigest = decodeMGF1AlgorithmIdentifier(fieldData);
            }
            else if (tag == WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_2) {
                /* saltLength [2] */
                saltLen = WolfCryptASN1Util.decodeDERInteger(fieldData);
            }
            else if (tag == WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_3) {
                /* trailerField [3] */
                trailer = WolfCryptASN1Util.decodeDERInteger(fieldData);
            }
            else {
                throw new IOException(
                    "Invalid PSS parameters: unknown tag 0x" +
                    Integer.toHexString(tag & 0xff));
            }
        }

        /* Validate trailer field */
        if (trailer != 1) {
            throw new IOException(
                "Invalid PSS parameters: trailerField must be 1");
        }

        /* Create and return PSSParameterSpec */
        return new PSSParameterSpec(digestAlg, "MGF1",
            new MGF1ParameterSpec(mgfDigest), saltLen, trailer
        );
    }

    /**
     * Encode AlgorithmIdentifier for a hash algorithm.
     *
     * @param digestAlg The digest algorithm name
     *
     * @return DER-encoded AlgorithmIdentifier
     *
     * @throws IOException if encoding fails
     */
    private byte[] encodeAlgorithmIdentifier(String digestAlg)
        throws IOException {

        byte[] oid = getHashOID(digestAlg);

        ByteArrayOutputStream seq = new ByteArrayOutputStream();

        /* Write OID */
        seq.write(WolfCryptASN1Util.encodeDERObjectIdentifier(oid));

        /* Write NULL parameters */
        seq.write(WolfCryptASN1Util.encodeDERNull());

        /* Wrap in SEQUENCE */
        return WolfCryptASN1Util.encodeDERSequence(seq.toByteArray());
    }

    /**
     * Decode AlgorithmIdentifier and extract the hash algorithm name.
     *
     * @param data DER-encoded AlgorithmIdentifier
     *
     * @return Hash algorithm name
     *
     * @throws IOException if decoding fails
     */
    private String decodeAlgorithmIdentifier(byte[] data) throws IOException {

        int idx = 0, oidLen = 0;
        int[] lenInfo;
        byte[] oid;

        if (data == null || data.length < 2) {
            throw new IOException("Invalid AlgorithmIdentifier: too short");
        }

        /* Check SEQUENCE tag */
        if (data[idx++] != WolfCryptASN1Util.ASN1_SEQUENCE) {
            throw new IOException(
                "Invalid AlgorithmIdentifier: expected SEQUENCE");
        }

        /* Skip SEQUENCE length */
        lenInfo = WolfCryptASN1Util.decodeDERLengthWithOffset(data, idx);
        idx = lenInfo[1];

        /* Check OBJECT IDENTIFIER tag */
        if (idx >= data.length ||
            data[idx++] != WolfCryptASN1Util.ASN1_OBJECT_IDENTIFIER) {
            throw new IOException(
                "Invalid AlgorithmIdentifier: expected OBJECT IDENTIFIER");
        }

        /* Get OID length */
        lenInfo = WolfCryptASN1Util.decodeDERLengthWithOffset(data, idx);
        oidLen = lenInfo[0];
        idx = lenInfo[1];

        if (idx + oidLen > data.length) {
            throw new IOException(
                "Invalid AlgorithmIdentifier: OID extends beyond data");
        }

        /* Extract OID bytes */
        oid = new byte[oidLen];
        System.arraycopy(data, idx, oid, 0, oidLen);
        idx += oidLen;

        /* Verify parameters follow OID (per RFC 4055), can be either
         * NULL or absent */
        if (idx < data.length) {
            /* Parameters are present, verify they are NULL */
            if ((idx + 2 > data.length) ||
                (data[idx] != WolfCryptASN1Util.ASN1_NULL) ||
                (data[idx + 1] != 0x00)) {
                throw new IOException(
                    "Invalid AlgorithmIdentifier: expected NULL parameters");
            }
        }

        /* Map OID to hash algorithm name */
        return WolfCryptASN1Util.getHashAlgorithmName(oid);
    }

    /**
     * Encode MGF1 AlgorithmIdentifier with embedded hash AlgorithmIdentifier.
     *
     * @param hashAlgId DER-encoded hash AlgorithmIdentifier
     *
     * @return DER-encoded MGF1 AlgorithmIdentifier
     *
     * @throws IOException if encoding fails
     */
    private byte[] encodeMGF1AlgorithmIdentifier(byte[] hashAlgId)
        throws IOException {

        ByteArrayOutputStream seq = new ByteArrayOutputStream();

        /* Write MGF1 OID */
        seq.write(WolfCryptASN1Util.encodeDERObjectIdentifier(
            WolfCryptASN1Util.getMGF1OID()));

        /* Write hash AlgorithmIdentifier as parameters */
        seq.write(hashAlgId);

        /* Wrap in SEQUENCE */
        return WolfCryptASN1Util.encodeDERSequence(seq.toByteArray());
    }

    /**
     * Decode MGF1 AlgorithmIdentifier and extract hash algorithm name.
     *
     * @param data DER-encoded MGF1 AlgorithmIdentifier
     *
     * @return Hash algorithm name for MGF
     *
     * @throws IOException if decoding fails
     */
    private String decodeMGF1AlgorithmIdentifier(byte[] data)
        throws IOException {

        int idx = 0, oidLen = 0;
        int[] lenInfo;
        byte[] oid, hashAlgId;

        if (data == null || data.length < 2) {
            throw new IOException("Invalid MGF1 AlgorithmIdentifier");
        }

        /* Check SEQUENCE tag */
        if (data[idx++] != WolfCryptASN1Util.ASN1_SEQUENCE) {
            throw new IOException(
                "Invalid MGF1 AlgorithmIdentifier: expected SEQUENCE");
        }

        /* Skip SEQUENCE length */
        lenInfo = WolfCryptASN1Util.decodeDERLengthWithOffset(data, idx);
        idx = lenInfo[1];

        /* Check MGF1 OID */
        if (idx >= data.length ||
            data[idx++] != WolfCryptASN1Util.ASN1_OBJECT_IDENTIFIER) {
            throw new IOException(
                "Invalid MGF1 AlgorithmIdentifier: expected OID");
        }

        lenInfo = WolfCryptASN1Util.decodeDERLengthWithOffset(data, idx);
        oidLen = lenInfo[0];
        idx = lenInfo[1];

        if (idx + oidLen > data.length) {
            throw new IOException("Invalid MGF1 AlgorithmIdentifier");
        }

        /* Verify it's the MGF1 OID */
        oid = new byte[oidLen];
        System.arraycopy(data, idx, oid, 0, oidLen);
        idx += oidLen;

        if (!WolfCryptASN1Util.bytesEqual(oid,
            WolfCryptASN1Util.getMGF1OID())) {
            throw new IOException(
                "Invalid MGF1 AlgorithmIdentifier: not MGF1 OID");
        }

        /* Decode embedded hash AlgorithmIdentifier */
        hashAlgId = new byte[data.length - idx];
        System.arraycopy(data, idx, hashAlgId, 0, hashAlgId.length);

        return decodeAlgorithmIdentifier(hashAlgId);
    }

    /**
     * Get OID bytes for a hash algorithm name.
     *
     * @param digestAlg The hash algorithm name
     *
     * @return OID bytes
     *
     * @throws IOException if algorithm not supported
     */
    private byte[] getHashOID(String digestAlg) throws IOException {
        try {
            return WolfCryptASN1Util.getHashAlgorithmOID(digestAlg);

        } catch (IllegalArgumentException e) {
            throw new IOException(e.getMessage(), e);
        }
    }
}

