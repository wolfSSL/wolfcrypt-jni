/* WolfCryptDhParameters.java
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;

/**
 * wolfCrypt JCE DH AlgorithmParameters implementation
 */
public class WolfCryptDhParameters extends AlgorithmParametersSpi {

    /* DH parameters */
    private BigInteger p = null;
    private BigInteger g = null;
    private int l = 0;

    /**
     * Create new WolfCryptDhParameters object
     */
    public WolfCryptDhParameters() {
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException {

        if (!(paramSpec instanceof DHParameterSpec)) {
            throw new InvalidParameterSpecException(
                "Expected DHParameterSpec");
        }

        DHParameterSpec dhSpec = (DHParameterSpec)paramSpec;
        this.p = dhSpec.getP();
        this.g = dhSpec.getG();
        this.l = dhSpec.getL();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {

        int idx = 0;
        int seqLen = 0;
        int pLen = 0;
        int gLen = 0;
        byte[] pBytes = null;
        byte[] gBytes = null;

        /* Parse DER-encoded DH parameters. Doing basic DER parsing here
         * since wolfCrypt does not have DER parsing support for this
         * encoded parameters format.
         *
         * Format: SEQUENCE { prime INTEGER, generator INTEGER } */
        try {
            /* Check SEQUENCE tag */
            if (params[idx++] != 0x30) {
                throw new IOException(
                    "Invalid DH parameters: expected SEQUENCE tag");
            }

            /* Get sequence length */
            seqLen = WolfCryptASN1Util.getDERLength(params, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(params, idx);

            /* Decode prime (p) INTEGER */
            if (params[idx++] != 0x02) {
                throw new IOException(
                    "Invalid DH parameters: expected INTEGER tag for p");
            }
            pLen = WolfCryptASN1Util.getDERLength(params, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(params, idx);
            pBytes = new byte[pLen];
            System.arraycopy(params, idx, pBytes, 0, pLen);
            idx += pLen;
            this.p = new BigInteger(1, pBytes);

            /* Decode generator (g) INTEGER */
            if (params[idx++] != 0x02) {
                throw new IOException(
                    "Invalid DH parameters: expected INTEGER tag for g");
            }
            gLen = WolfCryptASN1Util.getDERLength(params, idx);
            idx += WolfCryptASN1Util.getDERLengthSize(params, idx);
            gBytes = new byte[gLen];
            System.arraycopy(params, idx, gBytes, 0, gLen);
            this.g = new BigInteger(1, gBytes);

            /* Private value length not encoded in standard DH params */
            this.l = 0;

        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IOException(
                "Invalid DH parameters encoding: " + e.getMessage());
        }
    }

    @Override
    protected void engineInit(byte[] params, String format)
        throws IOException {

        if (format != null && !format.equalsIgnoreCase("ASN.1") &&
            !format.equalsIgnoreCase("DER")) {
            throw new IOException(
                "Unsupported format: " + format +
                ". Only ASN.1/DER is supported");
        }

        engineInit(params);
    }

    @Override
    protected <T extends AlgorithmParameterSpec>
        T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException {

        if (paramSpec == null) {
            throw new InvalidParameterSpecException(
                "paramSpec cannot be null");
        }

        if (!paramSpec.isAssignableFrom(DHParameterSpec.class)) {
            throw new InvalidParameterSpecException(
                "Only DHParameterSpec is supported");
        }

        if (this.p == null || this.g == null) {
            throw new InvalidParameterSpecException(
                "Parameters not initialized");
        }

        return paramSpec.cast(new DHParameterSpec(this.p, this.g, this.l));
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        return engineGetEncoded("ASN.1");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {

        if (format != null && !format.equalsIgnoreCase("ASN.1") &&
            !format.equalsIgnoreCase("DER")) {
            throw new IOException(
                "Unsupported format: " + format +
                ". Only ASN.1/DER is supported");
        }

        if (this.p == null || this.g == null) {
            throw new IOException("Parameters not initialized");
        }

        try {
            /* Convert BigIntegers to byte arrays */
            byte[] pBytes = this.p.toByteArray();
            byte[] gBytes = this.g.toByteArray();

            /* Encode as ASN.1 SEQUENCE { prime, generator } */
            ByteArrayOutputStream seq = new ByteArrayOutputStream();

            /* Encode p as INTEGER */
            seq.write(0x02); /* INTEGER tag */
            seq.write(WolfCryptASN1Util.encodeDERLength(pBytes.length));
            seq.write(pBytes);

            /* Encode g as INTEGER */
            seq.write(0x02); /* INTEGER tag */
            seq.write(WolfCryptASN1Util.encodeDERLength(gBytes.length));
            seq.write(gBytes);

            byte[] seqBytes = seq.toByteArray();

            /* Wrap in SEQUENCE */
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            result.write(0x30); /* SEQUENCE tag */
            result.write(WolfCryptASN1Util.encodeDERLength(seqBytes.length));
            result.write(seqBytes);

            return result.toByteArray();

        } catch (Exception e) {
            throw new IOException(
                "Failed to encode DH parameters: " + e.getMessage());
        }
    }

    @Override
    protected String engineToString() {
        if (this.p == null || this.g == null) {
            return "DH Parameters: not initialized";
        }

        return "DH Parameters:\n" +
               "  p: " + this.p.toString(16) + "\n" +
               "  g: " + this.g.toString(16) +
               (this.l > 0 ? "\n  l: " + this.l : "");
    }
}


