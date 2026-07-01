/* WolfCryptXmssUtil.java
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
import java.util.Arrays;

/**
 * ASN.1/DER helpers for XMSS/XMSS^MT (RFC 8391) public keys.
 *
 * <p>Native wolfCrypt provides a raw XMSS public-key format
 * (wc_XmssKey_Export/ImportPubRaw()) and no SPKI decode, so the X.509
 * SubjectPublicKeyInfo wrapping is done here until native wolfSSL gets that
 * functionality. DER <i>encoding</i> reuses the shared
 * {@link WolfCryptASN1Util} helpers. DER <i>decoding</i> uses a small
 * self-contained strict reader. The XMSS algorithm OIDs are RFC 9802
 * {@code id-alg-xmss-hashsig = 1.3.6.1.5.5.7.6.34} and
 * {@code id-alg-xmssmt-hashsig = 1.3.6.1.5.5.7.6.35}.</p>
 *
 * <p>The DER reader here is intentionally self-contained and stricter than the
 * general-purpose {@link WolfCryptASN1Util}: it checks every tag and rejects
 * non-minimal long-form lengths, because it parses untrusted X.509
 * SubjectPublicKeyInfo input.</p>
 *
 * <p>Public key (SubjectPublicKeyInfo):</p>
 * <pre>
 *   SEQUENCE {
 *     algorithm  SEQUENCE { OBJECT IDENTIFIER } -- parameters absent
 *     subjectPublicKey BIT STRING               -- raw XMSS public key
 *   }
 * </pre>
 * RFC 9802 / BouncyCastle place the raw RFC 8391 public key
 * ({@code 4-byte param-set OID || root || SEED}) directly in the BIT STRING.
 * wolfJCE writes that unwrapped form and reads it. Defensively, an inner
 * OCTET STRING wrapper is also accepted on input: the raw XMSS public key
 * always begins with a 4-byte big-endian parameter-set OID whose first byte is
 * {@code 0x00}, so a leading {@code 0x04} unambiguously means the wrapped form.
 *
 * <p>wolfJCE provides verify-only XMSS support, so there is no private-key
 * encoding here.</p>
 */
final class WolfCryptXmssUtil {

    /* DER tags used here. */
    private static final int TAG_BIT_STRING   = 0x03;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_NULL         = 0x05;
    private static final int TAG_OID          = 0x06;
    private static final int TAG_SEQUENCE     = 0x30;

    /* OID content bytes (no tag/length) for
     * 1.3.6.1.5.5.7.6.34 (id-alg-xmss-hashsig). */
    private static final byte[] OID_XMSS = {
        (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x05, (byte)0x05,
        (byte)0x07, (byte)0x06, (byte)0x22
    };

    /* OID content bytes (no tag/length) for
     * 1.3.6.1.5.5.7.6.35 (id-alg-xmssmt-hashsig). */
    private static final byte[] OID_XMSSMT = {
        (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x05, (byte)0x05,
        (byte)0x07, (byte)0x06, (byte)0x23
    };

    /** Private constructor, all methods are static. */
    private WolfCryptXmssUtil() {
    }

    /**
     * Result of parsing an XMSS SubjectPublicKeyInfo: the raw RFC 8391 public
     * key bytes and the family (single-tree XMSS vs multi-tree XMSS^MT), taken
     * from the AlgorithmIdentifier OID. The family is needed because a raw
     * XMSS public key's 4-byte OID prefix is ambiguous between the two
     * registries.
     */
    static final class ParsedPub {
        /** Raw RFC 8391 public key ({@code OID || root || SEED}). */
        final byte[] raw;
        /** True if the AlgorithmIdentifier was id-alg-xmssmt-hashsig. */
        final boolean isXmssMt;

        ParsedPub(byte[] raw, boolean isXmssMt) {
            this.raw = raw;
            this.isXmssMt = isXmssMt;
        }
    }

    /**
     * Encode a raw XMSS/XMSS^MT public key as an X.509 SubjectPublicKeyInfo
     * DER, RFC 9802 form (raw key directly in the BIT STRING).
     *
     * @param rawPub raw XMSS public key bytes
     * @param isXmssMt true to use the XMSS^MT OID, false for single-tree XMSS
     *
     * @return X.509 SubjectPublicKeyInfo DER
     */
    static byte[] encodePublicKeyDer(byte[] rawPub, boolean isXmssMt) {

        byte[] algId;
        byte[] bitString;

        if (rawPub == null || rawPub.length == 0) {
            throw new IllegalArgumentException(
                "raw public key cannot be null or empty");
        }

        algId = WolfCryptASN1Util.encodeDERSequence(
            WolfCryptASN1Util.encodeDERObjectIdentifier(
                isXmssMt ? OID_XMSSMT : OID_XMSS));

        /* RFC 9802 form: the raw key sits directly in the BIT STRING
         * (encodeDERBitString prepends the 0x00 unused-bits octet). */
        bitString = WolfCryptASN1Util.encodeDERBitString(rawPub);

        return WolfCryptASN1Util.encodeDERSequence(concat(algId, bitString));
    }

    /**
     * Parse an X.509 SubjectPublicKeyInfo DER carrying an XMSS or XMSS^MT
     * public key and return the raw RFC 8391 public key bytes. Accepts either
     * the {@code id-alg-xmss-hashsig} or {@code id-alg-xmssmt-hashsig} OID, and
     * both the RFC 9802 unwrapped form and an inner OCTET STRING wrapped form.
     *
     * @param x509 X.509 SubjectPublicKeyInfo DER
     *
     * @return parsed raw XMSS public key bytes and family
     *
     * @throws IllegalArgumentException if the DER is malformed or not an XMSS
     *         SubjectPublicKeyInfo
     */
    static ParsedPub parsePublicKeyDer(byte[] x509) {

        int end;
        int bsStart;
        int bsEnd;
        int contentStart;
        boolean isXmssMt;
        int[] spki, algId, oid, bitStr, oct;

        if (x509 == null || x509.length == 0) {
            throw new IllegalArgumentException(
                "encoded key cannot be null or empty");
        }

        /* outer SubjectPublicKeyInfo SEQUENCE, no trailing data */
        spki = readTLV(x509, 0, x509.length, TAG_SEQUENCE);
        if (spki[1] != x509.length) {
            throw new IllegalArgumentException(
                "trailing data after SubjectPublicKeyInfo");
        }
        end = spki[1];

        /* AlgorithmIdentifier SEQUENCE { OID [, parameters] }.
         * OID selects the family (XMSS vs XMSS^MT). */
        algId = readTLV(x509, spki[0], end, TAG_SEQUENCE);
        oid = readTLV(x509, algId[0], algId[1], TAG_OID);
        if (regionEquals(x509, oid[0], oid[1], OID_XMSS)) {
            isXmssMt = false;
        }
        else if (regionEquals(x509, oid[0], oid[1], OID_XMSSMT)) {
            isXmssMt = true;
        }
        else {
            throw new IllegalArgumentException(
                "not an XMSS/XMSS^MT AlgorithmIdentifier OID");
        }
        /* RFC 9802 says parameters field is absent for XMSS/XMSS^MT, but
         * also accept an explicit ASN.1 NULL. JDK X.509 re-encodes the
         * AlgorithmIdentifier with a NULL parameters field when it hands a
         * certificate SubjectPublicKeyInfo to this KeyFactory by OID. */
        if (oid[1] != algId[1]) {
            int[] params = readTLV(x509, oid[1], algId[1], TAG_NULL);
            if (params[0] != params[1] || params[1] != algId[1]) {
                throw new IllegalArgumentException(
                    "unexpected AlgorithmIdentifier parameters");
            }
        }

        /* subjectPublicKey BIT STRING, no trailing data */
        bitStr = readTLV(x509, algId[1], end, TAG_BIT_STRING);
        if (bitStr[1] != end) {
            throw new IllegalArgumentException(
                "trailing data after subjectPublicKey");
        }
        bsStart = bitStr[0];
        bsEnd = bitStr[1];
        if (bsStart >= bsEnd) {
            throw new IllegalArgumentException(
                "empty subjectPublicKey BIT STRING");
        }
        if ((x509[bsStart] & 0xFF) != 0x00) {
            throw new IllegalArgumentException(
                "unexpected unused bits in subjectPublicKey");
        }
        contentStart = bsStart + 1;
        if (contentStart >= bsEnd) {
            throw new IllegalArgumentException(
                "missing public key in subjectPublicKey");
        }

        /* The raw XMSS public key always begins with a 4-byte big-endian
         * parameter-set OID whose first byte is 0x00, so a leading 0x04
         * unambiguously means the key was wrapped in an inner OCTET STRING. */
        if ((x509[contentStart] & 0xFF) == TAG_OCTET_STRING) {
            oct = readTLV(x509, contentStart, bsEnd, TAG_OCTET_STRING);
            if (oct[1] != bsEnd) {
                throw new IllegalArgumentException(
                    "trailing data in wrapped public key");
            }
            return new ParsedPub(Arrays.copyOfRange(x509, oct[0], oct[1]),
                isXmssMt);
        }

        return new ParsedPub(Arrays.copyOfRange(x509, contentStart, bsEnd),
            isXmssMt);
    }

    /*
     * Parse a definite-form DER TLV at offset 'off' within [off, limit),
     * requiring the given tag. Returns {contentStart, contentEnd}. Rejects
     * indefinite/non-minimal lengths and overruns.
     */
    private static int[] readTLV(byte[] in, int off, int limit, int tag) {

        int lenByte, contentStart, length, numLenBytes;

        if (off + 2 > limit) {
            throw new IllegalArgumentException(
                "truncated TLV header");
        }

        if ((in[off] & 0xFF) != tag) {
            throw new IllegalArgumentException("unexpected tag 0x" +
                Integer.toHexString(in[off] & 0xFF) + ", expected 0x" +
                Integer.toHexString(tag));
        }

        lenByte = in[off + 1] & 0xFF;

        if (lenByte < 0x80) {
            length = lenByte;
            contentStart = off + 2;
        }
        else {
            numLenBytes = lenByte & 0x7F;

            if (numLenBytes == 0 || numLenBytes > 4) {
                throw new IllegalArgumentException(
                    "unsupported DER length form");
            }

            if (off + 2 + numLenBytes > limit) {
                throw new IllegalArgumentException(
                    "truncated DER length");
            }

            /* The first length octet must be non-zero, otherwise the long
             * form carries redundant leading zero octets (non-minimal). */
            if (in[off + 2] == 0x00) {
                throw new IllegalArgumentException(
                    "non-minimal DER length (leading zero)");
            }
            length = 0;

            for (int i = 0; i < numLenBytes; i++) {
                length = (length << 8) | (in[off + 2 + i] & 0xFF);
            }

            if (length < 0x80) {
                throw new IllegalArgumentException(
                    "non-minimal DER length");
            }

            contentStart = off + 2 + numLenBytes;
        }

        /* contentStart <= limit was checked above, so limit - contentStart is
         * non-negative and a crafted ~2GB long-form length cannot overflow
         * the comparison. */
        if ((length < 0) || (length > limit - contentStart)) {
            throw new IllegalArgumentException(
                "DER length exceeds buffer");
        }

        return new int[] { contentStart, contentStart + length };
    }

    /* Compare a region of 'in' against 'expected'. */
    private static boolean regionEquals(byte[] in, int start, int end,
        byte[] expected) {

        if ((end - start) != expected.length) {
            return false;
        }

        for (int i = 0; i < expected.length; i++) {
            if (in[start + i] != expected[i]) {
                return false;
            }
        }

        return true;
    }

    /* Concatenate byte arrays. */
    private static byte[] concat(byte[]... parts) {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
        }

        return out.toByteArray();
    }
}
