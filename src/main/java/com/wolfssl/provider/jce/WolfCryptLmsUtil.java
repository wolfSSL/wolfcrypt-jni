/* WolfCryptLmsUtil.java
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
 * ASN.1/DER helpers for LMS/HSS (RFC 8554) public keys.
 *
 * <p>Native wolfCrypt provides a raw HSS/LMS public-key format
 * (wc_LmsKey_Export/ImportPubRaw()) and no SPKI decode, so the X.509
 * SubjectPublicKeyInfo wrapping is done here until native wolfSSL gets that
 * functionality. DER <i>encoding</i> reuses the shared
 * {@link WolfCryptASN1Util} helpers. DER <i>decoding</i> uses a small
 * self-contained strict reader. The LMS algorithm OID is
 * {@code id-alg-hss-lms-hashsig = 1.2.840.113549.1.9.16.3.17} (RFC 8708,
 * retained in RFC 9708).</p>
 *
 * <p>The DER reader here is intentionally self-contained and stricter than the
 * general-purpose {@link WolfCryptASN1Util}: it checks every tag and rejects
 * non-minimal long-form lengths, because it parses untrusted X.509
 * SubjectPublicKeyInfo input.</p>
 *
 * <p>Public key (SubjectPublicKeyInfo):</p>
 * <pre>
 *   SEQUENCE {
 *     algorithm  SEQUENCE { OBJECT IDENTIFIER } -- parameters absent or NULL
 *     subjectPublicKey BIT STRING               -- raw HSS/LMS public key
 *   }
 * </pre>
 * The raw HSS/LMS public key has two encodings in the wild: RFC 8708 / JDK
 * &lt;= 23 wrap it in an extra inner OCTET STRING inside the BIT STRING.
 * RFC 9708 / JDK 24+ / BouncyCastle place the raw bytes directly. wolfJCE
 * writes the unwrapped RFC 9708 form and reads both.
 *
 * <p>wolfJCE provides verify-only LMS/HSS support, so there is no private-key
 * encoding here (matching the JDK SUN provider).</p>
 */
final class WolfCryptLmsUtil {

    /* DER tags used here. */
    private static final int TAG_BIT_STRING   = 0x03;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_NULL         = 0x05;
    private static final int TAG_OID          = 0x06;
    private static final int TAG_SEQUENCE     = 0x30;

    /* OID content bytes (no tag/length) for
     * 1.2.840.113549.1.9.16.3.17 (id-alg-hss-lms-hashsig). */
    private static final byte[] OID_HSS_LMS = {
        (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0x86, (byte)0xF7,
        (byte)0x0D, (byte)0x01, (byte)0x09, (byte)0x10, (byte)0x03,
        (byte)0x11
    };

    /** Private constructor, all methods are static. */
    private WolfCryptLmsUtil() {
    }

    /**
     * Encode a raw HSS/LMS public key as an X.509 SubjectPublicKeyInfo DER,
     * RFC 9708 unwrapped form (raw key directly in the BIT STRING).
     *
     * @param rawPub raw HSS/LMS public key bytes
     *
     * @return X.509 SubjectPublicKeyInfo DER
     */
    static byte[] encodePublicKeyDer(byte[] rawPub) {

        byte[] algId;
        byte[] bitString;

        if (rawPub == null || rawPub.length == 0) {
            throw new IllegalArgumentException(
                "raw public key cannot be null or empty");
        }

        algId = WolfCryptASN1Util.encodeDERSequence(
            WolfCryptASN1Util.encodeDERObjectIdentifier(OID_HSS_LMS));

        /* RFC 9708 unwrapped form: the raw key sits directly in the BIT STRING
         * (encodeDERBitString prepends the 0x00 unused-bits octet). */
        bitString = WolfCryptASN1Util.encodeDERBitString(rawPub);

        return WolfCryptASN1Util.encodeDERSequence(concat(algId, bitString));
    }

    /**
     * Parse an X.509 SubjectPublicKeyInfo DER carrying an LMS/HSS public key
     * and return the raw HSS/LMS public key bytes. Accepts both the RFC 9708
     * unwrapped form and the RFC 8708 form (raw key wrapped in an inner OCTET
     * STRING).
     *
     * @param x509 X.509 SubjectPublicKeyInfo DER
     *
     * @return raw HSS/LMS public key bytes
     *
     * @throws IllegalArgumentException if the DER is malformed or not an LMS
     *         SubjectPublicKeyInfo
     */
    static byte[] parsePublicKeyDer(byte[] x509) {

        int end;
        int bsStart;
        int bsEnd;
        int contentStart;
        int[] spki, algId, oid, bitStr, oct, nullParam;

        if (x509 == null || x509.length == 0) {
            throw new IllegalArgumentException(
                "encoded key cannot be null or empty");
        }

        /* outer SubjectPublicKeyInfo SEQUENCE, no trailing data */
        spki = readTLV(x509, 0, x509.length, TAG_SEQUENCE);
        if (spki[1] != x509.length) {
            throw bad("trailing data after SubjectPublicKeyInfo");
        }
        end = spki[1];

        /* AlgorithmIdentifier SEQUENCE { OID [, NULL] }. Parameters should be
         * absent (RFC 8708/9708), but JDK <= 17 re-encodes them as an explicit
         * NULL, so a single trailing NULL is also tolerated. */
        algId = readTLV(x509, spki[0], end, TAG_SEQUENCE);
        oid = readTLV(x509, algId[0], algId[1], TAG_OID);
        if (!regionEquals(x509, oid[0], oid[1], OID_HSS_LMS)) {
            throw bad("not an LMS/HSS AlgorithmIdentifier OID");
        }
        if (oid[1] != algId[1]) {
            /* The parameters must be a single NULL (05 00) */
            if ((x509[oid[1]] & 0xFF) != TAG_NULL) {
                throw bad("unexpected AlgorithmIdentifier parameters");
            }
            nullParam = readTLV(x509, oid[1], algId[1], TAG_NULL);
            if (nullParam[0] != nullParam[1] || nullParam[1] != algId[1]) {
                throw bad("unexpected AlgorithmIdentifier parameters");
            }
        }

        /* subjectPublicKey BIT STRING, no trailing data */
        bitStr = readTLV(x509, algId[1], end, TAG_BIT_STRING);
        if (bitStr[1] != end) {
            throw bad("trailing data after subjectPublicKey");
        }
        bsStart = bitStr[0];
        bsEnd = bitStr[1];
        if (bsStart >= bsEnd) {
            throw bad("empty subjectPublicKey BIT STRING");
        }
        if ((x509[bsStart] & 0xFF) != 0x00) {
            throw bad("unexpected unused bits in subjectPublicKey");
        }
        contentStart = bsStart + 1;
        if (contentStart >= bsEnd) {
            throw bad("missing public key in subjectPublicKey");
        }

        /* RFC 8708 wraps the raw key in an OCTET STRING (tag 0x04). The raw
         * HSS public key always begins with u32(L), L in 1..4, (ie byte
         * 0x00), so a leading 0x04 unambiguously means the wrapped form. */
        if ((x509[contentStart] & 0xFF) == TAG_OCTET_STRING) {
            oct = readTLV(x509, contentStart, bsEnd, TAG_OCTET_STRING);
            if (oct[1] != bsEnd) {
                throw bad("trailing data in wrapped public key");
            }
            return Arrays.copyOfRange(x509, oct[0], oct[1]);
        }

        return Arrays.copyOfRange(x509, contentStart, bsEnd);
    }

    /*
     * Parse a definite-form DER TLV at offset 'off' within [off, limit),
     * requiring the given tag. Returns {contentStart, contentEnd}. Rejects
     * indefinite/non-minimal lengths and overruns.
     */
    private static int[] readTLV(byte[] in, int off, int limit, int tag) {

        int lenByte, contentStart, length, numLenBytes;

        if (off + 2 > limit) {
            throw bad("truncated TLV header");
        }

        if ((in[off] & 0xFF) != tag) {
            throw bad("unexpected tag 0x" +
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
                throw bad("unsupported DER length form");
            }

            if (off + 2 + numLenBytes > limit) {
                throw bad("truncated DER length");
            }
            length = 0;

            for (int i = 0; i < numLenBytes; i++) {
                length = (length << 8) | (in[off + 2 + i] & 0xFF);
            }

            /* Values < 0x80 must use the short form. n-octet length must
             * be n-octets long. */
            if (length < 0x80 ||
                length < (1 << ((numLenBytes - 1) * 8))) {
                throw bad("non-minimal DER length");
            }

            contentStart = off + 2 + numLenBytes;
        }

        /* contentStart <= limit was checked above, so limit - contentStart is
         * non-negative and a crafted ~2GB long-form length cannot overflow
         * the comparison. */
        if ((length < 0) || (length > limit - contentStart)) {
            throw bad("DER length exceeds buffer");
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

    private static IllegalArgumentException bad(String msg) {
        return new IllegalArgumentException("LMS DER parse error: " + msg);
    }
}
