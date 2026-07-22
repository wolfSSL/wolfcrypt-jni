/* WolfCryptSpkiUtil.java
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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * ASN.1/DER X.509 SubjectPublicKeyInfo helpers for the hash-based signature
 * public keys wolfJCE wraps in Java: LMS/HSS (RFC 8554) and XMSS/XMSS^MT
 * (RFC 8391). Native wolfCrypt only provides raw public-key import/export
 * for these algorithms (wc_LmsKey/wc_XmssKey Export/ImportPubRaw()) and no
 * SPKI decode, so the SPKI wrapping is done here until native wolfSSL gets
 * that functionality.
 *
 * <p>DER <i>encoding</i> reuses the shared {@link WolfCryptASN1Util}
 * helpers. DER <i>decoding</i> uses the strict reader here: it checks every
 * tag and rejects indefinite and non-minimal lengths, because it parses
 * untrusted X.509 SubjectPublicKeyInfo input. This reader is intentionally
 * separate from and stricter than the general-purpose
 * {@link WolfCryptASN1Util}.</p>
 *
 * <p>SubjectPublicKeyInfo layout produced and parsed here:</p>
 * <pre>
 *   SEQUENCE {
 *     algorithm  SEQUENCE { OBJECT IDENTIFIER } -- params absent or NULL
 *     subjectPublicKey BIT STRING               -- raw public key
 *   }
 * </pre>
 *
 * <p>Encoding places the raw key directly in the BIT STRING: the RFC 9708
 * form for LMS ({@code id-alg-hss-lms-hashsig = 1.2.840.113549.1.9.16.3.17},
 * assigned in RFC 8708 and retained in RFC 9708) and the RFC 9802 form for
 * XMSS/XMSS^MT ({@code id-alg-xmss-hashsig = 1.3.6.1.5.5.7.6.34},
 * {@code id-alg-xmssmt-hashsig = 1.3.6.1.5.5.7.6.35}). Parsing also accepts
 * the raw key wrapped in an inner OCTET STRING (the RFC 8708 / JDK &lt;= 23
 * form): the raw LMS and XMSS public keys always begin with a 4-byte
 * big-endian word whose first byte is 0x00, so a leading 0x04 unambiguously
 * means the wrapped form. Parsing also tolerates an explicit ASN.1 NULL in
 * the AlgorithmIdentifier parameters, which the JDK X.509 stack re-encodes
 * even where the RFCs say absent.</p>
 *
 * <p>wolfJCE provides verify-only LMS and XMSS support, so there are no
 * private-key encodings here (matching the JDK SUN provider posture).</p>
 */
final class WolfCryptSpkiUtil {

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

    /* Index of OID_XMSSMT in the allowed-OID array used by
     * parseXmssPublicKeyDer(). */
    private static final int OID_INDEX_XMSSMT = 1;

    /** Private constructor, all methods are static. */
    private WolfCryptSpkiUtil() {
    }

    /**
     * If the SubjectPublicKeyInfo AlgorithmIdentifier carries an explicit
     * NULL parameters field, return a copy re-encoded with the parameters
     * absent, otherwise return the input unchanged.
     *
     * <p>JDK X.509 stack can re-encode an absent AlgorithmIdentifier param
     * field as an explicit ASN.1 NULL when routing a certificate public key
     * to a KeyFactory by OID. Native wolfSSL SLH-DSA SPKI decode requires
     * the parameters to be absent (RFC 9909), so callers normalize with this
     * before handing DER to native.</p>
     *
     * @param spki X.509 SubjectPublicKeyInfo DER
     *
     * @return spki with an explicit NULL AlgorithmIdentifier parameters
     *         field removed, or the input reference unchanged
     */
    static byte[] stripNullAlgIdParams(byte[] spki) {

        int[] outer, algId, oid, nullParam;
        byte[] oidTlv;
        byte[] restTlv;
        byte[] newAlgId;

        if (spki == null || spki.length == 0) {
            return spki;
        }

        try {
            /* outer SEQUENCE, AlgorithmIdentifier SEQUENCE { OID ... } */
            outer = readTLV(spki, 0, spki.length, TAG_SEQUENCE, "SPKI");
            algId = readTLV(spki, outer[0], outer[1], TAG_SEQUENCE, "SPKI");
            oid = readTLV(spki, algId[0], algId[1], TAG_OID, "SPKI");

            if (oid[1] == algId[1]) {
                /* parameters already absent */
                return spki;
            }

            /* Only rewrite the single explicit NULL (05 00) form. */
            nullParam = readTLV(spki, oid[1], algId[1], TAG_NULL, "SPKI");
            if (nullParam[0] != nullParam[1] || nullParam[1] != algId[1]) {
                return spki;
            }
        }
        catch (IllegalArgumentException e) {
            /* not the expected shape, let the native decoder report it */
            return spki;
        }

        /* Rebuild: SEQUENCE { SEQUENCE { OID }, <rest unchanged> }. The
         * OID TLV starts at the AlgorithmIdentifier content start, the
         * rest (subjectPublicKey BIT STRING) follows the old algId TLV. */
        oidTlv = Arrays.copyOfRange(spki, algId[0], oid[1]);
        restTlv = Arrays.copyOfRange(spki, algId[1], outer[1]);
        newAlgId = WolfCryptASN1Util.encodeDERSequence(oidTlv);

        return WolfCryptASN1Util.encodeDERSequence(
            concat(newAlgId, restTlv));
    }

    /**
     * Result of parsing an XMSS SubjectPublicKeyInfo: the raw RFC 8391
     * public key bytes and the family (single-tree XMSS vs multi-tree
     * XMSS^MT), taken from the AlgorithmIdentifier OID. The family is needed
     * because a raw XMSS public key's 4-byte OID prefix is ambiguous between
     * the two registries.
     */
    static final class ParsedXmssPub {
        /** Raw RFC 8391 public key ({@code OID || root || SEED}). */
        final byte[] raw;
        /** True if the AlgorithmIdentifier was id-alg-xmssmt-hashsig. */
        final boolean isXmssMt;

        ParsedXmssPub(byte[] raw, boolean isXmssMt) {
            this.raw = raw;
            this.isXmssMt = isXmssMt;
        }
    }

    /**
     * Encode a raw HSS/LMS public key as an X.509 SubjectPublicKeyInfo DER,
     * RFC 9708 unwrapped form (raw key directly in the BIT STRING).
     *
     * @param rawPub raw HSS/LMS public key bytes
     *
     * @return X.509 SubjectPublicKeyInfo DER
     */
    static byte[] encodeLmsPublicKeyDer(byte[] rawPub) {

        return encodeSpki(rawPub, OID_HSS_LMS);
    }

    /**
     * Parse an X.509 SubjectPublicKeyInfo DER carrying an LMS/HSS public
     * key and return the raw HSS/LMS public key bytes. Accepts both the
     * RFC 9708 unwrapped form and the RFC 8708 form (raw key wrapped in an
     * inner OCTET STRING).
     *
     * @param x509 X.509 SubjectPublicKeyInfo DER
     *
     * @return raw HSS/LMS public key bytes
     *
     * @throws IllegalArgumentException if the DER is malformed or not an
     *         LMS SubjectPublicKeyInfo
     */
    static byte[] parseLmsPublicKeyDer(byte[] x509) {

        return parseSpki(x509, new byte[][] { OID_HSS_LMS }, "LMS").raw;
    }

    /**
     * Encode a raw XMSS/XMSS^MT public key as an X.509 SubjectPublicKeyInfo
     * DER, RFC 9802 form (raw key directly in the BIT STRING).
     *
     * @param rawPub raw XMSS public key bytes
     * @param isXmssMt true to use the XMSS^MT OID, false for single-tree
     *        XMSS
     *
     * @return X.509 SubjectPublicKeyInfo DER
     */
    static byte[] encodeXmssPublicKeyDer(byte[] rawPub, boolean isXmssMt) {

        return encodeSpki(rawPub, isXmssMt ? OID_XMSSMT : OID_XMSS);
    }

    /**
     * Parse an X.509 SubjectPublicKeyInfo DER carrying an XMSS or XMSS^MT
     * public key and return the raw RFC 8391 public key bytes and family.
     * Accepts either the {@code id-alg-xmss-hashsig} or
     * {@code id-alg-xmssmt-hashsig} OID, and both the RFC 9802 unwrapped
     * form and an inner OCTET STRING wrapped form.
     *
     * @param x509 X.509 SubjectPublicKeyInfo DER
     *
     * @return parsed raw XMSS public key bytes and family
     *
     * @throws IllegalArgumentException if the DER is malformed or not an
     *         XMSS SubjectPublicKeyInfo
     */
    static ParsedXmssPub parseXmssPublicKeyDer(byte[] x509) {

        ParsedSpki parsed = parseSpki(x509,
            new byte[][] { OID_XMSS, OID_XMSSMT }, "XMSS");

        return new ParsedXmssPub(parsed.raw,
            parsed.oidIndex == OID_INDEX_XMSSMT);
    }

    /* Raw public key bytes plus the index (into the allowed-OID array) of
     * the AlgorithmIdentifier OID that matched. */
    private static final class ParsedSpki {

        final byte[] raw;
        final int oidIndex;

        ParsedSpki(byte[] raw, int oidIndex) {
            this.raw = raw;
            this.oidIndex = oidIndex;
        }
    }

    /*
     * Encode a raw public key as SubjectPublicKeyInfo DER with the raw key
     * directly in the BIT STRING and no AlgorithmIdentifier parameters.
     */
    private static byte[] encodeSpki(byte[] rawPub, byte[] oidContent) {

        byte[] algId;
        byte[] bitString;

        if (rawPub == null || rawPub.length == 0) {
            throw new IllegalArgumentException(
                "raw public key cannot be null or empty");
        }

        algId = WolfCryptASN1Util.encodeDERSequence(
            WolfCryptASN1Util.encodeDERObjectIdentifier(oidContent));

        /* The raw key sits directly in the BIT STRING (encodeDERBitString
         * prepends the 0x00 unused-bits octet). */
        bitString = WolfCryptASN1Util.encodeDERBitString(rawPub);

        return WolfCryptASN1Util.encodeDERSequence(concat(algId, bitString));
    }

    /*
     * Strict SubjectPublicKeyInfo parse. Returns the raw public key bytes
     * from the BIT STRING (unwrapping one inner OCTET STRING if present)
     * and which of the allowed AlgorithmIdentifier OIDs matched. algLabel
     * is used to prefix parse error messages.
     */
    private static ParsedSpki parseSpki(byte[] x509, byte[][] allowedOids,
        String algLabel) {

        int end;
        int bsStart;
        int bsEnd;
        int contentStart;
        int oidIndex = -1;
        int[] spki, algId, oid, bitStr, oct, nullParam;

        if (x509 == null || x509.length == 0) {
            throw new IllegalArgumentException(
                "encoded key cannot be null or empty");
        }

        /* outer SubjectPublicKeyInfo SEQUENCE, no trailing data */
        spki = readTLV(x509, 0, x509.length, TAG_SEQUENCE, algLabel);
        if (spki[1] != x509.length) {
            throw bad(algLabel, "trailing data after SubjectPublicKeyInfo");
        }
        end = spki[1];

        /* AlgorithmIdentifier SEQUENCE { OID [, NULL] }. Parameters should
         * be absent, but the JDK X.509 stack re-encodes them as an explicit
         * NULL, so a single trailing NULL is also tolerated. */
        algId = readTLV(x509, spki[0], end, TAG_SEQUENCE, algLabel);
        oid = readTLV(x509, algId[0], algId[1], TAG_OID, algLabel);
        for (int i = 0; i < allowedOids.length; i++) {
            if (regionEquals(x509, oid[0], oid[1], allowedOids[i])) {
                oidIndex = i;
                break;
            }
        }
        if (oidIndex < 0) {
            throw bad(algLabel, "unexpected AlgorithmIdentifier OID");
        }
        if (oid[1] != algId[1]) {
            /* The parameters must be a single NULL (05 00) */
            nullParam = readTLV(x509, oid[1], algId[1], TAG_NULL, algLabel);
            if (nullParam[0] != nullParam[1] || nullParam[1] != algId[1]) {
                throw bad(algLabel,
                    "unexpected AlgorithmIdentifier parameters");
            }
        }

        /* subjectPublicKey BIT STRING, no trailing data */
        bitStr = readTLV(x509, algId[1], end, TAG_BIT_STRING, algLabel);
        if (bitStr[1] != end) {
            throw bad(algLabel, "trailing data after subjectPublicKey");
        }
        bsStart = bitStr[0];
        bsEnd = bitStr[1];
        if (bsStart >= bsEnd) {
            throw bad(algLabel, "empty subjectPublicKey BIT STRING");
        }
        if ((x509[bsStart] & 0xFF) != 0x00) {
            throw bad(algLabel, "unexpected unused bits in subjectPublicKey");
        }
        contentStart = bsStart + 1;
        if (contentStart >= bsEnd) {
            throw bad(algLabel, "missing public key in subjectPublicKey");
        }

        /* An inner OCTET STRING wrapper means the RFC 8708 / older-JDK
         * form. The raw LMS and XMSS keys start with a 0x00 byte, so a
         * leading 0x04 unambiguously means the wrapped form. */
        if ((x509[contentStart] & 0xFF) == TAG_OCTET_STRING) {
            oct = readTLV(x509, contentStart, bsEnd, TAG_OCTET_STRING,
                algLabel);
            if (oct[1] != bsEnd) {
                throw bad(algLabel, "trailing data in wrapped public key");
            }
            return new ParsedSpki(
                Arrays.copyOfRange(x509, oct[0], oct[1]), oidIndex);
        }

        return new ParsedSpki(
            Arrays.copyOfRange(x509, contentStart, bsEnd), oidIndex);
    }

    /*
     * Parse a definite-form DER TLV at offset 'off' within [off, limit),
     * requiring the given tag. Returns {contentStart, contentEnd}. Rejects
     * indefinite/non-minimal lengths and overruns.
     */
    private static int[] readTLV(byte[] in, int off, int limit, int tag,
        String algLabel) {

        int lenByte, contentStart, length, numLenBytes;

        if (off + 2 > limit) {
            throw bad(algLabel, "truncated TLV header");
        }

        if ((in[off] & 0xFF) != tag) {
            throw bad(algLabel, "unexpected tag 0x" +
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
                throw bad(algLabel, "unsupported DER length form");
            }

            if (off + 2 + numLenBytes > limit) {
                throw bad(algLabel, "truncated DER length");
            }
            length = 0;

            for (int i = 0; i < numLenBytes; i++) {
                length = (length << 8) | (in[off + 2 + i] & 0xFF);
            }

            /* Values < 0x80 must use the short form, and an n-octet length
             * must actually need n octets (no leading zero octets). */
            if (length < 0x80 ||
                length < (1 << ((numLenBytes - 1) * 8))) {
                throw bad(algLabel, "non-minimal DER length");
            }

            contentStart = off + 2 + numLenBytes;
        }

        /* contentStart <= limit was checked above, so limit - contentStart
         * is non-negative and a crafted ~2GB long-form length cannot
         * overflow the comparison. */
        if ((length < 0) || (length > limit - contentStart)) {
            throw bad(algLabel, "DER length exceeds buffer");
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

    private static IllegalArgumentException bad(String algLabel, String msg) {
        return new IllegalArgumentException(
            algLabel + " DER parse error: " + msg);
    }
}
