/* WolfCryptMlKemUtil.java
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
import java.io.IOException;
import java.security.Security;
import java.util.Arrays;

import com.wolfssl.wolfcrypt.MlKem;

/**
 * ASN.1/DER helpers for ML-KEM (FIPS 203) keys.
 *
 * Native wolfSSL (as of 5.9.1) provides only raw, fixed-size ML-KEM key
 * encode/decode (wc_MlKemKey_Encode/DecodePublicKey and Encode/
 * DecodePrivateKey), no ASN.1/DER layer for ML-KEM. So both public-key X.509
 * SubjectPublicKeyInfo and the private-key PKCS#8 PrivateKeyInfo wrapping are
 * done here in Java, on top of the primitives in {@link WolfCryptASN1Util}.
 * As native wolfSSL gains functionality, some of this may be migrated to
 * use that instead. The encodings follow RFC 9935 (ML-KEM in X.509/PKCS#8).
 *
 * Public keys (SubjectPublicKeyInfo):
 *   SEQUENCE {
 *     algorithm  SEQUENCE { OBJECT IDENTIFIER }   -- parameters absent
 *     subjectPublicKey BIT STRING                 -- raw encapsulation key
 *   }
 *
 * Private keys (PrivateKeyInfo / OneAsymmetricKey):
 *   SEQUENCE {
 *     version    INTEGER (0)
 *     algorithm  SEQUENCE { OBJECT IDENTIFIER }   -- parameters absent
 *     privateKey OCTET STRING { ML-KEM-PrivateKey }
 *   }
 *
 * where ML-KEM-PrivateKey ::= CHOICE {
 *     seed         [0] OCTET STRING (SIZE (64)),
 *     expandedKey      OCTET STRING,
 *     both             SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
 *   }
 *
 * wolfJCE outputs the expandedKey form by default (compatible with JDK
 * reference implementation) but accepts all three forms on input.
 */
final class WolfCryptMlKemUtil {

    /* ML-KEM OID content bytes (without tag/length).
     * Arc 2.16.840.1.101.3.4.4 = NIST kems, with final arc per parameter
     * set: ML-KEM-512 .1, ML-KEM-768 .2, ML-KEM-1024 .3. */
    private static final byte[] OID_ML_KEM_512 = {
        (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65,
        (byte)0x03, (byte)0x04, (byte)0x04, (byte)0x01
    };
    private static final byte[] OID_ML_KEM_768 = {
        (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65,
        (byte)0x03, (byte)0x04, (byte)0x04, (byte)0x02
    };
    private static final byte[] OID_ML_KEM_1024 = {
        (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01, (byte)0x65,
        (byte)0x03, (byte)0x04, (byte)0x04, (byte)0x03
    };

    /* Context-specific [0] primitive tag (0x80), used for the seed CHOICE.
     * The tag in WolfCryptASN1Util is a signed byte, so mask with 0xFF when
     * comparing against a tag read as an unsigned int. */
    private static final int ASN1_CONTEXT_0_PRIMITIVE =
        WolfCryptASN1Util.ASN1_CONTEXT_SPECIFIC_0_PRIMITIVE & 0xFF;

    /* ML-KEM-PrivateKey PKCS#8 CHOICE output forms. */
    static final int ENCODING_EXPANDED = 0;
    static final int ENCODING_SEED     = 1;
    static final int ENCODING_BOTH     = 2;

    /* JDK Security/system property that controls PKCS#8 output form of newly
     * created ML-KEM private keys. A system property of the same name
     * overrides the Security property, matching JDK behavior. */
    private static final String PKCS8_ENCODING_PROPERTY =
        "jdk.mlkem.pkcs8.encoding";

    /** Private constructor, all methods are static. */
    private WolfCryptMlKemUtil() {
    }

    /**
     * Result of parsing a public key SubjectPublicKeyInfo.
     */
    static final class ParsedPublic {

        final int level;
        final byte[] rawPublic;

        ParsedPublic(int level, byte[] rawPublic) {
            this.level = level;
            this.rawPublic = rawPublic;
        }
    }

    /**
     * Result of parsing a private key PKCS#8 structure. Exactly one or both
     * of seed/expanded will be non-null depending on the CHOICE present.
     */
    static final class ParsedPrivate {

        final int level;
        final byte[] seed;
        final byte[] expanded;

        ParsedPrivate(int level, byte[] seed, byte[] expanded) {
            this.level = level;
            this.seed = seed;
            this.expanded = expanded;
        }
    }

    /**
     * Get the ML-KEM OID content bytes (no tag/length) for a level.
     */
    private static byte[] oidContent(int level)
        throws IllegalArgumentException {

        switch (level) {
            case MlKem.ML_KEM_512:
                return OID_ML_KEM_512;
            case MlKem.ML_KEM_768:
                return OID_ML_KEM_768;
            case MlKem.ML_KEM_1024:
                return OID_ML_KEM_1024;
            default:
                throw new IllegalArgumentException(
                    "Invalid ML-KEM level: " + level);
        }
    }

    /**
     * Map ML-KEM OID content bytes to the corresponding parameter set level.
     */
    private static int levelFromOidContent(byte[] oid)
        throws IllegalArgumentException {

        if (WolfCryptASN1Util.bytesEqual(oid, OID_ML_KEM_512)) {
            return MlKem.ML_KEM_512;
        }
        else if (WolfCryptASN1Util.bytesEqual(oid, OID_ML_KEM_768)) {
            return MlKem.ML_KEM_768;
        }
        else if (WolfCryptASN1Util.bytesEqual(oid, OID_ML_KEM_1024)) {
            return MlKem.ML_KEM_1024;
        }
        else {
            throw new IllegalArgumentException("Unrecognized ML-KEM OID");
        }
    }

    /**
     * Expected raw public (encapsulation) key size for a parameter set.
     */
    private static int expectedPublicKeySize(int level) {

        switch (level) {
            case MlKem.ML_KEM_512:
                return MlKem.ML_KEM_512_PUBLIC_KEY_SIZE;
            case MlKem.ML_KEM_768:
                return MlKem.ML_KEM_768_PUBLIC_KEY_SIZE;
            case MlKem.ML_KEM_1024:
                return MlKem.ML_KEM_1024_PUBLIC_KEY_SIZE;
            default:
                throw new IllegalArgumentException(
                    "Invalid ML-KEM level: " + level);
        }
    }

    /**
     * Expected raw expanded private (decapsulation) key size for a parameter
     * set.
     */
    private static int expectedExpandedKeySize(int level) {
        switch (level) {
            case MlKem.ML_KEM_512:
                return MlKem.ML_KEM_512_PRIVATE_KEY_SIZE;
            case MlKem.ML_KEM_768:
                return MlKem.ML_KEM_768_PRIVATE_KEY_SIZE;
            case MlKem.ML_KEM_1024:
                return MlKem.ML_KEM_1024_PRIVATE_KEY_SIZE;
            default:
                throw new IllegalArgumentException(
                    "Invalid ML-KEM level: " + level);
        }
    }

    /**
     * Ciphertext (encapsulation) size in bytes for a parameter set. Also
     * validates that level is a supported ML-KEM parameter set.
     *
     * @throws IllegalArgumentException if level is unsupported
     */
    static int expectedCiphertextSize(int level)
        throws IllegalArgumentException {

        switch (level) {
            case MlKem.ML_KEM_512:
                return MlKem.ML_KEM_512_CIPHERTEXT_SIZE;
            case MlKem.ML_KEM_768:
                return MlKem.ML_KEM_768_CIPHERTEXT_SIZE;
            case MlKem.ML_KEM_1024:
                return MlKem.ML_KEM_1024_CIPHERTEXT_SIZE;
            default:
                throw new IllegalArgumentException(
                    "Invalid ML-KEM level: " + level);
        }
    }

    /**
     * Validate a raw public (encapsulation) key length against a parameter
     * set. Also validates that level is a supported ML-KEM parameter set.
     *
     * @throws IllegalArgumentException if level is unsupported or the length
     *         does not match the parameter set
     */
    static void checkPublicKeyLength(int level, int len)
        throws IllegalArgumentException {

        /* oidContent() throws for an unsupported parameter set level. */
        oidContent(level);

        if (len != expectedPublicKeySize(level)) {
            throw new IllegalArgumentException(
                "ML-KEM public key length " + len +
                " does not match parameter set");
        }
    }

    /**
     * Validate a raw expanded private (decapsulation) key length against a
     * parameter set. Also validates that level is a supported ML-KEM
     * parameter set.
     *
     * @throws IllegalArgumentException if level is unsupported or the length
     *         does not match the parameter set
     */
    static void checkExpandedKeyLength(int level, int len)
        throws IllegalArgumentException {

        /* oidContent() throws for an unsupported parameter set level. */
        oidContent(level);

        if (len != expectedExpandedKeySize(level)) {
            throw new IllegalArgumentException(
                "ML-KEM private key length " + len +
                " does not match parameter set");
        }
    }

    /**
     * Build the AlgorithmIdentifier SEQUENCE for an ML-KEM level. The
     * parameters field is absent per RFC 9935.
     */
    private static byte[] algorithmId(int level)
        throws IllegalArgumentException {

        byte[] oid =
            WolfCryptASN1Util.encodeDERObjectIdentifier(oidContent(level));

        return WolfCryptASN1Util.encodeDERSequence(oid);
    }

    /**
     * Read a single TLV at offset 'off' in 'd', optionally validating the
     * tag. Returns {contentOffset, contentLength, nextOffset}.
     */
    private static int[] readTLV(byte[] d, int off, int expectedTag)
        throws IllegalArgumentException {

        int tag;
        int[] lenInfo;

        if (d == null || off < 0 || off >= d.length) {
            throw new IllegalArgumentException("Invalid DER: bad offset");
        }

        tag = d[off] & 0xFF;
        /* -1 means "accept any tag". Any other value (including a signed
         * byte constant such as (byte)0x80) is masked and enforced. */
        if (expectedTag != -1 && tag != (expectedTag & 0xFF)) {
            throw new IllegalArgumentException(
                "Invalid DER: expected tag 0x" +
                Integer.toHexString(expectedTag & 0xFF) + ", got 0x" +
                Integer.toHexString(tag));
        }

        lenInfo = WolfCryptASN1Util.decodeDERLengthWithOffset(d, off + 1);

        /* Reject negative (long-form length with the sign bit set) and
         * out of range content lengths without integer overflow. */
        if (lenInfo[0] < 0 || lenInfo[0] > d.length - lenInfo[1]) {
            throw new IllegalArgumentException(
                "Invalid DER: content extends beyond data");
        }

        return new int[] { lenInfo[1], lenInfo[0], lenInfo[1] + lenInfo[0] };
    }

    /**
     * Encode an ML-KEM public key as an X.509 SubjectPublicKeyInfo.
     *
     * @param level ML-KEM parameter set
     * @param rawPublic raw encapsulation key bytes
     *
     * @return DER-encoded SubjectPublicKeyInfo
     */
    static byte[] encodePublicKey(int level, byte[] rawPublic)
        throws IllegalArgumentException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        if (rawPublic == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }

        try {
            out.write(algorithmId(level));
            out.write(WolfCryptASN1Util.encodeDERBitString(rawPublic));

            return WolfCryptASN1Util.encodeDERSequence(out.toByteArray());

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode ML-KEM public key: " + e.getMessage(), e);
        }
    }

    /**
     * Parse an X.509 SubjectPublicKeyInfo into level and raw public key.
     *
     * @param der DER-encoded SubjectPublicKeyInfo
     *
     * @return parsed level and raw public key bytes
     */
    static ParsedPublic parsePublicKey(byte[] der)
        throws IllegalArgumentException {

        int[] seq, alg, oidTlv, bit;
        int level;
        byte[] oid, rawPublic;

        if (der == null) {
            throw new IllegalArgumentException("Encoded key cannot be null");
        }

        /* SubjectPublicKeyInfo SEQUENCE. It's the entire input, reject
         * trailing data (SubjectPublicKeyInfo has no optional fields). */
        seq = readTLV(der, 0, WolfCryptASN1Util.ASN1_SEQUENCE);
        if (seq[2] != der.length) {
            throw new IllegalArgumentException(
                "Invalid DER: trailing data after SubjectPublicKeyInfo");
        }

        /* algorithm AlgorithmIdentifier SEQUENCE { OID } */
        alg = readTLV(der, seq[0], WolfCryptASN1Util.ASN1_SEQUENCE);
        oidTlv = readTLV(der, alg[0], WolfCryptASN1Util.ASN1_OBJECT_IDENTIFIER);
        /* The OID must consume the entire AlgorithmIdentifier SEQUENCE;
         * ML-KEM has no algorithm parameters (RFC 9935). */
        if (oidTlv[2] != alg[2]) {
            throw new IllegalArgumentException(
                "Invalid DER: unexpected ML-KEM algorithm parameters");
        }
        oid = Arrays.copyOfRange(der, oidTlv[0], oidTlv[0] + oidTlv[1]);
        level = levelFromOidContent(oid);

        /* subjectPublicKey BIT STRING, first content byte is unused bits.
         * It must be the final element of the SubjectPublicKeyInfo. */
        bit = readTLV(der, alg[2], WolfCryptASN1Util.ASN1_BIT_STRING);
        if (bit[2] != seq[2]) {
            throw new IllegalArgumentException(
                "Invalid DER: trailing data in SubjectPublicKeyInfo");
        }
        if (bit[1] < 1 || (der[bit[0]] & 0xFF) != 0x00) {
            throw new IllegalArgumentException(
                "Invalid ML-KEM public key BIT STRING");
        }
        rawPublic = Arrays.copyOfRange(der, bit[0] + 1, bit[0] + bit[1]);

        if (rawPublic.length != expectedPublicKeySize(level)) {
            throw new IllegalArgumentException(
                "ML-KEM public key length " + rawPublic.length +
                " does not match parameter set");
        }

        return new ParsedPublic(level, rawPublic);
    }

    /**
     * Encode an ML-KEM private key as PKCS#8 using the expandedKey CHOICE.
     *
     * @param level ML-KEM parameter set
     * @param expanded raw expanded (FIPS 203) decapsulation key bytes
     *
     * @return DER-encoded PrivateKeyInfo
     */
    static byte[] encodePrivateKeyExpanded(int level, byte[] expanded)
        throws IllegalArgumentException {

        byte[] choice;

        if (expanded == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }

        /* expandedKey CHOICE is a universal OCTET STRING */
        choice = WolfCryptASN1Util.encodeDEROctetString(expanded);
        return wrapPkcs8(level, choice);
    }

    /**
     * Encode an ML-KEM private key as PKCS#8 using the seed [0] CHOICE.
     *
     * @param level ML-KEM parameter set
     * @param seed 64-byte FIPS 203 key generation seed
     *
     * @return DER-encoded PrivateKeyInfo
     */
    static byte[] encodePrivateKeySeed(int level, byte[] seed)
        throws IllegalArgumentException {

        ByteArrayOutputStream choice = new ByteArrayOutputStream();

        if (seed == null || seed.length != MlKem.ML_KEM_SEED_SIZE) {
            throw new IllegalArgumentException(
                "ML-KEM seed must be " + MlKem.ML_KEM_SEED_SIZE + " bytes");
        }

        try {
            /* seed [0] IMPLICIT OCTET STRING, context primitive tag 0x80 */
            choice.write(ASN1_CONTEXT_0_PRIMITIVE);
            choice.write(WolfCryptASN1Util.encodeDERLength(seed.length));
            choice.write(seed);

            return wrapPkcs8(level, choice.toByteArray());

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode ML-KEM seed key: " + e.getMessage(), e);
        }
    }

    /**
     * Encode an ML-KEM private key as PKCS#8 using the both CHOICE, a
     * SEQUENCE of the seed and the expanded key.
     *
     * @param level ML-KEM parameter set
     * @param seed 64-byte FIPS 203 key generation seed
     * @param expanded raw expanded (FIPS 203) decapsulation key bytes
     *
     * @return DER-encoded PrivateKeyInfo
     */
    static byte[] encodePrivateKeyBoth(int level, byte[] seed, byte[] expanded)
        throws IllegalArgumentException {

        ByteArrayOutputStream seq = new ByteArrayOutputStream();

        if (seed == null || seed.length != MlKem.ML_KEM_SEED_SIZE ||
            expanded == null) {
            throw new IllegalArgumentException(
                "ML-KEM both encoding requires a " + MlKem.ML_KEM_SEED_SIZE +
                "-byte seed and expanded key");
        }

        try {
            /* both ::= SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
             * Note: inside the SEQUENCE the seed is a universal OCTET STRING,
             * not the [0] context tag used by the standalone seed CHOICE. */
            seq.write(WolfCryptASN1Util.encodeDEROctetString(seed));
            seq.write(WolfCryptASN1Util.encodeDEROctetString(expanded));

            return wrapPkcs8(level,
                WolfCryptASN1Util.encodeDERSequence(seq.toByteArray()));

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode ML-KEM both key: " + e.getMessage(), e);
        }
    }

    /**
     * Determine ML-KEM PKCS#8 private key output form from the
     * {@code jdk.mlkem.pkcs8.encoding} property (system property overrides
     * Security property), matching JDK reference implementation. wolfJCE
     * defaults to the expandedKey form when the property is unset or
     * unrecognized, as it is importable by the widest range of providers
     * (including JDK 24, which only understands expandedKey).
     *
     * @return one of {@link #ENCODING_EXPANDED}, {@link #ENCODING_SEED},
     *         {@link #ENCODING_BOTH}
     */
    static int configuredPkcs8Encoding() {

        /* The system property takes precedence over the Security property
         * only when set to a recognized value. An unset or unrecognized value
         * at one source falls through to the next, then to the default. */
        int enc;

        try {
            enc = parseEncoding(System.getProperty(PKCS8_ENCODING_PROPERTY));
        } catch (Exception e) {
            enc = -1;
        }

        if (enc >= 0) {
            return enc;
        }

        try {
            enc = parseEncoding(Security.getProperty(PKCS8_ENCODING_PROPERTY));
        } catch (Exception e) {
            enc = -1;
        }

        if (enc >= 0) {
            return enc;
        }

        /* Unset or unrecognized at both sources: wolfJCE default. */
        return ENCODING_EXPANDED;
    }

    /**
     * Parse a {@code jdk.mlkem.pkcs8.encoding} value to an ENCODING_*
     * constant, or -1 if null or unrecognized. Case-insensitive.
     */
    private static int parseEncoding(String value) {

        if (value == null) {
            return -1;
        }

        value = value.trim();

        if (value.equalsIgnoreCase("seed")) {
            return ENCODING_SEED;
        }
        else if (value.equalsIgnoreCase("both")) {
            return ENCODING_BOTH;
        }
        else if (value.equalsIgnoreCase("expandedKey")) {
            return ENCODING_EXPANDED;
        }

        return -1;
    }

    /**
     * Check whether an algorithm name identifies an ML-KEM key. Accepts the
     * family name and the parameter-set-specific names.
     *
     * @param alg algorithm name from a Key
     *
     * @return true if the name is an ML-KEM family or parameter-set name
     */
    static boolean isMlKemAlgorithm(String alg) {

        if (alg == null) {
            return false;
        }

        String upper = alg.toUpperCase();
        return upper.equals("ML-KEM") || upper.equals("ML-KEM-512") ||
               upper.equals("ML-KEM-768") || upper.equals("ML-KEM-1024");
    }

    /**
     * Wrap an ML-KEM-PrivateKey CHOICE encoding in the PKCS#8 PrivateKeyInfo
     * structure (version, algorithm, privateKey OCTET STRING).
     */
    private static byte[] wrapPkcs8(int level, byte[] choice)
        throws IllegalArgumentException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            out.write(WolfCryptASN1Util.encodeDERInteger(0));
            out.write(algorithmId(level));
            out.write(WolfCryptASN1Util.encodeDEROctetString(choice));

            return WolfCryptASN1Util.encodeDERSequence(out.toByteArray());

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode ML-KEM private key: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a PKCS#8 PrivateKeyInfo into level and seed/expanded key material.
     * Accepts all three ML-KEM-PrivateKey CHOICE alternatives: seed [0],
     * expandedKey OCTET STRING, and both SEQUENCE.
     *
     * @param der DER-encoded PrivateKeyInfo
     *
     * @return parsed level with seed and/or expanded key material
     */
    static ParsedPrivate parsePrivateKey(byte[] der)
        throws IllegalArgumentException {

        int[] seq, ver, alg, oidTlv, pk;
        int level, innerOff, choiceTag, choiceEnd;
        byte[] oid, seed = null, expanded = null;

        if (der == null) {
            throw new IllegalArgumentException("Encoded key cannot be null");
        }

        /* PrivateKeyInfo SEQUENCE, the entire input. Reject trailing
         * data after it. */
        seq = readTLV(der, 0, WolfCryptASN1Util.ASN1_SEQUENCE);
        if (seq[2] != der.length) {
            throw new IllegalArgumentException(
                "Invalid DER: trailing data after PrivateKeyInfo");
        }

        /* version INTEGER, must be v1(0) for an ML-KEM PrivateKeyInfo. */
        ver = readTLV(der, seq[0], WolfCryptASN1Util.ASN1_INTEGER);
        if (ver[1] != 1 || (der[ver[0]] & 0xFF) != 0x00) {
            throw new IllegalArgumentException(
                "Invalid ML-KEM private key: unsupported version");
        }

        /* privateKeyAlgorithm AlgorithmIdentifier SEQUENCE { OID } */
        alg = readTLV(der, ver[2], WolfCryptASN1Util.ASN1_SEQUENCE);
        oidTlv = readTLV(der, alg[0], WolfCryptASN1Util.ASN1_OBJECT_IDENTIFIER);
        /* The OID must consume the entire AlgorithmIdentifier SEQUENCE;
         * ML-KEM has no algorithm parameters (RFC 9935). */
        if (oidTlv[2] != alg[2]) {
            throw new IllegalArgumentException(
                "Invalid DER: unexpected ML-KEM algorithm parameters");
        }
        oid = Arrays.copyOfRange(der, oidTlv[0], oidTlv[0] + oidTlv[1]);
        level = levelFromOidContent(oid);

        /* privateKey OCTET STRING wrapping the ML-KEM-PrivateKey CHOICE */
        pk = readTLV(der, alg[2], WolfCryptASN1Util.ASN1_OCTET_STRING);
        if (pk[1] < 1) {
            throw new IllegalArgumentException(
                "Invalid ML-KEM private key: empty privateKey OCTET STRING");
        }

        /* privateKey must be the final element, reject trailing optional
         * fields (attributes/publicKey) we do not parse. */
        if (pk[2] != seq[2]) {
            throw new IllegalArgumentException(
                "Invalid ML-KEM private key: trailing data after privateKey");
        }
        innerOff = pk[0];
        choiceTag = der[innerOff] & 0xFF;

        if (choiceTag == ASN1_CONTEXT_0_PRIMITIVE) {
            /* seed [0] IMPLICIT OCTET STRING (RFC 9935) */
            int[] s = readTLV(der, innerOff, ASN1_CONTEXT_0_PRIMITIVE);
            seed = Arrays.copyOfRange(der, s[0], s[0] + s[1]);
            choiceEnd = s[2];
        }
        else if (choiceTag == WolfCryptASN1Util.ASN1_OCTET_STRING) {
            /* expandedKey OCTET STRING */
            int[] e = readTLV(der, innerOff,
                WolfCryptASN1Util.ASN1_OCTET_STRING);
            expanded = Arrays.copyOfRange(der, e[0], e[0] + e[1]);
            choiceEnd = e[2];
        }
        else if (choiceTag == WolfCryptASN1Util.ASN1_SEQUENCE) {
            /* both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING } */
            int[] both = readTLV(der, innerOff,
                WolfCryptASN1Util.ASN1_SEQUENCE);
            int[] s = readTLV(der, both[0],
                WolfCryptASN1Util.ASN1_OCTET_STRING);
            int[] e = readTLV(der, s[2],
                WolfCryptASN1Util.ASN1_OCTET_STRING);
            /* The two OCTET STRINGs must consume the whole SEQUENCE. */
            if (e[2] != both[2]) {
                throw new IllegalArgumentException(
                    "Invalid ML-KEM private key: trailing data in both form");
            }
            seed = Arrays.copyOfRange(der, s[0], s[0] + s[1]);
            expanded = Arrays.copyOfRange(der, e[0], e[0] + e[1]);
            choiceEnd = both[2];
        }
        else {
            throw new IllegalArgumentException(
                "Unsupported ML-KEM private key encoding, tag 0x" +
                Integer.toHexString(choiceTag));
        }

        /* The ML-KEM-PrivateKey CHOICE must consume the entire privateKey
         * OCTET STRING content. Reject trailing data. */
        if (choiceEnd != innerOff + pk[1]) {
            throw new IllegalArgumentException(
                "Invalid ML-KEM private key: trailing data after key material");
        }

        /* Validate key-material lengths against the parameter set. */
        if (seed != null && seed.length != MlKem.ML_KEM_SEED_SIZE) {
            throw new IllegalArgumentException(
                "ML-KEM seed length " + seed.length + " is invalid");
        }

        if (expanded != null &&
            expanded.length != expectedExpandedKeySize(level)) {
            throw new IllegalArgumentException(
                "ML-KEM private key length " + expanded.length +
                " does not match parameter set");
        }

        if (seed == null && expanded == null) {
            throw new IllegalArgumentException(
                "ML-KEM private key contained no key material");
        }

        return new ParsedPrivate(level, seed, expanded);
    }
}
