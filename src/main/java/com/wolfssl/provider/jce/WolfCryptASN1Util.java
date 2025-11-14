/* WolfCryptASN1Util.java
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

/**
 * Utility class for ASN.1/DER encoding and decoding operations.
 *
 * This class provides helper methods for manually constructing DER-encoded
 * structures when native wolfSSL functionality is not available (ex:
 * FIPS builds that do not define WOLFSSL_DH_EXTRA).
 */
public class WolfCryptASN1Util {

    /* ASN.1 Universal Tags */
    static final byte ASN1_INTEGER           = 0x02;
    static final byte ASN1_BIT_STRING        = 0x03;
    static final byte ASN1_OCTET_STRING      = 0x04;
    static final byte ASN1_NULL              = 0x05;
    static final byte ASN1_OBJECT_IDENTIFIER = 0x06;
    static final byte ASN1_SEQUENCE          = 0x30;

    /* ASN.1 Context-Specific Tags (Constructed) */
    static final byte ASN1_CONTEXT_SPECIFIC_0 = (byte)0xa0;
    static final byte ASN1_CONTEXT_SPECIFIC_1 = (byte)0xa1;
    static final byte ASN1_CONTEXT_SPECIFIC_2 = (byte)0xa2;
    static final byte ASN1_CONTEXT_SPECIFIC_3 = (byte)0xa3;

    /* Hash Algorithm OIDs. No tag/length, just encoded value. */
    private static final byte[] OID_SHA1 =
        { 0x2b, 0x0e, 0x03, 0x02, 0x1a };
    private static final byte[] OID_SHA224 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 };
    private static final byte[] OID_SHA256 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
    private static final byte[] OID_SHA384 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
    private static final byte[] OID_SHA512 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
    private static final byte[] OID_SHA512_224 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05 };
    private static final byte[] OID_SHA512_256 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06 };
    private static final byte[] OID_SHA3_224 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07 };
    private static final byte[] OID_SHA3_256 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08 };
    private static final byte[] OID_SHA3_384 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09 };
    private static final byte[] OID_SHA3_512 =
        { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a };

    /* MGF1 OID: 1.2.840.113549.1.1.8 */
    private static final byte[] OID_MGF1 =
        { 0x2a, (byte)0x86, 0x48, (byte)0x86, (byte)0xf7,
         0x0d, 0x01, 0x01, 0x08 };

    /* DH Algorithm OID: 1.2.840.113549.1.3.1 (pkcs-3) */
    private static final byte[] DH_ALGORITHM_OID = {
        (byte)0x06, (byte)0x09,  /* OID tag and length */
        (byte)0x2A, (byte)0x86, (byte)0x48, (byte)0x86,
        (byte)0xF7, (byte)0x0D, (byte)0x01, (byte)0x03,
        (byte)0x01
    };

    /** Private constructor, all methods are static. */
    private WolfCryptASN1Util() {
    }

    /**
     * Encode BigInteger as a DER INTEGER.
     *
     * DER INTEGER format:
     * - Tag: 0x02
     * - Length: variable
     * - Value: big-endian bytes, with leading 0x00 if MSB is set
     *
     * @param value the BigInteger to encode
     *
     * @return DER-encoded INTEGER (tag + length + value)
     *
     * @throws IllegalArgumentException if value is null, or encoding fails
     */
    public static byte[] encodeDERInteger(BigInteger value)
        throws IllegalArgumentException {

        byte[] valueBytes;
        ByteArrayOutputStream out;

        if (value == null) {
            throw new IllegalArgumentException("BigInteger cannot be null");
        }

        /* Get big-endian byte representation */
        valueBytes = value.toByteArray();

        /* BigInteger.toByteArray() handles sign bit correctly:
         * - Positive numbers, adds leading 0x00 if MSB is set
         * - Negative numbers, uses two's complement */
        out = new ByteArrayOutputStream();

        try {
            out.write(ASN1_INTEGER);
            out.write(encodeDERLength(valueBytes.length));
            out.write(valueBytes);

            return out.toByteArray();

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode INTEGER: " + e.getMessage(), e);
        }
    }

    /**
     * Encode contents as a DER SEQUENCE.
     *
     * DER SEQUENCE format:
     * - Tag: 0x30
     * - Length: variable
     * - Contents: concatenated DER-encoded elements
     *
     * @param contents the already-encoded contents to wrap in SEQUENCE
     *
     * @return DER-encoded SEQUENCE (tag + length + contents)
     *
     * @throws IllegalArgumentException if contents is null or encoding fails
     */
    public static byte[] encodeDERSequence(byte[] contents)
        throws IllegalArgumentException {

        ByteArrayOutputStream out;

        if (contents == null) {
            throw new IllegalArgumentException("Contents cannot be null");
        }

        out = new ByteArrayOutputStream();

        try {
            out.write(ASN1_SEQUENCE);
            out.write(encodeDERLength(contents.length));
            out.write(contents);

            return out.toByteArray();

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode SEQUENCE: " + e.getMessage(), e);
        }
    }

    /**
     * Encode contents as a DER OCTET STRING.
     *
     * DER OCTET STRING format:
     * - Tag: 0x04
     * - Length: variable
     * - Contents: raw bytes
     *
     * @param contents the bytes to encode as OCTET STRING
     *
     * @return DER-encoded OCTET STRING (tag + length + contents)
     *
     * @throws IllegalArgumentException if contents is null or encoding fails
     */
    public static byte[] encodeDEROctetString(byte[] contents)
        throws IllegalArgumentException {

        ByteArrayOutputStream out;

        if (contents == null) {
            throw new IllegalArgumentException("Contents cannot be null");
        }

        out = new ByteArrayOutputStream();

        try {
            out.write(ASN1_OCTET_STRING);
            out.write(encodeDERLength(contents.length));
            out.write(contents);

            return out.toByteArray();

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode OCTET STRING: " + e.getMessage(), e);
        }
    }

    /**
     * Encode contents as a DER BIT STRING.
     *
     * DER BIT STRING format:
     * - Tag: 0x03
     * - Length: variable (includes unused bits byte)
     * - Unused bits: 0x00 (we always use whole bytes)
     * - Contents: raw bytes
     *
     * @param contents the bytes to encode as BIT STRING
     *
     * @return DER-encoded BIT STRING (tag + length + 0x00 + contents)
     *
     * @throws IllegalArgumentException if contents is null
     */
    public static byte[] encodeDERBitString(byte[] contents)
        throws IllegalArgumentException {

        ByteArrayOutputStream out;

        if (contents == null) {
            throw new IllegalArgumentException("Contents cannot be null");
        }

        out = new ByteArrayOutputStream();

        try {
            out.write(ASN1_BIT_STRING);
            /* Length includes the unused bits byte */
            out.write(encodeDERLength(contents.length + 1));
            /* Unused bits byte - always 0x00 for whole bytes */
            out.write(0x00);
            out.write(contents);

            return out.toByteArray();

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode BIT STRING: " + e.getMessage(), e);
        }
    }

    /**
     * Encode a length value using DER length encoding rules.
     *
     * DER length encoding:
     * - Short form (length less than 128): one byte with value
     * - Long form (length greater than or equal to 128): first byte has
     *   bit 7 set and lower 7 bits indicate number of following length
     *   bytes, then length bytes in big-endian order
     *
     * Examples:
     * - Length 5: 0x05
     * - Length 200: 0x81 0xC8 (long form, 1 byte follows)
     * - Length 1000: 0x82 0x03 0xE8 (long form, 2 bytes follow)
     *
     * @param length the length to encode (must be non-negative)
     *
     * @return DER-encoded length bytes
     *
     * @throws IllegalArgumentException if length is negative
     */
    public static byte[] encodeDERLength(int length)
        throws IllegalArgumentException {

        int numLengthBytes = 0;
        int tempLength;
        byte[] encoded;

        if (length < 0) {
            throw new IllegalArgumentException(
                "Length cannot be negative: " + length);
        }

        /* Short form: length < 128 */
        if (length < 128) {
            return new byte[] { (byte)length };
        }

        /* Long form: determine how many bytes needed */
        tempLength = length;
        while (tempLength > 0) {
            numLengthBytes++;
            tempLength >>= 8;
        }

        /* First byte: 0x80 | numLengthBytes */
        encoded = new byte[1 + numLengthBytes];
        encoded[0] = (byte)(0x80 | numLengthBytes);

        /* Following bytes: length in big-endian */
        for (int i = 0; i < numLengthBytes; i++) {
            encoded[1 + i] = (byte)(length >> ((numLengthBytes - 1 - i) * 8));
        }

        return encoded;
    }

    /**
     * Get the DER-encoded DH algorithm OID.
     *
     * Returns: 1.2.840.113549.1.3.1 (PKCS #3 DH)
     *
     * @return DER-encoded OBJECT IDENTIFIER for DH algorithm
     */
    public static byte[] getDHAlgorithmOID() {

        return DH_ALGORITHM_OID.clone();
    }

    /**
     * Encode DH parameters (p, g) as a DER SEQUENCE.
     *
     * Structure:
     * SEQUENCE {
     *   p INTEGER
     *   g INTEGER
     * }
     *
     * @param p the prime modulus
     * @param g the generator
     *
     * @return DER-encoded parameter SEQUENCE
     *
     * @throws IllegalArgumentException if p or g is null
     */
    public static byte[] encodeDHParameters(BigInteger p, BigInteger g)
        throws IllegalArgumentException {

        ByteArrayOutputStream out;

        if (p == null || g == null) {
            throw new IllegalArgumentException(
                "DH parameters p and g cannot be null");
        }

        out = new ByteArrayOutputStream();

        try {
            out.write(encodeDERInteger(p));
            out.write(encodeDERInteger(g));

            return encodeDERSequence(out.toByteArray());

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode DH parameters: " + e.getMessage(), e);
        }
    }

    /**
     * Encode DH AlgorithmIdentifier with parameters.
     *
     * Structure:
     * SEQUENCE {
     *   algorithm OBJECT IDENTIFIER (DH OID)
     *   parameters SEQUENCE { p INTEGER, g INTEGER }
     * }
     *
     * @param p the prime modulus
     * @param g the generator
     *
     * @return DER-encoded AlgorithmIdentifier
     *
     * @throws IllegalArgumentException if p or g is null
     */
    public static byte[] encodeDHAlgorithmIdentifier(BigInteger p, BigInteger g)
        throws IllegalArgumentException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            out.write(getDHAlgorithmOID());
            out.write(encodeDHParameters(p, g));

            return encodeDERSequence(out.toByteArray());

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode AlgorithmIdentifier: " +
                e.getMessage(), e);
        }
    }

    /**
     * Decode DER length from encoded bytes.
     *
     * Reads DER length encoding at the specified index and returns the
     * decoded length value.
     *
     * DER length encoding:
     * - Short form (length less than 128): one byte with value
     * - Long form (length greater than or equal to 128): first byte has
     *   bit 7 set and lower 7 bits indicate number of following length
     *   bytes, then length bytes in big-endian order
     *
     * @param data DER-encoded data
     * @param idx index where length encoding starts
     *
     * @return decoded length value
     *
     * @throws IllegalArgumentException if data is null or index is invalid
     * @throws ArrayIndexOutOfBoundsException if data is too short
     */
    public static int getDERLength(byte[] data, int idx)
        throws IllegalArgumentException {

        int len, numBytes, result;

        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (idx < 0 || idx >= data.length) {
            throw new IllegalArgumentException("Invalid index: " + idx);
        }

        len = data[idx] & 0xFF;

        if ((len & 0x80) == 0) {
            /* Short form */
            return len;
        }

        /* Long form */
        numBytes = len & 0x7F;
        result = 0;
        for (int i = 0; i < numBytes; i++) {
            result = (result << 8) | (data[idx + 1 + i] & 0xFF);
        }

        return result;
    }

    /**
     * Get size of DER length encoding at specified index.
     *
     * Returns the number of bytes used to encode the length value
     * at the given index.
     *
     * @param data DER-encoded data
     * @param idx index where length encoding starts
     *
     * @return size of length encoding in bytes (1 for short form,
     *         1 + n for long form)
     *
     * @throws IllegalArgumentException if data is null or index is invalid
     */
    public static int getDERLengthSize(byte[] data, int idx)
        throws IllegalArgumentException {

        int len;

        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (idx < 0 || idx >= data.length) {
            throw new IllegalArgumentException("Invalid index: " + idx);
        }

        len = data[idx] & 0xFF;

        if ((len & 0x80) == 0) {
            /* Short form - 1 byte */
            return 1;
        }

        /* Long form - 1 + number of length bytes */
        return 1 + (len & 0x7F);
    }

    /**
     * Convert BigInteger to byte array, removing leading zero if present.
     *
     * BigInteger.toByteArray() returns a two's complement representation,
     * which includes a leading zero byte if the most significant bit is
     * set (to distinguish positive from negative). This method removes
     * that leading zero byte if present.
     *
     * @param value BigInteger to convert
     *
     * @return byte array representation without unnecessary leading zero
     *
     * @throws IllegalArgumentException if value is null
     */
    public static byte[] bigIntegerToByteArray(BigInteger value)
        throws IllegalArgumentException {

        byte[] bytes, tmp;

        if (value == null) {
            throw new IllegalArgumentException("Value cannot be null");
        }

        bytes = value.toByteArray();

        /* Remove leading zero byte if present (sign bit padding) */
        if (bytes.length > 1 && bytes[0] == 0) {
            tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }

        return bytes;
    }

    /**
     * Encode an integer as a DER INTEGER.
     *
     * DER INTEGER format:
     * - Tag: 0x02
     * - Length: variable
     * - Value: big-endian bytes, with leading 0x00 if MSB is set
     *
     * @param value the integer value to encode (must be non-negative)
     *
     * @return DER-encoded INTEGER (tag + length + value)
     *
     * @throws IllegalArgumentException if value is negative
     */
    static byte[] encodeDERInteger(int value)
        throws IllegalArgumentException {

        ByteArrayOutputStream result;

        if (value < 0) {
            throw new IllegalArgumentException(
                "Negative integers not supported");
        }

        result = new ByteArrayOutputStream();

        try {
            result.write(ASN1_INTEGER);

            if (value == 0) {
                result.write(0x01);
                result.write(0x00);
            }
            else {
                /* Determine minimum bytes needed */
                int temp = value;
                int numBytes = 0;
                while (temp > 0) {
                    numBytes++;
                    temp >>= 8;
                }

                /* Build byte array */
                byte[] bytes = new byte[numBytes];
                int tempValue = value;
                for (int i = numBytes - 1; i >= 0; i--) {
                    bytes[i] = (byte) (tempValue & 0xff);
                    tempValue >>= 8;
                }

                /* Add padding byte if high bit set (to keep positive) */
                if ((bytes[0] & 0x80) != 0) {
                    result.write(encodeDERLength(numBytes + 1));
                    result.write(0x00);
                    result.write(bytes);
                }
                else {
                    result.write(encodeDERLength(numBytes));
                    result.write(bytes);
                }
            }

            return result.toByteArray();

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode INTEGER: " + e.getMessage(), e);
        }
    }

    /**
     * Decode DER length from encoded bytes, returning length and
     * new offset.
     *
     * Reads DER length encoding at the specified offset and returns
     * an array containing [length, newOffset] where newOffset points
     * to the first byte after the length encoding.
     *
     * @param data DER-encoded data
     * @param offset index where length encoding starts
     *
     * @return int array with [length, newOffset]
     *
     * @throws IllegalArgumentException if data is null, offset invalid,
     *         or encoding is invalid
     */
    static int[] decodeDERLengthWithOffset(byte[] data, int offset)
        throws IllegalArgumentException {

        int firstByte, numBytes, length;

        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (offset < 0 || offset >= data.length) {
            throw new IllegalArgumentException(
                "Invalid offset: " + offset);
        }

        firstByte = data[offset++] & 0xff;

        if ((firstByte & 0x80) == 0) {
            /* Short form */
            return new int[] {firstByte, offset};
        }
        else {
            /* Long form */
            numBytes = firstByte & 0x7f;

            if (numBytes == 0) {
                throw new IllegalArgumentException(
                    "Indefinite length encoding not supported");
            }

            if (numBytes > 4) {
                throw new IllegalArgumentException("Length too large");
            }

            if (offset + numBytes > data.length) {
                throw new IllegalArgumentException(
                    "Invalid DER length: extends beyond data");
            }

            length = 0;
            for (int i = 0; i < numBytes; i++) {
                length = (length << 8) | (data[offset++] & 0xff);
            }

            return new int[] {length, offset};
        }
    }

    /**
     * Decode a DER INTEGER value.
     *
     * Decodes a DER-encoded INTEGER (including tag and length) and
     * returns the integer value. Only supports non-negative integers
     * that fit in a Java int (32 bits).
     *
     * @param data DER-encoded INTEGER (including tag and length)
     *
     * @return the decoded integer value
     *
     * @throws IllegalArgumentException if data is null, invalid,
     *         or represents a negative number
     */
    static int decodeDERInteger(byte[] data)
        throws IllegalArgumentException {

        int idx, len, value;
        int[] lenInfo;

        if (data == null || data.length < 3) {
            throw new IllegalArgumentException(
                "Invalid INTEGER: too short");
        }

        idx = 0;

        /* Check INTEGER tag */
        if (data[idx++] != ASN1_INTEGER) {
            throw new IllegalArgumentException(
                "Invalid INTEGER: expected tag 0x02");
        }

        /* Get length */
        lenInfo = decodeDERLengthWithOffset(data, idx);
        len = lenInfo[0];
        idx = lenInfo[1];

        if (len < 1 || len > 4) {
            throw new IllegalArgumentException(
                "Invalid INTEGER: length out of range");
        }

        if (idx + len > data.length) {
            throw new IllegalArgumentException(
                "Invalid INTEGER: value extends beyond data");
        }

        /* Check for negative integers (high bit set on first byte).
         * We don't support negative integers. */
        if ((data[idx] & 0x80) != 0) {
            throw new IllegalArgumentException(
                "Negative integers not supported");
        }

        /* Decode value */
        value = 0;
        for (int i = 0; i < len; i++) {
            value = (value << 8) | (data[idx++] & 0xff);
        }

        return value;
    }

    /**
     * Encode contents as a DER OBJECT IDENTIFIER.
     *
     * DER OBJECT IDENTIFIER format:
     * - Tag: 0x06
     * - Length: variable
     * - Contents: encoded OID bytes
     *
     * @param oidBytes the OID bytes (already encoded, without tag/length)
     *
     * @return DER-encoded OBJECT IDENTIFIER (tag + length + oidBytes)
     *
     * @throws IllegalArgumentException if oidBytes is null
     */
    static byte[] encodeDERObjectIdentifier(byte[] oidBytes)
        throws IllegalArgumentException {

        ByteArrayOutputStream out;

        if (oidBytes == null) {
            throw new IllegalArgumentException("OID bytes cannot be null");
        }

        out = new ByteArrayOutputStream();

        try {
            out.write(ASN1_OBJECT_IDENTIFIER);
            out.write(encodeDERLength(oidBytes.length));
            out.write(oidBytes);

            return out.toByteArray();

        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Failed to encode OBJECT IDENTIFIER: " + e.getMessage(), e);
        }
    }

    /**
     * Encode NULL as a DER NULL.
     *
     * DER NULL format:
     * - Tag: 0x05
     * - Length: 0x00
     *
     * @return DER-encoded NULL (0x05 0x00)
     */
    static byte[] encodeDERNull() {
        return new byte[] {0x05, 0x00};
    }

    /**
     * Get hash algorithm OID bytes.
     *
     * Returns the OID bytes (without tag and length) for the specified
     * hash algorithm.
     *
     * @param hashAlgorithm the hash algorithm name
     *        (e.g., "SHA-1", "SHA-256", etc.)
     *
     * @return OID bytes (cloned array)
     *
     * @throws IllegalArgumentException if hash algorithm not supported
     */
    static byte[] getHashAlgorithmOID(String hashAlgorithm)
        throws IllegalArgumentException {

        if (hashAlgorithm == null) {
            throw new IllegalArgumentException(
                "Hash algorithm cannot be null");
        }

        switch (hashAlgorithm.toUpperCase()) {
            case "SHA-1":
                return OID_SHA1.clone();
            case "SHA-224":
                return OID_SHA224.clone();
            case "SHA-256":
                return OID_SHA256.clone();
            case "SHA-384":
                return OID_SHA384.clone();
            case "SHA-512":
                return OID_SHA512.clone();
            case "SHA-512/224":
                return OID_SHA512_224.clone();
            case "SHA-512/256":
                return OID_SHA512_256.clone();
            case "SHA3-224":
                return OID_SHA3_224.clone();
            case "SHA3-256":
                return OID_SHA3_256.clone();
            case "SHA3-384":
                return OID_SHA3_384.clone();
            case "SHA3-512":
                return OID_SHA3_512.clone();
            default:
                throw new IllegalArgumentException(
                    "Unsupported hash algorithm: " + hashAlgorithm);
        }
    }

    /**
     * Get hash algorithm name from OID bytes.
     *
     * Returns the hash algorithm name for the given OID bytes
     * (without tag and length).
     *
     * @param oidBytes the OID bytes
     *
     * @return hash algorithm name
     *
     * @throws IllegalArgumentException if OID not recognized
     */
    static String getHashAlgorithmName(byte[] oidBytes)
        throws IllegalArgumentException {

        if (oidBytes == null) {
            throw new IllegalArgumentException("OID bytes cannot be null");
        }

        if (bytesEqual(oidBytes, OID_SHA1)) {
            return "SHA-1";
        }
        else if (bytesEqual(oidBytes, OID_SHA224)) {
            return "SHA-224";
        }
        else if (bytesEqual(oidBytes, OID_SHA256)) {
            return "SHA-256";
        }
        else if (bytesEqual(oidBytes, OID_SHA384)) {
            return "SHA-384";
        }
        else if (bytesEqual(oidBytes, OID_SHA512)) {
            return "SHA-512";
        }
        else if (bytesEqual(oidBytes, OID_SHA512_224)) {
            return "SHA-512/224";
        }
        else if (bytesEqual(oidBytes, OID_SHA512_256)) {
            return "SHA-512/256";
        }
        else if (bytesEqual(oidBytes, OID_SHA3_224)) {
            return "SHA3-224";
        }
        else if (bytesEqual(oidBytes, OID_SHA3_256)) {
            return "SHA3-256";
        }
        else if (bytesEqual(oidBytes, OID_SHA3_384)) {
            return "SHA3-384";
        }
        else if (bytesEqual(oidBytes, OID_SHA3_512)) {
            return "SHA3-512";
        }
        else {
            throw new IllegalArgumentException("Unrecognized hash OID");
        }
    }

    /**
     * Get MGF1 algorithm OID bytes.
     *
     * Returns the OID bytes (without tag and length) for MGF1.
     *
     * @return MGF1 OID bytes (cloned array)
     */
    static byte[] getMGF1OID() {
        return OID_MGF1.clone();
    }

    /**
     * Compare two byte arrays for equality, constant time.
     *
     * @param a first array
     * @param b second array
     *
     * @return true if arrays are equal, false otherwise
     */
    static boolean bytesEqual(byte[] a, byte[] b) {
        int result = 0, i = 0;

        if (a == null || b == null || a.length != b.length) {
            return false;
        }

        for (i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }

        if (result == 0) {
            return true;
        }
        return false;
    }
}

