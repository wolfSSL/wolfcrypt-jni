/* WolfCryptASN1UtilTest.java
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;

import org.junit.Rule;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.math.BigInteger;

import com.wolfssl.provider.jce.WolfCryptASN1Util;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * JUnit test class for WolfCryptASN1Util DER encoding utilities.
 */
public class WolfCryptASN1UtilTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* ASN.1 Universal Tags */
    private static final byte ASN1_INTEGER = 0x02;
    private static final byte ASN1_BIT_STRING = 0x03;
    private static final byte ASN1_OCTET_STRING = 0x04;
    private static final byte ASN1_OBJECT_IDENTIFIER = 0x06;
    private static final byte ASN1_SEQUENCE = 0x30;

    @BeforeClass
    public static void testEntry() {
        System.out.println("JCE WolfCryptASN1UtilTest Class");
    }

    @Test
    public void testEncodeDERLengthShortForm() throws Exception {
        /* Short form: length < 128 */
        byte[] result = WolfCryptASN1Util.encodeDERLength(0);
        assertArrayEquals(new byte[] { 0x00 }, result);

        result = WolfCryptASN1Util.encodeDERLength(1);
        assertArrayEquals(new byte[] { 0x01 }, result);

        result = WolfCryptASN1Util.encodeDERLength(127);
        assertArrayEquals(new byte[] { 0x7F }, result);
    }

    @Test
    public void testEncodeDERLengthLongFormOneByte() throws Exception {
        /* Long form: length = 128 (requires 1 length byte) */
        byte[] result = WolfCryptASN1Util.encodeDERLength(128);
        assertArrayEquals(new byte[] { (byte)0x81, (byte)0x80 }, result);

        result = WolfCryptASN1Util.encodeDERLength(255);
        assertArrayEquals(new byte[] { (byte)0x81, (byte)0xFF }, result);
    }

    @Test
    public void testEncodeDERLengthLongFormTwoBytes() throws Exception {
        /* Long form: length = 256 (requires 2 length bytes) */
        byte[] result = WolfCryptASN1Util.encodeDERLength(256);
        assertArrayEquals(new byte[] { (byte)0x82, 0x01, 0x00 }, result);

        result = WolfCryptASN1Util.encodeDERLength(1000);
        assertArrayEquals(new byte[] { (byte)0x82, 0x03, (byte)0xE8 }, result);

        result = WolfCryptASN1Util.encodeDERLength(65535);
        assertArrayEquals(
            new byte[] { (byte)0x82, (byte)0xFF, (byte)0xFF }, result);
    }

    @Test
    public void testEncodeDERLengthLongFormThreeBytes() throws Exception {
        /* Long form: length = 65536 (requires 3 length bytes) */
        byte[] result = WolfCryptASN1Util.encodeDERLength(65536);
        assertArrayEquals(
            new byte[] { (byte)0x83, 0x01, 0x00, 0x00 }, result);
    }

    @Test
    public void testEncodeDERLengthLongFormFourBytes() throws Exception {
        /* Long form: length = 16777216 (requires 4 length bytes) */
        byte[] result = WolfCryptASN1Util.encodeDERLength(16777216);
        assertArrayEquals(
            new byte[] { (byte)0x84, 0x01, 0x00, 0x00, 0x00 }, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDERLengthNegativeThrows() throws Exception {
        WolfCryptASN1Util.encodeDERLength(-1);
    }

    @Test
    public void testEncodeDERIntegerZero() throws Exception {
        byte[] result = WolfCryptASN1Util.encodeDERInteger(BigInteger.ZERO);
        /* INTEGER tag + length 1 + value 0x00 */
        assertArrayEquals(new byte[] { 0x02, 0x01, 0x00 }, result);
    }

    @Test
    public void testEncodeDERIntegerOne() throws Exception {
        byte[] result = WolfCryptASN1Util.encodeDERInteger(BigInteger.ONE);
        /* INTEGER tag + length 1 + value 0x01 */
        assertArrayEquals(new byte[] { 0x02, 0x01, 0x01 }, result);
    }

    @Test
    public void testEncodeDERIntegerSmallPositive() throws Exception {
        byte[] result = WolfCryptASN1Util.encodeDERInteger(
            BigInteger.valueOf(127));
        /* INTEGER tag + length 1 + value 0x7F */
        assertArrayEquals(new byte[] { 0x02, 0x01, 0x7F }, result);
    }

    @Test
    public void testEncodeDERIntegerWithSignBit() throws Exception {
        /* 128 = 0x80, MSB set, needs leading 0x00 */
        byte[] result = WolfCryptASN1Util.encodeDERInteger(
            BigInteger.valueOf(128));
        /* INTEGER tag + length 2 + 0x00 + 0x80 */
        assertArrayEquals(new byte[] { 0x02, 0x02, 0x00, (byte)0x80 }, result);
    }

    @Test
    public void testEncodeDERIntegerLargeValue() throws Exception {
        /* 256-bit value */
        BigInteger large = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
            "FFFFFFFF", 16);
        byte[] result = WolfCryptASN1Util.encodeDERInteger(large);

        /* Verify tag and structure */
        assertEquals(ASN1_INTEGER, result[0]);
        /* Length should be 33 (32 bytes + leading 0x00 for sign) */
        assertEquals(0x21, result[1]);
        /* First value byte should be 0x00 (sign bit) */
        assertEquals(0x00, result[2]);
    }

    @Test
    public void testEncodeDERIntegerTwoBytes() throws Exception {
        byte[] result = WolfCryptASN1Util.encodeDERInteger(
            BigInteger.valueOf(255));
        /* INTEGER tag + length 2 + 0x00 + 0xFF */
        assertArrayEquals(new byte[] { 0x02, 0x02, 0x00, (byte)0xFF }, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDERIntegerNullThrows() throws Exception {
        WolfCryptASN1Util.encodeDERInteger(null);
    }

    @Test
    public void testEncodeDERSequenceEmpty() throws Exception {
        byte[] result = WolfCryptASN1Util.encodeDERSequence(new byte[0]);
        /* SEQUENCE tag + length 0 */
        assertArrayEquals(new byte[] { 0x30, 0x00 }, result);
    }

    @Test
    public void testEncodeDERSequenceSimple() throws Exception {
        byte[] contents = new byte[] { 0x01, 0x02, 0x03 };
        byte[] result = WolfCryptASN1Util.encodeDERSequence(contents);
        /* SEQUENCE tag + length 3 + contents */
        assertArrayEquals(
            new byte[] { 0x30, 0x03, 0x01, 0x02, 0x03 }, result);
    }

    @Test
    public void testEncodeDERSequenceLongLength() throws Exception {
        /* Create contents requiring long form length (> 127 bytes) */
        byte[] contents = new byte[200];
        for (int i = 0; i < contents.length; i++) {
            contents[i] = (byte) i;
        }

        byte[] result = WolfCryptASN1Util.encodeDERSequence(contents);

        /* SEQUENCE tag */
        assertEquals(ASN1_SEQUENCE, result[0]);
        /* Long form length: 0x81 (1 byte follows) + 0xC8 (200) */
        assertEquals((byte)0x81, result[1]);
        assertEquals((byte)0xC8, result[2]);
        /* First content byte */
        assertEquals(0x00, result[3]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDERSequenceNullThrows() throws Exception {
        WolfCryptASN1Util.encodeDERSequence(null);
    }

    @Test
    public void testEncodeDEROctetStringEmpty() throws Exception {
        byte[] result = WolfCryptASN1Util.encodeDEROctetString(new byte[0]);
        /* OCTET STRING tag + length 0 */
        assertArrayEquals(new byte[] { 0x04, 0x00 }, result);
    }

    @Test
    public void testEncodeDEROctetStringSimple() throws Exception {
        byte[] contents = new byte[] { 0x01, 0x02, 0x03 };
        byte[] result = WolfCryptASN1Util.encodeDEROctetString(contents);
        /* OCTET STRING tag + length 3 + contents */
        assertArrayEquals(
            new byte[] { 0x04, 0x03, 0x01, 0x02, 0x03 }, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDEROctetStringNullThrows() throws Exception {
        WolfCryptASN1Util.encodeDEROctetString(null);
    }

    @Test
    public void testEncodeDERBitStringEmpty() throws Exception {
        byte[] result = WolfCryptASN1Util.encodeDERBitString(new byte[0]);
        /* BIT STRING tag + length 1 (includes unused bits) + 0x00 */
        assertArrayEquals(new byte[] { 0x03, 0x01, 0x00 }, result);
    }

    @Test
    public void testEncodeDERBitStringSimple() throws Exception {
        byte[] contents = new byte[] { 0x01, 0x02, 0x03 };
        byte[] result = WolfCryptASN1Util.encodeDERBitString(contents);
        /* BIT STRING tag + length 4 + unused bits 0x00 + contents */
        assertArrayEquals(
            new byte[] { 0x03, 0x04, 0x00, 0x01, 0x02, 0x03 }, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDERBitStringNullThrows() throws Exception {
        WolfCryptASN1Util.encodeDERBitString(null);
    }

    @Test
    public void testGetDHAlgorithmOID() throws Exception {
        byte[] oid = WolfCryptASN1Util.getDHAlgorithmOID();

        /* DH OID: 1.2.840.113549.1.3.1 (PKCS #3) */
        /* Expected: 0x06 0x09 0x2A 0x86 0x48 0x86 0xF7 0x0D 0x01 0x03 0x01 */
        assertNotNull(oid);
        assertEquals(11, oid.length);
        assertEquals(ASN1_OBJECT_IDENTIFIER, oid[0]);
        assertEquals(0x09, oid[1]); /* Length */
        assertEquals(0x2A, oid[2]); /* First arc: 1.2 = 40*1+2 = 42 = 0x2A */
    }

    @Test
    public void testEncodeDHParametersSimple() throws Exception {
        BigInteger p = BigInteger.valueOf(23);
        BigInteger g = BigInteger.valueOf(5);

        byte[] result = WolfCryptASN1Util.encodeDHParameters(p, g);

        /* Should be SEQUENCE containing two INTEGERs */
        assertEquals(ASN1_SEQUENCE, result[0]);
        /* Content starts at index 2 (tag + length) */
        assertEquals(ASN1_INTEGER, result[2]); /* p */
        assertEquals(ASN1_INTEGER, result[5]); /* g */
    }

    @Test
    public void testEncodeDHParametersLarge() throws Exception {
        /* Use realistic 2048-bit DH parameters */
        BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);

        byte[] result = WolfCryptASN1Util.encodeDHParameters(p, g);

        /* Verify structure */
        assertEquals(ASN1_SEQUENCE, result[0]);
        assertTrue("Result should be substantial", result.length > 256);

        /* For large parameters, length is long-form encoded */
        /* result[0] = SEQUENCE tag (0x30) */
        /* result[1] = 0x82 (long form, 2 bytes follow) */
        /* result[2-3] = length bytes */
        /* result[4] = first content byte (should be INTEGER tag) */
        int idx;
        if ((result[1] & 0x80) != 0) {
            /* Long form length */
            int numLengthBytes = result[1] & 0x7F;
            /* Skip tag, length indicator, and length bytes */
            idx = 2 + numLengthBytes;
        } else {
            /* Short form length */
            idx = 2;
        }
        assertEquals("First content should be INTEGER tag",
            ASN1_INTEGER, result[idx]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDHParametersNullPThrows() throws Exception {
        WolfCryptASN1Util.encodeDHParameters(null, BigInteger.valueOf(2));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDHParametersNullGThrows() throws Exception {
        WolfCryptASN1Util.encodeDHParameters(BigInteger.valueOf(23), null);
    }

    @Test
    public void testEncodeDHAlgorithmIdentifier() throws Exception {
        BigInteger p = BigInteger.valueOf(23);
        BigInteger g = BigInteger.valueOf(5);

        byte[] result = WolfCryptASN1Util.encodeDHAlgorithmIdentifier(p, g);

        /* Should be SEQUENCE containing OID and parameters SEQUENCE */
        assertEquals(ASN1_SEQUENCE, result[0]);

        /* Find OID tag */
        int idx = 2; /* Skip outer SEQUENCE tag and length */
        assertEquals(ASN1_OBJECT_IDENTIFIER, result[idx]);

        /* OID length should be 9 */
        assertEquals(0x09, result[idx + 1]);

        /* After OID (11 bytes total: tag + length + 9 bytes) should be
         * parameters SEQUENCE */
        idx += 11;
        assertEquals(ASN1_SEQUENCE, result[idx]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDHAlgorithmIdentifierNullPThrows() throws Exception {
        WolfCryptASN1Util.encodeDHAlgorithmIdentifier(
            null, BigInteger.valueOf(2));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEncodeDHAlgorithmIdentifierNullGThrows() throws Exception {
        WolfCryptASN1Util.encodeDHAlgorithmIdentifier(
            BigInteger.valueOf(23), null);
    }

    @Test
    public void testEncodeDERIntegerMaxByte() throws Exception {
        /* Test boundary: max signed byte value (127) */
        byte[] result = WolfCryptASN1Util.encodeDERInteger(
            BigInteger.valueOf(127));
        assertArrayEquals(new byte[] { 0x02, 0x01, 0x7F }, result);
    }

    @Test
    public void testEncodeDERIntegerMinUnsignedByte() throws Exception {
        /* Test boundary: min value requiring 2 bytes (128) */
        byte[] result = WolfCryptASN1Util.encodeDERInteger(
            BigInteger.valueOf(128));
        assertArrayEquals(new byte[] { 0x02, 0x02, 0x00, (byte)0x80 }, result);
    }

    @Test
    public void testEncodeDERIntegerMaxShort() throws Exception {
        /* Test boundary: max signed short value (32767) */
        byte[] result = WolfCryptASN1Util.encodeDERInteger(
            BigInteger.valueOf(32767));
        assertArrayEquals(new byte[] { 0x02, 0x02, 0x7F, (byte)0xFF }, result);
    }

    @Test
    public void testEncodeDERIntegerMinUnsignedShort() throws Exception {
        /* Test boundary: 32768 requires leading zero */
        byte[] result = WolfCryptASN1Util.encodeDERInteger(
            BigInteger.valueOf(32768));
        assertArrayEquals(
            new byte[] { 0x02, 0x03, 0x00, (byte)0x80, 0x00 }, result);
    }

    @Test
    public void testEncodeDERSequenceNested() throws Exception {
        /* Create nested SEQUENCE structure */
        byte[] inner =
            WolfCryptASN1Util.encodeDERSequence(new byte[] { 0x01, 0x02 });
        byte[] outer = WolfCryptASN1Util.encodeDERSequence(inner);

        /* Verify outer structure */
        assertEquals(ASN1_SEQUENCE, outer[0]);
        /* Verify inner structure is embedded */
        assertEquals(ASN1_SEQUENCE, outer[2]);
    }

    @Test
    public void testEncodeDERIntegerPowerOfTwo() throws Exception {
        /* Test powers of 2 - some need leading zero, some don't */
        /* 2^7  = 128    = 0x80     - MSB set, needs leading zero */
        /* 2^8  = 256    = 0x100    - MSB clear, no leading zero */
        /* 2^15 = 32768  = 0x8000   - MSB set, needs leading zero */
        /* 2^16 = 65536  = 0x10000  - MSB clear, no leading zero */

        /* Test 2^7 = 128 (needs leading zero) */
        BigInteger val128 = BigInteger.valueOf(128);
        byte[] result128 = WolfCryptASN1Util.encodeDERInteger(val128);
        assertEquals(ASN1_INTEGER, result128[0]);
        /* Length is 2, value is 0x00 0x80 */
        assertArrayEquals(new byte[] { 0x02, 0x02, 0x00, (byte)0x80 },
            result128);

        /* Test 2^8 = 256 (no leading zero needed) */
        BigInteger val256 = BigInteger.valueOf(256);
        byte[] result256 = WolfCryptASN1Util.encodeDERInteger(val256);
        assertEquals(ASN1_INTEGER, result256[0]);
        /* Length is 2, value is 0x01 0x00 (no leading zero) */
        assertArrayEquals(new byte[] { 0x02, 0x02, 0x01, 0x00 }, result256);
    }

    @Test
    public void testGetDHAlgorithmOIDIsCloned() throws Exception {
        /* Verify that calling getDHAlgorithmOID returns independent copies */
        byte[] oid1 = WolfCryptASN1Util.getDHAlgorithmOID();
        byte[] oid2 = WolfCryptASN1Util.getDHAlgorithmOID();

        /* Should be equal but not same reference */
        assertArrayEquals(oid1, oid2);
        assertNotSame("Should return clone, not same reference", oid1, oid2);

        /* Modifying one should not affect the other */
        oid1[0] = 0x00;
        assertNotEquals(oid1[0], oid2[0]);
    }

    @Test
    public void testEncodeDHParametersWithZeroG() throws Exception {
        /* Edge case: g = 0 (invalid in practice, but test encoding) */
        BigInteger p = BigInteger.valueOf(23);
        BigInteger g = BigInteger.ZERO;

        byte[] result = WolfCryptASN1Util.encodeDHParameters(p, g);

        /* Should encode without error */
        assertEquals(ASN1_SEQUENCE, result[0]);
    }

    @Test
    public void testEncodeDHParametersWithLargeG() throws Exception {
        /* Edge case: g is larger than typical (usually 2 or 5) */
        BigInteger p = BigInteger.valueOf(23);
        BigInteger g = BigInteger.valueOf(1000000);

        byte[] result = WolfCryptASN1Util.encodeDHParameters(p, g);

        /* Should encode without error */
        assertEquals(ASN1_SEQUENCE, result[0]);
    }

    @Test
    public void testEncodeDERLengthBoundaryValues() throws Exception {
        /* Test all boundary values for length encoding */
        int[] boundaries = {
            0, 1, 127,          /* Short form */
            128, 255,           /* Long form, 1 byte */
            256, 65535,         /* Long form, 2 bytes */
            65536, 16777215     /* Long form, 3 bytes */
        };

        for (int length : boundaries) {
            byte[] result = WolfCryptASN1Util.encodeDERLength(length);
            assertNotNull("Length encoding should succeed for " + length,
                result);
            assertTrue("Length encoding should produce bytes",
                result.length > 0);
        }
    }

    @Test
    public void testEncodeDERIntegerConsistency() throws Exception {
        /* Verify that encoding is consistent across calls */
        BigInteger value = new BigInteger(
            "123456789ABCDEF0123456789ABCDEF0", 16);

        byte[] result1 = WolfCryptASN1Util.encodeDERInteger(value);
        byte[] result2 = WolfCryptASN1Util.encodeDERInteger(value);

        assertArrayEquals("Encoding should be deterministic",
            result1, result2);
    }

    @Test
    public void testEncodeDHAlgorithmIdentifierStructure() throws Exception {
        /* Verify complete structure of AlgorithmIdentifier */
        BigInteger p = BigInteger.valueOf(23);
        BigInteger g = BigInteger.valueOf(5);

        byte[] result = WolfCryptASN1Util.encodeDHAlgorithmIdentifier(p, g);

        /* Parse and verify structure:
         * SEQUENCE {
         *   OID (0x06 0x09 ...)
         *   SEQUENCE {
         *     INTEGER (p)
         *     INTEGER (g)
         *   }
         * }
         */
        int idx = 0;
        assertEquals("Should start with SEQUENCE", ASN1_SEQUENCE, result[idx]);
        idx += 2; /* Skip tag and length */

        assertEquals("Should contain OID", ASN1_OBJECT_IDENTIFIER,
            result[idx]);
        idx += 11; /* OID is 11 bytes total */

        assertEquals("Should contain parameters SEQUENCE", ASN1_SEQUENCE,
            result[idx]);
    }
}

