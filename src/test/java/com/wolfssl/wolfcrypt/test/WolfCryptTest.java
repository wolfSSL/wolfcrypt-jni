/* WolfCryptTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.TestRule;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * Unit tests for WolfCrypt class Base16/hex encoding methods.
 */
public class WolfCryptTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {
        System.out.println("JNI WolfCrypt Class");
    }

    @Test
    public void testBase16Enabled() {
        /* Just verify the method doesn't throw, result depends on build */
        boolean enabled = WolfCrypt.Base16Enabled();
        System.out.println("Base16 enabled: " + enabled);
    }

    @Test
    public void testToHexStringBasic() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test known value: "Hello" = 48 65 6C 6C 6F */
        byte[] input = "Hello".getBytes("UTF-8");
        String hex = WolfCrypt.toHexString(input);

        assertNotNull("Hex string should not be null", hex);
        /* wolfSSL Base16_Encode uses uppercase */
        assertEquals("Hex encoding of 'Hello'",
                     "48656C6C6F", hex.toUpperCase());
    }

    @Test
    public void testToHexStringSingleByte() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test single byte values */
        byte[] zero = new byte[] { 0x00 };
        assertEquals("00", WolfCrypt.toHexString(zero).toUpperCase());

        byte[] one = new byte[] { 0x01 };
        assertEquals("01", WolfCrypt.toHexString(one).toUpperCase());

        byte[] max = new byte[] { (byte)0xFF };
        assertEquals("FF", WolfCrypt.toHexString(max).toUpperCase());

        byte[] mid = new byte[] { (byte)0xAB };
        assertEquals("AB", WolfCrypt.toHexString(mid).toUpperCase());
    }

    @Test
    public void testToHexStringAllHexDigits() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test all hex digits 0-F in output */
        byte[] input = new byte[] {
            0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xAB, (byte)0xCD,
            (byte)0xEF
        };
        String hex = WolfCrypt.toHexString(input);

        assertEquals("0123456789ABCDEF", hex.toUpperCase());
    }

    @Test
    public void testToHexStringEmpty() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        byte[] empty = new byte[0];
        String hex = WolfCrypt.toHexString(empty);

        assertNotNull("Empty input should return empty string", hex);
        assertEquals("Empty input should return empty string", "", hex);
    }

    @Test(expected = WolfCryptException.class)
    public void testToHexStringNullInput() throws Exception {
        WolfCrypt.toHexString(null);
    }

    @Test
    public void testHexStringToByteArrayBasic() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test known value: "48656C6C6F" = "Hello" */
        byte[] result = WolfCrypt.hexStringToByteArray("48656C6C6F");

        assertNotNull("Result should not be null", result);
        assertArrayEquals("Hello".getBytes("UTF-8"), result);
    }

    @Test
    public void testHexStringToByteArrayUppercase() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test uppercase input */
        byte[] result = WolfCrypt.hexStringToByteArray("DEADBEEF");

        byte[] expected = new byte[] {
            (byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF
        };
        assertArrayEquals(expected, result);
    }

    @Test
    public void testHexStringToByteArrayLowercase() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test lowercase input */
        byte[] result = WolfCrypt.hexStringToByteArray("deadbeef");

        byte[] expected = new byte[] {
            (byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF
        };
        assertArrayEquals(expected, result);
    }

    @Test
    public void testHexStringToByteArrayMixedCase() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test mixed case input */
        byte[] result = WolfCrypt.hexStringToByteArray("DeAdBeEf");

        byte[] expected = new byte[] {
            (byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF
        };
        assertArrayEquals(expected, result);
    }

    @Test
    public void testHexStringToByteArrayEmpty() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        byte[] result = WolfCrypt.hexStringToByteArray("");

        assertNotNull("Empty input should return empty array", result);
        assertEquals("Empty input should return empty array", 0, result.length);
    }

    @Test(expected = WolfCryptException.class)
    public void testHexStringToByteArrayNullInput() throws Exception {
        WolfCrypt.hexStringToByteArray(null);
    }

    @Test(expected = WolfCryptException.class)
    public void testHexStringToByteArrayOddLength() throws Exception {
        /* Odd length hex string should fail */
        WolfCrypt.hexStringToByteArray("ABC");
    }

    @Test
    public void testHexStringToByteArrayInvalidCharacter() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Invalid hex character should throw exception */
        try {
            WolfCrypt.hexStringToByteArray("GHIJ");
            fail("Should have thrown exception for invalid hex characters");
        }
        catch (WolfCryptException e) {
            /* Expected */
        }
    }

    @Test
    public void testHexRoundTrip() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test round trip: bytes -> hex -> bytes */
        byte[] original = new byte[] {
            0x00, 0x01, 0x02, 0x7F, (byte)0x80, (byte)0xFE, (byte)0xFF
        };

        String hex = WolfCrypt.toHexString(original);
        byte[] decoded = WolfCrypt.hexStringToByteArray(hex);

        assertArrayEquals("Round trip should preserve data", original, decoded);
    }

    @Test
    public void testHexRoundTripRandomData() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test with all possible byte values */
        byte[] allBytes = new byte[256];
        for (int i = 0; i < 256; i++) {
            allBytes[i] = (byte)i;
        }

        String hex = WolfCrypt.toHexString(allBytes);
        byte[] decoded = WolfCrypt.hexStringToByteArray(hex);

        assertEquals("Hex string should be 512 characters", 512, hex.length());
        assertArrayEquals("Round trip should preserve all byte values",
                          allBytes, decoded);
    }

    @Test
    public void testHexLargeData() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test with larger data (1KB) */
        byte[] largeData = new byte[1024];
        for (int i = 0; i < largeData.length; i++) {
            largeData[i] = (byte)(i & 0xFF);
        }

        String hex = WolfCrypt.toHexString(largeData);
        byte[] decoded = WolfCrypt.hexStringToByteArray(hex);

        assertEquals("Hex string length should be 2x input",
                     2048, hex.length());
        assertArrayEquals("Large data round trip should succeed",
                          largeData, decoded);
    }

    @Test
    public void testHexOutputLength() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Verify hex output is exactly 2x input length */
        for (int len = 1; len <= 100; len++) {
            byte[] input = new byte[len];
            String hex = WolfCrypt.toHexString(input);
            assertEquals("Hex length should be 2x input length",
                         len * 2, hex.length());
        }
    }

    @Test
    public void testHexDecodeOutputLength() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Verify decode output is exactly half of hex input length */
        for (int len = 2; len <= 200; len += 2) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                sb.append("A");
            }
            byte[] result = WolfCrypt.hexStringToByteArray(sb.toString());
            assertEquals("Decoded length should be half of hex length",
                         len / 2, result.length);
        }
    }

    @Test
    public void testHexConsistentOutput() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        byte[] input = "test data".getBytes("UTF-8");

        /* Convert multiple times and verify consistent output */
        String hex1 = WolfCrypt.toHexString(input);
        String hex2 = WolfCrypt.toHexString(input);
        String hex3 = WolfCrypt.toHexString(input);

        assertEquals("Multiple conversions should produce same result",
                     hex1, hex2);
        assertEquals("Multiple conversions should produce same result",
                     hex2, hex3);
    }

    @Test
    public void testHexThreaded() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        final byte[] testData = "Thread safety test data".getBytes("UTF-8");
        final String expectedHex = WolfCrypt.toHexString(testData);

        int numThreads = 10;
        int iterations = 100;
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final AtomicInteger failures = new AtomicInteger(0);
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        for (int i = 0; i < numThreads; i++) {
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            /* Test encoding */
                            String hex = WolfCrypt.toHexString(testData);
                            if (!expectedHex.equals(hex)) {
                                failures.incrementAndGet();
                            }

                            /* Test decoding */
                            byte[] decoded =
                                WolfCrypt.hexStringToByteArray(expectedHex);
                            if (!Arrays.equals(testData, decoded)) {
                                failures.incrementAndGet();
                            }
                        }
                    }
                    catch (Exception e) {
                        failures.incrementAndGet();
                    }
                    finally {
                        latch.countDown();
                    }
                }
            });
        }

        latch.await();
        executor.shutdown();

        assertEquals("No thread failures should occur", 0, failures.get());
    }

    @Test
    public void testHexKnownVectors() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test known hex encoding vectors */
        String[][] testVectors = {
            {"", ""},
            {"f", "66"},
            {"fo", "666F"},
            {"foo", "666F6F"},
            {"foob", "666F6F62"},
            {"fooba", "666F6F6261"},
            {"foobar", "666F6F626172"}
        };

        for (String[] vector : testVectors) {
            String input = vector[0];
            String expectedHex = vector[1];

            if (input.length() == 0) {
                assertEquals("Empty string encoding",
                             "", WolfCrypt.toHexString(new byte[0]));
            }
            else {
                String hex = WolfCrypt.toHexString(input.getBytes("UTF-8"));
                assertEquals("Encoding of '" + input + "'",
                             expectedHex.toUpperCase(), hex.toUpperCase());
            }
        }
    }

    @Test
    public void testHexDecodeKnownVectors() throws Exception {

        if (!WolfCrypt.Base16Enabled()) {
            System.out.println("Skipping: Base16 not enabled in wolfSSL");
            return;
        }

        /* Test known hex decoding vectors */
        String[][] testVectors = {
            {"", ""},
            {"66", "f"},
            {"666F", "fo"},
            {"666F6F", "foo"},
            {"666F6F62", "foob"},
            {"666F6F6261", "fooba"},
            {"666F6F626172", "foobar"}
        };

        for (String[] vector : testVectors) {
            String hexInput = vector[0];
            String expectedOutput = vector[1];

            if (hexInput.length() == 0) {
                byte[] result = WolfCrypt.hexStringToByteArray("");
                assertEquals("Empty hex decoding", 0, result.length);
            }
            else {
                byte[] result = WolfCrypt.hexStringToByteArray(hexInput);
                assertEquals("Decoding of '" + hexInput + "'",
                             expectedOutput, new String(result, "UTF-8"));
            }
        }
    }
}

