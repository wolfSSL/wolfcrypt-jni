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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * Unit tests for WolfCrypt class.
 */
public class WolfCryptTest {

    private static final String CERT_PATH = "examples/certs/";

    /* RSA key file paths */
    private static final String clientKeyPem =
        CERT_PATH + "client-key.pem";
    private static final String clientKeyDer =
        CERT_PATH + "client-key.der";
    private static final String serverKeyPem =
        CERT_PATH + "server-key.pem";
    private static final String serverKeyDer =
        CERT_PATH + "server-key.der";
    private static final String caKeyPem =
        CERT_PATH + "ca-key.pem";
    private static final String caKeyDer =
        CERT_PATH + "ca-key.der";

    /* ECC key file paths */
    private static final String eccClientKeyPem =
        CERT_PATH + "ecc-client-key.pem";
    private static final String eccClientKeyDer =
        CERT_PATH + "ecc-client-key.der";

    /* RSA certificate file paths */
    private static final String clientCertPem =
        CERT_PATH + "client-cert.pem";
    private static final String clientCertDer =
        CERT_PATH + "client-cert.der";
    private static final String serverCertPem =
        CERT_PATH + "server-cert.pem";
    private static final String serverCertDer =
        CERT_PATH + "server-cert.der";
    private static final String caCertPem =
        CERT_PATH + "ca-cert.pem";
    private static final String caCertDer =
        CERT_PATH + "ca-cert.der";

    /* ECC certificate file paths */
    private static final String caEccCertPem =
        CERT_PATH + "ca-ecc-cert.pem";
    private static final String caEccCertDer =
        CERT_PATH + "ca-ecc-cert.der";
    private static final String clientEccCertPem =
        CERT_PATH + "client-ecc-cert.pem";
    private static final String clientEccCertDer =
        CERT_PATH + "client-ecc-cert.der";

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

    /**
     * Helper to read file contents as byte array.
     */
    private static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    /**
     * Helper to check if file exists.
     */
    private static boolean fileExists(String path) {
        return new File(path).exists();
    }

    @Test
    public void testKeyPemToDerRsaPrivateKey() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(clientKeyPem) || !fileExists(clientKeyDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(clientKeyPem);
        expectedDer = readFile(clientKeyDer);
        der = WolfCrypt.keyPemToDer(pem, null);

        assertNotNull("DER output should not be null", der);
        assertTrue("DER output should have content", der.length > 0);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test
    public void testKeyPemToDerServerKey() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(serverKeyPem) || !fileExists(serverKeyDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(serverKeyPem);
        expectedDer = readFile(serverKeyDer);
        der = WolfCrypt.keyPemToDer(pem, null);

        assertNotNull("DER output should not be null", der);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test
    public void testKeyPemToDerCaKey() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(caKeyPem) || !fileExists(caKeyDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(caKeyPem);
        expectedDer = readFile(caKeyDer);
        der = WolfCrypt.keyPemToDer(pem, null);

        assertNotNull("DER output should not be null", der);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test
    public void testKeyPemToDerEccKey() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(eccClientKeyPem) || !fileExists(eccClientKeyDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(eccClientKeyPem);
        expectedDer = readFile(eccClientKeyDer);
        der = WolfCrypt.keyPemToDer(pem, null);

        assertNotNull("DER output should not be null", der);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test(expected = WolfCryptException.class)
    public void testKeyPemToDerNullInput() throws Exception {
        WolfCrypt.keyPemToDer(null, null);
    }

    @Test(expected = WolfCryptException.class)
    public void testKeyPemToDerEmptyInput() throws Exception {
        WolfCrypt.keyPemToDer(new byte[0], null);
    }

    @Test(expected = WolfCryptException.class)
    public void testKeyPemToDerInvalidPem() throws Exception {
        byte[] invalidPem = "This is not a valid PEM file".getBytes();
        WolfCrypt.keyPemToDer(invalidPem, null);
    }

    @Test
    public void testKeyPemToDerOutputSmallerThanInput() throws Exception {

        byte[] pem = null;
        byte[] der = null;

        if (!fileExists(clientKeyPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        pem = readFile(clientKeyPem);
        der = WolfCrypt.keyPemToDer(pem, null);

        assertTrue("DER should be smaller than PEM", der.length < pem.length);
    }

    @Test
    public void testCertPemToDerClientCert() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(clientCertPem) || !fileExists(clientCertDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(clientCertPem);
        expectedDer = readFile(clientCertDer);
        der = WolfCrypt.certPemToDer(pem);

        assertNotNull("DER output should not be null", der);
        assertTrue("DER output should have content", der.length > 0);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test
    public void testCertPemToDerServerCert() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(serverCertPem) || !fileExists(serverCertDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(serverCertPem);
        expectedDer = readFile(serverCertDer);
        der = WolfCrypt.certPemToDer(pem);

        assertNotNull("DER output should not be null", der);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test
    public void testCertPemToDerCaCert() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(caCertPem) || !fileExists(caCertDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(caCertPem);
        expectedDer = readFile(caCertDer);
        der = WolfCrypt.certPemToDer(pem);

        assertNotNull("DER output should not be null", der);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test
    public void testCertPemToDerEccCert() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(caEccCertPem) || !fileExists(caEccCertDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(caEccCertPem);
        expectedDer = readFile(caEccCertDer);
        der = WolfCrypt.certPemToDer(pem);

        assertNotNull("DER output should not be null", der);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test
    public void testCertPemToDerClientEccCert() throws Exception {

        byte[] pem = null;
        byte[] expectedDer = null;
        byte[] der = null;

        if (!fileExists(clientEccCertPem) || !fileExists(clientEccCertDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        pem = readFile(clientEccCertPem);
        expectedDer = readFile(clientEccCertDer);
        der = WolfCrypt.certPemToDer(pem);

        assertNotNull("DER output should not be null", der);
        assertArrayEquals("DER output should match expected", expectedDer, der);
    }

    @Test(expected = WolfCryptException.class)
    public void testCertPemToDerNullInput() throws Exception {
        WolfCrypt.certPemToDer(null);
    }

    @Test(expected = WolfCryptException.class)
    public void testCertPemToDerEmptyInput() throws Exception {
        WolfCrypt.certPemToDer(new byte[0]);
    }

    @Test(expected = WolfCryptException.class)
    public void testCertPemToDerInvalidPem() throws Exception {
        byte[] invalidPem = "This is not a valid certificate PEM".getBytes();
        WolfCrypt.certPemToDer(invalidPem);
    }

    @Test
    public void testCertPemToDerOutputSmallerThanInput() throws Exception {

        byte[] pem = null;
        byte[] der = null;

        if (!fileExists(clientCertPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        pem = readFile(clientCertPem);
        der = WolfCrypt.certPemToDer(pem);

        assertTrue("DER should be smaller than PEM", der.length < pem.length);
    }

    @Test
    public void testKeyPemToDerValidOutput() throws Exception {

        byte[] pem = null;
        byte[] der = null;

        if (!fileExists(clientKeyPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        /* Test that keyPemToDer produces valid ASN.1 DER output */
        pem = readFile(clientKeyPem);
        der = WolfCrypt.keyPemToDer(pem, null);

        assertNotNull("DER output should not be null", der);
        assertTrue("DER should have valid ASN.1 SEQUENCE tag",
                   (der[0] & 0xFF) == 0x30);
    }

    @Test(expected = WolfCryptException.class)
    public void testPubKeyPemToDerNullInput() throws Exception {
        WolfCrypt.pubKeyPemToDer(null);
    }

    @Test(expected = WolfCryptException.class)
    public void testPubKeyPemToDerEmptyInput() throws Exception {
        WolfCrypt.pubKeyPemToDer(new byte[0]);
    }

    @Test(expected = WolfCryptException.class)
    public void testPubKeyPemToDerInvalidPem() throws Exception {
        byte[] invalidPem = "This is not a valid public key PEM".getBytes();
        WolfCrypt.pubKeyPemToDer(invalidPem);
    }

    @Test
    public void testKeyDerHasValidAsn1Structure() throws Exception {

        byte[] pem = null;
        byte[] der = null;

        if (!fileExists(clientKeyPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        pem = readFile(clientKeyPem);
        der = WolfCrypt.keyPemToDer(pem, null);

        /* Check ASN.1 SEQUENCE tag */
        assertEquals("DER should start with SEQUENCE tag",
                     0x30, der[0] & 0xFF);

        /* Check that length field is valid */
        int lengthByte = der[1] & 0xFF;
        if (lengthByte < 0x80) {
            /* Short form length */
            assertTrue("Short form length should be reasonable",
                       lengthByte > 0 && lengthByte < der.length);
        }
        else {
            /* Long form length */
            int numLengthBytes = lengthByte & 0x7F;
            assertTrue("Long form length byte count should be 1-4",
                       numLengthBytes >= 1 && numLengthBytes <= 4);
        }
    }

    @Test
    public void testCertDerHasValidAsn1Structure() throws Exception {

        byte[] pem = null;
        byte[] der = null;

        if (!fileExists(clientCertPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        pem = readFile(clientCertPem);
        der = WolfCrypt.certPemToDer(pem);

        /* Check ASN.1 SEQUENCE tag */
        assertEquals("DER should start with SEQUENCE tag",
                     0x30, der[0] & 0xFF);
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
    public void testKeyPemToDerThreaded() throws Exception {

        if (!fileExists(clientKeyPem) || !fileExists(clientKeyDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        final byte[] pem = readFile(clientKeyPem);
        final byte[] expectedDer = readFile(clientKeyDer);

        int numThreads = 10;
        int iterations = 50;
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final AtomicInteger failures = new AtomicInteger(0);
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        for (int i = 0; i < numThreads; i++) {
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            byte[] der = WolfCrypt.keyPemToDer(pem, null);
                            if (!Arrays.equals(expectedDer, der)) {
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

    @Test
    public void testCertPemToDerThreaded() throws Exception {

        if (!fileExists(clientCertPem) || !fileExists(clientCertDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        final byte[] pem = readFile(clientCertPem);
        final byte[] expectedDer = readFile(clientCertDer);

        int numThreads = 10;
        int iterations = 50;
        final CountDownLatch latch = new CountDownLatch(numThreads);
        final AtomicInteger failures = new AtomicInteger(0);
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        for (int i = 0; i < numThreads; i++) {
            executor.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        for (int j = 0; j < iterations; j++) {
                            byte[] der = WolfCrypt.certPemToDer(pem);
                            if (!Arrays.equals(expectedDer, der)) {
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
    public void testKeyPemToDerConsistentOutput() throws Exception {

        if (!fileExists(clientKeyPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        byte[] pem = readFile(clientKeyPem);

        /* Convert multiple times and verify consistent output */
        byte[] der1 = WolfCrypt.keyPemToDer(pem, null);
        byte[] der2 = WolfCrypt.keyPemToDer(pem, null);
        byte[] der3 = WolfCrypt.keyPemToDer(pem, null);

        assertArrayEquals("Multiple conversions should produce same result",
                          der1, der2);
        assertArrayEquals("Multiple conversions should produce same result",
                          der2, der3);
    }

    @Test
    public void testCertPemToDerConsistentOutput() throws Exception {

        if (!fileExists(clientCertPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        byte[] pem = readFile(clientCertPem);

        /* Convert multiple times and verify consistent output */
        byte[] der1 = WolfCrypt.certPemToDer(pem);
        byte[] der2 = WolfCrypt.certPemToDer(pem);
        byte[] der3 = WolfCrypt.certPemToDer(pem);

        assertArrayEquals("Multiple conversions should produce same result",
                          der1, der2);
        assertArrayEquals("Multiple conversions should produce same result",
                          der2, der3);
    }

    @Test
    public void testIoTimeoutEnabled() {
        /* Result depends on wolfSSL compile options, but multiple
         * calls should return a consistent value */
        boolean enabled1 = WolfCrypt.IoTimeoutEnabled();
        boolean enabled2 = WolfCrypt.IoTimeoutEnabled();
        assertEquals("IoTimeoutEnabled should return consistent value",
                     enabled1, enabled2);
    }

    @Test
    public void testSetIOTimeoutValidValues() {

        if (!WolfCrypt.IoTimeoutEnabled()) {
            System.out.println("Skipping: HAVE_IO_TIMEOUT not enabled");
            return;
        }

        /* Test a range of valid values */
        WolfCrypt.setIOTimeout(0);
        WolfCrypt.setIOTimeout(1);
        WolfCrypt.setIOTimeout(5);
        WolfCrypt.setIOTimeout(30);
        WolfCrypt.setIOTimeout(3600);

        /* Reset to default (no timeout) */
        WolfCrypt.setIOTimeout(0);
    }

    @Test
    public void testSetIOTimeoutZeroDisables() {

        if (!WolfCrypt.IoTimeoutEnabled()) {
            System.out.println("Skipping: HAVE_IO_TIMEOUT not enabled");
            return;
        }

        /* Zero should disable timeout (default behavior) */
        WolfCrypt.setIOTimeout(0);
    }

    @Test
    public void testSetIOTimeoutMaxBoundary() {

        if (!WolfCrypt.IoTimeoutEnabled()) {
            System.out.println("Skipping: HAVE_IO_TIMEOUT not enabled");
            return;
        }

        /* Exactly 3600 should succeed */
        WolfCrypt.setIOTimeout(3600);

        /* Reset to default */
        WolfCrypt.setIOTimeout(0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetIOTimeoutNegative() {
        WolfCrypt.setIOTimeout(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetIOTimeoutNegativeLarge() {
        WolfCrypt.setIOTimeout(Integer.MIN_VALUE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetIOTimeoutExceedsMax() {
        WolfCrypt.setIOTimeout(3601);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetIOTimeoutExceedsMaxLarge() {
        WolfCrypt.setIOTimeout(Integer.MAX_VALUE);
    }

    @Test
    public void testSetIOTimeoutNotCompiledIn() {

        if (WolfCrypt.IoTimeoutEnabled()) {
            /* Feature is available, skip this test */
            return;
        }

        /* When HAVE_IO_TIMEOUT is not compiled in, calling
         * setIOTimeout should throw WolfCryptException */
        try {
            WolfCrypt.setIOTimeout(5);
            fail("Should have thrown WolfCryptException " +
                 "when HAVE_IO_TIMEOUT not compiled in");
        }
        catch (WolfCryptException e) {
            /* Expected */
        }
    }
}

