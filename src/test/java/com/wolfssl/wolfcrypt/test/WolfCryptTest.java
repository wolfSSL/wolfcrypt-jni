/* WolfCryptTest.java
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
import java.security.KeyPairGenerator;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfCryptError;
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

    /**
     * Pad a PEM buffer out to the requested total size with newlines. The
     * PEM block stays parseable, so only the input size limit can reject it.
     */
    private static byte[] padPem(byte[] pem, int totalSz) {

        if (totalSz < pem.length) {
            throw new IllegalArgumentException(
                "totalSz must be >= PEM length");
        }

        byte[] padded = new byte[totalSz];

        Arrays.fill(padded, (byte)'\n');
        System.arraycopy(pem, 0, padded, 0, pem.length);

        return padded;
    }

    /* Input over the native size limit should be rejected before any large
     * native buffer is allocated, even though PEM block itself is valid. */
    @Test
    public void testCertPemToDerOversizedInput() throws Exception {

        if (!fileExists(clientCertPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        /* One byte past the inclusive limit is the first rejected size */
        int[] tooBig = { 1024 * 1024 + 1, 2 * 1024 * 1024 };
        for (int size : tooBig) {
            try {
                WolfCrypt.certPemToDer(
                    padPem(readFile(clientCertPem), size));
                fail("Should reject PEM input of " + size + " bytes");

            } catch (WolfCryptException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testKeyPemToDerOversizedInput() throws Exception {

        if (!fileExists(clientKeyPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        try {
            WolfCrypt.keyPemToDer(
                padPem(readFile(clientKeyPem), 2 * 1024 * 1024), null);
            fail("Should reject PEM input larger than the size limit");

        } catch (WolfCryptException e) {
            /* expected */
        }
    }

    @Test
    public void testCertPemToDerAtSizeLimitStillWorks() throws Exception {

        if (!fileExists(clientCertPem) || !fileExists(clientCertDer)) {
            System.out.println("Skipping: test files not found");
            return;
        }

        /* Exactly at the limit, which is inclusive, must still convert */
        byte[] der = WolfCrypt.certPemToDer(
            padPem(readFile(clientCertPem), 1024 * 1024));

        assertArrayEquals("DER output should match expected",
            readFile(clientCertDer), der);
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

    /* AES-256 encrypted PKCS#8 RSA-2048 private key, password below.
     * This is a test key only, so safe to ship here with password.  */
    private static final String encKeyPassword = "wolfsslpassword";
    private static final String encKeyPem =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
        "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\n" +
        "-----END ENCRYPTED PRIVATE KEY-----\n";

    /**
     * Decrypt the embedded key, or return null when the native build lacks
     * PKCS#8 encryption, PBKDF2, or AES-256-CBC support.
     */
    private static byte[] decryptEncKeyPem() throws Exception {
        try {
            return WolfCrypt.keyPemToDer(
                encKeyPem.getBytes("UTF-8"), encKeyPassword);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                return null;
            }
            throw e;
        }
    }

    @Test
    public void testKeyPemToDerWithPassword() throws Exception {

        byte[] der = decryptEncKeyPem();
        if (der == null) {
            System.out.println("Skipping: encrypted PKCS#8 not compiled in");
            return;
        }

        assertEquals("DER should start with SEQUENCE tag",
                     0x30, der[0] & 0xFF);
    }

    @Test
    public void testKeyPemToDerWrongPassword() throws Exception {

        /* Confirm the correct password works first, otherwise the negative
         * case below could pass for the wrong reason */
        if (decryptEncKeyPem() == null) {
            System.out.println("Skipping: encrypted PKCS#8 not compiled in");
            return;
        }

        try {
            WolfCrypt.keyPemToDer(
                encKeyPem.getBytes("UTF-8"), "wrongpassword");
            fail("Should reject an incorrect password");

        } catch (WolfCryptException e) {
            /* expected */
        }
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

    /**
     * Build a SubjectPublicKeyInfo PEM. No standalone public key PEM ships
     * under examples/certs, so one is generated here.
     */
    private static byte[] generatePubKeyPem() throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        byte[] spki = kpg.generateKeyPair().getPublic().getEncoded();

        StringBuilder sb = new StringBuilder("-----BEGIN PUBLIC KEY-----\n");
        String b64 = Base64.getEncoder().encodeToString(spki);
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END PUBLIC KEY-----\n");

        return sb.toString().getBytes("UTF-8");
    }

    @Test(expected = WolfCryptException.class)
    public void testPubKeyPemToDerOversizedInput() throws Exception {
        WolfCrypt.pubKeyPemToDer(
            padPem(generatePubKeyPem(), 2 * 1024 * 1024));
    }

    @Test
    public void testPubKeyPemToDerAtSizeLimitStillWorks() throws Exception {

        byte[] pem = generatePubKeyPem();
        byte[] expectedDer = WolfCrypt.pubKeyPemToDer(pem);

        /* Exactly at the limit, which is inclusive, must still convert */
        byte[] der = WolfCrypt.pubKeyPemToDer(padPem(pem, 1024 * 1024));

        assertArrayEquals("DER output should match unpadded conversion",
            expectedDer, der);
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

