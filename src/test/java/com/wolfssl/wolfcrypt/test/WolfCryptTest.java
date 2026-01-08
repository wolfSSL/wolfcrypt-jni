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
 * Unit tests for WolfCrypt class PEM to DER conversion methods.
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
    public void testPubKeyPemToDerValidOutput() throws Exception {

        byte[] pem = null;
        byte[] der = null;

        if (!fileExists(clientKeyPem)) {
            System.out.println("Skipping: test file not found");
            return;
        }

        /* Test that keyPemToDer works, pubKeyPemToDer needs public key PEM */
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
}

