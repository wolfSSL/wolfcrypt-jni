/* WolfCryptUtilsTest.java
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
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.BeforeClass;
import org.junit.AfterClass;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.File;
import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;
import java.util.Locale;
import java.security.Provider;
import java.security.KeyStore;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptUtil;
import com.wolfssl.provider.jce.WolfCryptECParameterSpec;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Test suite for WolfCryptUtils.convertKeyStoreToWKS method.
 *
 * Tests converting JKS KeyStore to WKS format and error handling.
 */
public class WolfCryptUtilTest {

    /* Common test password for test KeyStores */
    private static final char[] PASSWORD = "wolfsslpassword".toCharArray();
    private static final String WKS_PROVIDER = "wolfJCE";
    private static final String TEST_ALIAS = "server";
    private static final String TEST_JKS_PATH = "examples/certs/server.jks";
    private static final String TEST_P12_PATH = "examples/certs/client.p12";
    private static final String TEST_WKS_PATH = "examples/certs/server.wks";
    private static final char[] CACERTS_PASSWORD = "changeit".toCharArray();

    /* Original security property values */
    private static String origMapJksToWks = null;
    private static String origMapPkcs12ToWks = null;
    private static String origIterationCount = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUpClass() {

        System.out.println("JCE WolfCryptUtils Class");

        /* Register wolfJCE provider if not already done */
        Provider wolfJCE = Security.getProvider(WKS_PROVIDER);
        if (wolfJCE == null) {
            Security.insertProviderAt(new WolfCryptProvider(), 1);
        }

        /* Store original security property values */
        origMapJksToWks = Security.getProperty("wolfjce.mapJKStoWKS");
        origMapPkcs12ToWks = Security.getProperty("wolfjce.mapPKCS12toWKS");
        origIterationCount = Security.getProperty("wolfjce.wks.iterationCount");

        /* Make sure we set them to known values at the start */
        Security.setProperty("wolfjce.mapJKStoWKS", "false");
        Security.setProperty("wolfjce.mapPKCS12toWKS", "false");

        /* Set lower PBKDF2 iteration count for faster test execution.
         * Default 210,000 iterations makes conversion tests very slow. */
        Security.setProperty("wolfjce.wks.iterationCount", "10000");
    }

    @AfterClass
    public static void tearDownClass() {
        /* Restore original security property values */
        if (origMapJksToWks != null) {
            Security.setProperty("wolfjce.mapJKStoWKS", origMapJksToWks);
        } else {
            Security.setProperty("wolfjce.mapJKStoWKS", "false");
        }

        if (origMapPkcs12ToWks != null) {
            Security.setProperty("wolfjce.mapPKCS12toWKS", origMapPkcs12ToWks);
        } else {
            Security.setProperty("wolfjce.mapPKCS12toWKS", "false");
        }

        if (origIterationCount != null) {
            Security.setProperty("wolfjce.wks.iterationCount",
                origIterationCount);
        } else {
            Security.setProperty("wolfjce.wks.iterationCount", "");
        }
    }

    /**
     * Helper method to skip test if required test file doesn't exist.
     * Test certificate files are not available on Android.
     * @param path Path to test file
     */
    private void assumeTestFileExists(String path) {
        File file = new File(path);
        Assume.assumeTrue("Test file not available: " + path, file.exists());
    }

    /**
     * Helper method to load a KeyStore file into a ByteArrayInputStream
     * @param path Path to the KeyStore file
     * @return ByteArrayInputStream containing the KeyStore data
     * @throws Exception if file cannot be read
     */
    private static synchronized ByteArrayInputStream loadKeyStoreFile(
        String path) throws Exception {

        FileInputStream fis = new FileInputStream(path);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        fis.close();

        return new ByteArrayInputStream(baos.toByteArray());
    }

    /**
     * Helper method to find the Java cacerts file
     * @return Path to cacerts file if found, null otherwise
     */
    private static String findCacertsFile() {
        String javaHome = System.getProperty("java.home");
        if (javaHome == null) {
            return null;
        }

        /* Common locations for cacerts file */
        String[] possiblePaths = {
            /* Standard locations */
            javaHome + "/lib/security/cacerts",
            javaHome + "/jre/lib/security/cacerts",
            /* Android locations */
            javaHome + "/etc/security/cacerts",
            /* Windows specific */
            javaHome + "\\lib\\security\\cacerts",
            javaHome + "\\jre\\lib\\security\\cacerts"
        };

        for (String path : possiblePaths) {
            File file = new File(path);
            if (file.exists() && file.isFile()) {
                return path;
            }
        }

        return null;
    }

    /**
     * Test with null input stream (should throw an exception)
     */
    @Test
    public void testNullInputStream() {
        try {
            WolfCryptUtil.convertKeyStoreToWKS(null, PASSWORD, PASSWORD, true);
            fail("Should have thrown an exception for null input stream");
        } catch (IllegalArgumentException e) {
            /* Expected exception */
            assertTrue("Exception message should indicate null input stream",
                e.getMessage().contains("null"));
        } catch (Exception e) {
            fail("Unexpected exception type: " + e.getClass().getName());
        }
    }

    /**
     * Test with null password (should throw an exception)
     */
    @Test
    public void testNullPassword() {
        /* Create a dummy keystore for testing */
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, PASSWORD);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, PASSWORD);
            ByteArrayInputStream bais =
                new ByteArrayInputStream(baos.toByteArray());

            WolfCryptUtil.convertKeyStoreToWKS(bais, PASSWORD, null, true);
            fail("Should have thrown an exception for null password");
        } catch (IllegalArgumentException e) {
            /* Expected exception */
            assertTrue("Exception message should indicate null password",
                e.getMessage().contains("null"));
        } catch (Exception e) {
            fail("Unexpected exception type: " + e.getClass().getName());
        }
    }

    /**
     * Test converting JKS to WKS with mapJKStoWKS=false
     */
    @Test
    public void testConvertJksToWksWithoutMapping() throws Exception {
        assumeTestFileExists(TEST_JKS_PATH);

        /* Store original property value */
        String origValue = Security.getProperty("wolfjce.mapJKStoWKS");

        try {
            Security.setProperty("wolfjce.mapJKStoWKS", "false");

            /* Load test JKS KeyStore */
            ByteArrayInputStream jksStream = loadKeyStoreFile(TEST_JKS_PATH);

            /* Convert to WKS */
            ByteArrayInputStream wksStream = 
                (ByteArrayInputStream)WolfCryptUtil.convertKeyStoreToWKS(
                    jksStream, PASSWORD, PASSWORD, true);

            /* Load the converted WKS KeyStore */
            KeyStore wksStore = KeyStore.getInstance("WKS", "wolfJCE");
            wksStore.load(wksStream, PASSWORD);

            /* Verify the key and certificate were properly converted */
            assertTrue("Key entry should exist",
                wksStore.isKeyEntry(TEST_ALIAS));
            assertNotNull("Private key should exist", 
                wksStore.getKey(TEST_ALIAS, PASSWORD));
            assertNotNull("Certificate chain should exist", 
                wksStore.getCertificateChain(TEST_ALIAS));
            assertEquals("Certificate chain should have length 2",
                2, wksStore.getCertificateChain(TEST_ALIAS).length);
        } finally {
            /* Restore original property value */
            if (origValue != null) {
                Security.setProperty("wolfjce.mapJKStoWKS", origValue);
            } else {
                Security.setProperty("wolfjce.mapJKStoWKS", "false");
            }
        }
    }

    /**
     * Test converting JKS to WKS with mapJKStoWKS=true
     */
    @Test
    public void testConvertJksToWksWithMapping() throws Exception {
        assumeTestFileExists(TEST_JKS_PATH);

        /* Store original property value */
        String origValue = Security.getProperty("wolfjce.mapJKStoWKS");

        try {
            Security.setProperty("wolfjce.mapJKStoWKS", "true");

            /* Load test JKS KeyStore */
            ByteArrayInputStream jksStream = loadKeyStoreFile(TEST_JKS_PATH);

            /* Convert to WKS */
            ByteArrayInputStream wksStream = 
                (ByteArrayInputStream)WolfCryptUtil.convertKeyStoreToWKS(
                    jksStream, PASSWORD, PASSWORD, true);

            /* Load the converted WKS KeyStore */
            KeyStore wksStore = KeyStore.getInstance("WKS", "wolfJCE");
            wksStore.load(wksStream, PASSWORD);
 
            /* Verify the key and certificate were properly converted */
            assertTrue("Key entry should exist",
                wksStore.isKeyEntry(TEST_ALIAS));
            assertNotNull("Private key should exist", 
                wksStore.getKey(TEST_ALIAS, PASSWORD));
            assertNotNull("Certificate chain should exist", 
                wksStore.getCertificateChain(TEST_ALIAS));
            assertEquals("Certificate chain should have length 2",
                2, wksStore.getCertificateChain(TEST_ALIAS).length);

        } finally {
            /* Restore original property value */
            if (origValue != null) {
                Security.setProperty("wolfjce.mapJKStoWKS", origValue);
            } else {
                Security.setProperty("wolfjce.mapJKStoWKS", "false");
            }
        }
    }

    /**
     * Test converting PKCS12 to WKS with mapPKCS12toWKS=false
     */
    @Test
    public void testConvertP12ToWksWithoutMapping() throws Exception {
        assumeTestFileExists(TEST_P12_PATH);

        /* Store original property value */
        String origValue = Security.getProperty("wolfjce.mapPKCS12toWKS");

        try {
            Security.setProperty("wolfjce.mapPKCS12toWKS", "false");

            /* Load test PKCS12 KeyStore */
            ByteArrayInputStream p12Stream = loadKeyStoreFile(TEST_P12_PATH);

            /* Convert to WKS */
            ByteArrayInputStream wksStream = 
                (ByteArrayInputStream)WolfCryptUtil.convertKeyStoreToWKS(
                    p12Stream, PASSWORD, PASSWORD, true);

            /* Load the converted WKS KeyStore */
            KeyStore wksStore = KeyStore.getInstance("WKS", "wolfJCE");
            wksStore.load(wksStream, PASSWORD);

            /* Verify both entries were properly converted */
            assertTrue("RSA key entry should exist",
                wksStore.isKeyEntry("client"));
            assertTrue("ECC key entry should exist",
                wksStore.isKeyEntry("client-ecc"));

            /* Verify RSA key and certificate */
            assertNotNull("RSA private key should exist", 
                wksStore.getKey("client", PASSWORD));
            assertNotNull("RSA certificate chain should exist", 
                wksStore.getCertificateChain("client"));
            assertEquals("RSA certificate chain should have length 1",
                1, wksStore.getCertificateChain("client").length);

            /* Verify ECC key and certificate */
            assertNotNull("ECC private key should exist", 
                wksStore.getKey("client-ecc", PASSWORD));
            assertNotNull("ECC certificate chain should exist", 
                wksStore.getCertificateChain("client-ecc"));
            assertEquals("ECC certificate chain should have length 1",
                1, wksStore.getCertificateChain("client-ecc").length);

        } finally {
            /* Restore original property value */
            if (origValue != null) {
                Security.setProperty("wolfjce.mapPKCS12toWKS", origValue);
            } else {
                Security.setProperty("wolfjce.mapPKCS12toWKS", "false");
            }
        }
    }

    /**
     * Test converting PKCS12 to WKS with mapPKCS12toWKS=true
     */
    @Test
    public void testConvertP12ToWksWithMapping() throws Exception {
        assumeTestFileExists(TEST_P12_PATH);

        /* Store original property value */
        String origValue = Security.getProperty("wolfjce.mapPKCS12toWKS");

        try {
            Security.setProperty("wolfjce.mapPKCS12toWKS", "true");

            /* Load test PKCS12 KeyStore */
            ByteArrayInputStream p12Stream = loadKeyStoreFile(TEST_P12_PATH);
 
            /* Convert to WKS */
            ByteArrayInputStream wksStream = 
                (ByteArrayInputStream)WolfCryptUtil.convertKeyStoreToWKS(
                    p12Stream, PASSWORD, PASSWORD, true);

            /* Load the converted WKS KeyStore */
            KeyStore wksStore = KeyStore.getInstance("WKS", "wolfJCE");
            wksStore.load(wksStream, PASSWORD);

            /* Verify both entries were properly converted */
            assertTrue("RSA key entry should exist",
                wksStore.isKeyEntry("client"));
            assertTrue("ECC key entry should exist",
                wksStore.isKeyEntry("client-ecc"));

            /* Verify RSA key and certificate */
            assertNotNull("RSA private key should exist", 
                wksStore.getKey("client", PASSWORD));
            assertNotNull("RSA certificate chain should exist", 
                wksStore.getCertificateChain("client"));
            assertEquals("RSA certificate chain should have length 1",
                1, wksStore.getCertificateChain("client").length);

            /* Verify ECC key and certificate */
            assertNotNull("ECC private key should exist", 
                wksStore.getKey("client-ecc", PASSWORD));
            assertNotNull("ECC certificate chain should exist", 
                wksStore.getCertificateChain("client-ecc"));
            assertEquals("ECC certificate chain should have length 1",
                1, wksStore.getCertificateChain("client-ecc").length);

        } finally {
            /* Restore original property value */
            if (origValue != null) {
                Security.setProperty("wolfjce.mapPKCS12toWKS", origValue);
            } else {
                Security.setProperty("wolfjce.mapPKCS12toWKS", "false");
            }
        }
    }

    /**
     * Test converting WKS to WKS (should return same InputStream)
     */
    @Test
    public void testConvertWksToWks() throws Exception {
        assumeTestFileExists(TEST_WKS_PATH);

        /* Load test WKS KeyStore */
        ByteArrayInputStream wksStream = loadKeyStoreFile(TEST_WKS_PATH);

        /* Convert WKS to WKS */
        ByteArrayInputStream wksStreamB =
            (ByteArrayInputStream)WolfCryptUtil.convertKeyStoreToWKS(
                wksStream, PASSWORD, PASSWORD, true);

        /* Verify the KeyStore can still be loaded */
        KeyStore wksStore = KeyStore.getInstance("WKS", "wolfJCE");
        wksStore.load(wksStreamB, PASSWORD);

        /* Verify the key and certificate were preserved */
        assertTrue("Key entry should exist", wksStore.isKeyEntry(TEST_ALIAS));
        assertNotNull("Private key should exist",
            wksStore.getKey(TEST_ALIAS, PASSWORD));
        assertNotNull("Certificate chain should exist",
            wksStore.getCertificateChain(TEST_ALIAS));
        assertEquals("Certificate chain should have length 2",
            2, wksStore.getCertificateChain(TEST_ALIAS).length);
    }

    /**
     * Test converting Java cacerts to WKS format
     */
    @Test
    public void testConvertCacertsToWks() throws Exception {

        boolean failOnInsertErrors = true;
        char[] password = CACERTS_PASSWORD;

        /* Find cacerts file */
        String cacertsPath = findCacertsFile();
        if (cacertsPath == null) {
            System.out.println(
                "Skipping testConvertCacertsToWks: cacerts file not found");
            return;
        }

        /* If using FIPS mode, set failOnInsertErrors to false */
        if (Fips.enabled) {
            failOnInsertErrors = false;
            password = (new String(CACERTS_PASSWORD) +
                new String(CACERTS_PASSWORD)).toCharArray();
        }

        /* Load cacerts KeyStore */
        ByteArrayInputStream cacertsStream = loadKeyStoreFile(cacertsPath);

        /* Convert to WKS */
        ByteArrayInputStream wksStream =
            (ByteArrayInputStream)WolfCryptUtil.convertKeyStoreToWKS(
                cacertsStream, CACERTS_PASSWORD, password, failOnInsertErrors);

        /* Load the converted WKS KeyStore */
        KeyStore wksStore = KeyStore.getInstance("WKS", "wolfJCE");
        wksStore.load(wksStream, password);

        /* Verify the KeyStore was converted and contains entries */
        assertTrue("WKS KeyStore should contain entries",
                  wksStore.size() > 0);
    }

    @Test
    public void testIsAlgorithmDisabledSimple() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test simple algorithm name matching */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "MD2");
            assertTrue("MD2 should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD2", "jdk.certpath.disabledAlgorithms"));
            assertFalse("MD5 should not be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD5", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledCaseInsensitive() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test case-insensitive matching (matches SunJCE behavior) */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "md2");
            assertTrue("MD2 (uppercase) should match md2 (lowercase)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD2", "jdk.certpath.disabledAlgorithms"));
            assertTrue("md2 (lowercase) should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "md2", "jdk.certpath.disabledAlgorithms"));
            assertTrue("Md2 (mixed case) should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "Md2", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledComposite() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test decomposition of composite names like "MD2withRSA" */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "MD2");
            assertTrue("MD2withRSA should be disabled (MD2 part)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD2withRSA", "jdk.certpath.disabledAlgorithms"));
            assertTrue("md2WithRsa should be disabled (case-insensitive)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "md2WithRsa", "jdk.certpath.disabledAlgorithms"));
            assertFalse("SHA1withRSA should not be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledQualifiedEntries() {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* JDK 11+ factory default ships SHA1 only in qualified form and
             * key algorithms only as keySize constraints. */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "MD2, MD5, SHA1 jdkCA & denyAfter 2019-01-01, " +
                "RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224");

            /* Qualified SHA1 entry must still disable SHA1 signatures */
            assertTrue("SHA1withRSA should be disabled (qualified SHA1)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));
            assertTrue("SHA1withECDSA should be disabled (qualified SHA1)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA1withECDSA", "jdk.certpath.disabledAlgorithms"));

            /* Bare entries must still work */
            assertTrue("MD5withRSA should be disabled (bare MD5)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD5withRSA", "jdk.certpath.disabledAlgorithms"));

            /* keySize constraints must not disable the signature algorithm.
             * "RSA keySize < 1024" must not reject a SHA256withRSA
             * signature. */
            assertFalse("SHA256withRSA must not be disabled by keySize entry",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA256withRSA", "jdk.certpath.disabledAlgorithms"));
            assertFalse("SHA384withECDSA must not be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA384withECDSA", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledUsageQualifiers() {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* JDK factory default: SHA1 disabled only for TLS server chains
             * anchored to a JDK-shipped CA and for signed JARs, neither of
             * which applies to CertPath validation */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "MD2, MD5, SHA1 jdkCA & usage TLSServer, " +
                "RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224, " +
                "include jdk.disabled.namedCurves, " +
                "SHA1 usage SignedJAR & denyAfter 2019-01-01");

            assertFalse("SHA1withRSA must not be disabled by usage entries",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));
            assertFalse("SHA1withECDSA must not be disabled by usage entries",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withECDSA", "jdk.certpath.disabledAlgorithms"));

            /* The generic variant has no CertPath context and must treat
             * usage-scoped entries as active (fail closed) */
            assertTrue("SHA1withRSA should be disabled outside CertPath",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));

            /* Bare entries in the same property still apply */
            assertTrue("MD5withRSA should be disabled (bare MD5)",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "MD5withRSA", "jdk.certpath.disabledAlgorithms"));

            /* TLSClient usage can never apply to CertPath validation */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SHA1 usage TLSServer TLSClient");
            assertFalse("TLSServer/TLSClient usage entry must not apply",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));

            /* Unrecognized usage context must fail closed */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SHA1 usage FutureContext");
            assertTrue("Unrecognized usage context should fail closed",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));

            /* Mixed recognized/unrecognized usage contexts fail closed */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SHA1 usage TLSServer FutureContext");
            assertTrue("Partially recognized usage should fail closed",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));

            /* Unrecognized non-usage qualifier must fail closed */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SHA1 someNewQualifier 42");
            assertTrue("Unrecognized qualifier should fail closed",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));

            /* jdkCA alone cannot be evaluated here, fail closed */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SHA1 jdkCA");
            assertTrue("jdkCA-only qualifier should fail closed",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));

            /* denyAfter alone cannot be evaluated here, fail closed */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SHA1 denyAfter 2019-01-01");
            assertTrue("denyAfter-only qualifier should fail closed",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledPQFamilyNames() {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Family entry disables all of its parameter sets */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "ML-DSA");
            assertTrue("ML-DSA should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "ML-DSA", "jdk.certpath.disabledAlgorithms"));
            assertTrue("ML-DSA-65 should be disabled by family entry",
                WolfCryptUtil.isAlgorithmDisabled(
                    "ML-DSA-65", "jdk.certpath.disabledAlgorithms"));
            assertTrue("ML-DSA-87 should be disabled for CertPath too",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "ML-DSA-87", "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SLH-DSA");
            assertTrue("SLH-DSA-SHA2-128s should be disabled by family",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SLH-DSA-SHA2-128s", "jdk.certpath.disabledAlgorithms"));

            /* Parameter set entry disables only that set, not the family
             * or other sets */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "ML-DSA-44");
            assertTrue("ML-DSA-44 should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "ML-DSA-44", "jdk.certpath.disabledAlgorithms"));
            assertFalse("ML-DSA-65 should not be disabled by ML-DSA-44",
                WolfCryptUtil.isAlgorithmDisabled(
                    "ML-DSA-65", "jdk.certpath.disabledAlgorithms"));
            assertFalse("ML-DSA family should not be disabled by ML-DSA-44",
                WolfCryptUtil.isAlgorithmDisabled(
                    "ML-DSA", "jdk.certpath.disabledAlgorithms"));

            /* Prefix matching is scoped to PQ families only */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "SHA3");
            assertFalse("SHA3 entry should not disable SHA3-256",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA3-256", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsKeyAllowedPQKeys() throws Exception {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");
        PublicKey mlDsaPub = null;
        PublicKey slhDsaPub = null;

        try {
            mlDsaPub = KeyPairGenerator.getInstance("ML-DSA-65", "wolfJCE")
                .generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            /* ML-DSA-65 not compiled into native wolfSSL */
        }

        try {
            slhDsaPub = KeyPairGenerator.getInstance(
                "SLH-DSA-SHA2-128s", "wolfJCE")
                .generateKeyPair().getPublic();
        } catch (NoSuchAlgorithmException e) {
            /* SLH-DSA-SHA2-128s not compiled into native wolfSSL */
        }

        if (mlDsaPub == null && slhDsaPub == null) {
            /* skip, no PQ support in native library */
            return;
        }

        try {
            if (mlDsaPub != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "MD2");
                assertTrue("ML-DSA-65 key should be allowed",
                    WolfCryptUtil.isKeyAllowed(mlDsaPub,
                        "jdk.certpath.disabledAlgorithms"));

                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    "ML-DSA");
                assertFalse("family entry should block ML-DSA key",
                    WolfCryptUtil.isKeyAllowed(mlDsaPub,
                        "jdk.certpath.disabledAlgorithms"));
                assertFalse("family entry should block for CertPath too",
                    WolfCryptUtil.isKeyAllowedForCertPath(mlDsaPub,
                        "jdk.certpath.disabledAlgorithms"));

                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    "ML-DSA-65");
                assertFalse("matching parameter set entry should block key",
                    WolfCryptUtil.isKeyAllowed(mlDsaPub,
                        "jdk.certpath.disabledAlgorithms"));

                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    "ML-DSA-44");
                assertTrue("different parameter set should not block key",
                    WolfCryptUtil.isKeyAllowed(mlDsaPub,
                        "jdk.certpath.disabledAlgorithms"));
            }

            if (slhDsaPub != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    "SLH-DSA");
                assertFalse("family entry should block SLH-DSA key",
                    WolfCryptUtil.isKeyAllowed(slhDsaPub,
                        "jdk.certpath.disabledAlgorithms"));

                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    "SLH-DSA-SHA2-128s");
                assertFalse("matching parameter set entry should block key",
                    WolfCryptUtil.isKeyAllowed(slhDsaPub,
                        "jdk.certpath.disabledAlgorithms"));

                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    "SLH-DSA-SHAKE-128s");
                assertTrue("different parameter set should not block key",
                    WolfCryptUtil.isKeyAllowed(slhDsaPub,
                        "jdk.certpath.disabledAlgorithms"));
            }
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsKeyAllowedDHKeySize() throws Exception {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");
        PublicKey dhPub = null;

        /* RFC 3526 group 14, 2048-bit MODP prime, generator 2 */
        final BigInteger p = new BigInteger(
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
        final BigInteger g = BigInteger.valueOf(2);

        try {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("DH", "wolfJCE");
            kpg.initialize(new DHParameterSpec(p, g));
            dhPub = kpg.generateKeyPair().getPublic();
        } catch (Exception e) {
            /* skip, DH not available in native library */
            return;
        }

        try {
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "DH keySize < 2048");
            assertTrue("2048-bit DH key should be allowed",
                WolfCryptUtil.isKeyAllowed(dhPub,
                    "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "DH keySize < 3072");
            assertFalse("2048-bit DH key should be rejected",
                WolfCryptUtil.isKeyAllowed(dhPub,
                    "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledIncludeExpansion() {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");
        String origCurves = Security.getProperty(
            "jdk.disabled.namedCurves");

        try {
            Security.setProperty("jdk.disabled.namedCurves",
                "secp112r1, sect113r1");
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "MD2, include jdk.disabled.namedCurves");

            assertTrue("Included curve entry should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "secp112r1", "jdk.certpath.disabledAlgorithms"));
            assertTrue("Included entries apply for CertPath too",
                WolfCryptUtil.isAlgorithmDisabledForCertPath(
                    "sect113r1", "jdk.certpath.disabledAlgorithms"));
            assertFalse("Curve not in included list should be allowed",
                WolfCryptUtil.isAlgorithmDisabled(
                    "secp256r1", "jdk.certpath.disabledAlgorithms"));
            assertTrue("Entries next to the include still apply",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD2", "jdk.certpath.disabledAlgorithms"));

            /* Include cycles terminate, entries still found */
            Security.setProperty("jdk.disabled.namedCurves",
                "sect113r1, include jdk.certpath.disabledAlgorithms");
            assertTrue("Entries still found with include cycle",
                WolfCryptUtil.isAlgorithmDisabled(
                    "sect113r1", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
            if (origCurves != null) {
                Security.setProperty("jdk.disabled.namedCurves",
                    origCurves);
            } else {
                Security.setProperty("jdk.disabled.namedCurves", "");
            }
        }
    }

    @Test
    public void testGetDisabledAlgorithmsKeySizeLimitNameMatch() {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Entries match on leading algorithm name, "ECDH keySize"
             * must not set the "DH" limit */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "ECDH keySize < 4096");
            assertEquals("ECDH entry must not set DH key size limit", 0,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "DH", "jdk.certpath.disabledAlgorithms"));
            assertEquals("ECDH entry should set ECDH key size limit", 4096,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "ECDH", "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize < 1024, EC keySize < 224");
            assertEquals(1024,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "RSA", "jdk.certpath.disabledAlgorithms"));
            assertEquals(224,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "EC", "jdk.certpath.disabledAlgorithms"));

            /* "<=" operator disables through N, minimum allowed N + 1 */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize <= 1023");
            assertEquals("keySize <= N should yield minimum of N + 1", 1024,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "RSA", "jdk.certpath.disabledAlgorithms"));

            /* Unsupported operators are ignored */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize >= 8192");
            assertEquals("Unsupported operator should be ignored", 0,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "RSA", "jdk.certpath.disabledAlgorithms"));

            /* Strictest of multiple matching entries wins */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize < 2048, RSA keySize < 1024");
            assertEquals("Strictest of multiple entries should win", 2048,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "RSA", "jdk.certpath.disabledAlgorithms"));

            /* keySize matching is case-insensitive, consistent with the
             * keySize entry skip in the name check */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA KEYSIZE < 1024");
            assertEquals("Uppercase KEYSIZE entry should set limit", 1024,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "RSA", "jdk.certpath.disabledAlgorithms"));

            /* keySize entry skip in the name check must not depend on the
             * default locale. Turkish lowercases 'I' to dotless 'ı', which
             * broke locale-sensitive toLowerCase() matching and caused
             * "RSA KEYSIZE < 1024" to blanket-disable RSA. */
            Locale origLocale = Locale.getDefault();
            try {
                Locale.setDefault(Locale.forLanguageTag("tr-TR"));
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    "RSA KEYSIZE < 1024");
                assertFalse("keySize entry must be skipped in any locale",
                    WolfCryptUtil.isAlgorithmDisabled(
                        "SHA256withRSA", "jdk.certpath.disabledAlgorithms"));
            } finally {
                Locale.setDefault(origLocale);
            }
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsKeyAllowedKeySizeUsageQualifiers() throws Exception {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");
        PublicKey rsaPub = null;

        try {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("RSA", "wolfJCE");
            kpg.initialize(2048);
            rsaPub = kpg.generateKeyPair().getPublic();
        } catch (Exception e) {
            /* skip, RSA key generation not available */
            return;
        }

        try {
            /* Usage-scoped keySize entry never applies to CertPath
             * validation, but stays active (fail closed) for the
             * generic check */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize < 3072 & usage TLSServer");
            assertTrue("Usage-scoped keySize entry must not apply " +
                "to CertPath",
                WolfCryptUtil.isKeyAllowedForCertPath(rsaPub,
                    "jdk.certpath.disabledAlgorithms"));
            assertFalse("Generic check treats usage keySize as active",
                WolfCryptUtil.isKeyAllowed(rsaPub,
                    "jdk.certpath.disabledAlgorithms"));

            /* Unqualified keySize entry applies to both */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize < 3072");
            assertFalse("Unqualified keySize entry applies to CertPath",
                WolfCryptUtil.isKeyAllowedForCertPath(rsaPub,
                    "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsKeyAllowedECNamedCurve() throws Exception {

        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");
        PublicKey ecPub = null;

        try {
            KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("EC", "wolfJCE");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            ecPub = kpg.generateKeyPair().getPublic();
        } catch (Exception e) {
            /* skip, EC key generation not available */
            return;
        }

        /* Curve name check only applies when params carry a name */
        if (!(((ECPublicKey)ecPub).getParams()
                instanceof WolfCryptECParameterSpec)) {
            return;
        }

        try {
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "secp256r1");
            assertFalse("Key on disabled named curve should be rejected",
                WolfCryptUtil.isKeyAllowed(ecPub,
                    "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "secp112r1, sect113r1");
            assertTrue("Key on non-disabled curve should be allowed",
                WolfCryptUtil.isKeyAllowed(ecPub,
                    "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledPBE() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test PBE algorithms with "and" delimiter */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "DES");
            assertTrue("PBEWithMD5AndDES should be disabled (DES part)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "PBEWithMD5AndDES", "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms", "MD5");
            assertTrue("PBEWithMD5AndDES should be disabled (MD5 part)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "PBEWithMD5AndDES", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledWithSlash() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test algorithms with "/" delimiter (AES/CBC/PKCS5Padding) */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "CBC");
            assertTrue("AES/CBC/PKCS5Padding should be disabled (CBC part)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "AES/CBC/PKCS5Padding",
                    "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms", "AES");
            assertTrue("AES/CBC/PKCS5Padding should be disabled (AES part)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "AES/CBC/PKCS5Padding",
                    "jdk.certpath.disabledAlgorithms"));

            /* "Padding" should not split on "in" */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "PKCS5Padd");
            assertFalse("PKCS5Padding should not be split on 'in'",
                WolfCryptUtil.isAlgorithmDisabled(
                    "AES/CBC/PKCS5Padding",
                    "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledSHAVariants() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test SHA name variants (SHA1 vs SHA-1, etc.) */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "SHA1");
            assertTrue("SHA1withRSA should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA1withRSA", "jdk.certpath.disabledAlgorithms"));
            assertTrue("SHA-1withRSA should also be disabled (variant)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA-1withRSA", "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms", "SHA-256");
            assertTrue("SHA256withRSA should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA256withRSA", "jdk.certpath.disabledAlgorithms"));
            assertTrue("SHA-256withRSA should also be disabled (variant)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA-256withRSA", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledMultiple() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test multiple disabled algorithms */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "MD2, MD5, SHA1");
            assertTrue("MD2 should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD2", "jdk.certpath.disabledAlgorithms"));
            assertTrue("MD5withRSA should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD5withRSA", "jdk.certpath.disabledAlgorithms"));
            assertTrue("SHA1withECDSA should be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA1withECDSA", "jdk.certpath.disabledAlgorithms"));
            assertFalse("SHA256withRSA should not be disabled",
                WolfCryptUtil.isAlgorithmDisabled(
                    "SHA256withRSA", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testIsAlgorithmDisabledEmpty() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test empty property */
            Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            assertFalse("MD2 should not be disabled (empty property)",
                WolfCryptUtil.isAlgorithmDisabled(
                    "MD2", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }

    @Test
    public void testGetDisabledAlgorithmsKeySizeLimit() {
        String origProperty = Security.getProperty(
            "jdk.certpath.disabledAlgorithms");

        try {
            /* Test parsing keySize constraints */
            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "RSA keySize < 2048");
            assertEquals("RSA keySize limit should be 2048", 2048,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "RSA", "jdk.certpath.disabledAlgorithms"));

            Security.setProperty("jdk.certpath.disabledAlgorithms",
                "EC keySize < 256, RSA keySize < 1024");
            assertEquals("EC keySize limit should be 256", 256,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "EC", "jdk.certpath.disabledAlgorithms"));
            assertEquals("RSA keySize limit should be 1024", 1024,
                WolfCryptUtil.getDisabledAlgorithmsKeySizeLimit(
                    "RSA", "jdk.certpath.disabledAlgorithms"));
        } finally {
            if (origProperty != null) {
                Security.setProperty("jdk.certpath.disabledAlgorithms",
                    origProperty);
            } else {
                Security.setProperty("jdk.certpath.disabledAlgorithms", "");
            }
        }
    }
}

