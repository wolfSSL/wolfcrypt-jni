/* WolfSSLCertManagerOCSPTest.java
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.junit.runner.Description;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * JUnit4 test cases for WolfSSLCertManager OCSP functionality.
 */
public class WolfSSLCertManagerOCSPTest {

    private static String certPre = "";
    private static String caCertDer = null;
    private static String serverCertDer = null;
    private static String caEccCertDer = null;
    private static String serverEccDer = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Rule to check if cert files are available, skips tests if not. */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule certFilesAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base,
                               Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    File f = new File(caCertDer);
                    Assume.assumeTrue("Test cert files not available: " +
                        caCertDer, f.exists());
                    base.evaluate();
                }
            };
        }
    };

    /* Rule to check if OCSP/WolfSSLCertManager is available. */
    @Rule(order = Integer.MIN_VALUE + 2)
    public TestRule ocspAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base,
                               Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    try {
                        new WolfSSLCertManager();
                    } catch (WolfCryptException e) {
                        if (!WolfCrypt.OcspEnabled()) {
                            Assume.assumeTrue(
                                "WolfSSLCertManager OCSP test skipped: " +
                                "OCSP not compiled in", false);
                        }
                        Assume.assumeNoException(e);
                    }
                    base.evaluate();
                }
            };
        }
    };

    /**
     * Test if this environment is Android.
     * @return true if Android, otherwise false
     */
    private static boolean isAndroid() {
        if (System.getProperty("java.runtime.name").contains("Android")) {
            return true;
        }
        return false;
    }

    @BeforeClass
    public static void testSetup() throws Exception {

        System.out.println("JNI WolfSSLCertManager OCSP Class");

        if (isAndroid()) {
            /* On Android, example certs/keys are on SD card */
            certPre = "/data/local/tmp/";
        }

        /* Set paths to example certs */
        caCertDer =
            certPre.concat("examples/certs/ca-cert.der");
        serverCertDer =
            certPre.concat("examples/certs/server-cert.der");
        caEccCertDer =
            certPre.concat("examples/certs/ca-ecc-cert.der");
        serverEccDer =
            certPre.concat("examples/certs/server-ecc.der");
    }

    @BeforeClass
    public static void checkAvailability() {
        System.out.println("JNI WolfSSLCertManager OCSP Test");
    }

    @Test
    public void testOcspEnabled() {
        /* This test should always run, just checks if OCSP is compiled in */
        boolean ocspEnabled = WolfCrypt.OcspEnabled();
        System.out.println("OCSP support compiled in: " + ocspEnabled);
    }

    @Test
    public void testCertManagerEnableDisableOCSP() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            /* Enable OCSP with no options */
            cm.CertManagerEnableOCSP(0);

            /* Disable OCSP */
            cm.CertManagerDisableOCSP();

            /* Enable OCSP with CHECKALL option */
            cm.CertManagerEnableOCSP(WolfCrypt.WOLFSSL_OCSP_CHECKALL);

            /* Disable OCSP again */
            cm.CertManagerDisableOCSP();

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerSetOCSPOverrideURL() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            /* Enable OCSP */
            cm.CertManagerEnableOCSP(0);

            /* Set override URL */
            cm.CertManagerSetOCSPOverrideURL("http://127.0.0.1:22220");

            /* Disable OCSP */
            cm.CertManagerDisableOCSP();

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerSetOCSPOverrideURLNullShouldFail()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            /* Passing null URL should throw WolfCryptException */
            try {
                cm.CertManagerSetOCSPOverrideURL(null);
                fail("Expected WolfCryptException when setting null URL");
            } catch (WolfCryptException e) {
                /* expected */
            }

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerCheckOCSPByteArray() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;
        FileInputStream fis = null;
        byte[] certDer = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            /* Load CA cert */
            fis = new FileInputStream(caCertDer);
            certDer = new byte[fis.available()];
            if (fis.read(certDer) != certDer.length) {
                throw new IOException("Failed to read CA cert");
            }
            fis.close();
            cm.CertManagerLoadCABuffer(certDer, certDer.length,
                WolfCrypt.SSL_FILETYPE_ASN1);

            /* Enable OCSP - will fail if no OCSP responder available,
             * so we just test that the API works without throwing
             * unexpected exceptions */
            cm.CertManagerEnableOCSP(0);

            /* Load server cert */
            fis = new FileInputStream(serverCertDer);
            certDer = new byte[fis.available()];
            if (fis.read(certDer) != certDer.length) {
                throw new IOException("Failed to read server cert");
            }
            fis.close();

            /* Try to check OCSP - this will likely fail since no OCSP
             * responder is running, but we're testing the API works */
            try {
                cm.CertManagerCheckOCSP(certDer, certDer.length);
                /* If it succeeds, that's fine too */
            } catch (WolfCryptException e) {
                /* Expected - no OCSP responder available */
            }

        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    /* ignore */
                }
            }
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerCheckOCSPX509Certificate() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;
        FileInputStream fis = null;
        CertificateFactory cf = null;
        X509Certificate caCert = null;
        X509Certificate serverCert = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            cf = CertificateFactory.getInstance("X.509");

            /* Load CA cert */
            fis = new FileInputStream(caCertDer);
            caCert = (X509Certificate)cf.generateCertificate(fis);
            fis.close();
            cm.CertManagerLoadCA(caCert);

            /* Enable OCSP */
            cm.CertManagerEnableOCSP(0);

            /* Load server cert */
            fis = new FileInputStream(serverCertDer);
            serverCert = (X509Certificate)cf.generateCertificate(fis);
            fis.close();

            /* Try to check OCSP - will likely fail with no responder */
            try {
                cm.CertManagerCheckOCSP(serverCert);
            } catch (WolfCryptException e) {
                /* Expected - no OCSP responder available */
            }

        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    /* ignore */
                }
            }
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerCheckOCSPNullCertShouldFail() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            cm.CertManagerEnableOCSP(0);

            /* Null cert should throw exception */
            try {
                cm.CertManagerCheckOCSP((byte[])null, 0);
                fail("Expected WolfCryptException with null cert");
            } catch (WolfCryptException e) {
                /* expected */
            }

            /* Null X509Certificate should throw exception */
            try {
                cm.CertManagerCheckOCSP((X509Certificate)null);
                fail("Expected WolfCryptException with null X509Certificate");
            } catch (WolfCryptException e) {
                /* expected */
            }

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerCheckOCSPResponseByteArrays()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;
        FileInputStream fis = null;
        byte[] certDer = null;
        byte[] fakeResponse = new byte[256];

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            /* Load CA cert */
            fis = new FileInputStream(caCertDer);
            certDer = new byte[fis.available()];
            if (fis.read(certDer) != certDer.length) {
                throw new IOException("Failed to read CA cert");
            }
            fis.close();
            cm.CertManagerLoadCABuffer(certDer, certDer.length,
                WolfCrypt.SSL_FILETYPE_ASN1);

            /* Enable OCSP */
            cm.CertManagerEnableOCSP(0);

            /* Load server cert */
            fis = new FileInputStream(serverCertDer);
            certDer = new byte[fis.available()];
            if (fis.read(certDer) != certDer.length) {
                throw new IOException("Failed to read server cert");
            }
            fis.close();

            /* Try to check fake OCSP response - should fail parsing */
            try {
                cm.CertManagerCheckOCSPResponse(fakeResponse,
                    fakeResponse.length, certDer, certDer.length);
                fail("Expected WolfCryptException with invalid response");
            } catch (WolfCryptException e) {
                /* Expected - invalid OCSP response format */
            }

        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    /* ignore */
                }
            }
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerCheckOCSPResponseX509Certificate()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;
        FileInputStream fis = null;
        CertificateFactory cf = null;
        X509Certificate caCert = null;
        X509Certificate serverCert = null;
        byte[] fakeResponse = new byte[256];

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            cf = CertificateFactory.getInstance("X.509");

            /* Load CA cert */
            fis = new FileInputStream(caCertDer);
            caCert = (X509Certificate)cf.generateCertificate(fis);
            fis.close();
            cm.CertManagerLoadCA(caCert);

            /* Enable OCSP */
            cm.CertManagerEnableOCSP(0);

            /* Load server cert */
            fis = new FileInputStream(serverCertDer);
            serverCert = (X509Certificate)cf.generateCertificate(fis);
            fis.close();

            /* Try to check fake OCSP response */
            try {
                cm.CertManagerCheckOCSPResponse(fakeResponse, serverCert);
                fail("Expected WolfCryptException with invalid response");
            } catch (WolfCryptException e) {
                /* Expected - invalid OCSP response format */
            }

        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                    /* ignore */
                }
            }
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerCheckOCSPResponseNullsShouldFail()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;
        byte[] response = new byte[256];
        byte[] cert = new byte[256];

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            cm.CertManagerEnableOCSP(0);

            /* Null response should throw exception */
            try {
                cm.CertManagerCheckOCSPResponse(null, 0, cert, cert.length);
                fail("Expected WolfCryptException with null response");
            } catch (WolfCryptException e) {
                /* expected */
            }

            /* Null cert should throw exception */
            try {
                cm.CertManagerCheckOCSPResponse(response, response.length,
                    null, 0);
                fail("Expected WolfCryptException with null cert");
            } catch (WolfCryptException e) {
                /* expected */
            }

            /* Both null should throw exception */
            try {
                cm.CertManagerCheckOCSPResponse(null, 0, null, 0);
                fail("Expected WolfCryptException with null params");
            } catch (WolfCryptException e) {
                /* expected */
            }

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }

    @Test
    public void testCertManagerOCSPAfterFree() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);
            cm.free();

            /* Using OCSP methods after free should throw
             * IllegalStateException */
            try {
                cm.CertManagerEnableOCSP(0);
                fail("Expected IllegalStateException after free");
            } catch (IllegalStateException e) {
                /* expected */
            }

        } catch (WolfCryptException e) {
            /* CertManager creation failed */
        }
    }

    @Test
    public void testCertManagerEnableOCSPWithMultipleOptions()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* OCSP not compiled in, skip test */
            return;
        }

        WolfSSLCertManager cm = null;

        try {
            cm = new WolfSSLCertManager();
            assertNotNull(cm);

            /* Enable OCSP with multiple options combined */
            int options = WolfCrypt.WOLFSSL_OCSP_CHECKALL |
                          WolfCrypt.WOLFSSL_OCSP_NO_NONCE;
            cm.CertManagerEnableOCSP(options);

            /* Disable OCSP */
            cm.CertManagerDisableOCSP();

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }
}

