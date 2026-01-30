/* WolfSSLX509StoreCtxTest.java
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

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.junit.runner.Description;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.wolfssl.wolfcrypt.WolfSSLX509StoreCtx;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * Test cases for WolfSSLX509StoreCtx JNI wrapper.
 */
public class WolfSSLX509StoreCtxTest {

    private static String certPre = "";
    private static String caCertDer = null;
    private static String serverCertDer = null;
    private static String int1CertDer = null;
    private static String int2CertDer = null;
    private static String serverIntCertDer = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Rule to check if WolfSSLX509StoreCtx is available (OPENSSL_EXTRA) */
    @Rule(order = Integer.MIN_VALUE + 1)
    public TestRule storeCtxAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    try {
                        WolfSSLX509StoreCtx ctx = new WolfSSLX509StoreCtx();
                        ctx.free();
                    } catch (WolfCryptException e) {
                        Assume.assumeTrue(
                            "WolfSSLX509StoreCtx not available " +
                            "(OPENSSL_EXTRA not compiled in): " +
                            e.getMessage(), false);
                    } catch (UnsatisfiedLinkError e) {
                        Assume.assumeTrue(
                            "Native library not available: " +
                            e.getMessage(), false);
                    }
                    base.evaluate();
                }
            };
        }
    };

    /* Rule to check if cert files are available */
    @Rule(order = Integer.MIN_VALUE + 2)
    public TestRule certFilesAvailable = new TestRule() {
        @Override
        public Statement apply(final Statement base, Description description) {
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

        System.out.println("JNI WolfSSLX509StoreCtx Class");

        if (isAndroid()) {
            /* On Android, example certs/keys are on SD card */
            certPre = "/data/local/tmp/";
        }

        /* Set paths to example certs */
        caCertDer = certPre.concat("examples/certs/ca-cert.der");
        serverCertDer = certPre.concat("examples/certs/server-cert.der");
        int1CertDer = certPre.concat(
            "examples/certs/intermediate/ca-int-cert.der");
        int2CertDer = certPre.concat(
            "examples/certs/intermediate/ca-int2-cert.der");
        serverIntCertDer = certPre.concat(
            "examples/certs/intermediate/server-int-cert.der");
    }

    /**
     * Read file into byte array.
     */
    private byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    @Test
    public void testConstructorAndFree() throws Exception {

        WolfSSLX509StoreCtx ctx = new WolfSSLX509StoreCtx();
        assertNotNull(ctx);
        ctx.free();
    }

    @Test
    public void testDoubleFreeShouldNotThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = new WolfSSLX509StoreCtx();

        ctx.free();
        /* Second free should not throw */
        ctx.free();
    }

    @Test
    public void testAddCertificateWithValidCert() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();
            byte[] caCert = readFile(caCertDer);
            /* Should not throw */
            ctx.addCertificate(caCert);
        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testAddCertificateWithNullShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();
            ctx.addCertificate(null);
        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testAddCertificateWithEmptyShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();
            ctx.addCertificate(new byte[0]);
        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testAddCertificateWithInvalidDataShouldThrow()
        throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();
            ctx.addCertificate(new byte[] { 0x00, 0x01, 0x02, 0x03 });
        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testAddCertificateAfterFreeShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = new WolfSSLX509StoreCtx();
        ctx.free();
        byte[] caCert = readFile(caCertDer);
        ctx.addCertificate(caCert);
    }

    @Test
    public void testBuildSimpleChain() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            /* Add CA as trust anchor */
            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            /* Build chain for server cert */
            byte[] serverCert = readFile(serverCertDer);
            byte[][] chain = ctx.buildAndVerifyChain(serverCert, null, -1);

            /* Chain should have 2 certs: server + CA */
            assertNotNull(chain);
            assertEquals(2, chain.length);

            /* First cert should be server cert */
            assertNotNull(chain[0]);
            assertTrue(chain[0].length > 0);

            /* Second cert should be CA cert */
            assertNotNull(chain[1]);
            assertTrue(chain[1].length > 0);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test
    public void testBuildChainWithIntermediates() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        /* Check if intermediate cert files exist */
        File f = new File(int1CertDer);
        Assume.assumeTrue("Intermediate cert files not available",
            f.exists());

        try {
            ctx = new WolfSSLX509StoreCtx();

            /* Add root CA as trust anchor */
            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            /* Add intermediate certificates */
            byte[] int1Cert = readFile(int1CertDer);
            byte[] int2Cert = readFile(int2CertDer);
            ctx.addCertificate(int1Cert);
            ctx.addCertificate(int2Cert);

            /* Build chain for server cert that chains through intermediates */
            byte[] serverCert = readFile(serverIntCertDer);
            byte[][] chain = ctx.buildAndVerifyChain(serverCert, null, -1);

            /* Chain should have 4 certs: server + int2 + int1 + root */
            assertNotNull(chain);
            assertEquals(4, chain.length);

            /* Verify all certs in chain are valid */
            for (int i = 0; i < chain.length; i++) {
                assertNotNull("Chain cert " + i + " is null", chain[i]);
                assertTrue("Chain cert " + i + " is empty",
                    chain[i].length > 0);
            }

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test
    public void testBuildChainWithAdditionalIntermediatesParam()
        throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        /* Check if intermediate cert files exist */
        File f = new File(int1CertDer);
        Assume.assumeTrue("Intermediate cert files not available",
            f.exists());

        try {
            ctx = new WolfSSLX509StoreCtx();

            /* Add only root CA to store */
            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            /* Pass intermediates as parameter instead of adding to store */
            byte[] int1Cert = readFile(int1CertDer);
            byte[] int2Cert = readFile(int2CertDer);
            byte[][] intermediates = new byte[][] { int1Cert, int2Cert };

            /* Build chain for server cert */
            byte[] serverCert = readFile(serverIntCertDer);
            byte[][] chain = ctx.buildAndVerifyChain(
                serverCert, intermediates, -1);

            /* Chain should have 4 certs */
            assertNotNull(chain);
            assertEquals(4, chain.length);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testBuildChainWithNullTargetShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();
            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);
            ctx.buildAndVerifyChain(null, null, -1);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testBuildChainWithEmptyTargetShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();
            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);
            ctx.buildAndVerifyChain(new byte[0], null, -1);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testBuildChainWithNoTrustAnchorShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();
            /* Don't add any CA, just try to verify */
            byte[] serverCert = readFile(serverCertDer);
            ctx.buildAndVerifyChain(serverCert, null, -1);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testBuildChainWithWrongCAShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        /* Check if intermediate cert files exist */
        File f = new File(int1CertDer);
        Assume.assumeTrue("Intermediate cert files not available",
            f.exists());

        try {
            ctx = new WolfSSLX509StoreCtx();

            /* Add wrong CA (int1 as "root" - but server cert chains to int2) */
            byte[] int1Cert = readFile(int1CertDer);
            ctx.addCertificate(int1Cert);

            /* Try to verify server cert - should fail, can't build chain */
            byte[] serverCert = readFile(serverCertDer);
            ctx.buildAndVerifyChain(serverCert, null, -1);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testBuildChainAfterFreeShouldThrow() throws Exception {

        WolfSSLX509StoreCtx ctx = new WolfSSLX509StoreCtx();
        byte[] caCert = readFile(caCertDer);
        ctx.addCertificate(caCert);
        ctx.free();

        byte[] serverCert = readFile(serverCertDer);
        ctx.buildAndVerifyChain(serverCert, null, -1);
    }

    @Test
    public void testBuildChainWithMaxPathLength() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            byte[] serverCert = readFile(serverCertDer);

            /* With max path length of 1, should still work for simple chain */
            byte[][] chain = ctx.buildAndVerifyChain(serverCert, null, 1);
            assertNotNull(chain);
            assertEquals(2, chain.length);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test
    public void testBuildChainWithZeroMaxPathLength() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            byte[] serverCert = readFile(serverCertDer);

            /* With max path length of 0, only self-signed would work.
             * This test verifies the parameter is being passed correctly. */
            try {
                byte[][] chain = ctx.buildAndVerifyChain(serverCert, null, 0);
                /* wolfSSL may or may not enforce this strictly */
            } catch (WolfCryptException e) {
                /* Expected if strictly enforced */
            }

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test
    public void testMultipleChainBuilds() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            byte[] serverCert = readFile(serverCertDer);

            /* Build chain multiple times with same context */
            for (int i = 0; i < 5; i++) {
                byte[][] chain = ctx.buildAndVerifyChain(serverCert, null, -1);
                assertNotNull("Chain build " + i + " failed", chain);
                assertEquals("Chain build " + i + " wrong length",
                    2, chain.length);
            }

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test
    public void testAddMultipleCertificates() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            /* Add the same CA multiple times - should work */
            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);
            ctx.addCertificate(caCert);
            ctx.addCertificate(caCert);

            /* Should still be able to build chain */
            byte[] serverCert = readFile(serverCertDer);
            byte[][] chain = ctx.buildAndVerifyChain(serverCert, null, -1);
            assertNotNull(chain);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test
    public void testBuildChainWithEmptyIntermediatesArray() throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            byte[] serverCert = readFile(serverCertDer);

            /* Empty intermediates array should work like null */
            byte[][] chain = ctx.buildAndVerifyChain(
                serverCert, new byte[0][], -1);
            assertNotNull(chain);
            assertEquals(2, chain.length);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testBuildChainWithNullElementsInIntermediatesShouldThrow()
        throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            byte[] serverCert = readFile(serverCertDer);

            /* Intermediates array with null elements should throw */
            byte[][] intermediates = new byte[][] { null, null };
            ctx.buildAndVerifyChain(serverCert, intermediates, -1);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test(expected = WolfCryptException.class)
    public void testBuildChainWithEmptyElementsInIntermediatesShouldThrow()
        throws Exception {

        WolfSSLX509StoreCtx ctx = null;

        try {
            ctx = new WolfSSLX509StoreCtx();

            byte[] caCert = readFile(caCertDer);
            ctx.addCertificate(caCert);

            byte[] serverCert = readFile(serverCertDer);

            /* Intermediates array with empty elements should throw */
            byte[][] intermediates = new byte[][] { new byte[0] };
            ctx.buildAndVerifyChain(serverCert, intermediates, -1);

        } finally {
            if (ctx != null) {
                ctx.free();
            }
        }
    }

    @Test
    public void testAutoCloseable() throws Exception {

        /* Test try-with-resources works correctly */
        byte[] caCert = readFile(caCertDer);
        byte[] serverCert = readFile(serverCertDer);

        try (WolfSSLX509StoreCtx ctx = new WolfSSLX509StoreCtx()) {
            ctx.addCertificate(caCert);
            byte[][] chain = ctx.buildAndVerifyChain(serverCert, null, -1);
            assertNotNull(chain);
            assertEquals(2, chain.length);
        }
        /* ctx is automatically closed here */
    }

    @Test
    public void testConcurrentContexts() throws Exception {

        /* Test that multiple contexts can exist and work independently */
        WolfSSLX509StoreCtx ctx1 = null;
        WolfSSLX509StoreCtx ctx2 = null;

        try {
            ctx1 = new WolfSSLX509StoreCtx();
            ctx2 = new WolfSSLX509StoreCtx();

            byte[] caCert = readFile(caCertDer);
            byte[] serverCert = readFile(serverCertDer);

            /* Add CA to both contexts */
            ctx1.addCertificate(caCert);
            ctx2.addCertificate(caCert);

            /* Build chains with both contexts */
            byte[][] chain1 = ctx1.buildAndVerifyChain(serverCert, null, -1);
            byte[][] chain2 = ctx2.buildAndVerifyChain(serverCert, null, -1);

            assertNotNull(chain1);
            assertNotNull(chain2);
            assertEquals(chain1.length, chain2.length);

        } finally {
            if (ctx1 != null) {
                ctx1.free();
            }
            if (ctx2 != null) {
                ctx2.free();
            }
        }
    }
}

