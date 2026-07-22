/* WolfSSLCertManagerTest.java
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

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runners.model.Statement;
import org.junit.runner.Description;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * JUnit4 test cases for WolfSSLCertManager CA loading functionality.
 */
public class WolfSSLCertManagerTest {

    private static String certPre = "";
    private static String caCertPem = null;
    private static String caCertDer = null;
    private static String serverCertDer = null;
    private static String caEccCertPem = null;
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
                    String[] certs = { caCertPem, caCertDer, serverCertDer,
                                       caEccCertPem, serverEccDer };
                    for (String cert : certs) {
                        File f = new File(cert);
                        Assume.assumeTrue("Test cert files not available: " +
                            cert, f.exists());
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

        System.out.println("JNI WolfSSLCertManager Class");

        if (isAndroid()) {
            /* On Android, example certs/keys are on SD card */
            certPre = "/data/local/tmp/";
        }

        /* Set paths to example certs */
        caCertPem = certPre.concat("examples/certs/ca-cert.pem");
        caCertDer = certPre.concat("examples/certs/ca-cert.der");
        serverCertDer = certPre.concat("examples/certs/server-cert.der");
        caEccCertPem = certPre.concat("examples/certs/ca-ecc-cert.pem");
        serverEccDer = certPre.concat("examples/certs/server-ecc.der");
    }

    @Test
    public void testCertManagerLoadCAFromFileNullDir() throws Exception {

        WolfSSLCertManager cm = new WolfSSLCertManager();

        /* Directory argument is documented as optional, null should
         * be passed through to native wolfSSL without error */
        try {
            cm.CertManagerLoadCA(caCertPem, null);

        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                /* Skip test if filesystem support not compiled in */
                Assume.assumeNoException(e);
            }
            throw e;

        } finally {
            cm.free();
        }
    }

    @Test
    public void testCertManagerLoadCANullFileNullDir() throws Exception {

        WolfSSLCertManager cm = new WolfSSLCertManager();

        /* Both arguments null should throw exception, not crash */
        try {
            cm.CertManagerLoadCA(null, null);
            fail("CertManagerLoadCA(null, null) should throw exception");

        } catch (WolfCryptException e) {
            /* expected */

        } finally {
            cm.free();
        }
    }

    @Test
    public void testCertManagerLoadCABufferTrailingData() throws Exception {

        byte[] cert = Files.readAllBytes(Paths.get(caCertDer));

        /* Place cert into larger array with trailing padding bytes,
         * caller-provided sz should be honored over array length */
        byte[] padded = new byte[cert.length + 128];
        System.arraycopy(cert, 0, padded, 0, cert.length);

        WolfSSLCertManager cm = new WolfSSLCertManager();

        try {
            cm.CertManagerLoadCABuffer(padded, cert.length,
                WolfCrypt.SSL_FILETYPE_ASN1);

        } finally {
            cm.free();
        }
    }

    @Test
    public void testCertManagerLoadCABufferSzTooLarge() throws Exception {

        byte[] cert = Files.readAllBytes(Paths.get(caCertDer));

        WolfSSLCertManager cm = new WolfSSLCertManager();

        /* sz larger than array length should throw exception */
        try {
            cm.CertManagerLoadCABuffer(cert, cert.length + 1,
                WolfCrypt.SSL_FILETYPE_ASN1);
            fail("CertManagerLoadCABuffer() with sz > array length " +
                 "should throw exception");

        } catch (WolfCryptException e) {
            /* expected */

        } finally {
            cm.free();
        }
    }

    @Test
    public void testCertManagerVerifyBufferTrailingData() throws Exception {

        byte[] caCert = Files.readAllBytes(Paths.get(caCertDer));
        byte[] peerCert = Files.readAllBytes(Paths.get(serverCertDer));

        /* Place cert into larger array with trailing padding bytes,
         * caller-provided sz should be honored over array length */
        byte[] padded = new byte[peerCert.length + 128];
        System.arraycopy(peerCert, 0, padded, 0, peerCert.length);

        WolfSSLCertManager cm = new WolfSSLCertManager();

        try {
            cm.CertManagerLoadCABuffer(caCert, caCert.length,
                WolfCrypt.SSL_FILETYPE_ASN1);
            cm.CertManagerVerifyBuffer(padded, peerCert.length,
                WolfCrypt.SSL_FILETYPE_ASN1);

        } finally {
            cm.free();
        }
    }

    @Test
    public void testCertManagerLoadCABufferSzLimitsTrust() throws Exception {

        byte[] caRsaPem = Files.readAllBytes(Paths.get(caCertPem));
        byte[] caEccPem = Files.readAllBytes(Paths.get(caEccCertPem));
        byte[] serverEcc = Files.readAllBytes(Paths.get(serverEccDer));

        /* Two PEM CA certs in one array, sz covers only the first (RSA).
         * Second (ECC) CA is past sz and must NOT be loaded as trusted */
        byte[] twoCAs = new byte[caRsaPem.length + caEccPem.length];
        System.arraycopy(caRsaPem, 0, twoCAs, 0, caRsaPem.length);
        System.arraycopy(caEccPem, 0, twoCAs, caRsaPem.length,
            caEccPem.length);

        WolfSSLCertManager cm = new WolfSSLCertManager();

        try {
            cm.CertManagerLoadCABuffer(twoCAs, caRsaPem.length,
                WolfCrypt.SSL_FILETYPE_PEM);

            /* Cert signed by second CA should NOT verify */
            try {
                cm.CertManagerVerifyBuffer(serverEcc, serverEcc.length,
                    WolfCrypt.SSL_FILETYPE_ASN1);
                fail("Cert signed by CA past caller-provided sz should " +
                     "not verify");

            } catch (WolfCryptException e) {
                /* expected */
            }

        } finally {
            cm.free();
        }
    }

    @Test
    public void testCertManagerVerifyBufferSzTooLarge() throws Exception {

        byte[] caCert = Files.readAllBytes(Paths.get(caCertDer));
        byte[] peerCert = Files.readAllBytes(Paths.get(serverCertDer));

        WolfSSLCertManager cm = new WolfSSLCertManager();

        /* sz larger than array length should throw exception */
        try {
            cm.CertManagerLoadCABuffer(caCert, caCert.length,
                WolfCrypt.SSL_FILETYPE_ASN1);
            cm.CertManagerVerifyBuffer(peerCert, peerCert.length + 1,
                WolfCrypt.SSL_FILETYPE_ASN1);
            fail("CertManagerVerifyBuffer() with sz > array length " +
                 "should throw exception");

        } catch (WolfCryptException e) {
            /* expected */

        } finally {
            cm.free();
        }
    }
}
