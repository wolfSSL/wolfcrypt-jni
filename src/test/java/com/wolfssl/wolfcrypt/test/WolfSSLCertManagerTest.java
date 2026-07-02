/* WolfSSLCertManagerTest.java
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

import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * JUnit4 test cases for WolfSSLCertManager CA loading functionality.
 */
public class WolfSSLCertManagerTest {

    private static String certPre = "";
    private static String caCertPem = null;

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
                    File f = new File(caCertPem);
                    Assume.assumeTrue("Test cert files not available: " +
                        caCertPem, f.exists());
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
}
