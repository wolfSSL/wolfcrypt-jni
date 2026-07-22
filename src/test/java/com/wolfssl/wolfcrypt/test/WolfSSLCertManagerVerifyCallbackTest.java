/* WolfSSLCertManagerVerifyCallbackTest.java
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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfSSLCertManagerVerifyCallback;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * Tests for the WolfSSLCertManager verify callback, including concurrent
 * verification while callbacks are registered and cleared.
 */
public class WolfSSLCertManagerVerifyCallbackTest {

    private static String certPre = "";
    private static String caCertDer = null;
    private static String serverCertDer = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    /* Skip tests if example cert files are not available. */
    @Rule(order = Integer.MIN_VALUE + 1)
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

    /* Skip tests if WolfSSLCertManager or the verify callback are not
     * compiled into the native library. */
    @Rule(order = Integer.MIN_VALUE + 2)
    public TestRule verifyCallbackAvailable = new TestRule() {

        @Override
        public Statement apply(final Statement base, Description description) {

            return new Statement() {
                @Override
                public void evaluate() throws Throwable {
                    WolfSSLCertManager cm = null;
                    try {
                        cm = new WolfSSLCertManager();
                        cm.setVerifyCallback(
                            new WolfSSLCertManagerVerifyCallback() {
                                public int verify(int preverify, int error,
                                    int errorDepth) {
                                    return 1;
                                }
                            });
                    } catch (WolfCryptException e) {
                        Assume.assumeTrue(
                            "WolfSSLCertManager verify callback not " +
                            "available, skipping", false);
                    } finally {
                        if (cm != null) {
                            cm.free();
                        }
                    }
                    base.evaluate();
                }
            };
        }
    };

    private static boolean isAndroid() {
        if (System.getProperty("java.runtime.name").contains("Android")) {
            return true;
        }
        return false;
    }

    @BeforeClass
    public static void testSetup() throws Exception {

        System.out.println("JNI WolfSSLCertManagerVerifyCallback Class");

        if (isAndroid()) {
            /* On Android, example certs/keys are on SD card */
            certPre = "/data/local/tmp/";
        }

        caCertDer = certPre.concat("examples/certs/ca-cert.der");
        serverCertDer = certPre.concat("examples/certs/server-cert.der");
    }

    private static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    /**
     * Test invoking the verify callback during CertManagerVerifyBuffer().
     */
    @Test
    public void testVerifyCallbackInvoked() throws Exception {

        final AtomicBoolean invoked = new AtomicBoolean(false);
        WolfSSLCertManager cm = null;

        byte[] caDer = readFile(caCertDer);
        byte[] serverDer = readFile(serverCertDer);

        try {
            cm = new WolfSSLCertManager();
            cm.CertManagerLoadCABuffer(caDer, caDer.length,
                WolfCrypt.SSL_FILETYPE_ASN1);

            cm.setVerifyCallback(new WolfSSLCertManagerVerifyCallback() {
                public int verify(int preverify, int error, int errorDepth) {
                    invoked.set(true);
                    return 1;
                }
            });

            try {
                cm.CertManagerVerifyBuffer(serverDer, serverDer.length,
                    WolfCrypt.SSL_FILETYPE_ASN1);
            } catch (WolfCryptException e) {
                /* Verification result itself is not what we assert here */
            }

            assertTrue("verify callback should have been invoked",
                invoked.get());

        } finally {
            if (cm != null) {
                cm.free();
            }
        }
    }

    /**
     * Test concurrent certificate verification while callbacks are registered
     * and cleared. The native callback list is global across all CertManager
     * instances, so this runs many managers verifying.
     */
    @Test
    public void testConcurrentVerifyAndClearCallback()
        throws Exception {

        final int numPairs = 8;
        final long runMillis = 1500;
        final byte[] caDer = readFile(caCertDer);
        final byte[] serverDer = readFile(serverCertDer);

        final AtomicBoolean stop = new AtomicBoolean(false);
        final AtomicLong verifies = new AtomicLong(0);
        final List<Throwable> errors =
            Collections.synchronizedList(new ArrayList<Throwable>());

        List<Thread> threads = new ArrayList<Thread>();

        for (int i = 0; i < numPairs; i++) {

            /* Register a callback and verify in a loop */
            threads.add(new Thread(new Runnable() {
                public void run() {
                    WolfSSLCertManager cm = null;
                    try {
                        cm = new WolfSSLCertManager();
                        cm.CertManagerLoadCABuffer(caDer, caDer.length,
                            WolfCrypt.SSL_FILETYPE_ASN1);
                        cm.setVerifyCallback(
                            new WolfSSLCertManagerVerifyCallback() {
                                public int verify(int preverify, int error,
                                    int errorDepth) {
                                    return 1;
                                }
                            });

                        while (!stop.get()) {
                            try {
                                cm.CertManagerVerifyBuffer(serverDer,
                                    serverDer.length,
                                    WolfCrypt.SSL_FILETYPE_ASN1);
                            } catch (WolfCryptException e) {
                                /* Verification result itself is not
                                 * what we assert here */
                            }
                            verifies.incrementAndGet();
                        }
                    } catch (Throwable t) {
                        errors.add(t);
                    } finally {
                        if (cm != null) {
                            cm.free();
                        }
                    }
                }
            }));

            /* Churner: repeatedly registers then clears its callback,
             * freeing and reallocating its ctx node in the shared global
             * callback list. */
            threads.add(new Thread(new Runnable() {
                public void run() {
                    WolfSSLCertManager cm = null;
                    try {
                        cm = new WolfSSLCertManager();
                        cm.CertManagerLoadCABuffer(caDer, caDer.length,
                            WolfCrypt.SSL_FILETYPE_ASN1);
                        while (!stop.get()) {
                            cm.setVerifyCallback(
                                new WolfSSLCertManagerVerifyCallback() {
                                    public int verify(int preverify, int error,
                                        int errorDepth) {
                                        return 1;
                                    }
                                });
                            cm.setVerifyCallback(null);
                        }
                    } catch (Throwable t) {
                        errors.add(t);
                    } finally {
                        if (cm != null) {
                            cm.free();
                        }
                    }
                }
            }));
        }

        for (Thread t : threads) {
            t.start();
        }
        Thread.sleep(runMillis);
        stop.set(true);
        for (Thread t : threads) {
            t.join();
        }

        if (!errors.isEmpty()) {
            fail("Concurrent verify/clear raised " + errors.size() +
                " error(s), first: " + errors.get(0));
        }
        assertTrue("expected at least one verify to run",
            verifies.get() > 0);
    }
}
