/* WolfCryptPKIXRevocationCheckerTest.java
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

package com.wolfssl.provider.jce.test;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.security.Security;
import java.security.Provider;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXRevocationChecker.Option;
import java.security.cert.X509Certificate;
import java.security.cert.Extension;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.WolfSSLCertManager;
import com.wolfssl.wolfcrypt.WolfCryptException;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;
import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.provider.jce.WolfCryptPKIXRevocationChecker;

/**
 * JUnit4 test cases for WolfCryptPKIXRevocationChecker.
 */
public class WolfCryptPKIXRevocationCheckerTest {

    protected String provider = "wolfJCE";
    private static String certPre = "";
    private static String caCertDer = null;
    private static String serverCertDer = null;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

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

        System.out.println("JCE WolfCryptPKIXRevocationChecker Class");

        /* Install wolfJCE provider at runtime */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        Provider p = Security.getProvider("wolfJCE");
        assertNotNull(p);

        if (isAndroid()) {
            /* On Android, example certs are on SD card */
            certPre = "/sdcard/";
        }

        /* Set paths to example certs */
        caCertDer =
            certPre.concat("examples/certs/ca-cert.der");
        serverCertDer =
            certPre.concat("examples/certs/server-cert.der");

        /* Test if file exists. Skip tests gracefully if cert files not
         * available (eg running on Android). */
        File f = new File(caCertDer);
        Assume.assumeTrue("Test cert files not available: " + caCertDer,
            f.exists());
    }

    @BeforeClass
    public static void checkAvailability() {
        /* RevocationChecker can be created even without OCSP support,
         * it will fail during init() if OCSP is not compiled in */
        System.out.println("JCE WolfCryptPKIXRevocationChecker Test");
    }

    @Test
    public void testGetRevocationChecker() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        assertNotNull(cpv);

        /* Get revocation checker */
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();
        assertNotNull(checker);
        assertTrue(checker instanceof WolfCryptPKIXRevocationChecker);
    }

    @Test
    public void testRevocationCheckerClone() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        assertNotNull(cpv);

        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();
        assertNotNull(checker);

        /* Clone the checker */
        PKIXRevocationChecker cloned = checker.clone();
        assertNotNull(cloned);
        assertTrue(cloned instanceof WolfCryptPKIXRevocationChecker);

        /* Should be different objects */
        assertNotSame(checker, cloned);
    }

    @Test
    public void testRevocationCheckerGetSetOptions() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Default options should be empty */
        Set<Option> options = checker.getOptions();
        assertNotNull(options);
        assertEquals(0, options.size());

        /* Set some options */
        Set<Option> newOptions = EnumSet.of(
            Option.PREFER_CRLS,
            Option.SOFT_FAIL);
        checker.setOptions(newOptions);

        /* Verify options were set */
        options = checker.getOptions();
        assertNotNull(options);
        assertEquals(2, options.size());
        assertTrue(options.contains(Option.PREFER_CRLS));
        assertTrue(options.contains(Option.SOFT_FAIL));

        /* Set null should clear options */
        checker.setOptions(null);
        options = checker.getOptions();
        assertNotNull(options);
        assertEquals(0, options.size());
    }

    @Test
    public void testRevocationCheckerGetSetOcspResponder() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Default should be null */
        URI responder = checker.getOcspResponder();
        assertNull(responder);

        /* Set OCSP responder */
        URI testResponder = new URI("http://ocsp.example.com:80");
        checker.setOcspResponder(testResponder);

        /* Verify it was set */
        responder = checker.getOcspResponder();
        assertNotNull(responder);
        assertEquals(testResponder, responder);

        /* Set null should clear */
        checker.setOcspResponder(null);
        responder = checker.getOcspResponder();
        assertNull(responder);
    }

    @Test
    public void testRevocationCheckerGetSetOcspResponderCert()
        throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Default should be null */
        X509Certificate cert = checker.getOcspResponderCert();
        assertNull(cert);

        /* Load a cert to use as responder cert */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate testCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set OCSP responder cert */
        checker.setOcspResponderCert(testCert);

        /* Verify it was set */
        cert = checker.getOcspResponderCert();
        assertNotNull(cert);
        assertEquals(testCert, cert);

        /* Set null should clear */
        checker.setOcspResponderCert(null);
        cert = checker.getOcspResponderCert();
        assertNull(cert);
    }

    @Test
    public void testRevocationCheckerGetSetOcspExtensions() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Default should be empty list (not null) per Java API */
        List<Extension> extensions = checker.getOcspExtensions();
        assertNotNull(extensions);
        assertEquals(0, extensions.size());

        /* Create a list of extensions (empty for this test) */
        List<Extension> testExtensions = new ArrayList<Extension>();

        /* Set extensions */
        checker.setOcspExtensions(testExtensions);

        /* Verify it was set (will be unmodifiable copy) */
        extensions = checker.getOcspExtensions();
        assertNotNull(extensions);
        assertEquals(0, extensions.size());

        /* Returned list should be unmodifiable */
        try {
            extensions.add(null);
            fail("Expected UnsupportedOperationException");
        } catch (UnsupportedOperationException e) {
            /* expected */
        }

        /* Set null should reset to empty list */
        checker.setOcspExtensions(null);
        extensions = checker.getOcspExtensions();
        assertNotNull(extensions);
        assertEquals(0, extensions.size());
    }

    @Test
    public void testRevocationCheckerGetSetOcspResponses() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Default should be empty map */
        Map<X509Certificate, byte[]> responses = checker.getOcspResponses();
        assertNotNull(responses);
        assertEquals(0, responses.size());

        /* Load a cert to use as key */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate testCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Create test responses map */
        Map<X509Certificate, byte[]> testResponses =
            new HashMap<X509Certificate, byte[]>();
        testResponses.put(testCert, new byte[] {0x01, 0x02, 0x03});

        /* Set responses */
        checker.setOcspResponses(testResponses);

        /* Verify it was set */
        responses = checker.getOcspResponses();
        assertNotNull(responses);
        assertEquals(1, responses.size());
        assertTrue(responses.containsKey(testCert));

        /* Returned map must be mutable for compatibility with JDK
         * sun.security.validator.PKIXValidator.addResponses() which adds
         * OCSP responses directly to the map returned by getOcspResponses(). */
        responses.put(testCert, new byte[] {0x04});
        assertEquals(1, responses.size());
        assertArrayEquals(new byte[] {0x04}, responses.get(testCert));

        /* Set null should clear to empty map */
        checker.setOcspResponses(null);
        responses = checker.getOcspResponses();
        assertNotNull(responses);
        assertEquals(0, responses.size());
    }

    @Test
    public void testRevocationCheckerGetSoftFailExceptions() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Default should be empty list */
        List<CertPathValidatorException> exceptions =
            checker.getSoftFailExceptions();
        assertNotNull(exceptions);
        assertEquals(0, exceptions.size());

        /* List should be unmodifiable */
        try {
            exceptions.add(null);
            fail("Expected UnsupportedOperationException");
        } catch (UnsupportedOperationException e) {
            /* expected */
        }
    }

    @Test
    public void testRevocationCheckerIsForwardCheckingSupported()
        throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* wolfSSL validates in reverse order */
        assertFalse(checker.isForwardCheckingSupported());
    }

    @Test
    public void testRevocationCheckerGetSupportedExtensions()
        throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Currently no critical extensions are processed */
        Set<String> extensions = checker.getSupportedExtensions();
        assertNotNull(extensions);
        assertEquals(0, extensions.size());
    }

    @Test
    public void testRevocationCheckerInitWithoutOCSPSupport()
        throws Exception {

        if (WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP is compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Attempting to init without SOFT_FAIL should throw exception */
        try {
            checker.init(false);
            fail("Expected CertPathValidatorException when OCSP not " +
                "compiled in");
        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }

    @Test
    public void testRevocationCheckerInitWithSoftFail() throws Exception {

        if (WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP is compiled in (test is for
             * non-OCSP case) */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Set SOFT_FAIL option */
        Set<Option> options = EnumSet.of(Option.SOFT_FAIL);
        checker.setOptions(options);

        /* Init should succeed with SOFT_FAIL even without OCSP */
        checker.init(false);

        /* Soft fail exceptions should contain error about OCSP
         * not compiled in */
        List<CertPathValidatorException> exceptions =
            checker.getSoftFailExceptions();
        assertNotNull(exceptions);
        if (!WolfCrypt.OcspEnabled()) {
            /* Should have exception about OCSP not compiled in */
            assertEquals(1, exceptions.size());
        }
    }

    @Test
    public void testRevocationCheckerInitWithOCSP() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Create CertManager for checker to use */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);

        /* Init should succeed */
        checker.init(false);

        /* Verify soft fail exceptions is empty */
        List<CertPathValidatorException> exceptions =
            checker.getSoftFailExceptions();
        assertNotNull(exceptions);
        assertEquals(0, exceptions.size());

        cm.free();
    }

    @Test
    public void testRevocationCheckerInitWithOcspResponder()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Set OCSP responder URL */
        URI responder = new URI("http://ocsp.example.com:80");
        checker.setOcspResponder(responder);

        /* Create CertManager */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);

        /* Init should succeed and configure override URL */
        checker.init(false);

        cm.free();
    }

    @Test
    public void testRevocationCheckerWithOnlyEndEntityOption()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Set ONLY_END_ENTITY option */
        Set<Option> options = EnumSet.of(Option.ONLY_END_ENTITY);
        checker.setOptions(options);

        /* Create CertManager */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);

        /* Init should succeed */
        checker.init(false);

        /* CertManager should not have CHECKALL flag set
         * (we can't directly verify this without native access,
         * but init succeeding is a good sign) */

        cm.free();
    }

    @Test
    public void testRevocationCheckerWithPreferCrlsOption() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Set PREFER_CRLS option */
        Set<Option> options = EnumSet.of(Option.PREFER_CRLS);
        checker.setOptions(options);

        /* Create CertManager */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);

        /* Init should succeed even without OCSP compiled in */
        checker.init(false);

        cm.free();
    }

    @Test
    public void testRevocationCheckerWithAllOptions() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Set all options */
        Set<Option> options = EnumSet.of(
            Option.ONLY_END_ENTITY,
            Option.PREFER_CRLS,
            Option.NO_FALLBACK,
            Option.SOFT_FAIL);
        checker.setOptions(options);

        /* Create CertManager */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);

        /* Init should succeed */
        checker.init(false);

        cm.free();
    }

    @Test
    public void testRevocationCheckerClonePreservesOptions()
        throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        PKIXRevocationChecker checker = (PKIXRevocationChecker)
            cpv.getRevocationChecker();

        /* Set options and OCSP responder */
        Set<Option> options = EnumSet.of(Option.SOFT_FAIL, Option.NO_FALLBACK);
        checker.setOptions(options);

        URI responder = new URI("http://ocsp.example.com:80");
        checker.setOcspResponder(responder);

        /* Clone */
        PKIXRevocationChecker cloned = checker.clone();

        /* Verify cloned has same options */
        Set<Option> clonedOptions = cloned.getOptions();
        assertEquals(2, clonedOptions.size());
        assertTrue(clonedOptions.contains(Option.SOFT_FAIL));
        assertTrue(clonedOptions.contains(Option.NO_FALLBACK));

        /* Verify cloned has same OCSP responder */
        URI clonedResponder = cloned.getOcspResponder();
        assertNotNull(clonedResponder);
        assertEquals(responder, clonedResponder);

        /* Modifying clone should not affect original */
        cloned.setOptions(EnumSet.of(Option.PREFER_CRLS));
        options = checker.getOptions();
        assertEquals(2, options.size());
        assertFalse(options.contains(Option.PREFER_CRLS));
    }

    @Test
    public void testRevocationCheckerCheckNotInitialized() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load a cert */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Calling check() without init() should throw exception */
        try {
            checker.check(cert, null);
            fail("Expected CertPathValidatorException when not initialized");
        } catch (CertPathValidatorException e) {
            /* expected */
        }
    }

    @Test
    public void testRevocationCheckerCheckNonX509Cert() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Create CertManager and init */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);
        checker.init(false);

        /* Try to check a non-X509 certificate (use null as proxy) */
        try {
            checker.check(null, null);
            fail("Expected CertPathValidatorException for non-X509 cert");
        } catch (CertPathValidatorException e) {
            /* expected */
        } catch (NullPointerException e) {
            /* Also acceptable */
        }

        cm.free();
    }

    @Test
    public void testRevocationCheckerCheckWithPreloadedEmptyResponse()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load a cert */
        FileInputStream fis = new FileInputStream(serverCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set empty OCSP response for the cert */
        Map<X509Certificate, byte[]> responses =
            new HashMap<X509Certificate, byte[]>();
        responses.put(cert, new byte[0]);
        checker.setOcspResponses(responses);

        /* Create CertManager and init */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);
        checker.init(false);

        /* check() should fail with empty response */
        try {
            checker.check(cert, null);
            fail("Expected CertPathValidatorException with empty response");
        } catch (CertPathValidatorException e) {
            /* expected - empty OCSP response */
            assertTrue(e.getMessage().contains("Empty OCSP response"));
        }

        cm.free();
    }

    @Test
    public void testRevocationCheckerCheckWithPreloadedInvalidResponse()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load certs */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        fis = new FileInputStream(serverCertDer);
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set invalid OCSP response bytes */
        Map<X509Certificate, byte[]> responses =
            new HashMap<X509Certificate, byte[]>();
        responses.put(serverCert, new byte[] {0x30, 0x03, 0x01, 0x01, 0x00});
        checker.setOcspResponses(responses);

        /* Create CertManager, load CA, and init */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        cm.CertManagerLoadCA(caCert);
        checker.setCertManager(cm);
        checker.init(false);

        /* check() should fail with invalid response */
        try {
            checker.check(serverCert, null);
            fail("Expected CertPathValidatorException with invalid response");
        } catch (CertPathValidatorException e) {
            /* expected - invalid OCSP response format */
        }

        cm.free();
    }

    @Test
    public void testRevocationCheckerSoftFailCollectsExceptions()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load certs */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        fis = new FileInputStream(serverCertDer);
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set SOFT_FAIL option and OCSP override URL (unreachable) to force
         * OCSP lookup attempt. Test certs don't have embedded OCSP URL. */
        Set<Option> options = EnumSet.of(Option.SOFT_FAIL);
        checker.setOptions(options);
        checker.setOcspResponder(new URI("http://127.0.0.1:12345"));

        /* Create CertManager, load CA, and init */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        cm.CertManagerLoadCA(caCert);
        checker.setCertManager(cm);
        checker.init(false);

        /* Soft fail exceptions should be empty after init */
        List<CertPathValidatorException> exceptions =
            checker.getSoftFailExceptions();
        assertEquals(0, exceptions.size());

        /* check() should not throw with SOFT_FAIL. OCSP may fail (collecting
         * exception) or succeed if wolfSSL skips OCSP for certs without
         * embedded OCSP URLs despite override being set. */
        checker.check(serverCert, null);

        /* Soft fail exceptions may or may not be collected depending on
         * whether wolfSSL attempts OCSP for certs without embedded URLs.
         * Just verify the call completed without throwing. */

        cm.free();
    }

    @Test
    public void testRevocationCheckerCheckWithCertChain() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load certs */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        fis = new FileInputStream(serverCertDer);
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set up cert chain (server -> CA) */
        List<X509Certificate> certChain = new ArrayList<X509Certificate>();
        certChain.add(serverCert);
        certChain.add(caCert);

        /* Set SOFT_FAIL and OCSP override URL to force OCSP attempt.
         * Test certs don't have embedded OCSP URL. */
        Set<Option> options = EnumSet.of(Option.SOFT_FAIL);
        checker.setOptions(options);
        checker.setOcspResponder(new URI("http://127.0.0.1:12345"));

        /* Create CertManager and init */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        cm.CertManagerLoadCA(caCert);
        checker.setCertManager(cm);
        checker.setCertChain(certChain);
        checker.init(false);

        /* check() should work (soft fail mode) and issuer should be found
         * from the cert chain. wolfSSL may or may not actually attempt OCSP
         * for certs without embedded OCSP URLs */
        checker.check(serverCert, null);

        cm.free();
    }

    @Test
    public void testRevocationCheckerPreferCrlsSkipsOcsp() throws Exception {

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load cert */
        FileInputStream fis = new FileInputStream(serverCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set PREFER_CRLS with NO_FALLBACK - should skip OCSP */
        Set<Option> options =
            EnumSet.of(Option.PREFER_CRLS, Option.NO_FALLBACK);
        checker.setOptions(options);

        /* Create CertManager and init - should work even without OCSP */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        checker.setCertManager(cm);
        checker.init(false);

        /* check() should return without doing OCSP (CRL check happens
         * later in CertManagerVerify) */
        checker.check(serverCert, null);

        /* Should have no soft fail exceptions since OCSP wasn't tried */
        List<CertPathValidatorException> exceptions =
            checker.getSoftFailExceptions();
        assertEquals(0, exceptions.size());

        cm.free();
    }

    @Test
    public void testRevocationCheckerPreferCrlsWithFallbackTriesOcsp()
        throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load certs */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        fis = new FileInputStream(serverCertDer);
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set PREFER_CRLS with SOFT_FAIL (no NO_FALLBACK) - should try OCSP
         * as fallback. Set OCSP override URL to force attempt since test
         * certs don't have embedded OCSP URL. */
        Set<Option> options = EnumSet.of(Option.PREFER_CRLS, Option.SOFT_FAIL);
        checker.setOptions(options);
        checker.setOcspResponder(new URI("http://127.0.0.1:12345"));

        /* Create CertManager and init */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        cm.CertManagerLoadCA(caCert);
        checker.setCertManager(cm);
        checker.init(false);

        /* check() should try OCSP (as fallback) since NO_FALLBACK not set.
         * wolfSSL may or may not actually attempt OCSP for certs without
         * embedded OCSP URLs - the key is the call completes without
         * throwing in SOFT_FAIL mode. */
        checker.check(serverCert, null);

        cm.free();
    }

    @Test
    public void testRevocationCheckerCheckNoCertManager() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load cert */
        FileInputStream fis = new FileInputStream(serverCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Init without setting CertManager */
        checker.init(false);

        /* check() should fail - no CertManager available */
        try {
            checker.check(serverCert, null);
            fail("Expected CertPathValidatorException without CertManager");
        } catch (CertPathValidatorException e) {
            assertTrue(e.getMessage().contains("CertManager not available"));
        }
    }

    @Test
    public void testRevocationCheckerInitClearsExceptions() throws Exception {

        if (!WolfCrypt.OcspEnabled()) {
            /* Skip test if OCSP not compiled in */
            return;
        }

        CertPathValidator cpv =
            CertPathValidator.getInstance("PKIX", provider);
        WolfCryptPKIXRevocationChecker checker =
            (WolfCryptPKIXRevocationChecker)cpv.getRevocationChecker();

        /* Load certs */
        FileInputStream fis = new FileInputStream(caCertDer);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        fis = new FileInputStream(serverCertDer);
        X509Certificate serverCert =
            (X509Certificate)cf.generateCertificate(fis);
        fis.close();

        /* Set SOFT_FAIL and OCSP override URL to force OCSP attempt.
         * Test certs don't have embedded OCSP URL. */
        Set<Option> options = EnumSet.of(Option.SOFT_FAIL);
        checker.setOptions(options);
        checker.setOcspResponder(new URI("http://127.0.0.1:12345"));

        /* Create CertManager and init */
        WolfSSLCertManager cm = new WolfSSLCertManager();
        cm.CertManagerLoadCA(caCert);
        checker.setCertManager(cm);
        checker.init(false);

        /* Trigger check - may or may not collect soft fail exception
         * depending on wolfSSL behavior with override URLs */
        checker.check(serverCert, null);

        /* Re-init should clear any collected exceptions */
        checker.init(false);
        List<CertPathValidatorException> exceptions =
            checker.getSoftFailExceptions();
        assertEquals("init() should clear soft fail exceptions",
            0, exceptions.size());

        cm.free();
    }
}

