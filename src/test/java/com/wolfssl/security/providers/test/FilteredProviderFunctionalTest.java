/* FilteredProviderFunctionalTest.java
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

package com.wolfssl.security.providers.test;

import static org.junit.Assert.*;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.io.FileInputStream;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;

import java.security.Provider;
import java.security.Security;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.wolfssl.security.providers.FilteredSun;
import com.wolfssl.security.providers.FilteredSunEC;
import com.wolfssl.security.providers.FilteredSunRsaSign;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Functional test for the filtered Sun security providers.
 *
 * Proves the providers' service copying preserves real functionality
 * end-to-end:
 *     - FilteredSun parses an X.509 certificate (CertificateFactory).
 *     - FilteredSunEC initializes AlgorithmParameters EC with secp256r1. For
 *       FilteredSunEC the copied Provider.Service overrides newInstance() to
 *       delegate to the original SunEC service, so a working instance proves
 *       the delegation path executes.
 *
 * Also asserts "no crypto leaked". Iterating each provider's getServices()
 * must not surface any service whose type is in the blocked crypto set.
 *
 * Also covers the wolfssl.filtered.useOriginalNames Security property, which
 * makes the providers register under the original Sun provider names for
 * compatibility with code that hardcodes those names.
 *
 * Requires Java 9+. See examples/filtered-providers/docs/add-opens.md for the
 * required (JDK-version-dependent) JVM module flags.
 */
public class FilteredProviderFunctionalTest {

    /** Crypto service TYPES that must never be exposed by these providers. */
    private static final Set<String> BLOCKED_TYPES = new HashSet<>(
        Arrays.asList(
            "Cipher", "Signature", "MessageDigest", "Mac",
            "KeyPairGenerator", "KeyGenerator", "SecureRandom",
            "KeyAgreement"));

    private static String caEccCertDer;

    /** Security property controlling filtered provider registration names. */
    private static final String NAME_PROP = "wolfssl.filtered.useOriginalNames";

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkJavaVersionAndInstall() {
        Assume.assumeTrue(
            "FilteredSun* providers require Java 9 or greater",
            javaMajorVersion() >= 9);

        System.out.println("FilteredSun* provider functional test");

        /* Pin the name override property to "false" while constructing and
         * registering the providers, so registration names stay FilteredSun*
         * even if the test JVM's java.security sets
         * wolfssl.filtered.useOriginalNames=true (e.g. on a hardened
         * image). Restore the prior value afterward. */
        String prev = Security.getProperty(NAME_PROP);
        Security.setProperty(NAME_PROP, "false");
        try {
            Security.addProvider(new FilteredSun());
            Security.addProvider(new FilteredSunEC());
            Security.addProvider(new FilteredSunRsaSign());
        } finally {
            Security.setProperty(NAME_PROP, (prev != null) ? prev : "false");
        }

        /* Relative path from repo root; forked tests have cwd = basedir. */
        String certPre = "";
        if (isAndroid()) {
            certPre = "/data/local/tmp/";
        }
        caEccCertDer = certPre.concat("examples/certs/ca-ecc-cert.der");
    }

    private static int javaMajorVersion() {
        String v = System.getProperty("java.specification.version");
        if (v == null) {
            return 0;
        }
        if (v.startsWith("1.")) {
            v = v.substring(2);
        }
        int dot = v.indexOf('.');
        if (dot >= 0) {
            v = v.substring(0, dot);
        }
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static boolean isAndroid() {
        String name = System.getProperty("java.runtime.name");
        return (name != null && name.contains("Android"));
    }

    @Test
    public void testFilteredSunParsesX509Cert() throws Exception {
        CertificateFactory cf =
            CertificateFactory.getInstance("X.509", "FilteredSun");

        X509Certificate cert;
        try (FileInputStream fis = new FileInputStream(caEccCertDer)) {
            cert = (X509Certificate) cf.generateCertificate(fis);
        }

        assertNotNull("Failed to parse X.509 cert via FilteredSun", cert);
        assertNotNull("Parsed cert has null subject",
            cert.getSubjectX500Principal());
        assertEquals("FilteredSun", cf.getProvider().getName());
    }

    @Test
    public void testFilteredSunEcDelegatesNewInstance() throws Exception {
        AlgorithmParameters ap =
            AlgorithmParameters.getInstance("EC", "FilteredSunEC");

        /* init() exercises the delegating newInstance() path into SunEC. */
        ap.init(new ECGenParameterSpec("secp256r1"));

        assertNotNull("AlgorithmParameters EC encoding null after init",
            ap.getEncoded());
        assertEquals("FilteredSunEC", ap.getProvider().getName());
    }

    @Test
    public void testNoCryptoLeaked() {
        assertNoBlockedServices("FilteredSun");
        assertNoBlockedServices("FilteredSunEC");
        assertNoBlockedServices("FilteredSunRsaSign");
    }

    /**
     * Iterate the named provider's services and fail if any service type is in
     * the blocked crypto set. Version-robust: does not assume a fixed count.
     */
    private void assertNoBlockedServices(String providerName) {
        Provider p = Security.getProvider(providerName);
        assertNotNull(providerName + " not installed", p);

        for (Provider.Service svc : p.getServices()) {
            String type = svc.getType();
            assertFalse(providerName + " leaked blocked crypto service: "
                    + type + "." + svc.getAlgorithm(),
                BLOCKED_TYPES.contains(type));
        }
    }

    /**
     * Restore the Security property to its prior value, or to "false"
     * (equivalent to unset for name resolution) if it was never set.
     */
    private static void restoreSecurityProperty(String prev) {
        Security.setProperty(NAME_PROP, (prev != null) ? prev : "false");
    }

    /**
     * Return the 1-based registration position of the named provider,
     * or -1 if not registered.
     */
    private static int providerPosition(String name) {

        Provider[] providers = Security.getProviders();

        for (int i = 0; i < providers.length; i++) {
            if (providers[i].getName().equals(name)) {
                return i + 1;
            }
        }

        return -1;
    }

    @Test
    public void testDefaultNamesUnchanged() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            Security.setProperty(NAME_PROP, "false");

            assertEquals("FilteredSun",
                new FilteredSun().getName());
            assertEquals("FilteredSunEC",
                new FilteredSunEC().getName());
            assertEquals("FilteredSunRsaSign",
                new FilteredSunRsaSign().getName());

        } finally {
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testSecurityPropertyEnablesOriginalNames() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            Security.setProperty(NAME_PROP, "true");

            assertEquals("SUN", new FilteredSun().getName());
            assertEquals("SunEC", new FilteredSunEC().getName());
            assertEquals("SunRsaSign", new FilteredSunRsaSign().getName());

        } finally {
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testSystemPropertyIsIgnored() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            /* Only the Security property controls the name. A system property
             * of the same name must have no effect. */
            Security.setProperty(NAME_PROP, "false");
            System.setProperty(NAME_PROP, "true");

            assertEquals("FilteredSun", new FilteredSun().getName());

        } finally {
            System.clearProperty(NAME_PROP);
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testInfoStringUnchangedWithOverride() {
        String prev = Security.getProperty(NAME_PROP);

        try {
            Security.setProperty(NAME_PROP, "true");

            /* getInfo() must keep identifying the provider as filtered even
             * when registered under the original name, so audits and telemetry
             * can distinguish it from the stock SUN. */
            Provider p = new FilteredSun();
            assertEquals("SUN", p.getName());
            assertEquals("Filtered SUN for non-crypto ops", p.getInfo());

        } finally {
            restoreSecurityProperty(prev);
        }
    }

    @Test
    public void testHardcodedSunLookupResolvesWithOverride()
        throws Exception {

        String prev = Security.getProperty(NAME_PROP);
        Provider realSun = Security.getProvider("SUN");
        int realSunPos = providerPosition("SUN");
        Provider filtered = null;
        boolean filteredAdded = false;

        try {
            Security.setProperty(NAME_PROP, "true");

            filtered = new FilteredSun();
            assertEquals("SUN", filtered.getName());

            /* Simulate the hardened JRE: the real SUN is not registered, the
             * filtered provider takes its place. On a stock test JDK the real
             * SUN is registered, so swap it out for the test duration. */
            if (realSun != null) {
                Security.removeProvider("SUN");
            }
            assertTrue("could not register filtered provider as SUN",
                Security.addProvider(filtered) != -1);
            filteredAdded = true;

            /* Hardcoded provider name lookup must now resolve to the
             * filtered provider instance */
            CertificateFactory cf =
                CertificateFactory.getInstance("X.509", "SUN");
            assertNotNull("CertificateFactory X.509 not resolved from " +
                "provider registered as SUN", cf);
            assertSame("lookup did not resolve to the filtered provider",
                filtered, cf.getProvider());

        } finally {
            if (filteredAdded) {
                Security.removeProvider(filtered.getName());
            }
            if (realSun != null && Security.getProvider("SUN") == null) {
                if (realSunPos > 0) {
                    Security.insertProviderAt(realSun, realSunPos);
                } else {
                    Security.addProvider(realSun);
                }
            }
            restoreSecurityProperty(prev);
        }
    }
}

