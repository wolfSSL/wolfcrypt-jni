/* FilteredProviderSmokeTest.java
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

package com.wolfssl.security.providers.test;

import static org.junit.Assert.*;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import java.security.Provider;
import java.security.Security;
import java.security.KeyFactory;
import java.security.AlgorithmParameters;
import java.security.cert.CertificateFactory;

import com.wolfssl.security.providers.FilteredSun;
import com.wolfssl.security.providers.FilteredSunEC;
import com.wolfssl.security.providers.FilteredSunRsaSign;
import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * Smoke test for the filtered Sun security providers.
 *
 * Verifies that FilteredSun, FilteredSunEC, and FilteredSunRsaSign can each be
 * instantiated and registered without throwing, and that the allow-listed
 * (non-crypto) services they expose resolve via a provider-specific Security
 * lookup:
 *     FilteredSun        (CertificateFactory X.509)
 *     FilteredSunEC      (AlgorithmParameters EC)
 *     FilteredSunRsaSign (KeyFactory RSASSA-PSS)
 *
 * No exact service-count assertions are made: the count each provider exposes
 * is the intersection of its allow-list with what the underlying JDK Sun
 * provider offers at runtime, which varies by JDK version.
 *
 * Requires Java 9+. See examples/filtered-providers/docs/add-opens.md for the
 * required (JDK-version-dependent) JVM module flags.
 */
public class FilteredProviderSmokeTest {

    private static Provider sun;
    private static Provider sunEc;
    private static Provider sunRsa;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkJavaVersionAndInstall() {
        Assume.assumeTrue(
            "FilteredSun* providers require Java 9 or greater",
            javaMajorVersion() >= 9);

        System.out.println("FilteredSun* provider smoke test");

        /* Construct all three providers; must not throw. */
        sun    = new FilteredSun();
        sunEc  = new FilteredSunEC();
        sunRsa = new FilteredSunRsaSign();

        Security.addProvider(sun);
        Security.addProvider(sunEc);
        Security.addProvider(sunRsa);
    }

    /**
     * Parse the JDK feature/major version from "java.specification.version"
     * ("1.8" = 8, "9" = 9, "17" = 17, ...).
     */
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

    @Test
    public void testProvidersInstantiateAndRegister() {
        assertNotNull("FilteredSun construction returned null", sun);
        assertNotNull("FilteredSunEC construction returned null", sunEc);
        assertNotNull("FilteredSunRsaSign construction returned null", sunRsa);

        assertNotNull("FilteredSun not registered",
            Security.getProvider("FilteredSun"));
        assertNotNull("FilteredSunEC not registered",
            Security.getProvider("FilteredSunEC"));
        assertNotNull("FilteredSunRsaSign not registered",
            Security.getProvider("FilteredSunRsaSign"));
    }

    @Test
    public void testFilteredSunCertificateFactoryX509() throws Exception {
        CertificateFactory cf =
            CertificateFactory.getInstance("X.509", "FilteredSun");
        assertNotNull("CertificateFactory X.509 not resolved from FilteredSun",
            cf);
        assertEquals("FilteredSun", cf.getProvider().getName());
    }

    @Test
    public void testFilteredSunEcAlgorithmParametersEC() throws Exception {
        AlgorithmParameters ap =
            AlgorithmParameters.getInstance("EC", "FilteredSunEC");
        assertNotNull("AlgorithmParameters EC not resolved from FilteredSunEC",
            ap);
        assertEquals("FilteredSunEC", ap.getProvider().getName());
    }

    @Test
    public void testFilteredSunRsaSignKeyFactoryRsaPss() throws Exception {
        KeyFactory kf =
            KeyFactory.getInstance("RSASSA-PSS", "FilteredSunRsaSign");
        assertNotNull(
            "KeyFactory RSASSA-PSS not resolved from FilteredSunRsaSign", kf);
        assertEquals("FilteredSunRsaSign", kf.getProvider().getName());
    }
}

