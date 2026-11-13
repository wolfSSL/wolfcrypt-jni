/* FilteredProviderServiceLoaderTest.java
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

import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.wolfssl.wolfcrypt.test.TimedTestWatcher;

/**
 * ServiceLoader discovery test for the filtered Sun security providers.
 *
 * Verifies that FilteredSun, FilteredSunEC and FilteredSunRsaSign are found
 * through ServiceLoader.load(Provider.class), without constructing them
 * directly. JDK tools such as keytool find providers this way.
 *
 * On the class path, discovery uses META-INF/services/java.security.Provider.
 * On the module path (ant test-filtered-providers, second run), discovery
 * uses only the module-info "provides" clause, so this test fails if a
 * provider is missing from it.
 *
 * Requires Java 9+.
 */
public class FilteredProviderServiceLoaderTest {

    private static final String MODULE_NAME =
        "com.wolfssl.security.providers";

    /** Expected provider class name to provider name. */
    private static final Map<String, String> EXPECTED = new HashMap<>();
    static {
        EXPECTED.put("com.wolfssl.security.providers.FilteredSun",
            "FilteredSun");
        EXPECTED.put("com.wolfssl.security.providers.FilteredSunEC",
            "FilteredSunEC");
        EXPECTED.put("com.wolfssl.security.providers.FilteredSunRsaSign",
            "FilteredSunRsaSign");
    }

    /** Properties pinned to benign values while instantiating providers. */
    private static final String[] PIN_PROPS = {
        "wolfssl.filtered.useOriginalNames",
        "wolfssl.filtered.sun.additionalServices",
        "wolfssl.filtered.sunec.additionalServices",
        "wolfssl.filtered.sunrsasign.additionalServices" };

    /** Benign pin values for PIN_PROPS. */
    private static final String[] PIN_VALS = { "false", "", "", "" };

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkJavaVersion() {
        Assume.assumeTrue("FilteredSun* providers require Java 9 or greater",
            javaMajorVersion() >= 9);

        System.out.println("FilteredSun* provider ServiceLoader test");
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

    /**
     * Return the ServiceLoader entries for the filtered providers. Uses
     * stream() and type() so other providers on the class path (for example
     * wolfJCE, which needs its native library) are not instantiated.
     */
    private static Map<String, ServiceLoader.Provider<Provider>>
        findFilteredProviders() {

        return ServiceLoader.load(Provider.class).stream()
            .filter(p -> EXPECTED.containsKey(p.type().getName()))
            .collect(Collectors.toMap(p -> p.type().getName(), p -> p,
                (a, b) -> a));
    }

    @Test
    public void testAllProvidersDiscoverable() {

        Map<String, ServiceLoader.Provider<Provider>> found =
            findFilteredProviders();

        assertEquals("ServiceLoader should return all filtered providers",
            new TreeSet<>(EXPECTED.keySet()), new TreeSet<>(found.keySet()));
    }

    @Test
    public void testDiscoveredProvidersInstantiate() {

        Map<String, ServiceLoader.Provider<Provider>> found =
            findFilteredProviders();

        /* Pin properties so names stay FilteredSun* and no extra services
         * are granted, even if the test JVM's java.security sets them.
         * Restore afterward. */
        String[] prev = new String[PIN_PROPS.length];
        for (int i = 0; i < PIN_PROPS.length; i++) {
            prev[i] = Security.getProperty(PIN_PROPS[i]);
            Security.setProperty(PIN_PROPS[i], PIN_VALS[i]);
        }
        try {
            for (Map.Entry<String, String> e : EXPECTED.entrySet()) {
                ServiceLoader.Provider<Provider> sp = found.get(e.getKey());
                assertNotNull("Not discovered: " + e.getKey(), sp);

                Provider p = sp.get();
                assertNotNull("ServiceLoader returned null for " +
                    e.getKey(), p);
                assertEquals("Provider name for " + e.getKey(),
                    e.getValue(), p.getName());
            }
        } finally {
            for (int i = 0; i < PIN_PROPS.length; i++) {
                Security.setProperty(PIN_PROPS[i],
                    (prev[i] != null) ? prev[i] : PIN_VALS[i]);
            }
        }
    }

    /**
     * When the module is in the boot layer (module path run), the providers
     * must come from it, not from a copy on the class path. Otherwise they
     * are on the class path, in the unnamed module.
     */
    @Test
    public void testProvidersFromExpectedModule() {

        Optional<Module> module = ModuleLayer.boot().findModule(MODULE_NAME);

        for (ServiceLoader.Provider<Provider> sp :
                findFilteredProviders().values()) {
            Module actual = sp.type().getModule();
            if (module.isPresent()) {
                assertEquals("Module of " + sp.type().getName(),
                    module.get(), actual);
            }
            else {
                assertFalse("Expected unnamed module for " +
                    sp.type().getName() + ", got " + actual.getName(),
                    actual.isNamed());
            }
        }
    }
}
