/* WolfCryptServiceLoaderTest.java
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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.BeforeClass;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.ServiceLoader;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Test suite for ServiceLoader functionality.
 *
 * Tests that WolfCryptProvider can be discovered via Java ServiceLoader
 * mechanism, which is required for Java Module System compatibility and
 * some security frameworks.
 */
public class WolfCryptServiceLoaderTest {

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = new TestWatcher() {
        @Override
        protected void starting(Description desc) {
            System.out.println("\t" + desc.getMethodName());
        }
    };

    @BeforeClass
    public static void setUpClass() {
        System.out.println("JCE WolfCryptProvider ServiceLoader Test");
    }

    /**
     * Test that WolfCryptProvider can be discovered via ServiceLoader.
     * This verifies that the META-INF/services/java.security.Provider
     * file exists in the JAR and contains the correct provider class name.
     */
    @Test
    public void testProviderDiscoverableViaServiceLoader() {
        ServiceLoader<Provider> serviceLoader =
            ServiceLoader.load(Provider.class);

        boolean foundWolfCrypt = false;
        Iterator<Provider> iterator = serviceLoader.iterator();

        while (iterator.hasNext()) {
            Provider provider = iterator.next();
            String className = provider.getClass().getName();

            /* Check if we found WolfCryptProvider */
            if (className.equals(
                "com.wolfssl.provider.jce.WolfCryptProvider")) {
                foundWolfCrypt = true;

                /* Verify provider name is correct */
                assertEquals("Provider name should be wolfJCE",
                    "wolfJCE", provider.getName());

                /* Verify it's the right class */
                assertTrue("Provider should be instance of " +
                    "WolfCryptProvider",
                    provider instanceof WolfCryptProvider);

                break;
            }
        }

        assertTrue("WolfCryptProvider should be discoverable via " +
            "ServiceLoader", foundWolfCrypt);
    }

    /**
     * Test that ServiceLoader-discovered provider is functional.
     * This verifies that providers loaded via ServiceLoader can actually
     * be used for cryptographic operations.
     */
    @Test
    public void testServiceLoaderProviderIsFunctional() throws Exception {
        ServiceLoader<Provider> serviceLoader =
            ServiceLoader.load(Provider.class);

        Provider wolfCryptProvider = null;
        Iterator<Provider> iterator = serviceLoader.iterator();

        while (iterator.hasNext()) {
            Provider provider = iterator.next();
            if (provider instanceof WolfCryptProvider) {
                wolfCryptProvider = provider;
                break;
            }
        }

        assertNotNull("Should find WolfCryptProvider via ServiceLoader",
            wolfCryptProvider);

        /* Add provider temporarily for testing */
        int position = Security.addProvider(wolfCryptProvider);

        try {
            /* Test that we can get a service from this provider */
            assertNotNull("Should be able to get MessageDigest.SHA-256",
                java.security.MessageDigest.getInstance(
                    "SHA-256", wolfCryptProvider));

        } finally {
            /* Remove provider after test */
            if (position != -1) {
                Security.removeProvider(wolfCryptProvider.getName());
            }
        }
    }

    /**
     * Test that WolfCryptProvider loaded via ServiceLoader matches
     * directly instantiated provider.
     */
    @Test
    public void testServiceLoaderProviderMatchesDirectInstance() {
        ServiceLoader<Provider> serviceLoader =
            ServiceLoader.load(Provider.class);

        Provider serviceLoaderProvider = null;
        Iterator<Provider> iterator = serviceLoader.iterator();

        while (iterator.hasNext()) {
            Provider provider = iterator.next();
            if (provider instanceof WolfCryptProvider) {
                serviceLoaderProvider = provider;
                break;
            }
        }

        assertNotNull("Should find provider via ServiceLoader",
            serviceLoaderProvider);

        /* Create direct instance */
        Provider directProvider = new WolfCryptProvider();

        /* Verify they have same name */
        assertEquals("Provider names should match",
            directProvider.getName(), serviceLoaderProvider.getName());

        /* Verify they have same version */
        assertEquals("Provider versions should match",
            directProvider.getVersion(),
            serviceLoaderProvider.getVersion(), 0.0);

        /* Verify they are same class */
        assertEquals("Provider classes should match",
            directProvider.getClass(), serviceLoaderProvider.getClass());
    }
}

