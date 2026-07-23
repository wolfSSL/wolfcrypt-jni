/* FilteredSunEC.java
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
package com.wolfssl.security.providers;

import java.security.Provider;
import java.util.Set;

/**
 * FilteredSunEC is a custom security provider that filters out cryptographic
 * services from the original SunEC provider, retaining only the supporting
 * non-cryptographic services.
 *
 * It retains only:
 *
 *     - AlgorithmParameters.EC
 *
 * Set the wolfssl.filtered.useOriginalNames Security property to "true" (in
 * java.security, or via Security.setProperty() before this provider is first
 * instantiated) to register this provider under the original "SunEC" name
 * instead of "FilteredSunEC". This keeps applications and JDK code with
 * hardcoded provider names working. Only the allow-listed services above are
 * exposed regardless of the registered name.
 *
 * Set the system property wolfssl.filtered.debug=true to enable verbose
 * load/copy logging to stderr. Requires Java 9+ and the JVM module flags
 * documented in docs/add-opens.md.
 */
public class FilteredSunEC extends Provider {

    private static final boolean DEBUG =
        Boolean.getBoolean("wolfssl.filtered.debug");

    public FilteredSunEC() {

        super(ProviderServiceCopier.resolveName("FilteredSunEC", "SunEC"),
            System.getProperty("java.specification.version"),
            "Filtered SunEC for non-crypto ops");

        try {
            if (DEBUG) {
                System.err.println("Loading original SunEC...");
            }
            /* Unlike Sun/SunRsaSign (in java.base, reachable via the default
             * Class.forName() lookup), SunEC may live in the jdk.crypto.ec
             * module (JDK < 22), which only the platform loader can load. */
            ClassLoader pl = ClassLoader.getPlatformClassLoader();
            Class<?> originalClass =
                Class.forName("sun.security.ec.SunEC", true, pl);
            Provider original =
                (Provider) originalClass.getDeclaredConstructor().newInstance();
            if (DEBUG) {
                System.err.println("Original SunEC loaded. Services " +
                    "available: " + original.getServices().size());
            }

            Set<Provider.Service> services = original.getServices();
            for (Provider.Service s : services) {
                if (serviceSupported(s)) {
                    if (DEBUG) {
                        System.err.println("Copying " + s.getType() + "." +
                            s.getAlgorithm() + " with class: " +
                            s.getClassName() + ", attributes: " +
                            s.getAttribute("SupportedKeyClasses"));
                    }
                    putService(
                        ProviderServiceCopier.buildService(this, s, true));
                }
            }
            if (DEBUG) {
                System.err.println("FilteredSunEC initialized successfully " +
                    "with " + getServices().size() + " services.");
            }

        } catch (Exception e) {
            System.err.println("Failed to initialize FilteredSunEC: " + e);
            if (DEBUG) {
                e.printStackTrace(System.err);
            }
            throw new RuntimeException(
                "Failed to load and copy from original SunEC", e);
        }
    }

    /**
     * Checks if the given service is supported by this provider.
     * This is the filtering logic that determines which services
     * are retained in the FilteredSunEC provider.
     *
     * Edit this method to change the filtering logic.
     *
     * @param service the service to check
     *
     * @return true if the service is supported, false otherwise
     */
    public boolean serviceSupported(Provider.Service service) {

        String type = service.getType();
        String algo = service.getAlgorithm();

        switch (type) {
            case "AlgorithmParameters":
                if (algo.equals("EC")) {
                    return true;
                }
                break;
            default:
                break;
        }

        return false;
    }
}

