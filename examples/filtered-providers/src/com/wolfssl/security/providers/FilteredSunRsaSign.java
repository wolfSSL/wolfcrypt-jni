/* FilteredSunRsaSign.java
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
 * FilteredSunRsaSign is a custom security provider that filters out
 * cryptographic services from the original SunRsaSign provider,
 * retaining only the supporting non-cryptographic services.
 *
 * It retains only:
 *     - KeyFactory.RSASSA-PSS
 *
 * Set the system property wolfssl.filtered.debug=true to enable verbose
 * load/copy logging to stderr. Requires Java 9+ and the JVM module flags
 * documented in docs/add-opens.md.
 */
public class FilteredSunRsaSign extends Provider {

    private static final boolean DEBUG =
        Boolean.getBoolean("wolfssl.filtered.debug");

    public FilteredSunRsaSign() {

        super("FilteredSunRsaSign",
            System.getProperty("java.specification.version"),
            "Filtered SunRsaSign for non-crypto ops");

        try {
            if (DEBUG) {
                System.err.println("Loading original SunRsaSign...");
            }
            Class<?> originalClass =
                Class.forName("sun.security.rsa.SunRsaSign");
            Provider original =
                (Provider) originalClass.getDeclaredConstructor().newInstance();
            if (DEBUG) {
                System.err.println("Original SunRsaSign loaded. " +
                    "Services available: " + original.getServices().size());
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
                System.err.println("FilteredSunRsaSign initialized " +
                    "successfully with " + getServices().size() +
                    " services.");
            }

        } catch (Exception e) {
            System.err.println("Failed to initialize FilteredSunRsaSign: " + e);
            if (DEBUG) {
                e.printStackTrace(System.err);
            }
            throw new RuntimeException(
                "Failed to load and copy from original SunRsaSign", e);
        }
    }

    /**
     * Checks if the given service is supported by this provider.
     * This is the filtering logic that determines which services
     * are retained in the FilteredSunRsaSign provider.
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
            case "KeyFactory":
                if (algo.equals("RSASSA-PSS")) {
                    return true;
                }
                break;
            default:
                break;
        }

        return false;
    }
}

