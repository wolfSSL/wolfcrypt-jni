/* WolfObject.java
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

package com.wolfssl.wolfcrypt;

/**
 * Loader for the native WolfCrypt implementation.
 * All classes in this package must inherit from it.
 *
 * Native library loading can be skipped by setting the System property
 * "wolfssl.skipLibraryLoad" to "true". This is useful for applications
 * that bundle native libraries inside JAR files and load them using
 * System.load() with absolute paths before any wolfSSL classes are
 * accessed. When this property is set, the application is responsible
 * for loading the native libraries before using any wolfSSL/wolfCrypt
 * functionality.
 */
public class WolfObject {

    private static native int init();

    /* Track if library loading was skipped via system property */
    private static boolean libraryLoadSkipped = false;

    /**
     * Check if native library loading was skipped.
     *
     * Library loading is skipped when the System property
     * "wolfssl.skipLibraryLoad" is set to "true".
     *
     * @return true if library loading was skipped, false otherwise
     */
    public static boolean isLibraryLoadSkipped() {
        return libraryLoadSkipped;
    }

    /**
     * Loads JNI library.
     *
     * The native library is expected to be called "wolfcryptjni", and must be
     * on the system library search path.
     *
     * "wolfcryptjni" links against the wolfSSL native C library ("wolfssl"),
     * and for Windows compatibility "wolfssl" needs to be explicitly loaded
     * first here.
     *
     * Library loading can be skipped by setting the System property
     * "wolfssl.skipLibraryLoad" to "true". This allows applications to
     * load native libraries manually using System.load() before accessing
     * any wolfSSL classes.
     */
    static {
        int fipsLoaded = 0;

        String skipLoad = System.getProperty("wolfssl.skipLibraryLoad");
        if (skipLoad != null && skipLoad.equalsIgnoreCase("true")) {
            /* User indicated they will load native libraries manually */
            libraryLoadSkipped = true;
        }
        else {
            String osName = System.getProperty("os.name");
            if (osName != null && osName.toLowerCase().contains("win")) {
                try {
                    /* Default wolfCrypt FIPS library on Windows is compiled
                     * as "wolfssl-fips" by Visual Studio solution */
                    System.loadLibrary("wolfssl-fips");
                    fipsLoaded = 1;
                } catch (UnsatisfiedLinkError e) {
                    /* wolfCrypt FIPS not available */
                }

                if (fipsLoaded == 0) {
                    /* FIPS library not loaded, try normal libwolfssl */
                    System.loadLibrary("wolfssl");
                }
            }

            /* Load wolfcryptjni library */
            System.loadLibrary("wolfcryptjni");
        }

        /* Initialize native wolfCrypt library */
        init();

        /* Run FIPS CAST if we are in FIPS mode. Will only forcefully
         * be run once - Fips class keeps track of a successful run. */
        if (Fips.enabled) {
            Fips.runAllCast_fips();
        }
    }

    /**
     * Create new WolfObject object
     */
    protected WolfObject() {
    }
}

