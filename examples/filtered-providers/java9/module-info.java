/* module-info.java
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

/**
 * Filtered Sun security providers module (FilteredSun, FilteredSunEC,
 * FilteredSunRsaSign).
 *
 * On the module path, --add-opens / --add-exports flags must target this
 * module name (see docs/add-opens.md). Ignored on the class path.
 *
 * Kept outside src/ because the Maven filtered-providers profile compiles
 * src/ into target/classes, which holds wolfcrypt-jni's own module-info.
 */
module com.wolfssl.security.providers {

    /* Allows explicit use, ex: Security.addProvider(new FilteredSun()) */
    exports com.wolfssl.security.providers;

    /* Keep in sync with src/META-INF/services/java.security.Provider */
    provides java.security.Provider with
        com.wolfssl.security.providers.FilteredSun,
        com.wolfssl.security.providers.FilteredSunEC,
        com.wolfssl.security.providers.FilteredSunRsaSign;
}
