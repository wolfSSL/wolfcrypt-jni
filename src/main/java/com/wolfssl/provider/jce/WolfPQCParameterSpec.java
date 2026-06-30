/* WolfPQCParameterSpec.java
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

package com.wolfssl.provider.jce;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Named parameter spec for PQC algorithms, used as a JDK 8-10 fallback for
 * {@code java.security.spec.NamedParameterSpec} (introduced in JDK 11).
 *
 * <p>On JDK 11+, callers should prefer {@code NamedParameterSpec} directly.
 * wolfJCE KeyPairGenerators accept either form via reflection. On JDK 8-10
 * this class is the only option.</p>
 *
 * <p>The {@link #getName()} return matches the
 * {@code Signature}/{@code KEM}/{@code KeyPairGenerator}
 * algorithm-name conventions used in JDK 24 (JEP 497): {@code "ML-DSA-44"},
 * {@code "ML-DSA-65"}, {@code "ML-DSA-87"}, {@code "ML-KEM-512"},
 * {@code "ML-KEM-768"}, {@code "ML-KEM-1024"}, and the FIPS 205 SLH-DSA
 * parameter-set names ({@code "SLH-DSA-SHA2-128s"} ...
 * {@code "SLH-DSA-SHAKE-256f"}).</p>
 */
public class WolfPQCParameterSpec implements AlgorithmParameterSpec {

    /** ML-DSA-44 (FIPS 204). */
    public static final WolfPQCParameterSpec ML_DSA_44 =
        new WolfPQCParameterSpec("ML-DSA-44");

    /** ML-DSA-65 (FIPS 204). */
    public static final WolfPQCParameterSpec ML_DSA_65 =
        new WolfPQCParameterSpec("ML-DSA-65");

    /** ML-DSA-87 (FIPS 204). */
    public static final WolfPQCParameterSpec ML_DSA_87 =
        new WolfPQCParameterSpec("ML-DSA-87");

    /** ML-KEM-512 (FIPS 203). */
    public static final WolfPQCParameterSpec ML_KEM_512 =
        new WolfPQCParameterSpec("ML-KEM-512");

    /** ML-KEM-768 (FIPS 203). */
    public static final WolfPQCParameterSpec ML_KEM_768 =
        new WolfPQCParameterSpec("ML-KEM-768");

    /** ML-KEM-1024 (FIPS 203). */
    public static final WolfPQCParameterSpec ML_KEM_1024 =
        new WolfPQCParameterSpec("ML-KEM-1024");

    /** SLH-DSA-SHAKE-128s (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHAKE_128S =
        new WolfPQCParameterSpec("SLH-DSA-SHAKE-128s");

    /** SLH-DSA-SHAKE-128f (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHAKE_128F =
        new WolfPQCParameterSpec("SLH-DSA-SHAKE-128f");

    /** SLH-DSA-SHAKE-192s (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHAKE_192S =
        new WolfPQCParameterSpec("SLH-DSA-SHAKE-192s");

    /** SLH-DSA-SHAKE-192f (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHAKE_192F =
        new WolfPQCParameterSpec("SLH-DSA-SHAKE-192f");

    /** SLH-DSA-SHAKE-256s (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHAKE_256S =
        new WolfPQCParameterSpec("SLH-DSA-SHAKE-256s");

    /** SLH-DSA-SHAKE-256f (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHAKE_256F =
        new WolfPQCParameterSpec("SLH-DSA-SHAKE-256f");

    /** SLH-DSA-SHA2-128s (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHA2_128S =
        new WolfPQCParameterSpec("SLH-DSA-SHA2-128s");

    /** SLH-DSA-SHA2-128f (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHA2_128F =
        new WolfPQCParameterSpec("SLH-DSA-SHA2-128f");

    /** SLH-DSA-SHA2-192s (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHA2_192S =
        new WolfPQCParameterSpec("SLH-DSA-SHA2-192s");

    /** SLH-DSA-SHA2-192f (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHA2_192F =
        new WolfPQCParameterSpec("SLH-DSA-SHA2-192f");

    /** SLH-DSA-SHA2-256s (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHA2_256S =
        new WolfPQCParameterSpec("SLH-DSA-SHA2-256s");

    /** SLH-DSA-SHA2-256f (FIPS 205). */
    public static final WolfPQCParameterSpec SLH_DSA_SHA2_256F =
        new WolfPQCParameterSpec("SLH-DSA-SHA2-256f");

    private final String name;

    /**
     * Create a named PQC parameter spec.
     *
     * @param name canonical parameter-set name, e.g., {@code "ML-DSA-87"}
     *
     * @throws NullPointerException if {@code name} is null
     */
    public WolfPQCParameterSpec(String name) {
        if (name == null) {
            throw new NullPointerException("name is null");
        }
        this.name = name;
    }

    /**
     * Get the canonical parameter-set name.
     *
     * @return the name, e.g., {@code "ML-DSA-87"}
     */
    public String getName() {
        return this.name;
    }

    @Override
    public String toString() {
        return "WolfPQCParameterSpec(" + this.name + ")";
    }
}
