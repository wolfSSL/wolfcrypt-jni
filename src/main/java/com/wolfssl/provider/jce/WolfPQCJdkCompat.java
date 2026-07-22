/* WolfPQCJdkCompat.java
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

package com.wolfssl.provider.jce;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.spec.AlgorithmParameterSpec;

import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.MlKem;
import com.wolfssl.wolfcrypt.SlhDsa;

/**
 * JDK reflection helpers for PQC named parameter specs.
 *
 * <p>{@link java.security.spec.NamedParameterSpec} was introduced in JDK 11.
 * Predefined ML-DSA / ML-KEM constants on it were added in JDK 24. We dispatch
 * via reflection so wolfJCE compiled with {@code -source 8 -target 8} still
 * works on every JDK at runtime.</p>
 *
 * <p>JDK 24+: returns the predefined {@code NamedParameterSpec} constant.
 * JDK 11-23: constructs a {@code NamedParameterSpec(name)}.
 * JDK 8-10: returns {@code null} (the standard class doesn't exist).</p>
 */
final class WolfPQCJdkCompat {

    /* NamedParameterSpec class and getName() Method.
     * Both null on JDK 8-10 where the class does not exist. */
    private static final Class<?> NPS_CLASS;
    private static final Method NPS_GET_NAME;

    /* Per-level NamedParameterSpec instances. The spec objects are immutable
     * so sharing them is safe. Null on JDK 8-10. */
    private static final AlgorithmParameterSpec NPS_ML_DSA_44;
    private static final AlgorithmParameterSpec NPS_ML_DSA_65;
    private static final AlgorithmParameterSpec NPS_ML_DSA_87;

    static {
        Class<?> cls = null;
        Method getName = null;
        try {
            cls = Class.forName("java.security.spec.NamedParameterSpec");
            getName = cls.getMethod("getName");
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            /* JDK 8-10, class does not exist */
            cls = null;
            getName = null;
        }
        NPS_CLASS = cls;
        NPS_GET_NAME = getName;
        NPS_ML_DSA_44 = resolveNamedParameterSpec(MlDsa.ML_DSA_44);
        NPS_ML_DSA_65 = resolveNamedParameterSpec(MlDsa.ML_DSA_65);
        NPS_ML_DSA_87 = resolveNamedParameterSpec(MlDsa.ML_DSA_87);
    }

    /* Per-parameter-set NamedParameterSpec instances for SLH-DSA, indexed by
     * the native SlhDsa parameter value (0-11). The JDK ships no SLH-DSA
     * predefined constants, so on JDK 11+ these are constructed as
     * NamedParameterSpec(name). null on JDK 8-10. */
    private static final AlgorithmParameterSpec[] NPS_SLH_DSA =
        new AlgorithmParameterSpec[12];

    static {
        for (int p = SlhDsa.SLH_DSA_SHAKE_128S;
             p <= SlhDsa.SLH_DSA_SHA2_256F; p++) {
            NPS_SLH_DSA[p] = resolveSlhDsaNamedParamSpec(slhDsaParamToName(p));
        }
    }

    private WolfPQCJdkCompat() { }

    /**
     * Map an ML-DSA level to the canonical FIPS 204 parameter set name.
     *
     * @param level {@link MlDsa#ML_DSA_44}, {@link MlDsa#ML_DSA_65},
     *              or {@link MlDsa#ML_DSA_87}
     *
     * @return canonical name like {@code "ML-DSA-87"}
     *
     * @throws IllegalArgumentException on unknown level
     */
    static String levelToParamName(int level) {

        switch (level) {
            case MlDsa.ML_DSA_44: return "ML-DSA-44";
            case MlDsa.ML_DSA_65: return "ML-DSA-65";
            case MlDsa.ML_DSA_87: return "ML-DSA-87";
            default:
                throw new IllegalArgumentException(
                    "Invalid ML-DSA level: " + level);
        }
    }

    /**
     * Map an ML-DSA level to the {@code NamedParameterSpec} field name
     * used in JDK 24+ ({@code ML_DSA_44} / {@code ML_DSA_65} /
     * {@code ML_DSA_87}).
     *
     * @param level level value
     *
     * @return field name like {@code "ML_DSA_87"}
     *
     * @throws IllegalArgumentException on unknown level
     */
    static String levelToConstantName(int level) {

        switch (level) {
            case MlDsa.ML_DSA_44: return "ML_DSA_44";
            case MlDsa.ML_DSA_65: return "ML_DSA_65";
            case MlDsa.ML_DSA_87: return "ML_DSA_87";
            default:
                throw new IllegalArgumentException(
                    "Invalid ML-DSA level: " + level);
        }
    }

    /**
     * If {@code spec} is a JDK {@code NamedParameterSpec} (JDK 11+), return
     * its {@code getName()} value via reflection. Returns {@code null} for any
     * other type, or on a JDK that lacks {@code NamedParameterSpec} (JDK 8-10).
     *
     * <p>Used by KeyPairGenerator and KeyFactory to accept either the standard
     * {@code NamedParameterSpec} (JDK 11+) or our {@link WolfPQCParameterSpec}
     * fallback without a {@code -source 11} dependency.</p>
     *
     * @param spec a parameter spec
     *
     * @return the name string, or null if not a {@code NamedParameterSpec}
     */
    static String namedParameterSpecGetName(AlgorithmParameterSpec spec) {

        if (spec == null || NPS_CLASS == null ||
            !NPS_CLASS.isInstance(spec)) {
            return null;
        }

        try {
            return (String) NPS_GET_NAME.invoke(spec);
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }

    /**
     * Map a canonical ML-DSA parameter-set name (ie: {@code "ML-DSA-87"})
     * to the corresponding {@link MlDsa} level constant. Comparison is
     * case-insensitive.
     *
     * @param name parameter-set name
     *
     * @return one of {@link MlDsa#ML_DSA_44}, {@link MlDsa#ML_DSA_65},
     *         {@link MlDsa#ML_DSA_87}
     *
     * @throws IllegalArgumentException on unrecognized name
     */
    static int paramNameToLevel(String name) {

        if (name == null) {
            throw new IllegalArgumentException("name is null");
        }
        if (name.equalsIgnoreCase("ML-DSA-44")) {
            return MlDsa.ML_DSA_44;
        }
        if (name.equalsIgnoreCase("ML-DSA-65")) {
            return MlDsa.ML_DSA_65;
        }
        if (name.equalsIgnoreCase("ML-DSA-87")) {
            return MlDsa.ML_DSA_87;
        }
        throw new IllegalArgumentException(
            "Unknown ML-DSA parameter-set name: " + name);
    }

    /**
     * Map a canonical ML-KEM parameter-set name (ie: {@code "ML-KEM-768"})
     * to the corresponding {@link MlKem} level constant. Comparison is
     * case-insensitive.
     *
     * @param name parameter-set name
     *
     * @return one of {@link MlKem#ML_KEM_512}, {@link MlKem#ML_KEM_768},
     *         {@link MlKem#ML_KEM_1024}
     *
     * @throws IllegalArgumentException on unrecognized name
     */
    static int mlkemParamNameToLevel(String name) {

        if (name == null) {
            throw new IllegalArgumentException("name is null");
        }
        if (name.equalsIgnoreCase("ML-KEM-512")) {
            return MlKem.ML_KEM_512;
        }
        if (name.equalsIgnoreCase("ML-KEM-768")) {
            return MlKem.ML_KEM_768;
        }
        if (name.equalsIgnoreCase("ML-KEM-1024")) {
            return MlKem.ML_KEM_1024;
        }
        throw new IllegalArgumentException(
            "Unknown ML-KEM parameter-set name: " + name);
    }

    /**
     * Return the cached {@code NamedParameterSpec} for the given ML-DSA
     * level, resolved once at class load.
     *
     * @param level level value
     *
     * @return JDK {@code NamedParameterSpec} on JDK 11+, else null
     *
     * @throws IllegalArgumentException on unknown level
     */
    static AlgorithmParameterSpec namedParameterSpec(int level) {

        switch (level) {
            case MlDsa.ML_DSA_44: return NPS_ML_DSA_44;
            case MlDsa.ML_DSA_65: return NPS_ML_DSA_65;
            case MlDsa.ML_DSA_87: return NPS_ML_DSA_87;
            default:
                throw new IllegalArgumentException(
                    "Invalid ML-DSA level: " + level);
        }
    }

    /**
     * Resolve a {@code NamedParameterSpec} for the given ML-DSA level
     * via reflection. Called once per level from the static initializer.
     *
     * @param level level value
     *
     * @return JDK {@code NamedParameterSpec} on JDK 11+, else null
     */
    private static AlgorithmParameterSpec resolveNamedParameterSpec(
        int level) {

        String name = levelToParamName(level);
        String constName = levelToConstantName(level);

        if (NPS_CLASS == null) {
            /* Class doesn't exist in JDK 8-10, no spec to return. */
            return null;
        }

        /* JDK 24+: predefined static constant. */
        try {
            Field f = NPS_CLASS.getField(constName);
            return (AlgorithmParameterSpec) f.get(null);
        } catch (NoSuchFieldException ignored) {
            /* JDK 11-23: no predefined constant, fall through. */
        } catch (ReflectiveOperationException e) {
            return null;
        }

        /* JDK 11-23: construct via NamedParameterSpec(String). */
        try {
            return (AlgorithmParameterSpec) NPS_CLASS
                .getConstructor(String.class).newInstance(name);
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }

    /**
     * Map an SLH-DSA parameter set to its canonical FIPS 205 name.
     *
     * @param param one of {@code SlhDsa.SLH_DSA_*} (0-11)
     *
     * @return canonical name like {@code "SLH-DSA-SHA2-128f"}
     *
     * @throws IllegalArgumentException on unknown parameter set
     */
    static String slhDsaParamToName(int param) {

        switch (param) {
            case SlhDsa.SLH_DSA_SHAKE_128S:
                return "SLH-DSA-SHAKE-128s";
            case SlhDsa.SLH_DSA_SHAKE_128F:
                return "SLH-DSA-SHAKE-128f";
            case SlhDsa.SLH_DSA_SHAKE_192S:
                return "SLH-DSA-SHAKE-192s";
            case SlhDsa.SLH_DSA_SHAKE_192F:
                return "SLH-DSA-SHAKE-192f";
            case SlhDsa.SLH_DSA_SHAKE_256S:
                return "SLH-DSA-SHAKE-256s";
            case SlhDsa.SLH_DSA_SHAKE_256F:
                return "SLH-DSA-SHAKE-256f";
            case SlhDsa.SLH_DSA_SHA2_128S:
                return "SLH-DSA-SHA2-128s";
            case SlhDsa.SLH_DSA_SHA2_128F:
                return "SLH-DSA-SHA2-128f";
            case SlhDsa.SLH_DSA_SHA2_192S:
                return "SLH-DSA-SHA2-192s";
            case SlhDsa.SLH_DSA_SHA2_192F:
                return "SLH-DSA-SHA2-192f";
            case SlhDsa.SLH_DSA_SHA2_256S:
                return "SLH-DSA-SHA2-256s";
            case SlhDsa.SLH_DSA_SHA2_256F:
                return "SLH-DSA-SHA2-256f";
            default:
                throw new IllegalArgumentException(
                    "Invalid SLH-DSA parameter set: " + param);
        }
    }

    /**
     * Map a canonical SLH-DSA parameter-set name (ie:
     * {@code "SLH-DSA-SHA2-128f"}) to the corresponding {@link SlhDsa}
     * parameter set constant. Comparison is case-insensitive.
     *
     * @param name parameter-set name
     *
     * @return one of {@code SlhDsa.SLH_DSA_*} (0-11)
     *
     * @throws IllegalArgumentException on unrecognized name
     */
    static int slhDsaNameToParam(String name) {

        if (name == null) {
            throw new IllegalArgumentException("name is null");
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHAKE-128s")) {
            return SlhDsa.SLH_DSA_SHAKE_128S;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHAKE-128f")) {
            return SlhDsa.SLH_DSA_SHAKE_128F;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHAKE-192s")) {
            return SlhDsa.SLH_DSA_SHAKE_192S;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHAKE-192f")) {
            return SlhDsa.SLH_DSA_SHAKE_192F;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHAKE-256s")) {
            return SlhDsa.SLH_DSA_SHAKE_256S;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHAKE-256f")) {
            return SlhDsa.SLH_DSA_SHAKE_256F;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHA2-128s")) {
            return SlhDsa.SLH_DSA_SHA2_128S;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHA2-128f")) {
            return SlhDsa.SLH_DSA_SHA2_128F;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHA2-192s")) {
            return SlhDsa.SLH_DSA_SHA2_192S;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHA2-192f")) {
            return SlhDsa.SLH_DSA_SHA2_192F;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHA2-256s")) {
            return SlhDsa.SLH_DSA_SHA2_256S;
        }
        if (name.equalsIgnoreCase("SLH-DSA-SHA2-256f")) {
            return SlhDsa.SLH_DSA_SHA2_256F;
        }
        throw new IllegalArgumentException(
            "Unknown SLH-DSA parameter-set name: " + name);
    }

    /**
     * Return the cached {@code NamedParameterSpec} for the given SLH-DSA
     * parameter set, resolved once at class load.
     *
     * @param param one of {@code SlhDsa.SLH_DSA_*} (0-11)
     *
     * @return JDK {@code NamedParameterSpec} on JDK 11+, else null
     *
     * @throws IllegalArgumentException on unknown parameter set
     */
    static AlgorithmParameterSpec slhDsaNamedParameterSpec(int param) {

        if (param < SlhDsa.SLH_DSA_SHAKE_128S ||
            param > SlhDsa.SLH_DSA_SHA2_256F) {
            throw new IllegalArgumentException(
                "Invalid SLH-DSA parameter set: " + param);
        }
        return NPS_SLH_DSA[param];
    }

    /**
     * Resolve a {@code NamedParameterSpec} for the given SLH-DSA name via
     * reflection. The JDK ships no SLH-DSA predefined constants, so this only
     * uses the {@code NamedParameterSpec(String)} constructor path.
     *
     * @param name canonical SLH-DSA parameter-set name
     *
     * @return JDK {@code NamedParameterSpec} on JDK 11+, else null
     */
    private static AlgorithmParameterSpec resolveSlhDsaNamedParamSpec(
        String name) {

        if (NPS_CLASS == null) {
            /* Class doesn't exist in JDK 8-10, no spec to return. */
            return null;
        }

        try {
            return (AlgorithmParameterSpec) NPS_CLASS
                .getConstructor(String.class).newInstance(name);
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }
}
