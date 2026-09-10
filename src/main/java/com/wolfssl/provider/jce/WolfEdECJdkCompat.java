/* WolfEdECJdkCompat.java
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

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.util.Optional;

/**
 * JDK reflection helpers for the EdDSA types introduced after Java 8.
 *
 * <p>wolfJCE compiles with JDK 8, but the JDK EdDSA API lives in
 * java.security.spec.NamedParameterSpec (JDK 11, the ED25519/ED448
 * constants in JDK 15), EdDSAParameterSpec, EdECPoint, EdECPublicKeySpec,
 * EdECPrivateKeySpec and the java.security.interfaces.EdEC* key interfaces
 * (all JDK 15). Everything here is reached through reflection resolved
 * once at class load, so on a JDK that lacks a type the helpers can report
 * 'absent' (null/false) instead of throwing an exception.</p>
 *
 * <p>This class also has conversion logic between the RFC 8032 raw public key
 * encoding (little-endian y with the x sign in the top bit) and the JDK
 * EdECPoint view of it.</p>
 */
final class WolfEdECJdkCompat {

    /* NamedParameterSpec (JDK 11+) */
    private static final Class<?> NPS_CLASS;
    private static final Method NPS_GET_NAME;
    private static final AlgorithmParameterSpec NPS_ED25519;
    private static final AlgorithmParameterSpec NPS_ED448;

    /* EdDSAParameterSpec (JDK 15+) */
    private static final Class<?> EDDSA_SPEC_CLASS;
    private static final Method EDDSA_SPEC_IS_PREHASH;
    private static final Method EDDSA_SPEC_GET_CONTEXT;

    /* EdECPoint (JDK 15+) */
    private static final Constructor<?> POINT_CTOR;
    private static final Method POINT_IS_X_ODD;
    private static final Method POINT_GET_Y;

    /* EdECPublicKeySpec / EdECPrivateKeySpec (JDK 15+) */
    private static final Class<?> PUB_SPEC_CLASS;
    private static final Constructor<?> PUB_SPEC_CTOR;
    private static final Method PUB_SPEC_GET_PARAMS;
    private static final Method PUB_SPEC_GET_POINT;
    private static final Class<?> PRIV_SPEC_CLASS;
    private static final Constructor<?> PRIV_SPEC_CTOR;
    private static final Method PRIV_SPEC_GET_PARAMS;
    private static final Method PRIV_SPEC_GET_BYTES;

    /* java.security.interfaces.EdECPublicKey / EdECPrivateKey (JDK 15+) */
    private static final Class<?> EDEC_PUB_KEY_CLASS;
    private static final Method EDEC_PUB_KEY_GET_PARAMS;
    private static final Method EDEC_PUB_KEY_GET_POINT;
    private static final Class<?> EDEC_PRIV_KEY_CLASS;
    private static final Method EDEC_PRIV_KEY_GET_PARAMS;
    private static final Method EDEC_PRIV_KEY_GET_BYTES;

    static {
        Class<?> nps = loadClass("java.security.spec.NamedParameterSpec");
        NPS_CLASS = nps;
        NPS_GET_NAME = method(nps, "getName");
        NPS_ED25519 = resolveNamedParameterSpec(nps, "ED25519", "Ed25519");
        NPS_ED448 = resolveNamedParameterSpec(nps, "ED448", "Ed448");

        Class<?> eddsa = loadClass("java.security.spec.EdDSAParameterSpec");
        EDDSA_SPEC_CLASS = eddsa;
        EDDSA_SPEC_IS_PREHASH = method(eddsa, "isPrehash");
        EDDSA_SPEC_GET_CONTEXT = method(eddsa, "getContext");

        Class<?> point = loadClass("java.security.spec.EdECPoint");
        POINT_CTOR = constructor(point, boolean.class, BigInteger.class);
        POINT_IS_X_ODD = method(point, "isXOdd");
        POINT_GET_Y = method(point, "getY");

        Class<?> pubSpec = loadClass("java.security.spec.EdECPublicKeySpec");
        PUB_SPEC_CLASS = pubSpec;
        PUB_SPEC_CTOR = (nps != null && point != null) ?
            constructor(pubSpec, nps, point) : null;
        PUB_SPEC_GET_PARAMS = method(pubSpec, "getParams");
        PUB_SPEC_GET_POINT = method(pubSpec, "getPoint");

        Class<?> privSpec = loadClass("java.security.spec.EdECPrivateKeySpec");
        PRIV_SPEC_CLASS = privSpec;
        PRIV_SPEC_CTOR = (nps != null) ?
            constructor(privSpec, nps, byte[].class) : null;
        PRIV_SPEC_GET_PARAMS = method(privSpec, "getParams");
        PRIV_SPEC_GET_BYTES = method(privSpec, "getBytes");

        Class<?> pubKey = loadClass("java.security.interfaces.EdECPublicKey");
        EDEC_PUB_KEY_CLASS = pubKey;
        EDEC_PUB_KEY_GET_PARAMS = method(pubKey, "getParams");
        EDEC_PUB_KEY_GET_POINT = method(pubKey, "getPoint");

        Class<?> privKey = loadClass("java.security.interfaces.EdECPrivateKey");
        EDEC_PRIV_KEY_CLASS = privKey;
        EDEC_PRIV_KEY_GET_PARAMS = method(privKey, "getParams");
        EDEC_PRIV_KEY_GET_BYTES = method(privKey, "getBytes");
    }

    private WolfEdECJdkCompat() { }

    private static Class<?> loadClass(String name) {
        try {
            return Class.forName(name);
        } catch (ClassNotFoundException | RuntimeException | LinkageError e) {
            return null;
        }
    }

    private static Method method(Class<?> cls, String name,
        Class<?>... params) {

        if (cls == null) {
            return null;
        }

        try {
            return cls.getMethod(name, params);
        } catch (NoSuchMethodException | SecurityException |
                 LinkageError e) {
            return null;
        }
    }

    private static Constructor<?> constructor(Class<?> cls,
        Class<?>... params) {

        if (cls == null) {
            return null;
        }

        try {
            return cls.getConstructor(params);
        } catch (NoSuchMethodException | SecurityException |
                 LinkageError e) {
            return null;
        }
    }

    /* JDK 15+: predefined constant. JDK 11-14: new instance by name.
     * JDK 8-10: null. */
    private static AlgorithmParameterSpec resolveNamedParameterSpec(
        Class<?> nps, String constName, String name) {

        if (nps == null) {
            return null;
        }

        try {
            Field f = nps.getField(constName);
            return (AlgorithmParameterSpec) f.get(null);
        } catch (ReflectiveOperationException | RuntimeException |
                 LinkageError ignored) {
            /* no constant (JDK 11-14) or not readable, try by name */
        }
        try {
            return (AlgorithmParameterSpec) nps.getConstructor(String.class)
                .newInstance(name);
        } catch (ReflectiveOperationException | RuntimeException |
                 LinkageError e) {
            return null;
        }
    }

    /**
     * Like invoke(), but when the target itself throws, the cause is rethrown
     * so callers can chain it. A method absent on this JDK still yields null.
     *
     * @param m method, may be null
     * @param target object to call it on, may be null
     * @param what description for the exception message
     *
     * @return the result, or null when the method is not available
     *
     * @throws IllegalArgumentException when the target throws
     */
    private static Object invokeOrThrow(Method m, Object target, String what)
        throws IllegalArgumentException {

        if (m == null || target == null) {
            return null;
        }

        try {
            return m.invoke(target);
        } catch (InvocationTargetException e) {
            Throwable cause = (e.getCause() != null) ? e.getCause() : e;
            throw new IllegalArgumentException(what + ": " + cause, cause);
        } catch (ReflectiveOperationException | RuntimeException e) {
            WolfCryptDebug.log(WolfEdECJdkCompat.class, WolfCryptDebug.INFO,
                () -> "[EdEC compat] " + m.getName() + " failed: " + e);
            return null;
        }
    }

    private static Object invoke(Method m, Object target) {

        if (m == null || target == null) {
            return null;
        }

        try {
            return m.invoke(target);
        } catch (ReflectiveOperationException | RuntimeException e) {
            /* absent on this JDK or refused by the key, callers treat null
             * as "not available", keep the cause visible in the debug log */
            WolfCryptDebug.log(WolfEdECJdkCompat.class, WolfCryptDebug.INFO,
                () -> "[EdEC compat] " + m.getName() + " failed: " + e);
            return null;
        }
    }

    /**
     * Get the {@code NamedParameterSpec} for a curve.
     *
     * @param curve curve
     *
     * @return JDK 15+ constant, JDK 11-14 instance, or null on JDK 8-10 or
     *         for a null curve
     */
    static AlgorithmParameterSpec namedParameterSpec(
        WolfCryptEdDSACurve curve) {

        if (curve == null) {
            return null;
        }

        if (curve == WolfCryptEdDSACurve.ED25519){
            return NPS_ED25519;
        } else {
            return NPS_ED448;
        }
    }

    /**
     * If {@code spec} is a {@code NamedParameterSpec}, return its name.
     *
     * @param spec any parameter spec
     *
     * @return the name, or null when spec is not a NamedParameterSpec or
     *         the class does not exist on this JDK
     */
    static String namedParameterSpecGetName(AlgorithmParameterSpec spec) {

        if (spec == null || NPS_CLASS == null || !NPS_CLASS.isInstance(spec)) {
            return null;
        }

        return (String) invokeOrThrow(NPS_GET_NAME, spec,
            "NamedParameterSpec.getName() failed");
    }

    /**
     * Resolve the curve named by a NamedParameterSpec, which is what
     * EdECKey.getParams() returns.
     *
     * @param params params object
     *
     * @return curve or null
     */
    private static WolfCryptEdDSACurve curveFromParams(Object params) {

        if (params == null) {
            return null;
        }

        if (params instanceof AlgorithmParameterSpec) {
            String name = namedParameterSpecGetName(
                (AlgorithmParameterSpec) params);
            if (name != null) {
                return WolfCryptEdDSACurve.fromName(name);
            }
        }
        return null;
    }

    /**
     * Check whether a parameter spec is a JDK 15+
     * java.security.spec.EdDSAParameterSpec.
     *
     * @param spec any parameter spec, may be null
     *
     * @return true if spec is an EdDSAParameterSpec, otherwise false
     */
    static boolean isEdDSAParameterSpec(AlgorithmParameterSpec spec) {

        return spec != null && EDDSA_SPEC_CLASS != null &&
            EDDSA_SPEC_CLASS.isInstance(spec);
    }

    /**
     * Read the pre-hash flag of a EdDSAParameterSpec.
     *
     * @param spec an EdDSAParameterSpec
     *
     * @return its isPrehash() value
     *
     * @throws IllegalArgumentException if the value cannot be read
     */
    static boolean edDSAParameterSpecIsPrehash(AlgorithmParameterSpec spec)
        throws IllegalArgumentException {

        Object r = invokeOrThrow(EDDSA_SPEC_IS_PREHASH, spec,
            "EdDSAParameterSpec.isPrehash() failed");

        if (!(r instanceof Boolean)) {
            throw new IllegalArgumentException(
                "Cannot read EdDSAParameterSpec.isPrehash()");
        }

        return ((Boolean) r).booleanValue();
    }

    /**
     * Read the context of a EdDSAParameterSpec, unwrapping the Optional
     * it returns.
     *
     * @param spec an EdDSAParameterSpec
     *
     * @return a copy of its context, or null when the context is absent
     *
     * @throws IllegalArgumentException if the value cannot be read
     */
    static byte[] edDSAParameterSpecGetContext(AlgorithmParameterSpec spec)
        throws IllegalArgumentException {

        Object r = invokeOrThrow(EDDSA_SPEC_GET_CONTEXT, spec,
            "EdDSAParameterSpec.getContext() failed");

        if (!(r instanceof Optional)) {
            throw new IllegalArgumentException(
                "Cannot read EdDSAParameterSpec.getContext()");
        }

        Optional<?> o = (Optional<?>) r;
        if (o.isPresent() && o.get() instanceof byte[]) {
            return ((byte[]) o.get()).clone();
        }

        return null;
    }

    /**
     * Check whether a key spec is a JDK 15+
     * java.security.spec.EdECPublicKeySpec.
     *
     * @param spec any key spec, may be null
     *
     * @return true if spec is an EdECPublicKeySpec, otherwise false
     */
    static boolean isEdECPublicKeySpec(KeySpec spec) {

        return spec != null && PUB_SPEC_CLASS != null &&
            PUB_SPEC_CLASS.isInstance(spec);
    }

    /**
     * Check whether a key spec is a JDK 15+
     * java.security.spec.EdECPrivateKeySpec.
     *
     * @param spec any key spec, may be null
     *
     * @return true if spec is an EdECPrivateKeySpec, otherwise false
     */
    static boolean isEdECPrivateKeySpec(KeySpec spec) {

        return spec != null && PRIV_SPEC_CLASS != null &&
            PRIV_SPEC_CLASS.isInstance(spec);
    }

    /**
     * Check whether a requested KeySpec class is exactly the JDK 15+
     * EdECPublicKeySpec class.
     *
     * @param cls requested KeySpec class, may be null
     *
     * @return true if cls is the EdECPublicKeySpec class, else false
     */
    static boolean isEdECPublicKeySpecClass(Class<?> cls) {

        return cls != null && cls == PUB_SPEC_CLASS;
    }

    /**
     * Check whether a requested KeySpec class is exactly the JDK 15+
     * EdECPrivateKeySpec class.
     *
     * @param cls requested KeySpec class, may be null
     *
     * @return true if cls is the EdECPrivateKeySpec class, else false
     */
    static boolean isEdECPrivateKeySpecClass(Class<?> cls) {

        return cls != null && cls == PRIV_SPEC_CLASS;
    }

    /**
     * Curve of an EdECPublicKeySpec.
     *
     * @param spec EdECPublicKeySpec
     *
     * @return curve or null if the params do not name a supported curve
     */
    static WolfCryptEdDSACurve curveFromEdECPublicKeySpec(KeySpec spec) {
        return curveFromParams(invokeOrThrow(PUB_SPEC_GET_PARAMS, spec,
            "EdECPublicKeySpec.getParams() failed"));
    }

    /**
     * Curve of an EdECPrivateKeySpec.
     *
     * @param spec EdECPrivateKeySpec
     *
     * @return curve or null if the params do not name a supported curve
     */
    static WolfCryptEdDSACurve curveFromEdECPrivateKeySpec(KeySpec spec) {
        return curveFromParams(invokeOrThrow(PRIV_SPEC_GET_PARAMS, spec,
            "EdECPrivateKeySpec.getParams() failed"));
    }

    /**
     * Raw RFC 8032 public key from an EdECPublicKeySpec.
     *
     * @param curve curve the spec names
     * @param spec EdECPublicKeySpec
     *
     * @return raw public key
     *
     * @throws IllegalArgumentException if the point cannot be read or
     *         encoded for the curve
     */
    static byte[] rawPublicFromEdECPublicKeySpec(WolfCryptEdDSACurve curve,
        KeySpec spec) throws IllegalArgumentException {

        Object point = invokeOrThrow(PUB_SPEC_GET_POINT, spec,
            "EdECPublicKeySpec.getPoint() failed");
        if (point == null) {
            throw new IllegalArgumentException(
                "EdECPublicKeySpec has no point");
        }

        return pointToRaw(curve, point);
    }

    /**
     * Raw private key from an EdECPrivateKeySpec.
     *
     * @param spec EdECPrivateKeySpec
     *
     * @return a copy of the private key bytes
     *
     * @throws IllegalArgumentException if the bytes cannot be read
     */
    static byte[] rawPrivateFromEdECPrivateKeySpec(KeySpec spec)
        throws IllegalArgumentException {

        Object r = invokeOrThrow(PRIV_SPEC_GET_BYTES, spec,
            "EdECPrivateKeySpec.getBytes() failed");
        if (!(r instanceof byte[])) {
            throw new IllegalArgumentException(
                "EdECPrivateKeySpec has no key bytes");
        }

        return ((byte[]) r).clone();
    }

    /**
     * Build an EdECPublicKeySpec for a raw public key.
     *
     * @param curve curve
     * @param rawPub raw public key
     *
     * @return the spec, or null when the JDK lacks the class (pre-15)
     *
     * @throws IllegalArgumentException on a malformed raw key
     */
    static KeySpec newEdECPublicKeySpec(WolfCryptEdDSACurve curve,
        byte[] rawPub) throws IllegalArgumentException {

        AlgorithmParameterSpec nps = namedParameterSpec(curve);
        if (PUB_SPEC_CTOR == null || POINT_CTOR == null || nps == null) {
            return null;
        }

        try {
            Object point = POINT_CTOR.newInstance(
                Boolean.valueOf(rawIsXOdd(rawPub)), rawToY(curve, rawPub));
            return (KeySpec) PUB_SPEC_CTOR.newInstance(nps, point);

        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException(
                "Failed to build EdECPublicKeySpec: " + e.getMessage(), e);
        }
    }

    /**
     * Build an EdECPrivateKeySpec for a raw private key.
     *
     * @param curve curve
     * @param rawPriv raw private key (copied)
     *
     * @return the spec, or null when the JDK lacks the class (pre-15)
     *
     * @throws IllegalArgumentException on failure
     */
    static KeySpec newEdECPrivateKeySpec(WolfCryptEdDSACurve curve,
        byte[] rawPriv) throws IllegalArgumentException {

        AlgorithmParameterSpec nps = namedParameterSpec(curve);
        if (PRIV_SPEC_CTOR == null || nps == null) {
            return null;
        }

        try {
            return (KeySpec) PRIV_SPEC_CTOR.newInstance(nps, rawPriv);
        } catch (ReflectiveOperationException e) {
            throw new IllegalArgumentException(
                "Failed to build EdECPrivateKeySpec: " + e.getMessage(), e);
        }
    }

    /**
     * Check whether a key implements the JDK 15+ EdECPublicKey interface.
     *
     * @param key any key, may be null
     *
     * @return true if key implements EdECPublicKey, else false
     */
    static boolean isEdECPublicKey(Key key) {

        return key != null && EDEC_PUB_KEY_CLASS != null &&
            EDEC_PUB_KEY_CLASS.isInstance(key);
    }

    /**
     * Check whether a key implements the EdECPrivateKey interface.
     *
     * @param key any key, may be null
     *
     * @return true if key implements EdECPrivateKey, else false
     */
    static boolean isEdECPrivateKey(Key key) {

        return key != null && EDEC_PRIV_KEY_CLASS != null &&
            EDEC_PRIV_KEY_CLASS.isInstance(key);
    }

    /**
     * Curve of an EdECPublicKey.
     *
     * @param key EdECPublicKey
     *
     * @return curve or null
     */
    static WolfCryptEdDSACurve curveFromEdECPublicKey(Key key) {
        return curveFromParams(invokeOrThrow(EDEC_PUB_KEY_GET_PARAMS, key,
            "EdECPublicKey.getParams() failed"));
    }

    /**
     * Curve of an EdECPrivateKey.
     *
     * @param key EdECPrivateKey
     *
     * @return curve or null
     */
    static WolfCryptEdDSACurve curveFromEdECPrivateKey(Key key) {
        return curveFromParams(invokeOrThrow(EDEC_PRIV_KEY_GET_PARAMS, key,
            "EdECPrivateKey.getParams() failed"));
    }

    /**
     * Raw public key from an EdECPublicKey.
     *
     * @param curve curve the key params name
     * @param key EdECPublicKey
     *
     * @return raw public key
     *
     * @throws IllegalArgumentException if point cannot be read or encoded
     */
    static byte[] rawPublicFromEdECPublicKey(WolfCryptEdDSACurve curve,
        Key key) throws IllegalArgumentException {

        Object point = invokeOrThrow(EDEC_PUB_KEY_GET_POINT, key,
            "EdECPublicKey.getPoint() failed");
        if (point == null) {
            throw new IllegalArgumentException("EdECPublicKey has no point");
        }

        return pointToRaw(curve, point);
    }

    /**
     * Raw private key from an EdECPrivateKey.
     *
     * @param key EdECPrivateKey
     *
     * @return a copy of the private key bytes, or null when the key does
     *         not expose them (getBytes() empty)
     *
     * @throws IllegalArgumentException if getBytes() throws, with the
     *         key's exception as the cause
     */
    static byte[] rawPrivateFromEdECPrivateKey(Key key)
        throws IllegalArgumentException {

        Object r = invokeOrThrow(EDEC_PRIV_KEY_GET_BYTES, key,
            "EdECPrivateKey.getBytes() failed");
        if (r instanceof Optional) {
            Optional<?> o = (Optional<?>) r;
            if (o.isPresent() && o.get() instanceof byte[]) {
                return ((byte[]) o.get()).clone();
            }
        }

        return null;
    }

    /**
     * Read the x coordinate parity from a raw RFC 8032 public key, where
     * it is stored in the top bit of the last byte.
     *
     * @param rawPub raw public key
     *
     * @return true if the x coordinate is odd, otherwise false
     *
     * @throws IllegalArgumentException if rawPub is null or empty
     */
    static boolean rawIsXOdd(byte[] rawPub) {

        if (rawPub == null || rawPub.length == 0) {
            throw new IllegalArgumentException("Empty public key");
        }

        return (rawPub[rawPub.length - 1] & 0x80) != 0;
    }

    /**
     * Read the y coordinate from a raw RFC 8032 public key: the key is a
     * little-endian integer with the x parity bit set in its top bit, so
     * the bit is cleared and the bytes reversed.
     *
     * @param curve curve, gives the expected key size
     * @param rawPub raw public key
     *
     * @return the y coordinate as a non-negative BigInteger
     *
     * @throws IllegalArgumentException if rawPub is not the curve's public
     *         key size
     */
    static BigInteger rawToY(WolfCryptEdDSACurve curve, byte[] rawPub) {

        if (rawPub == null || rawPub.length != curve.getPublicKeySize()) {
            throw new IllegalArgumentException(
                curve.getJcaName() + " public key must be " +
                curve.getPublicKeySize() + " bytes");
        }

        /* big-endian with a leading 0x00 sign byte */
        byte[] be = new byte[rawPub.length + 1];
        for (int i = 0; i < rawPub.length; i++) {
            be[1 + i] = rawPub[rawPub.length - 1 - i];
        }
        be[1] &= 0x7f;

        return new BigInteger(be);
    }

    /**
     * Encode an (xOdd, y) point as the RFC 8032 raw public key.
     *
     * @param curve curve
     * @param xOdd x parity
     * @param y y coordinate
     *
     * @return raw public key
     *
     * @throws IllegalArgumentException if y is negative or not below the
     *         field prime of the curve
     */
    static byte[] pointToRaw(WolfCryptEdDSACurve curve, boolean xOdd,
        BigInteger y) throws IllegalArgumentException {

        if (y == null || y.signum() < 0) {
            throw new IllegalArgumentException("y must be non-negative");
        }

        /* RFC 8032 decoding fails for y >= p, reject non-canonical range
         * instead of relying on native to notice */
        if (y.compareTo(curve.getFieldPrime()) >= 0) {
            throw new IllegalArgumentException(
                "y is not below the field prime of " + curve.getJcaName());
        }

        /* toByteArray() returns the big-endian magnitude and prepends 0x00
         * sign byte when the top bit is set */
        byte[] be = y.toByteArray();
        int n = be.length;
        if (n > 1 && be[0] == 0) {
            /* skip the sign byte */
            n--;
        }

        /* Copy magnitude into raw as little-endian */
        byte[] raw = new byte[curve.getPublicKeySize()];
        for (int i = 0; i < n; i++) {
            raw[i] = be[be.length - 1 - i];
        }

        if (xOdd) {
            raw[raw.length - 1] |= (byte)0x80;
        }

        return raw;
    }

    /* Encode an EdECPoint object as a raw key. */
    private static byte[] pointToRaw(WolfCryptEdDSACurve curve,
        Object point) throws IllegalArgumentException {

        Object xOdd = invokeOrThrow(POINT_IS_X_ODD, point,
            "EdECPoint.isXOdd() failed");
        Object y = invokeOrThrow(POINT_GET_Y, point,
            "EdECPoint.getY() failed");

        if (!(xOdd instanceof Boolean) || !(y instanceof BigInteger)) {
            throw new IllegalArgumentException("Cannot read EdECPoint");
        }

        return pointToRaw(curve, ((Boolean) xOdd).booleanValue(),
            (BigInteger) y);
    }
}
