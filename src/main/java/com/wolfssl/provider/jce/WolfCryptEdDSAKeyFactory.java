/* WolfCryptEdDSAKeyFactory.java
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

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * wolfJCE EdDSA (Ed25519 / Ed448, RFC 8032) KeyFactory.
 *
 * Converts between the encoded forms (X509EncodedKeySpec for public
 * keys, PKCS8EncodedKeySpec for private keys), on JDK 15+ the JDK
 * EdECPublicKeySpec / EdECPrivateKeySpec and WolfCryptEdDSAPublicKey /
 * WolfCryptEdDSAPrivateKey objects. The curve is stored in the encoded
 * AlgorithmIdentifier OID (RFC 8410) or the spec's NamedParameterSpec.
 */
public class WolfCryptEdDSAKeyFactory extends KeyFactorySpi {

    /** Curve this factory is locked to, or null to accept both */
    private final WolfCryptEdDSACurve lockedCurve;

    /**
     * Create a new wolfJCE EdDSA KeyFactory accepting both curves.
     */
    public WolfCryptEdDSAKeyFactory() {
        this(null);
    }

    /**
     * Create a new wolfJCE EdDSA KeyFactory locked to a curve.
     *
     * @param lockedCurve curve to accept, or null for any
     */
    WolfCryptEdDSAKeyFactory(WolfCryptEdDSACurve lockedCurve) {
        this.lockedCurve = lockedCurve;
        log("created new EdDSA KeyFactory (curve: " +
            ((lockedCurve == null) ? "any" : lockedCurve.getJcaName()) + ")");
    }

    /**
     * Ed25519 only KeyFactory.
     */
    public static final class wcEd25519 extends WolfCryptEdDSAKeyFactory {
        /** Default constructor. */
        public wcEd25519() {
            super(WolfCryptEdDSACurve.ED25519);
        }
    }

    /**
     * Ed448 only KeyFactory.
     */
    public static final class wcEd448 extends WolfCryptEdDSAKeyFactory {
        /** Default constructor. */
        public wcEd448() {
            super(WolfCryptEdDSACurve.ED448);
        }
    }

    /** Generic EdDSA KeyFactory, accepts either curve. */
    public static final class wcEdDSA extends WolfCryptEdDSAKeyFactory {
        /** Create a KeyFactory for either curve. */
        public wcEdDSA() {
            super();
        }
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[EdDSA KeyFactory] " + msg);
    }

    /**
     * Check a curve against this factory's locked curve.
     *
     * @param curve curve of the key being produced or inspected
     *
     * @throws InvalidKeySpecException if the factory is locked to the
     *         other curve
     */
    private void checkCurve(WolfCryptEdDSACurve curve)
        throws InvalidKeySpecException {

        if (lockedCurve != null && curve != lockedCurve) {
            throw new InvalidKeySpecException(
                "Key curve does not match KeyFactory: expected " +
                lockedCurve.getJcaName() + ", got " + curve.getJcaName());
        }
    }

    /**
     * Convert any EdDSA PublicKey to a wolfJCE key. wolfJCE keys pass through,
     * other keys are re-created from their X.509 encoding, or from their
     * point when they only implement the JDK 15 EdECPublicKey interface
     * without an encoding.
     *
     * @param key public key
     *
     * @return wolfJCE public key
     *
     * @throws InvalidKeyException if the key is null, not an EdDSA key, or
     *         cannot be decoded
     */
    static WolfCryptEdDSAPublicKey toWolfPublicKey(PublicKey key)
        throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("PublicKey is null");
        }

        if (key instanceof WolfCryptEdDSAPublicKey) {
            if (((WolfCryptEdDSAPublicKey) key).isDestroyed()) {
                throw new InvalidKeyException("PublicKey has been destroyed");
            }
            return (WolfCryptEdDSAPublicKey) key;
        }

        /* Encoded form first */
        boolean encodedFormat = "X.509".equalsIgnoreCase(key.getFormat());
        if (encodedFormat) {
            byte[] der = key.getEncoded();
            if (der != null && der.length > 0) {
                try {
                    return WolfCryptEdDSAKeys.publicKey(der);
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Not a valid Ed25519/Ed448 X.509 public key: " +
                        e.getMessage(), e);
                }
            }
        }

        /* JDK 15+ EdECPublicKey without an encoding */
        if (WolfEdECJdkCompat.isEdECPublicKey(key)) {
            WolfCryptEdDSACurve curve;
            try {
                curve = WolfEdECJdkCompat.curveFromEdECPublicKey(key);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException(e.getMessage(), e);
            }
            if (curve == null) {
                throw new InvalidKeyException(
                    "EdECPublicKey params do not name Ed25519 or Ed448");
            }
            try {
                return WolfCryptEdDSAKeys.publicKey(curve,
                    WolfEdECJdkCompat.rawPublicFromEdECPublicKey(curve, key));
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException("Invalid EdECPublicKey: " +
                    e.getMessage(), e);
            }
        }

        if (encodedFormat) {
            throw new InvalidKeyException(
                "EdDSA public key reports X.509 format but has no encoding");
        }
        throw new InvalidKeyException("Unsupported EdDSA public key: " +
            key.getClass().getName() + " (format " + key.getFormat() + ")");
    }

    /**
     * Convert any EdDSA PrivateKey to a wolfJCE key. wolfJCE keys pass through,
     * other keys are re-created from their PKCS#8 encoding or, when they only
     * implement the JDK 15 EdECPrivateKey interface without an encoding, from
     * their raw bytes.
     *
     * @param key private key
     *
     * @return wolfJCE private key
     *
     * @throws InvalidKeyException if the key is null, not an EdDSA key, or
     *         cannot be decoded
     */
    static WolfCryptEdDSAPrivateKey toWolfPrivateKey(PrivateKey key)
        throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("PrivateKey is null");
        }

        if (key instanceof WolfCryptEdDSAPrivateKey) {
            if (((WolfCryptEdDSAPrivateKey) key).isDestroyed()) {
                throw new InvalidKeyException("PrivateKey has been destroyed");
            }
            return (WolfCryptEdDSAPrivateKey) key;
        }

        boolean encodedFormat = "PKCS#8".equalsIgnoreCase(key.getFormat());
        if (encodedFormat) {
            /* zeroed as WolfCryptECKeyFactory does, providers return a copy */
            byte[] der = key.getEncoded();
            if (der != null && der.length > 0) {
                try {
                    return WolfCryptEdDSAKeys.privateKey(der);
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Not a valid Ed25519/Ed448 PKCS#8 private key: " +
                        e.getMessage(), e);
                }
                finally {
                    WolfCryptEdDSACurve.zero(der);
                }
            }
        }

        if (WolfEdECJdkCompat.isEdECPrivateKey(key)) {
            WolfCryptEdDSACurve curve;
            try {
                curve = WolfEdECJdkCompat.curveFromEdECPrivateKey(key);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException(e.getMessage(), e);
            }
            if (curve == null) {
                throw new InvalidKeyException(
                    "EdECPrivateKey params do not name Ed25519 or Ed448");
            }
            byte[] raw;
            try {
                raw = WolfEdECJdkCompat.rawPrivateFromEdECPrivateKey(key);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException(e.getMessage(), e);
            }

            if (raw == null) {
                throw new InvalidKeyException(
                    "EdECPrivateKey does not expose its key bytes");
            }

            try {
                return WolfCryptEdDSAKeys.privateKey(curve, raw);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException("Invalid EdECPrivateKey: " +
                    e.getMessage(), e);
            }
            finally {
                WolfCryptEdDSACurve.zero(raw);
            }
        }

        if (encodedFormat) {
            throw new InvalidKeyException(
                "EdDSA private key reports PKCS#8 format but has no encoding");
        }
        throw new InvalidKeyException("Unsupported EdDSA private key: " +
            key.getClass().getName() + " (format " + key.getFormat() + ")");
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        WolfCryptEdDSAPublicKey key = null;

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        try {
            if (keySpec instanceof X509EncodedKeySpec) {
                byte[] encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
                if (encoded == null || encoded.length == 0) {
                    throw new InvalidKeySpecException(
                        "X509EncodedKeySpec is empty");
                }
                key = WolfCryptEdDSAKeys.publicKey(encoded);
            }
            else if (WolfEdECJdkCompat.isEdECPublicKeySpec(keySpec)) {
                WolfCryptEdDSACurve curve =
                    WolfEdECJdkCompat.curveFromEdECPublicKeySpec(keySpec);
                if (curve == null) {
                    throw new InvalidKeySpecException(
                        "EdECPublicKeySpec params do not name Ed25519 or " +
                        "Ed448");
                }
                key = WolfCryptEdDSAKeys.publicKey(curve,
                    WolfEdECJdkCompat.rawPublicFromEdECPublicKeySpec(curve,
                        keySpec));
            }
            else {
                throw new InvalidKeySpecException(
                    "Unsupported KeySpec type for EdDSA public key: " +
                    keySpec.getClass().getName() +
                    " (expected X509EncodedKeySpec or EdECPublicKeySpec)");
            }
        }
        catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid EdDSA public key: " + e.getMessage(), e);
        }

        checkCurve(key.curve());

        return key;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        WolfCryptEdDSAPrivateKey key = null;

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        try {
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                byte[] encoded = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
                if (encoded == null || encoded.length == 0) {
                    throw new InvalidKeySpecException(
                        "PKCS8EncodedKeySpec is empty");
                }
                try {
                    key = WolfCryptEdDSAKeys.privateKey(encoded);
                }
                finally {
                    WolfCryptEdDSACurve.zero(encoded);
                }
            }
            else if (WolfEdECJdkCompat.isEdECPrivateKeySpec(keySpec)) {
                WolfCryptEdDSACurve curve =
                    WolfEdECJdkCompat.curveFromEdECPrivateKeySpec(keySpec);
                if (curve == null) {
                    throw new InvalidKeySpecException(
                        "EdECPrivateKeySpec params do not name Ed25519 or " +
                        "Ed448");
                }
                byte[] raw =
                    WolfEdECJdkCompat.rawPrivateFromEdECPrivateKeySpec(keySpec);
                try {
                    key = WolfCryptEdDSAKeys.privateKey(curve, raw);
                }
                finally {
                    WolfCryptEdDSACurve.zero(raw);
                }
            }
            else {
                throw new InvalidKeySpecException(
                    "Unsupported KeySpec type for EdDSA private key: " +
                    keySpec.getClass().getName() +
                    " (expected PKCS8EncodedKeySpec or EdECPrivateKeySpec)");
            }
        }
        catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid EdDSA private key: " + e.getMessage(), e);
        }

        try {
            checkCurve(key.curve());
        }
        catch (InvalidKeySpecException e) {
            key.destroy();
            throw e;
        }

        return key;
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key,
        Class<T> keySpec) throws InvalidKeySpecException {

        Key wolfKey;

        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "Requested KeySpec class cannot be null");
        }

        /* Normalize key type, validates curve and encoding */
        try {
            wolfKey = engineTranslateKey(key);
        }
        catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }

        try {
            return getKeySpec(wolfKey, keySpec);
        }
        finally {
            if (wolfKey != key &&
                wolfKey instanceof WolfCryptEdDSAPrivateKey) {
                ((WolfCryptEdDSAPrivateKey) wolfKey).destroy();
            }
        }
    }

    /**
     * engineGetKeySpec() on a key already converted to a wolfJCE key.
     *
     * @param wolfKey wolfJCE EdDSA key
     * @param keySpec requested KeySpec class
     *
     * @return the KeySpec
     *
     * @throws InvalidKeySpecException if the class is not supported for the
     *         key or the key has been destroyed
     */
    private <T extends KeySpec> T getKeySpec(Key wolfKey, Class<T> keySpec)
        throws InvalidKeySpecException {

        if (wolfKey instanceof WolfCryptEdDSAPrivateKey) {
            WolfCryptEdDSAPrivateKey priv = (WolfCryptEdDSAPrivateKey) wolfKey;

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] encoded = WolfCryptUtil.requireEncoded(priv, "PKCS#8");
                try {
                    return keySpec.cast(new PKCS8EncodedKeySpec(encoded));
                }
                finally {
                    WolfCryptEdDSACurve.zero(encoded);
                }
            }

            if (WolfEdECJdkCompat.isEdECPrivateKeySpecClass(keySpec)) {
                byte[] raw = priv.getRawPrivateKey();
                if (raw == null) {
                    throw new InvalidKeySpecException("Key has been destroyed");
                }
                try {
                    KeySpec spec = WolfEdECJdkCompat.newEdECPrivateKeySpec(
                        priv.curve(), raw);
                    if (spec == null) {
                        throw new InvalidKeySpecException(
                            "EdECPrivateKeySpec not available on this JDK");
                    }
                    return keySpec.cast(spec);
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeySpecException(e.getMessage(), e);
                }
                finally {
                    WolfCryptEdDSACurve.zero(raw);
                }
            }
            throw new InvalidKeySpecException(
                "EdDSA private keys can only be expressed as " +
                "PKCS8EncodedKeySpec or EdECPrivateKeySpec, got request " +
                "for: " + keySpec.getName());
        }

        if (wolfKey instanceof WolfCryptEdDSAPublicKey) {
            WolfCryptEdDSAPublicKey pub = (WolfCryptEdDSAPublicKey) wolfKey;

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                byte[] encoded = WolfCryptUtil.requireEncoded(pub, "X.509");
                return keySpec.cast(new X509EncodedKeySpec(encoded));
            }

            if (WolfEdECJdkCompat.isEdECPublicKeySpecClass(keySpec)) {
                byte[] raw = pub.getRawPublicKey();
                if (raw == null) {
                    throw new InvalidKeySpecException("Key has been destroyed");
                }
                try {
                    KeySpec spec = WolfEdECJdkCompat.newEdECPublicKeySpec(
                        pub.curve(), raw);
                    if (spec == null) {
                        throw new InvalidKeySpecException(
                            "EdECPublicKeySpec not available on this JDK");
                    }
                    return keySpec.cast(spec);
                }
                catch (IllegalArgumentException e) {
                    throw new InvalidKeySpecException(e.getMessage(), e);
                }
            }
            throw new InvalidKeySpecException(
                "EdDSA public keys can only be expressed as " +
                "X509EncodedKeySpec or EdECPublicKeySpec, got request " +
                "for: " + keySpec.getName());
        }

        throw new InvalidKeySpecException(
            "Unsupported Key type: " + wolfKey.getClass().getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        try {
            if (key instanceof PrivateKey) {
                WolfCryptEdDSAPrivateKey priv =
                    toWolfPrivateKey((PrivateKey) key);
                try {
                    checkCurve(priv.curve());
                }
                catch (InvalidKeySpecException e) {
                    /* Foreign key was decoded into a temporary copy, destroy */
                    if (priv != key) {
                        priv.destroy();
                    }
                    throw e;
                }
                return priv;
            }

            if (key instanceof PublicKey) {
                WolfCryptEdDSAPublicKey pub = toWolfPublicKey((PublicKey) key);
                checkCurve(pub.curve());
                return pub;
            }
        }
        catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        }

        throw new InvalidKeyException("Unsupported Key type: " +
            key.getClass().getName());
    }
}
