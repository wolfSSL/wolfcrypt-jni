/* WolfCryptX25519KeyFactory.java
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

import java.util.Arrays;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

/**
 * wolfJCE KeyFactory implementation for X25519 (XDH key agreement).
 *
 * Supports:
 *   Private: PKCS8EncodedKeySpec, XECPrivateKeySpec
 *   Public:  X509EncodedKeySpec, XECPublicKeySpec
 */
public class WolfCryptX25519KeyFactory extends KeyFactorySpi {

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            byte[] der = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            try {
                return new WolfCryptX25519PrivateKey(der, true);
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException(
                    "Invalid X25519 PKCS#8 key: " + e.getMessage(), e);
            } finally {
                if (der != null) {
                    Arrays.fill(der, (byte) 0);
                }
            }

        } else if (keySpec instanceof XECPrivateKeySpec) {
            XECPrivateKeySpec spec = (XECPrivateKeySpec) keySpec;
            validateX25519Params(spec.getParams());
            byte[] scalar = spec.getScalar();
            if (scalar == null || scalar.length != 32) {
                throw new InvalidKeySpecException(
                    "X25519 private scalar must be 32 bytes");
            }
            try {
                return new WolfCryptX25519PrivateKey(scalar);
            } finally {
                Arrays.fill(scalar, (byte) 0);
            }

        } else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName() +
                ". Use PKCS8EncodedKeySpec or XECPrivateKeySpec.");
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec instanceof X509EncodedKeySpec) {
            byte[] der = ((X509EncodedKeySpec) keySpec).getEncoded();
            try {
                return new WolfCryptX25519PublicKey(der, true);
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException(
                    "Invalid X25519 SPKI key: " + e.getMessage(), e);
            }

        } else if (keySpec instanceof XECPublicKeySpec) {
            XECPublicKeySpec spec = (XECPublicKeySpec) keySpec;
            validateX25519Params(spec.getParams());
            return new WolfCryptX25519PublicKey(
                NamedParameterSpec.X25519, spec.getU());

        } else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName() +
                ". Use X509EncodedKeySpec or XECPublicKeySpec.");
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> specClass)
        throws InvalidKeySpecException {

        if (key instanceof XECPrivateKey) {
            XECPrivateKey xPriv = (XECPrivateKey) key;

            if (specClass == PKCS8EncodedKeySpec.class ||
                specClass == KeySpec.class) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "Key encoding not available (key may be destroyed)");
                }
                try {
                    return specClass.cast(new PKCS8EncodedKeySpec(encoded));
                } finally {
                    Arrays.fill(encoded, (byte) 0);
                }

            } else if (specClass == XECPrivateKeySpec.class) {
                java.util.Optional<byte[]> scalarOpt = xPriv.getScalar();
                if (!scalarOpt.isPresent()) {
                    throw new InvalidKeySpecException(
                        "Private scalar not available (key may be destroyed)");
                }
                byte[] scalar = scalarOpt.get();
                try {
                    return specClass.cast(
                        new XECPrivateKeySpec(NamedParameterSpec.X25519,
                            scalar));
                } finally {
                    Arrays.fill(scalar, (byte) 0);
                }

            } else {
                throw new InvalidKeySpecException(
                    "Unsupported spec class for XECPrivateKey: " +
                    specClass.getName());
            }

        } else if (key instanceof XECPublicKey) {
            XECPublicKey xPub = (XECPublicKey) key;

            if (specClass == X509EncodedKeySpec.class ||
                specClass == KeySpec.class) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "Key encoding not available (key may be destroyed)");
                }
                return specClass.cast(new X509EncodedKeySpec(encoded));

            } else if (specClass == XECPublicKeySpec.class) {
                return specClass.cast(
                    new XECPublicKeySpec(xPub.getParams(), xPub.getU()));

            } else {
                throw new InvalidKeySpecException(
                    "Unsupported spec class for XECPublicKey: " +
                    specClass.getName());
            }

        } else {
            throw new InvalidKeySpecException(
                "Key is not an XECPrivateKey or XECPublicKey");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key instanceof WolfCryptX25519PrivateKey ||
            key instanceof WolfCryptX25519PublicKey) {
            return key;
        }

        if (key instanceof XECPrivateKey) {
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                try {
                    return new WolfCryptX25519PrivateKey(encoded, true);
                } catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Cannot translate XECPrivateKey: " + e.getMessage(), e);
                } finally {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
            java.util.Optional<byte[]> scalarOpt =
                ((XECPrivateKey) key).getScalar();
            if (scalarOpt.isPresent()) {
                byte[] raw = scalarOpt.get();
                try {
                    return new WolfCryptX25519PrivateKey(raw);
                } finally {
                    Arrays.fill(raw, (byte) 0);
                }
            }
            throw new InvalidKeyException(
                "Cannot translate XECPrivateKey: no encoding available");
        }

        if (key instanceof XECPublicKey) {
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                try {
                    return new WolfCryptX25519PublicKey(encoded, true);
                } catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Cannot translate XECPublicKey: " + e.getMessage(), e);
                }
            }
            throw new InvalidKeyException(
                "Cannot translate XECPublicKey: no encoding available");
        }

        throw new InvalidKeyException(
            "Cannot translate key of type: " + key.getClass().getName());
    }

    private void validateX25519Params(AlgorithmParameterSpec params)
        throws InvalidKeySpecException {

        if (!(params instanceof NamedParameterSpec)) {
            throw new InvalidKeySpecException(
                "AlgorithmParameterSpec must be NamedParameterSpec");
        }
        NamedParameterSpec named = (NamedParameterSpec) params;
        if (!named.getName().equalsIgnoreCase("X25519")) {
            throw new InvalidKeySpecException(
                "Only X25519 is supported, got: " + named.getName());
        }
    }
}
