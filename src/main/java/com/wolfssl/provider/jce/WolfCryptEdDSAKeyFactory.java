/* WolfCryptEdDSAKeyFactory.java
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

import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * wolfJCE KeyFactory implementation for Ed25519 (EdDSA).
 *
 * Supports:
 *   Private: PKCS8EncodedKeySpec, EdECPrivateKeySpec
 *   Public:  X509EncodedKeySpec, EdECPublicKeySpec
 */
public class WolfCryptEdDSAKeyFactory extends KeyFactorySpi {

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            byte[] der = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
            try {
                return new WolfCryptEdDSAPrivateKey(der, true);
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException(
                    "Invalid Ed25519 PKCS#8 key: " + e.getMessage(), e);
            }

        } else if (keySpec instanceof EdECPrivateKeySpec) {
            EdECPrivateKeySpec spec = (EdECPrivateKeySpec) keySpec;
            validateEd25519Params(spec.getParams());
            byte[] bytes = spec.getBytes();
            if (bytes == null || bytes.length != 32) {
                throw new InvalidKeySpecException(
                    "Ed25519 private key bytes must be 32 bytes");
            }
            return new WolfCryptEdDSAPrivateKey(bytes);

        } else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName() +
                ". Use PKCS8EncodedKeySpec or EdECPrivateKeySpec.");
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        if (keySpec instanceof X509EncodedKeySpec) {
            byte[] der = ((X509EncodedKeySpec) keySpec).getEncoded();
            try {
                return new WolfCryptEdDSAPublicKey(der, true);
            } catch (IllegalArgumentException e) {
                throw new InvalidKeySpecException(
                    "Invalid Ed25519 SPKI key: " + e.getMessage(), e);
            }

        } else if (keySpec instanceof EdECPublicKeySpec) {
            EdECPublicKeySpec spec = (EdECPublicKeySpec) keySpec;
            validateEd25519Params(spec.getParams());
            return new WolfCryptEdDSAPublicKey(
                (NamedParameterSpec) spec.getParams(), spec.getPoint());

        } else {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type: " + keySpec.getClass().getName() +
                ". Use X509EncodedKeySpec or EdECPublicKeySpec.");
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> specClass)
        throws InvalidKeySpecException {

        if (key instanceof EdECPrivateKey) {
            EdECPrivateKey edPriv = (EdECPrivateKey) key;

            if (specClass == PKCS8EncodedKeySpec.class ||
                specClass == KeySpec.class) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "Key encoding is not available (key may be destroyed)");
                }
                return specClass.cast(new PKCS8EncodedKeySpec(encoded));

            } else if (specClass == EdECPrivateKeySpec.class) {
                java.util.Optional<byte[]> bytesOpt = edPriv.getBytes();
                if (!bytesOpt.isPresent()) {
                    throw new InvalidKeySpecException(
                        "Private key bytes not available (key may be destroyed)");
                }
                return specClass.cast(
                    new EdECPrivateKeySpec(NamedParameterSpec.ED25519,
                        bytesOpt.get()));

            } else {
                throw new InvalidKeySpecException(
                    "Unsupported spec class for EdECPrivateKey: " +
                    specClass.getName());
            }

        } else if (key instanceof EdECPublicKey) {
            EdECPublicKey edPub = (EdECPublicKey) key;

            if (specClass == X509EncodedKeySpec.class ||
                specClass == KeySpec.class) {
                byte[] encoded = key.getEncoded();
                if (encoded == null) {
                    throw new InvalidKeySpecException(
                        "Key encoding is not available (key may be destroyed)");
                }
                return specClass.cast(new X509EncodedKeySpec(encoded));

            } else if (specClass == EdECPublicKeySpec.class) {
                return specClass.cast(
                    new EdECPublicKeySpec(edPub.getParams(), edPub.getPoint()));

            } else {
                throw new InvalidKeySpecException(
                    "Unsupported spec class for EdECPublicKey: " +
                    specClass.getName());
            }

        } else {
            throw new InvalidKeySpecException(
                "Key is not an EdECPrivateKey or EdECPublicKey");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key instanceof WolfCryptEdDSAPrivateKey ||
            key instanceof WolfCryptEdDSAPublicKey) {
            return key;
        }

        if (key instanceof EdECPrivateKey) {
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                try {
                    return new WolfCryptEdDSAPrivateKey(encoded, true);
                } catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Cannot translate EdECPrivateKey: " + e.getMessage(), e);
                }
            }
            /* Fall back to EdECPrivateKeySpec if getEncoded() returns null */
            java.util.Optional<byte[]> bytesOpt =
                ((EdECPrivateKey) key).getBytes();
            if (bytesOpt.isPresent()) {
                return new WolfCryptEdDSAPrivateKey(bytesOpt.get());
            }
            throw new InvalidKeyException(
                "Cannot translate EdECPrivateKey: no encoding available");
        }

        if (key instanceof EdECPublicKey) {
            byte[] encoded = key.getEncoded();
            if (encoded != null) {
                try {
                    return new WolfCryptEdDSAPublicKey(encoded, true);
                } catch (IllegalArgumentException e) {
                    throw new InvalidKeyException(
                        "Cannot translate EdECPublicKey: " + e.getMessage(), e);
                }
            }
            throw new InvalidKeyException(
                "Cannot translate EdECPublicKey: no encoding available");
        }

        throw new InvalidKeyException(
            "Cannot translate key of type: " + key.getClass().getName());
    }

    private void validateEd25519Params(AlgorithmParameterSpec params)
        throws InvalidKeySpecException {

        if (!(params instanceof NamedParameterSpec)) {
            throw new InvalidKeySpecException(
                "AlgorithmParameterSpec must be NamedParameterSpec");
        }
        NamedParameterSpec named = (NamedParameterSpec) params;
        if (!named.getName().equalsIgnoreCase("Ed25519")) {
            throw new InvalidKeySpecException(
                "Only Ed25519 is supported, got: " + named.getName());
        }
    }
}
