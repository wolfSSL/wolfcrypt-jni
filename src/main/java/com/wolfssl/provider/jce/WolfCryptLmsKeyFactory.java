/* WolfCryptLmsKeyFactory.java
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * wolfJCE LMS/HSS (RFC 8554) KeyFactory implementation.
 *
 * <p>Verify-only: converts between {@link X509EncodedKeySpec} and
 * {@link WolfCryptLmsPublicKey} public keys. Both RFC 9708 and RFC 8708 X.509
 * SubjectPublicKeyInfo forms are accepted on input. Private keys are not
 * supported (matching the JDK SUN provider). {@code generatePrivate} throws
 * {@link InvalidKeySpecException}.</p>
 */
public class WolfCryptLmsKeyFactory extends KeyFactorySpi {

    /**
     * Create a new wolfJCE LMS KeyFactory.
     */
    public WolfCryptLmsKeyFactory() {
        log("created new LMS KeyFactory");
    }

    private void log(String msg) {
        WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
            () -> "[LMS KeyFactory] " + msg);
    }

    /**
     * Private keys are not supported: wolfJCE provides verify-only LMS/HSS.
     */
    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
        throws InvalidKeySpecException {

        throw new InvalidKeySpecException(
            "LMS/HSS private keys are not supported (verify-only)");
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
        throws InvalidKeySpecException {

        byte[] encoded;

        if (keySpec == null) {
            throw new InvalidKeySpecException("KeySpec cannot be null");
        }

        if (!(keySpec instanceof X509EncodedKeySpec)) {
            throw new InvalidKeySpecException(
                "Unsupported KeySpec type for LMS public key: " +
                keySpec.getClass().getName() +
                " (expected X509EncodedKeySpec)");
        }

        encoded = ((X509EncodedKeySpec) keySpec).getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeySpecException("X509EncodedKeySpec is empty");
        }

        try {
            return new WolfCryptLmsPublicKey(encoded);
        }
        catch (IllegalArgumentException e) {
            throw new InvalidKeySpecException(
                "Invalid LMS X.509 SPKI DER: " + e.getMessage(), e);
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
        throws InvalidKeySpecException {

        byte[] encoded;
        Key wolfKey;

        if (key == null) {
            throw new InvalidKeySpecException("Key cannot be null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException(
                "Requested KeySpec class cannot be null");
        }

        /* Normalize key, validates foreign keys (encoding, type, DER) */
        try {
            wolfKey = engineTranslateKey(key);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }

        if (wolfKey instanceof PublicKey) {
            if (!keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                throw new InvalidKeySpecException(
                    "LMS public keys can only be expressed as " +
                    "X509EncodedKeySpec, got request for: " +
                    keySpec.getName());
            }
            encoded = WolfCryptUtil.requireEncoded(wolfKey, "X.509");
            return keySpec.cast(new X509EncodedKeySpec(encoded));
        }

        throw new InvalidKeySpecException(
            "Unsupported Key type: " + key.getClass().getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        byte[] encoded;

        if (key == null) {
            throw new InvalidKeyException("Key cannot be null");
        }

        /* Already one of our key objects */
        if (key instanceof WolfCryptLmsPublicKey) {
            return key;
        }

        if (key instanceof PublicKey) {
            String fmt = key.getFormat();
            if (!"X.509".equalsIgnoreCase(fmt)) {
                throw new InvalidKeyException(
                    "Cannot translate LMS public key with format: " + fmt +
                    " (expected X.509)");
            }

            encoded = key.getEncoded();
            if (encoded == null || encoded.length == 0) {
                throw new InvalidKeyException(
                    "Source public key has no X.509 encoding");
            }

            try {
                return new WolfCryptLmsPublicKey(encoded);
            }
            catch (IllegalArgumentException e) {
                throw new InvalidKeyException(
                    "Source key is not a valid LMS X.509 SPKI: " +
                    e.getMessage(), e);
            }
        }

        throw new InvalidKeyException(
            "Unsupported Key type: " + key.getClass().getName());
    }

}
