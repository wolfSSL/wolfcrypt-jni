/* WolfCryptEdDSAKeys.java (JDK 15+ multi-release overlay)
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

/**
 * JDK 15+ factory for wolfJCE EdDSA key objects.
 *
 * This class is in the multi-release JAR and replaces the Java 8 base
 * variant at runtime on JDK 15 and later. It creates
 * WolfCryptEdDSAPublicKey15 / WolfCryptEdDSAPrivateKey15, which implement
 * the JDK 15 java.security.interfaces.EdECPublicKey / EdECPrivateKey
 * interfaces. API is identical to the base variant.
 */
final class WolfCryptEdDSAKeys {

    private WolfCryptEdDSAKeys() { }

    /**
     * Public key from an X.509 SubjectPublicKeyInfo DER.
     *
     * @param spkiDer SubjectPublicKeyInfo DER
     *
     * @return public key
     *
     * @throws IllegalArgumentException if the DER is invalid
     */
    static WolfCryptEdDSAPublicKey publicKey(byte[] spkiDer)
        throws IllegalArgumentException {

        return new WolfCryptEdDSAPublicKey15(spkiDer);
    }

    /**
     * Public key from a curve and raw key, validated by native wolfCrypt.
     *
     * @param curve curve
     * @param rawPub raw public key
     *
     * @return public key
     *
     * @throws IllegalArgumentException if the key is invalid
     */
    static WolfCryptEdDSAPublicKey publicKey(WolfCryptEdDSACurve curve,
        byte[] rawPub) throws IllegalArgumentException {

        return new WolfCryptEdDSAPublicKey15(curve, rawPub);
    }

    /**
     * Public key from a raw key and its SubjectPublicKeyInfo.
     *
     * @param curve curve
     * @param rawPub raw public key
     * @param spkiDer SubjectPublicKeyInfo DER from native
     *
     * @return public key
     *
     * @throws IllegalArgumentException on a wrong length
     */
    static WolfCryptEdDSAPublicKey trustedPublicKey(
        WolfCryptEdDSACurve curve, byte[] rawPub, byte[] spkiDer)
        throws IllegalArgumentException {

        return new WolfCryptEdDSAPublicKey15(curve, rawPub, spkiDer);
    }

    /**
     * Private key from a PKCS#8 DER.
     *
     * @param pkcs8Der PKCS#8 DER
     *
     * @return private key
     *
     * @throws IllegalArgumentException if the DER is invalid
     */
    static WolfCryptEdDSAPrivateKey privateKey(byte[] pkcs8Der)
        throws IllegalArgumentException {

        return new WolfCryptEdDSAPrivateKey15(pkcs8Der);
    }

    /**
     * Private key from a curve and raw private key (public key derived).
     *
     * @param curve curve
     * @param rawPriv raw private key
     *
     * @return private key
     *
     * @throws IllegalArgumentException if the key is invalid
     */
    static WolfCryptEdDSAPrivateKey privateKey(WolfCryptEdDSACurve curve,
        byte[] rawPriv) throws IllegalArgumentException {

        return new WolfCryptEdDSAPrivateKey15(curve, rawPriv);
    }

    /**
     * Private key from a raw key pair and its PKCS#8 encoding.
     *
     * @param curve curve
     * @param rawPriv raw private key
     * @param rawPub raw public key
     * @param pkcs8Der PKCS#8 v1 DER from native
     *
     * @return private key
     *
     * @throws IllegalArgumentException on wrong lengths
     */
    static WolfCryptEdDSAPrivateKey trustedPrivateKey(
        WolfCryptEdDSACurve curve, byte[] rawPriv, byte[] rawPub,
        byte[] pkcs8Der) throws IllegalArgumentException {

        return new WolfCryptEdDSAPrivateKey15(curve, rawPriv, rawPub, pkcs8Der);
    }
}
