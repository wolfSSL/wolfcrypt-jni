/* WolfCryptEdDSAPublicKey15.java (JDK 15+ multi-release overlay)
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

import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;

/**
 * wolfJCE EdDSA (Ed25519 / Ed448) public key that also implements the
 * JDK 15 EdECPublicKey interface.
 *
 * Only in the JDK 15 multi-release JAR, created by the JDK 15+ variant of
 * WolfCryptEdDSAKeys, so every key produced by the wolfJCE KeyPairGenerator
 * and KeyFactory on JDK 15+ is one of these. Everything except getParams(),
 * getPoint() and writeReplace() is inherited from WolfCryptEdDSAPublicKey.
 * getPoint() throws IllegalStateException on a destroyed key, EdECPoint has
 * no empty form.
 */
final class WolfCryptEdDSAPublicKey15 extends WolfCryptEdDSAPublicKey
    implements EdECPublicKey {

    private static final long serialVersionUID = 1L;

    WolfCryptEdDSAPublicKey15(byte[] spkiDer)
        throws IllegalArgumentException {

        super(spkiDer);
    }

    WolfCryptEdDSAPublicKey15(WolfCryptEdDSACurve curve, byte[] rawPub)
        throws IllegalArgumentException {

        super(curve, rawPub);
    }

    WolfCryptEdDSAPublicKey15(WolfCryptEdDSACurve curve, byte[] rawPub,
        byte[] spkiDer) throws IllegalArgumentException {

        super(curve, rawPub, spkiDer);
    }

    /**
     * Serialize as the base class (every JDK can read).
     * readResolve() restores this class on JDK 15+.
     *
     * @return base class copy of this key
     */
    private Object writeReplace() {

        byte[] rawPub = getRawPublicKey();
        byte[] encoded = getEncoded();

        if (rawPub == null || encoded == null) {
            /* destroyed, possibly by another thread between the accessor
             * calls, write a destroyed base key */
            WolfCryptEdDSAPublicKey base = new WolfCryptEdDSAPublicKey(
                curve(), new byte[curve().getPublicKeySize()], new byte[0]);
            base.destroy();
            return base;
        }

        return new WolfCryptEdDSAPublicKey(curve(), rawPub, encoded);
    }

    /**
     * Get the curve parameters of this key.
     *
     * @return {@link NamedParameterSpec#ED25519} or
     *         {@link NamedParameterSpec#ED448}
     */
    @Override
    public NamedParameterSpec getParams() {
        if (curve() == WolfCryptEdDSACurve.ED25519) {
            return NamedParameterSpec.ED25519;
        } else {
            return NamedParameterSpec.ED448;
        }
    }

    /**
     * Get the public point: RFC 8032 raw key decoded into its x and y
     * coordinates.
     *
     * @return the point
     *
     * @throws IllegalStateException if the key has been destroyed
     */
    @Override
    public EdECPoint getPoint() {
        byte[] raw = getRawPublicKey();
        if (raw == null) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return new EdECPoint(WolfEdECJdkCompat.rawIsXOdd(raw),
            WolfEdECJdkCompat.rawToY(curve(), raw));
    }
}
