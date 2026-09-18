/* WolfCryptEdDSAPrivateKey15.java (JDK 15+ multi-release overlay)
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

import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;

/**
 * wolfJCE EdDSA (Ed25519 / Ed448) private key that also implements the
 * JDK 15 EdECPrivateKey interface.
 *
 * Only present in JDK 15 multi-release JAR, created by the JDK 15+ variant of
 * WolfCryptEdDSAKeys. Only getParams() and writeReplace() are declared
 * here, the base class already declares getBytes() with the EdECPrivateKey
 * signature.
 */
final class WolfCryptEdDSAPrivateKey15 extends WolfCryptEdDSAPrivateKey
    implements EdECPrivateKey {

    private static final long serialVersionUID = 1L;

    WolfCryptEdDSAPrivateKey15(byte[] pkcs8Der)
        throws IllegalArgumentException {

        super(pkcs8Der);
    }

    WolfCryptEdDSAPrivateKey15(WolfCryptEdDSACurve curve, byte[] rawPriv)
        throws IllegalArgumentException {

        super(curve, rawPriv);
    }

    WolfCryptEdDSAPrivateKey15(WolfCryptEdDSACurve curve, byte[] rawPriv,
        byte[] rawPub, byte[] pkcs8Der) throws IllegalArgumentException {

        super(curve, rawPriv, rawPub, pkcs8Der);
    }

    /**
     * Serialize as the base class (readable by every JDK).
     * readResolve() restores this class on JDK 15+.
     *
     * @return base class copy of this key
     */
    private Object writeReplace() {

        byte[] rawPriv = null;
        byte[] rawPub = null;
        byte[] encoded = null;

        try {
            rawPriv = getRawPrivateKey();
            rawPub = getRawPublicKey();
            encoded = getEncoded();

            if (rawPriv == null || rawPub == null || encoded == null) {
                /* destroyed, possibly by another thread between the accessor
                 * calls, write a destroyed base key */
                WolfCryptEdDSAPrivateKey base = new WolfCryptEdDSAPrivateKey(
                    curve(), new byte[curve().getPrivateKeySize()],
                    new byte[curve().getPublicKeySize()], new byte[0]);
                base.destroy();
                return base;
            }

            return new WolfCryptEdDSAPrivateKey(curve(), rawPriv, rawPub,
                encoded);
        }
        finally {
            WolfCryptEdDSACurve.zero(rawPriv);
            WolfCryptEdDSACurve.zero(encoded);
        }
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
}
