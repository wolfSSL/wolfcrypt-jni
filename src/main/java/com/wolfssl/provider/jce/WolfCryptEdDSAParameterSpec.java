/* WolfCryptEdDSAParameterSpec.java
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

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * wolfJCE EdDSA signature parameter spec. Selects the pre-hash variant
 * (Ed25519ph / Ed448ph) and the RFC 8032 context.
 *
 * Java 8 compatible equivalent of the JDK 15
 * java.security.spec.EdDSAParameterSpec, with the same semantics: with
 * 'prehash == false' and no context the pure variant is used. A present context
 * (even empty) selects Ed25519ctx for Ed25519 and is passed to Ed448 as-is.
 * 'prehash == true' selects Ed25519ph / Ed448ph. Set it via
 * Signature.setParameter(AlgorithmParameterSpec). On JDK 15+ the JDK
 * EdDSAParameterSpec is also accepted.
 */
public final class WolfCryptEdDSAParameterSpec
    implements AlgorithmParameterSpec {

    /** Maximum context length in bytes (RFC 8032). */
    public static final int MAX_CONTEXT_LEN = 255;

    private final boolean prehash;

    /** Context bytes, or null when no context was given */
    private final byte[] context;

    /**
     * Create a spec with no context.
     *
     * @param prehash true for the pre-hash variant (Ed25519ph / Ed448ph)
     */
    public WolfCryptEdDSAParameterSpec(boolean prehash) {
        this.prehash = prehash;
        this.context = null;
    }

    /**
     * Create a spec with a context.
     *
     * @param prehash true for the pre-hash variant (Ed25519ph / Ed448ph)
     * @param context context bytes, at most MAX_CONTEXT_LEN, null means
     *                no context
     *
     * @throws IllegalArgumentException if context exceeds 255 bytes
     */
    public WolfCryptEdDSAParameterSpec(boolean prehash, byte[] context)
        throws IllegalArgumentException {

        if (context != null && context.length > MAX_CONTEXT_LEN) {
            throw new IllegalArgumentException("Context length exceeds " +
                MAX_CONTEXT_LEN + " bytes");
        }

        this.prehash = prehash;
        this.context = (context == null) ? null : context.clone();
    }

    /**
     * Check whether the pre-hash variant (Ed25519ph / Ed448ph) is selected.
     *
     * @return true if the pre-hash variant is selected, otherwise false
     */
    public boolean isPrehash() {
        return this.prehash;
    }

    /**
     * Check whether a context was given. Empty context counts as present,
     * which for Ed25519 selects Ed25519ctx rather than pure Ed25519.
     *
     * @return true if a context is present (possibly empty), otherwise false
     */
    public boolean hasContext() {
        return this.context != null;
    }

    /**
     * Get the context bytes.
     *
     * @return copy of the context bytes, or null when no context was given
     */
    public byte[] getContext() {

        if (this.context == null) {
            return null;
        }

        return this.context.clone();
    }

    @Override
    public String toString() {
        return "WolfCryptEdDSAParameterSpec(prehash=" + this.prehash +
            ", context=" + ((this.context == null) ? "absent" :
            (this.context.length + " bytes")) + ")";
    }

    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof WolfCryptEdDSAParameterSpec)) {
            return false;
        }

        WolfCryptEdDSAParameterSpec o = (WolfCryptEdDSAParameterSpec) obj;

        return this.prehash == o.prehash &&
            Arrays.equals(this.context, o.context);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(this.context) + (this.prehash ? 1 : 0);
    }
}
