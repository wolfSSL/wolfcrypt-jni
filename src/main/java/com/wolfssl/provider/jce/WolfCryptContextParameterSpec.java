/* WolfCryptContextParameterSpec.java
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
import java.security.spec.AlgorithmParameterSpec;

/**
 * wolfJCE context-string parameter spec.
 *
 * <p>Carries an application context string for signature schemes that accept
 * one (for example SLH-DSA / FIPS 205, which allows a 0..255 byte context).
 * Set it on a {@link java.security.Signature} via
 * {@code Signature.setParameter(AlgorithmParameterSpec)}. The context may be
 * set before or after {@code initSign}/{@code initVerify}. It persists across
 * init calls until replaced. The signer and verifier must agree on the same
 * context or verification fails. The default is an empty context, which
 * matches X.509, CMS, and TLS usage.</p>
 */
public class WolfCryptContextParameterSpec implements AlgorithmParameterSpec {

    /** Maximum context length in bytes (FIPS 205). */
    public static final int MAX_CONTEXT_LEN = 255;

    /** Context bytes, never null (empty array for an empty context). */
    private final byte[] context;

    /**
     * Create a context parameter spec.
     *
     * @param context context bytes, may be null (treated as empty) and must
     *                be at most {@link #MAX_CONTEXT_LEN} bytes
     *
     * @throws IllegalArgumentException if {@code context} exceeds 255 bytes
     */
    public WolfCryptContextParameterSpec(byte[] context)
        throws IllegalArgumentException {

        if (context == null) {
            this.context = new byte[0];
        }
        else {
            if (context.length > MAX_CONTEXT_LEN) {
                throw new IllegalArgumentException(
                    "Context length exceeds " + MAX_CONTEXT_LEN + " bytes");
            }
            this.context = context.clone();
        }
    }

    /**
     * Get the context bytes.
     *
     * @return a copy of the context bytes (empty array for an empty context)
     */
    public byte[] getContext() {
        return this.context.clone();
    }

    @Override
    public String toString() {
        return "WolfCryptContextParameterSpec(len=" + this.context.length + ")";
    }

    @Override
    public boolean equals(Object obj) {

        WolfCryptContextParameterSpec other;

        if (this == obj) {
            return true;
        }

        if (!(obj instanceof WolfCryptContextParameterSpec)) {
            return false;
        }
        other = (WolfCryptContextParameterSpec) obj;

        return Arrays.equals(this.context, other.context);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.context);
    }
}
