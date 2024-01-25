/* Asn.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt ASN.1 implementation.
 *
 * @author wolfSSL Inc.
 */
public class Asn extends WolfObject {

    /** Maximum encoded signature size */
    public static final int MAX_ENCODED_SIG_SIZE = 512;

    /* Key Sum values, from asn.h Key_Sum enum */

    /** DSA key value, from asn.h Key_Sum enum */
    public static final int DSAk = 515;
    /** RSA key value, from asn.h Key_Sum enum */
    public static final int RSAk = 645;
    /** RSA-PSS key value, from asn.h Key_Sum enum */
    public static final int RSAPSSk = 654;
    /** RSA-OAEP key value, from asn.h Key_Sum enum */
    public static final int RSAESOAEPk = 651;
    /** ECDSA key value, from asn.h Key_Sum enum */
    public static final int ECDSAk = 518;

    /** Default Asn constructor */
    public Asn() { }

    /** ASN.1 encode message digest, before it is signed
     *
     * @param encoded output buffer to place encoded data
     * @param hash input hash to encode
     * @param hashSize size of hash, bytes
     * @param hashOID hash algorithm OID
     */
    public static native void encodeSignature(ByteBuffer encoded,
            ByteBuffer hash, long hashSize, int hashOID);

    /** ASN.1 encode message digest, before it is signed
     *
     * @param encoded output array to place encoded data
     * @param hash input hash to encode
     * @param hashSize size of hash, bytes
     * @param hashOID hash algorithm OID
     *
     * @return number of bytes written to encoded array
     */
    public static native long encodeSignature(byte[] encoded,
            byte[] hash, long hashSize, int hashOID);

    /**
     * Get hash algorithm OID from algorithm type
     *
     * @param type algorithm type. Comes from each algorithm class, for example:
     *        Sha.TYPE, Sha256.TYPE
     *
     * @return hash algorithm OID, for use with encodeSignature()
     */
    public static native int getCTC_HashOID(int type);

    /**
     * Get the Algorithm Identifier from inside DER-encoded PKCS#8 key.
     *
     * @param pkcs8Der DER-encoded PKCS#8 private key
     *
     * @return Algorithm Identifier on success, will match one of the values
     *         for key sums (ie: Asn.RSAk, Asn.ECDSAk, etc)
     *
     * @throws WolfCryptException upon native error
     */
    public static native int getPkcs8AlgoID(byte[] pkcs8Der);
}

