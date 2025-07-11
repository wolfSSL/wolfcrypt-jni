/* Asn.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
    public static final int DSAk;
    /** RSA key value, from asn.h Key_Sum enum */
    public static final int RSAk;
    /** RSA-PSS key value, from asn.h Key_Sum enum */
    public static final int RSAPSSk;
    /** RSA-OAEP key value, from asn.h Key_Sum enum */
    public static final int RSAESOAEPk;
    /** ECDSA key value, from asn.h Key_Sum enum */
    public static final int ECDSAk;

    /* Hash Sum values, from oid_sum.h Hash_Sum enum */

    /** MD5 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int MD5h;
    /** SHA-1 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHAh;
    /** SHA-224 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA224h;
    /** SHA-256 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA256h;
    /** SHA-384 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA384h;
    /** SHA-512 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA512h;
    /** SHA3-224 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA3_224h;
    /** SHA3-256 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA3_256h;
    /** SHA3-384 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA3_384h;
    /** SHA3-512 hash OID value, from oid_sum.h Hash_Sum enum */
    public static final int SHA3_512h;

    static {
        DSAk = getDSAk();
        RSAk = getRSAk();
        RSAPSSk = getRSAPSSk();
        RSAESOAEPk = getRSAESOAEPk();
        ECDSAk = getECDSAk();

        MD5h = getMD5h();
        SHAh = getSHAh();
        SHA224h = getSHA224h();
        SHA256h = getSHA256h();
        SHA384h = getSHA384h();
        SHA512h = getSHA512h();
        SHA3_224h = getSHA3_224h();
        SHA3_256h = getSHA3_256h();
        SHA3_384h = getSHA3_384h();
        SHA3_512h = getSHA3_512h();
    }

    /** Return value of native DSAk enum */
    private static native int getDSAk();

    /** Return value of native RSAk enum */
    private static native int getRSAk();

    /** Return value of native RSAPSSk enum */
    private static native int getRSAPSSk();

    /** Return value of native RSAESOAEPk enum */
    private static native int getRSAESOAEPk();

    /** Return value of native ECDSAk enum */
    private static native int getECDSAk();

    /** Return value of native MD5h enum */
    private static native int getMD5h();

    /** Return value of native SHAh enum */
    private static native int getSHAh();

    /** Return value of native SHA224h enum */
    private static native int getSHA224h();

    /** Return value of native SHA256h enum */
    private static native int getSHA256h();

    /** Return value of native SHA384h enum */
    private static native int getSHA384h();

    /** Return value of native SHA512h enum */
    private static native int getSHA512h();

    /** Return value of native SHA3_224h enum */
    private static native int getSHA3_224h();

    /** Return value of native SHA3_256h enum */
    private static native int getSHA3_256h();

    /** Return value of native SHA3_384h enum */
    private static native int getSHA3_384h();

    /** Return value of native SHA3_512h enum */
    private static native int getSHA3_512h();

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

