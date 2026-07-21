/* Asn.java
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt ASN.1 implementation.
 *
 * @author wolfSSL Inc.
 */
public class Asn extends WolfObject {

    /** Default Asn constructor. */
    public Asn() {
    }

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
    /** ML-DSA-44 (FIPS 204) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.17. */
    public static final int ML_DSA_LEVEL2k;
    /** ML-DSA-65 (FIPS 204) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.18. */
    public static final int ML_DSA_LEVEL3k;
    /** ML-DSA-87 (FIPS 204) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.19. */
    public static final int ML_DSA_LEVEL5k;
    /** SLH-DSA-SHA2-128s (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.20. */
    public static final int SLH_DSA_SHA2_128Sk;
    /** SLH-DSA-SHA2-128f (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.21. */
    public static final int SLH_DSA_SHA2_128Fk;
    /** SLH-DSA-SHA2-192s (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.22. */
    public static final int SLH_DSA_SHA2_192Sk;
    /** SLH-DSA-SHA2-192f (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.23. */
    public static final int SLH_DSA_SHA2_192Fk;
    /** SLH-DSA-SHA2-256s (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.24. */
    public static final int SLH_DSA_SHA2_256Sk;
    /** SLH-DSA-SHA2-256f (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.25. */
    public static final int SLH_DSA_SHA2_256Fk;
    /** SLH-DSA-SHAKE-128s (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.26. */
    public static final int SLH_DSA_SHAKE_128Sk;
    /** SLH-DSA-SHAKE-128f (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.27. */
    public static final int SLH_DSA_SHAKE_128Fk;
    /** SLH-DSA-SHAKE-192s (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.28. */
    public static final int SLH_DSA_SHAKE_192Sk;
    /** SLH-DSA-SHAKE-192f (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.29. */
    public static final int SLH_DSA_SHAKE_192Fk;
    /** SLH-DSA-SHAKE-256s (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.30. */
    public static final int SLH_DSA_SHAKE_256Sk;
    /** SLH-DSA-SHAKE-256f (FIPS 205) key value, from oid_sum.h Key_Sum enum.
     * OID 2.16.840.1.101.3.4.3.31. */
    public static final int SLH_DSA_SHAKE_256Fk;

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
        ML_DSA_LEVEL2k = getML_DSA_LEVEL2k();
        ML_DSA_LEVEL3k = getML_DSA_LEVEL3k();
        ML_DSA_LEVEL5k = getML_DSA_LEVEL5k();
        SLH_DSA_SHA2_128Sk = getSLH_DSA_SHA2_128Sk();
        SLH_DSA_SHA2_128Fk = getSLH_DSA_SHA2_128Fk();
        SLH_DSA_SHA2_192Sk = getSLH_DSA_SHA2_192Sk();
        SLH_DSA_SHA2_192Fk = getSLH_DSA_SHA2_192Fk();
        SLH_DSA_SHA2_256Sk = getSLH_DSA_SHA2_256Sk();
        SLH_DSA_SHA2_256Fk = getSLH_DSA_SHA2_256Fk();
        SLH_DSA_SHAKE_128Sk = getSLH_DSA_SHAKE_128Sk();
        SLH_DSA_SHAKE_128Fk = getSLH_DSA_SHAKE_128Fk();
        SLH_DSA_SHAKE_192Sk = getSLH_DSA_SHAKE_192Sk();
        SLH_DSA_SHAKE_192Fk = getSLH_DSA_SHAKE_192Fk();
        SLH_DSA_SHAKE_256Sk = getSLH_DSA_SHAKE_256Sk();
        SLH_DSA_SHAKE_256Fk = getSLH_DSA_SHAKE_256Fk();

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

    /** Return value of native ML_DSA_LEVEL2k enum */
    private static native int getML_DSA_LEVEL2k();

    /** Return value of native ML_DSA_LEVEL3k enum */
    private static native int getML_DSA_LEVEL3k();

    /** Return value of native ML_DSA_LEVEL5k enum */
    private static native int getML_DSA_LEVEL5k();

    /** Return value of native SLH_DSA_SHA2_128Sk enum */
    private static native int getSLH_DSA_SHA2_128Sk();

    /** Return value of native SLH_DSA_SHA2_128Fk enum */
    private static native int getSLH_DSA_SHA2_128Fk();

    /** Return value of native SLH_DSA_SHA2_192Sk enum */
    private static native int getSLH_DSA_SHA2_192Sk();

    /** Return value of native SLH_DSA_SHA2_192Fk enum */
    private static native int getSLH_DSA_SHA2_192Fk();

    /** Return value of native SLH_DSA_SHA2_256Sk enum */
    private static native int getSLH_DSA_SHA2_256Sk();

    /** Return value of native SLH_DSA_SHA2_256Fk enum */
    private static native int getSLH_DSA_SHA2_256Fk();

    /** Return value of native SLH_DSA_SHAKE_128Sk enum */
    private static native int getSLH_DSA_SHAKE_128Sk();

    /** Return value of native SLH_DSA_SHAKE_128Fk enum */
    private static native int getSLH_DSA_SHAKE_128Fk();

    /** Return value of native SLH_DSA_SHAKE_192Sk enum */
    private static native int getSLH_DSA_SHAKE_192Sk();

    /** Return value of native SLH_DSA_SHAKE_192Fk enum */
    private static native int getSLH_DSA_SHAKE_192Fk();

    /** Return value of native SLH_DSA_SHAKE_256Sk enum */
    private static native int getSLH_DSA_SHAKE_256Sk();

    /** Return value of native SLH_DSA_SHAKE_256Fk enum */
    private static native int getSLH_DSA_SHAKE_256Fk();

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

