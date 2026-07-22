/* wolfCryptProvider.java
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

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.Fips;
import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.SlhDsa;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfSSLX509StoreCtx;

/**
 * wolfCrypt JCE Provider implementation
 */
public final class WolfCryptProvider extends Provider {

    private static final long serialVersionUID = 1L;

    /**
     * Default FIPS error callback for wolfJCE provider.
     *
     * Logs FIPS errors to aid in debugging module failures. Registered
     * automatically when wolfJCE provider is instantiated with FIPS wolfCrypt.
     */
    private static class JCEFIPSErrorCallback implements Fips.ErrorCallback {

        /* Track last error code to suppress repeated consecutive messages.
         * Native wolfCrypt may call the callback with the same error code
         * multiple times during a failure sequence. */
        private static final AtomicInteger lastErr = new AtomicInteger(0);

        /**
         * Called by native wolfCrypt when FIPS error occurs.
         *
         * @param ok 1 if verification passed, otherwise 0
         * @param err wolfCrypt FIPS error code
         * @param hash expected verifyCore hash value
         */
        @Override
        public void errorCallback(int ok, int err, String hash) {

            int prev = lastErr.getAndSet(err);
            if (prev == err) {
                return;
            }

            String errStr = WolfCryptError.fromInt(err).getDescription();

            System.err.println("wolfJCE FIPS error: ok = " + ok + ", err = " +
                err + " (" + errStr + "), hash = " + hash);

            if (err == WolfCryptError.IN_CORE_FIPS_E.getCode()) {
                System.err.println("wolfJCE FIPS: in core integrity hash " +
                    "check failure. Copy hash above into verifyCore[] in " +
                    "fips_test.c and rebuild");
            }

            WolfCryptDebug.log(JCEFIPSErrorCallback.class, WolfCryptDebug.ERROR,
                () -> "FIPS error: ok = " + ok + ", err = " + err + " (" +
                errStr + "), hash = " + hash);
        }
    }

    /**
     * Create new WolfCryptProvider object
     */
    @SuppressWarnings("deprecation")
    public WolfCryptProvider() {
        super("wolfJCE", 1.10, "wolfCrypt JCE Provider");

        /* Refresh debug flags in case system properties were set after
         * WolfCryptDebug class was first loaded (e.g., via JAVA_OPTS) */
        WolfCryptDebug.refreshDebugFlags();

        /* Register default FIPS error callback if FIPS enabled. */
        if (Fips.enabled) {
            Fips.wolfCrypt_SetCb_fips(new JCEFIPSErrorCallback());

            WolfCryptDebug.log(getClass(), WolfCryptDebug.INFO,
                () -> "Registered wolfCrypt FIPS error callback");
        }

        registerServices();
    }

    /**
     * Refresh the services provided by this JCE provider.
     *
     * This is required when one of the Security properties has been changed
     * that affect the services offered by this provider. For example:
     *     wolfjce.mapJKStoWKS
     *     wolfjce.mapPKCS12toWKS
     */
    public void refreshServices() {
        registerServices();
    }

    /**
     * Register services provided by wolfJCE, called by class constructor.
     */
    private void registerServices() {
        String mapJksToWks = null;
        String mapPkcs12ToWks = null;

        /* Run FIPS algorithm self tests (CASTs) if needed */
        if (Fips.enabled) {
            Fips.runAllCast_fips();
        }

        /* MessageDigest */
        if (FeatureDetect.Md5Enabled()) {
            put("MessageDigest.MD5",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestMd5");
        }
        if (FeatureDetect.ShaEnabled()) {
            put("MessageDigest.SHA",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
            put("MessageDigest.SHA1",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
            put("MessageDigest.SHA-1",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha");
        }
        if (FeatureDetect.Sha224Enabled()) {
            put("MessageDigest.SHA-224",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha224");
            /* SHA-224 OID */
            put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.4",
                    "SHA-224");
        }
        if (FeatureDetect.Sha256Enabled()) {
            put("MessageDigest.SHA-256",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha256");
            /* SHA-256 OID */
            put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.1",
                    "SHA-256");
        }
        if (FeatureDetect.Sha384Enabled()) {
            put("MessageDigest.SHA-384",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha384");
            /* SHA-384 OID */
            put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.2",
                    "SHA-384");
        }
        if (FeatureDetect.Sha512Enabled()) {
            put("MessageDigest.SHA-512",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha512");
            /* SHA-512 OID */
            put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.3",
                    "SHA-512");
        }
        if (FeatureDetect.Sha3Enabled()) {
            put("MessageDigest.SHA3-224",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_224");
            put("MessageDigest.SHA3-256",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_256");
            put("MessageDigest.SHA3-384",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_384");
            put("MessageDigest.SHA3-512",
                    "com.wolfssl.provider.jce.WolfCryptMessageDigestSha3$wcSHA3_512");
        }

        /* SecureRandom */
        /* TODO: May need to add "SHA1PRNG" alias, other JCA consumemrs may
         * explicitly request it? Needs more testing. */
        put("SecureRandom.DEFAULT",
                "com.wolfssl.provider.jce.WolfCryptRandom");
        put("SecureRandom.HashDRBG",
                "com.wolfssl.provider.jce.WolfCryptRandom");
        put("SecureRandom.Hash_DRBG",
                "com.wolfssl.provider.jce.WolfCryptRandom");
        put("SecureRandom.DRBG",
                "com.wolfssl.provider.jce.WolfCryptRandom");

        /* Signature */
        if (FeatureDetect.Md5Enabled()) {
            put("Signature.MD5withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcMD5wRSA");
        }
        if (FeatureDetect.ShaEnabled()) {
            put("Signature.SHA1withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA1wRSA");

            /* FIPS 186-5 (wolfCrypt FIPS v7+) no longer allows SHA-1 for
             * ECDSA signatures. Only register SHA1withECDSA when not using
             * FIPS, or when using FIPS versions prior to v7 which follow
             * FIPS 186-4. */
            if (!Fips.enabled || Fips.fipsVersion < 7) {
                put("Signature.SHA1withECDSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA1wECDSA");
                put("Alg.Alias.Signature.1.2.840.10045.4.1", "SHA1withECDSA");
            }
        }
        if (FeatureDetect.Sha224Enabled()) {
            put("Signature.SHA224withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA224wRSA");
            put("Signature.SHA224withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA224wECDSA");
            put("Alg.Alias.Signature.1.2.840.10045.4.3.1", "SHA224withECDSA");
        }
        if (FeatureDetect.Sha256Enabled()) {
            put("Signature.SHA256withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA256wRSA");
            put("Signature.SHA256withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA256wECDSA");
            put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
            /* IEEE P1363 format ECDSA */
            put("Signature.SHA256withECDSAinP1363Format",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA256wECDSAP1363");
        }
        if (FeatureDetect.Sha384Enabled()) {
            put("Signature.SHA384withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA384wRSA");
            put("Signature.SHA384withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA384wECDSA");
            put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");
            /* IEEE P1363 format ECDSA */
            put("Signature.SHA384withECDSAinP1363Format",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA384wECDSAP1363");
        }
        if (FeatureDetect.Sha512Enabled()) {
            put("Signature.SHA512withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA512wRSA");
            put("Signature.SHA512withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA512wECDSA");
            put("Alg.Alias.Signature.1.2.840.10045.4.3.4", "SHA512withECDSA");
            /* IEEE P1363 format ECDSA */
            put("Signature.SHA512withECDSAinP1363Format",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA512wECDSAP1363");
        }
        if (FeatureDetect.Sha3Enabled()) {
            put("Signature.SHA3-224withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_224wRSA");
            put("Signature.SHA3-256withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_256wRSA");
            put("Signature.SHA3-384withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_384wRSA");
            put("Signature.SHA3-512withRSA",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_512wRSA");

            put("Signature.SHA3-224withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_224wECDSA");
            put("Signature.SHA3-256withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_256wECDSA");
            put("Signature.SHA3-384withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_384wECDSA");
            put("Signature.SHA3-512withECDSA",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_512wECDSA");

            /* IEEE P1363 format ECDSA with SHA3 */
            put("Signature.SHA3-256withECDSAinP1363Format",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_256wECDSAP1363");
            put("Signature.SHA3-384withECDSAinP1363Format",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_384wECDSAP1363");
            put("Signature.SHA3-512withECDSAinP1363Format",
                  "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA3_512wECDSAP1363");
        }

        /* RSA-PSS Signature support.
         * Include Bouncy Castle and other alias styles for compatibility */
        if (FeatureDetect.RsaEnabled()) {

            if (FeatureDetect.Sha224Enabled()) {
                put("Signature.SHA224withRSA/PSS",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA224wRSAPSS");
                put("Alg.Alias.Signature.SHA224withRSAandMGF1", "SHA224withRSA/PSS");
                put("Alg.Alias.Signature.SHA224WITHRSAANDMGF1", "SHA224withRSA/PSS");
            }
            if (FeatureDetect.Sha256Enabled()) {
                /* Primary RSA-PSS algorithm (SunJCE style), uses SHA-256 */
                put("Signature.RSASSA-PSS",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcRSAPSS");
                put("Signature.SHA256withRSA/PSS",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA256wRSAPSS");
                put("Alg.Alias.Signature.SHA256withRSAandMGF1", "SHA256withRSA/PSS");
                put("Alg.Alias.Signature.SHA256WITHRSAANDMGF1", "SHA256withRSA/PSS");
            }
            if (FeatureDetect.Sha384Enabled()) {
                put("Signature.SHA384withRSA/PSS",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA384wRSAPSS");
                put("Alg.Alias.Signature.SHA384withRSAandMGF1", "SHA384withRSA/PSS");
                put("Alg.Alias.Signature.SHA384WITHRSAANDMGF1", "SHA384withRSA/PSS");
            }
            if (FeatureDetect.Sha512Enabled()) {
                put("Signature.SHA512withRSA/PSS",
                    "com.wolfssl.provider.jce.WolfCryptSignature$wcSHA512wRSAPSS");
                put("Alg.Alias.Signature.SHA512withRSAandMGF1", "SHA512withRSA/PSS");
                put("Alg.Alias.Signature.SHA512WITHRSAANDMGF1", "SHA512withRSA/PSS");
            }

            /* OID mappings */
            put("Alg.Alias.Signature.1.2.840.113549.1.1.10", "RSASSA-PSS");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.10", "RSASSA-PSS");

            /* Algorithm parameters */
            put("AlgorithmParameters.RSASSA-PSS",
                "com.wolfssl.provider.jce.WolfCryptPssParameters");
            put("Alg.Alias.AlgorithmParameters.1.2.840.113549.1.1.10", "RSASSA-PSS");
            put("Alg.Alias.AlgorithmParameters.OID.1.2.840.113549.1.1.10", "RSASSA-PSS");
        }

        /* ML-DSA (FIPS 204) Signature support */
        if (FeatureDetect.MlDsaEnabled()) {
            /* Generic alias accepts any of the three ML-DSA parameter sets */
            put("Signature.ML-DSA",
                "com.wolfssl.provider.jce.WolfCryptMlDsaSignature$wcMlDsa");

            /* Per-level aliases */
            put("Signature.ML-DSA-44",
                "com.wolfssl.provider.jce.WolfCryptMlDsaSignature$wcMlDsa44");
            put("Signature.ML-DSA-65",
                "com.wolfssl.provider.jce.WolfCryptMlDsaSignature$wcMlDsa65");
            put("Signature.ML-DSA-87",
                "com.wolfssl.provider.jce.WolfCryptMlDsaSignature$wcMlDsa87");

            /* OID aliases (FIPS 204: 2.16.840.1.101.3.4.3.17/18/19) */
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.17", "ML-DSA-44");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.17", "ML-DSA-44");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.18", "ML-DSA-65");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.18", "ML-DSA-65");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.19", "ML-DSA-87");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.19", "ML-DSA-87");
        }

        /* XMSS / XMSS^MT (RFC 8391) Signature support (verify-only). A single
         * implementation handles both, the parameter set is derived from the
         * imported public key. */
        if (FeatureDetect.XmssEnabled()) {
            put("Signature.XMSS",
                "com.wolfssl.provider.jce.WolfCryptXmssSignature");
            put("Signature.XMSSMT",
                "com.wolfssl.provider.jce.WolfCryptXmssSignature");

            /* OID aliases (RFC 9802: id-alg-xmss-hashsig 1.3.6.1.5.5.7.6.34,
             * id-alg-xmssmt-hashsig 1.3.6.1.5.5.7.6.35) */
            put("Alg.Alias.Signature.1.3.6.1.5.5.7.6.34", "XMSS");
            put("Alg.Alias.Signature.OID.1.3.6.1.5.5.7.6.34", "XMSS");
            put("Alg.Alias.Signature.1.3.6.1.5.5.7.6.35", "XMSSMT");
            put("Alg.Alias.Signature.OID.1.3.6.1.5.5.7.6.35", "XMSSMT");
        }

        /* LMS / HSS (RFC 8554) Signature support (verify-only) */
        if (FeatureDetect.LmsEnabled()) {
            put("Signature.LMS",
                "com.wolfssl.provider.jce.WolfCryptLmsSignature");
            put("Alg.Alias.Signature.HSS/LMS", "LMS");
            put("Alg.Alias.Signature.1.2.840.113549.1.9.16.3.17", "LMS");
            put("Alg.Alias.Signature.OID.1.2.840.113549.1.9.16.3.17", "LMS");
        }

        /* SLH-DSA (FIPS 205) Signature support */
        if (FeatureDetect.SlhDsaEnabled()) {
            /* Generic alias accepts any of the SLH-DSA parameter sets */
            put("Signature.SLH-DSA",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsa");

            /* Per-parameter-set aliases */
            put("Signature.SLH-DSA-SHA2-128s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaSha2_128s");
            put("Signature.SLH-DSA-SHA2-128f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaSha2_128f");
            put("Signature.SLH-DSA-SHA2-192s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaSha2_192s");
            put("Signature.SLH-DSA-SHA2-192f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaSha2_192f");
            put("Signature.SLH-DSA-SHA2-256s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaSha2_256s");
            put("Signature.SLH-DSA-SHA2-256f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaSha2_256f");
            put("Signature.SLH-DSA-SHAKE-128s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaShake_128s");
            put("Signature.SLH-DSA-SHAKE-128f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaShake_128f");
            put("Signature.SLH-DSA-SHAKE-192s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaShake_192s");
            put("Signature.SLH-DSA-SHAKE-192f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaShake_192f");
            put("Signature.SLH-DSA-SHAKE-256s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaShake_256s");
            put("Signature.SLH-DSA-SHAKE-256f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcSlhDsaShake_256f");

            /* OID aliases (FIPS 205: 2.16.840.1.101.3.4.3.20-.31) */
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.20",
                "SLH-DSA-SHA2-128s");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.20",
                "SLH-DSA-SHA2-128s");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.21",
                "SLH-DSA-SHA2-128f");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.21",
                "SLH-DSA-SHA2-128f");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.22",
                "SLH-DSA-SHA2-192s");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.22",
                "SLH-DSA-SHA2-192s");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.23",
                "SLH-DSA-SHA2-192f");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.23",
                "SLH-DSA-SHA2-192f");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.24",
                "SLH-DSA-SHA2-256s");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.24",
                "SLH-DSA-SHA2-256s");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.25",
                "SLH-DSA-SHA2-256f");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.25",
                "SLH-DSA-SHA2-256f");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.26",
                "SLH-DSA-SHAKE-128s");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.26",
                "SLH-DSA-SHAKE-128s");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.27",
                "SLH-DSA-SHAKE-128f");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.27",
                "SLH-DSA-SHAKE-128f");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.28",
                "SLH-DSA-SHAKE-192s");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.28",
                "SLH-DSA-SHAKE-192s");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.29",
                "SLH-DSA-SHAKE-192f");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.29",
                "SLH-DSA-SHAKE-192f");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.30",
                "SLH-DSA-SHAKE-256s");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.30",
                "SLH-DSA-SHAKE-256s");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.31",
                "SLH-DSA-SHAKE-256f");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.31",
                "SLH-DSA-SHAKE-256f");

            /* HashSLH-DSA (pre-hash, FIPS 205 Section 10.2.2). Keys are
             * regular SLH-DSA keys, only the signature algorithm differs,
             * so only Signature services are registered. */
            put("Signature.HASH-SLH-DSA",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsa");
            put("Signature.SLH-DSA-SHA2-128s-WITH-SHA256",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaSha2_128sWithSha256");
            put("Signature.SLH-DSA-SHA2-128f-WITH-SHA256",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaSha2_128fWithSha256");
            put("Signature.SLH-DSA-SHA2-192s-WITH-SHA512",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaSha2_192sWithSha512");
            put("Signature.SLH-DSA-SHA2-192f-WITH-SHA512",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaSha2_192fWithSha512");
            put("Signature.SLH-DSA-SHA2-256s-WITH-SHA512",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaSha2_256sWithSha512");
            put("Signature.SLH-DSA-SHA2-256f-WITH-SHA512",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaSha2_256fWithSha512");
            put("Signature.SLH-DSA-SHAKE-128s-WITH-SHAKE128",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaShake_128sWithShake128");
            put("Signature.SLH-DSA-SHAKE-128f-WITH-SHAKE128",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaShake_128fWithShake128");
            put("Signature.SLH-DSA-SHAKE-192s-WITH-SHAKE256",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaShake_192sWithShake256");
            put("Signature.SLH-DSA-SHAKE-192f-WITH-SHAKE256",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaShake_192fWithShake256");
            put("Signature.SLH-DSA-SHAKE-256s-WITH-SHAKE256",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaShake_256sWithShake256");
            put("Signature.SLH-DSA-SHAKE-256f-WITH-SHAKE256",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaSignature$wcHashSlhDsaShake_256fWithShake256");

            /* HashSLH-DSA OID aliases (FIPS 205: 2.16.840.1.101.3.4.3.35-.46) */
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.35",
                "SLH-DSA-SHA2-128s-WITH-SHA256");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.35",
                "SLH-DSA-SHA2-128s-WITH-SHA256");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.36",
                "SLH-DSA-SHA2-128f-WITH-SHA256");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.36",
                "SLH-DSA-SHA2-128f-WITH-SHA256");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.37",
                "SLH-DSA-SHA2-192s-WITH-SHA512");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.37",
                "SLH-DSA-SHA2-192s-WITH-SHA512");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.38",
                "SLH-DSA-SHA2-192f-WITH-SHA512");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.38",
                "SLH-DSA-SHA2-192f-WITH-SHA512");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.39",
                "SLH-DSA-SHA2-256s-WITH-SHA512");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.39",
                "SLH-DSA-SHA2-256s-WITH-SHA512");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.40",
                "SLH-DSA-SHA2-256f-WITH-SHA512");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.40",
                "SLH-DSA-SHA2-256f-WITH-SHA512");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.41",
                "SLH-DSA-SHAKE-128s-WITH-SHAKE128");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.41",
                "SLH-DSA-SHAKE-128s-WITH-SHAKE128");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.42",
                "SLH-DSA-SHAKE-128f-WITH-SHAKE128");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.42",
                "SLH-DSA-SHAKE-128f-WITH-SHAKE128");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.43",
                "SLH-DSA-SHAKE-192s-WITH-SHAKE256");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.43",
                "SLH-DSA-SHAKE-192s-WITH-SHAKE256");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.44",
                "SLH-DSA-SHAKE-192f-WITH-SHAKE256");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.44",
                "SLH-DSA-SHAKE-192f-WITH-SHAKE256");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.45",
                "SLH-DSA-SHAKE-256s-WITH-SHAKE256");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.45",
                "SLH-DSA-SHAKE-256s-WITH-SHAKE256");
            put("Alg.Alias.Signature.2.16.840.1.101.3.4.3.46",
                "SLH-DSA-SHAKE-256f-WITH-SHAKE256");
            put("Alg.Alias.Signature.OID.2.16.840.1.101.3.4.3.46",
                "SLH-DSA-SHAKE-256f-WITH-SHAKE256");
        }

        /* Mac */
        if (FeatureDetect.HmacMd5Enabled()) {
            put("Mac.HmacMD5",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacMD5");
        }
        if (FeatureDetect.HmacShaEnabled()) {
            put("Mac.HmacSHA1",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA1");
            /* HMAC-SHA1 OID */
            put("Alg.Alias.Mac.1.2.840.113549.2.7", "HmacSHA1");
        }
        if (FeatureDetect.HmacSha224Enabled()) {
            put("Mac.HmacSHA224",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA224");
            /* HMAC-SHA224 OID */
            put("Alg.Alias.Mac.1.2.840.113549.2.8", "HmacSHA224");
        }
        if (FeatureDetect.HmacSha256Enabled()) {
            put("Mac.HmacSHA256",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA256");
            /* HMAC-SHA256 OID */
            put("Alg.Alias.Mac.1.2.840.113549.2.9", "HmacSHA256");
        }
        if (FeatureDetect.HmacSha384Enabled()) {
            put("Mac.HmacSHA384",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA384");
            /* HMAC-SHA384 OID */
            put("Alg.Alias.Mac.1.2.840.113549.2.10", "HmacSHA384");
        }
        if (FeatureDetect.HmacSha512Enabled()) {
            put("Mac.HmacSHA512",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA512");
            /* HMAC-SHA512 OID */
            put("Alg.Alias.Mac.1.2.840.113549.2.11", "HmacSHA512");
        }
        if (FeatureDetect.HmacSha3_224Enabled()) {
            put("Mac.HmacSHA3-224",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA3_224");
        }
        if (FeatureDetect.HmacSha3_256Enabled()) {
            put("Mac.HmacSHA3-256",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA3_256");
        }
        if (FeatureDetect.HmacSha3_384Enabled()) {
            put("Mac.HmacSHA3-384",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA3_384");
        }
        if (FeatureDetect.HmacSha3_512Enabled()) {
            put("Mac.HmacSHA3-512",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcHmacSHA3_512");
        }
        if (FeatureDetect.AesCmacEnabled()) {
            put("Mac.AESCMAC",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcAesCmac");
            put("Alg.Alias.Mac.AES-CMAC", "AESCMAC");
        }

        if (FeatureDetect.AesGmacEnabled()) {
            put("Mac.AESGMAC",
                    "com.wolfssl.provider.jce.WolfCryptMac$wcAesGmac");
            put("Alg.Alias.Mac.AES-GMAC", "AESGMAC");
        }

        /* Cipher */
        if (FeatureDetect.AesCbcEnabled()) {
            put("Cipher.AES/CBC/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCBCNoPadding");
            put("Cipher.AES/CBC/PKCS5Padding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCBCPKCS5Padding");

            /* NIST AES-CBC algorithm aliases with key sizes */
            put("Alg.Alias.Cipher.AES_128/CBC/NoPadding",
                "AES/CBC/NoPadding");
            put("Alg.Alias.Cipher.AES_192/CBC/NoPadding",
                "AES/CBC/NoPadding");
            put("Alg.Alias.Cipher.AES_256/CBC/NoPadding",
                "AES/CBC/NoPadding");

            /* NIST AES-CBC OID aliases */
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.2",
                "AES/CBC/NoPadding");
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.22",
                "AES/CBC/NoPadding");
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.42",
                "AES/CBC/NoPadding");
        }
        if (FeatureDetect.AesEcbEnabled()) {
            put("Cipher.AES/ECB/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESECBNoPadding");
            put("Cipher.AES/ECB/PKCS5Padding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESECBPKCS5Padding");

            /* SunJCE and Bouncy Castle alias AES to AES/ECB/PKCS5Padding,
             * we do the same here for compatibility. */
            put("Cipher.AES",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESECBPKCS5Padding");
            put("Cipher.AES SupportedModes", "ECB");
            put("Cipher.AES SupportedPaddings", "NoPadding, PKCS5Padding");

            /* NIST AES-ECB algorithm aliases with key sizes */
            put("Alg.Alias.Cipher.AES_128/ECB/NoPadding",
                "AES/ECB/NoPadding");
            put("Alg.Alias.Cipher.AES_192/ECB/NoPadding",
                "AES/ECB/NoPadding");
            put("Alg.Alias.Cipher.AES_256/ECB/NoPadding",
                "AES/ECB/NoPadding");

            /* NIST AES-ECB OID aliases */
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.1",
                "AES/ECB/NoPadding");
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.21",
                "AES/ECB/NoPadding");
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.41",
                "AES/ECB/NoPadding");
        }
        if (FeatureDetect.AesCtrEnabled()) {
            put("Cipher.AES/CTR/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCTRNoPadding");
        }
        if (FeatureDetect.AesOfbEnabled()) {
            put("Cipher.AES/OFB/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESOFBNoPadding");

            /* NIST AES-OFB algorithm aliases with key sizes */
            put("Alg.Alias.Cipher.AES_128/OFB/NoPadding",
                "AES/OFB/NoPadding");
            put("Alg.Alias.Cipher.AES_192/OFB/NoPadding",
                "AES/OFB/NoPadding");
            put("Alg.Alias.Cipher.AES_256/OFB/NoPadding",
                "AES/OFB/NoPadding");

            /* NIST AES-OFB OID aliases */
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.3",
                "AES/OFB/NoPadding");
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.23",
                "AES/OFB/NoPadding");
            put("Alg.Alias.Cipher.2.16.840.1.101.3.4.1.43",
                "AES/OFB/NoPadding");
        }
        if (FeatureDetect.AesGcmEnabled()) {
            put("Cipher.AES/GCM/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESGCMNoPadding");

            /* GCM Algorithm Parameters */
            put("AlgorithmParameters.GCM",
                "com.wolfssl.provider.jce.WolfCryptGcmParameters");
            /* Alias for AES-GCM */
            put("Alg.Alias.AlgorithmParameters.AES-GCM", "GCM");
        }
        if (FeatureDetect.AesCcmEnabled()) {
            put("Cipher.AES/CCM/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCCMNoPadding");
        }
        if (FeatureDetect.AesCtsEnabled()) {
            put("Cipher.AES/CTS/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcAESCTSNoPadding");
        }

        if (FeatureDetect.Des3Enabled()) {
            put("Cipher.DESede/CBC/NoPadding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcDESedeCBCNoPadding");
        }

        if (FeatureDetect.RsaEnabled()) {
            put("Cipher.RSA",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcRSAECBPKCS1Padding");
            put("Cipher.RSA/ECB/PKCS1Padding",
                "com.wolfssl.provider.jce.WolfCryptCipher$wcRSAECBPKCS1Padding");

            if (FeatureDetect.Sha256Enabled() &&
                FeatureDetect.RsaOaepEnabled()) {
                put("Cipher.RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                    "com.wolfssl.provider.jce.WolfCryptCipher$" +
                    "wcRSAECBOAEPSHA256Padding");
                put("Alg.Alias.Cipher.RSA/ECB/OAEPWithSHA256AndMGF1Padding",
                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            }

            if (FeatureDetect.ShaEnabled() &&
                FeatureDetect.RsaOaepEnabled()) {
                put("Cipher.RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                    "com.wolfssl.provider.jce.WolfCryptCipher$" +
                    "wcRSAECBOAEPSHA1Padding");
                put("Alg.Alias.Cipher.RSA/ECB/OAEPWithSHA1AndMGF1Padding",
                    "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            }
        }

        /* KeyAgreement */
        if (FeatureDetect.DhEnabled()) {
            put("KeyAgreement.DiffieHellman",
                "com.wolfssl.provider.jce.WolfCryptKeyAgreement$wcDH");
            put("Alg.Alias.KeyAgreement.DH", "DiffieHellman");

            /* DH AlgorithmParameters */
            put("AlgorithmParameters.DH",
                "com.wolfssl.provider.jce.WolfCryptDhParameters");
            put("Alg.Alias.AlgorithmParameters.DiffieHellman", "DH");

            /* DH AlgorithmParameterGenerator */
            put("AlgorithmParameterGenerator.DH",
                "com.wolfssl.provider.jce.WolfCryptDhParameterGenerator");
            put("Alg.Alias.AlgorithmParameterGenerator.DiffieHellman", "DH");
        }
        if (FeatureDetect.EccDheEnabled()) {
            put("KeyAgreement.ECDH",
                "com.wolfssl.provider.jce.WolfCryptKeyAgreement$wcECDH");
        }

        /* KeyGenerator */
        if (FeatureDetect.AesEnabled()) {
            put("KeyGenerator.AES",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcAESKeyGenerator");

            /* AES Algorithm Parameters */
            put("AlgorithmParameters.AES",
                "com.wolfssl.provider.jce.WolfCryptAesParameters");
        }
        if (FeatureDetect.HmacShaEnabled()) {
            put("KeyGenerator.HmacSHA1",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha1KeyGenerator");
        }
        if (FeatureDetect.HmacSha224Enabled()) {
            put("KeyGenerator.HmacSHA224",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha224KeyGenerator");
        }
        if (FeatureDetect.HmacSha256Enabled()) {
            put("KeyGenerator.HmacSHA256",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha256KeyGenerator");
        }
        if (FeatureDetect.HmacSha384Enabled()) {
            put("KeyGenerator.HmacSHA384",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha384KeyGenerator");
        }
        if (FeatureDetect.HmacSha512Enabled()) {
            put("KeyGenerator.HmacSHA512",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha512KeyGenerator");
        }
        if (FeatureDetect.HmacSha3_224Enabled()) {
            put("KeyGenerator.HmacSHA3-224",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha3_224KeyGenerator");
        }
        if (FeatureDetect.HmacSha3_256Enabled()) {
            put("KeyGenerator.HmacSHA3-256",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha3_256KeyGenerator");
        }
        if (FeatureDetect.HmacSha3_384Enabled()) {
            put("KeyGenerator.HmacSHA3-384",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha3_384KeyGenerator");
        }
        if (FeatureDetect.HmacSha3_512Enabled()) {
            put("KeyGenerator.HmacSHA3-512",
                "com.wolfssl.provider.jce.WolfCryptKeyGenerator$wcHMACSha3_512KeyGenerator");
        }

        /* KeyPairGenerator */
        if (FeatureDetect.RsaKeyGenEnabled()) {
            put("KeyPairGenerator.RSA",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenRSA");
            put("KeyPairGenerator.RSASSA-PSS",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenRSAPSS");
            put("Alg.Alias.KeyPairGenerator.1.2.840.113549.1.1.10", "RSASSA-PSS");
        }
        if (FeatureDetect.EccKeyGenEnabled()) {
            put("KeyPairGenerator.EC",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenECC");
            put("Alg.Alias.KeyPairGenerator.1.2.840.10045.2.1", "EC");
        }
        if (FeatureDetect.DhEnabled()) {
            put("KeyPairGenerator.DH",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenDH");
            put("Alg.Alias.KeyPairGenerator.DiffieHellman", "DH");
        }
        if (FeatureDetect.MlDsaEnabled()) {
            /* Generic alias: defaults to ML-DSA-65, level overridable via
             * initialize(NamedParameterSpec) / WolfPQCParameterSpec. */
            put("KeyPairGenerator.ML-DSA",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlDsa");

            /* Per-level aliases */
            put("KeyPairGenerator.ML-DSA-44",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlDsa44");
            put("KeyPairGenerator.ML-DSA-65",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlDsa65");
            put("KeyPairGenerator.ML-DSA-87",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlDsa87");

            /* OID aliases */
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.17",
                "ML-DSA-44");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.17",
                "ML-DSA-44");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.18",
                "ML-DSA-65");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.18",
                "ML-DSA-65");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.19",
                "ML-DSA-87");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.19",
                "ML-DSA-87");
        }
        if (FeatureDetect.SlhDsaKeyGenEnabled()) {
            /* Generic alias: defaults to SLH-DSA-SHA2-128f, parameter set
             * overridable via initialize(NamedParameterSpec). */
            put("KeyPairGenerator.SLH-DSA",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsa");

            put("KeyPairGenerator.SLH-DSA-SHA2-128s",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaSha2_128s");
            put("KeyPairGenerator.SLH-DSA-SHA2-128f",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaSha2_128f");
            put("KeyPairGenerator.SLH-DSA-SHA2-192s",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaSha2_192s");
            put("KeyPairGenerator.SLH-DSA-SHA2-192f",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaSha2_192f");
            put("KeyPairGenerator.SLH-DSA-SHA2-256s",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaSha2_256s");
            put("KeyPairGenerator.SLH-DSA-SHA2-256f",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaSha2_256f");
            put("KeyPairGenerator.SLH-DSA-SHAKE-128s",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaShake_128s");
            put("KeyPairGenerator.SLH-DSA-SHAKE-128f",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaShake_128f");
            put("KeyPairGenerator.SLH-DSA-SHAKE-192s",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaShake_192s");
            put("KeyPairGenerator.SLH-DSA-SHAKE-192f",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaShake_192f");
            put("KeyPairGenerator.SLH-DSA-SHAKE-256s",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaShake_256s");
            put("KeyPairGenerator.SLH-DSA-SHAKE-256f",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenSlhDsaShake_256f");

            /* OID aliases (FIPS 205: 2.16.840.1.101.3.4.3.20-.31) */
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.20",
                "SLH-DSA-SHA2-128s");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.20",
                "SLH-DSA-SHA2-128s");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.21",
                "SLH-DSA-SHA2-128f");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.21",
                "SLH-DSA-SHA2-128f");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.22",
                "SLH-DSA-SHA2-192s");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.22",
                "SLH-DSA-SHA2-192s");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.23",
                "SLH-DSA-SHA2-192f");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.23",
                "SLH-DSA-SHA2-192f");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.24",
                "SLH-DSA-SHA2-256s");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.24",
                "SLH-DSA-SHA2-256s");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.25",
                "SLH-DSA-SHA2-256f");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.25",
                "SLH-DSA-SHA2-256f");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.26",
                "SLH-DSA-SHAKE-128s");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.26",
                "SLH-DSA-SHAKE-128s");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.27",
                "SLH-DSA-SHAKE-128f");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.27",
                "SLH-DSA-SHAKE-128f");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.28",
                "SLH-DSA-SHAKE-192s");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.28",
                "SLH-DSA-SHAKE-192s");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.29",
                "SLH-DSA-SHAKE-192f");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.29",
                "SLH-DSA-SHAKE-192f");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.30",
                "SLH-DSA-SHAKE-256s");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.30",
                "SLH-DSA-SHAKE-256s");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.3.31",
                "SLH-DSA-SHAKE-256f");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.3.31",
                "SLH-DSA-SHAKE-256f");
        }
        if (FeatureDetect.MlKemEnabled()) {
            /* Generic alias: defaults to ML-KEM-768 */
            put("KeyPairGenerator.ML-KEM",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlKem");
            put("KeyPairGenerator.ML-KEM-512",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlKem512");
            put("KeyPairGenerator.ML-KEM-768",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlKem768");
            put("KeyPairGenerator.ML-KEM-1024",
                "com.wolfssl.provider.jce.WolfCryptKeyPairGenerator$wcKeyPairGenMlKem1024");
            /* OID aliases (RFC 9935, arc 2.16.840.1.101.3.4.4) */
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.4.1",
                "ML-KEM-512");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.4.1",
                "ML-KEM-512");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.4.2",
                "ML-KEM-768");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.4.2",
                "ML-KEM-768");
            put("Alg.Alias.KeyPairGenerator.2.16.840.1.101.3.4.4.3",
                "ML-KEM-1024");
            put("Alg.Alias.KeyPairGenerator.OID.2.16.840.1.101.3.4.4.3",
                "ML-KEM-1024");
        }


        /* CertPathValidator */
        put("CertPathValidator.PKIX",
                "com.wolfssl.provider.jce.WolfCryptPKIXCertPathValidator");

        /* CertPathBuilder requires wolfSSL 5.8.0 or later */
        if (WolfSSLX509StoreCtx.isSupported()) {
            put("CertPathBuilder.PKIX",
                    "com.wolfssl.provider.jce.WolfCryptPKIXCertPathBuilder");
        }

        /* SecretKeyFactory */
        if (FeatureDetect.Pbkdf2Enabled()) {
            if (FeatureDetect.HmacShaEnabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA1",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA1");
            }
            if (FeatureDetect.HmacSha224Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA224",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA224");
            }
            if (FeatureDetect.HmacSha256Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA256",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA256");
            }
            if (FeatureDetect.HmacSha384Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA384",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA384");
            }
            if (FeatureDetect.HmacSha512Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA512",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA512");
            }
            if (FeatureDetect.HmacSha3_224Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-224",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_224");
            }
            if (FeatureDetect.HmacSha3_256Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-256",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_256");
            }
            if (FeatureDetect.HmacSha3_384Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-384",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_384");
            }
            if (FeatureDetect.HmacSha3_512Enabled()) {
                put("SecretKeyFactory.PBKDF2WithHmacSHA3-512",
                    "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcPBKDF2WithHmacSHA3_512");
            }
        }
        if (FeatureDetect.AesEnabled()) {
            put("SecretKeyFactory.AES",
                "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcAES");
        }
        if (FeatureDetect.Des3Enabled() && !Fips.enabled) {
            put("SecretKeyFactory.DESede",
                "com.wolfssl.provider.jce.WolfCryptSecretKeyFactory$wcDESede");
        }

        /* KeyFactory */
        if (FeatureDetect.EccEnabled()) {
            put("KeyFactory.EC",
                "com.wolfssl.provider.jce.WolfCryptECKeyFactory");
            put("Alg.Alias.KeyFactory.1.2.840.10045.2.1", "EC");
            put("Alg.Alias.KeyFactory.OID.1.2.840.10045.2.1", "EC");
        }
        if (FeatureDetect.DhEnabled()) {
            put("KeyFactory.DH",
                "com.wolfssl.provider.jce.WolfCryptDHKeyFactory");
            put("Alg.Alias.KeyFactory.DiffieHellman", "DH");
            put("Alg.Alias.KeyFactory.1.2.840.113549.1.3.1", "DH");
        }
        /* RSA KeyFactory requires WOLFSSL_PUBLIC_MP for CRT key import */
        if (FeatureDetect.RsaEnabled() &&
            FeatureDetect.WolfSSLPublicMpEnabled()) {
            put("KeyFactory.RSA",
                "com.wolfssl.provider.jce.WolfCryptRSAKeyFactory");
            put("Alg.Alias.KeyFactory.1.2.840.113549.1.1.1", "RSA");
        }
        if (FeatureDetect.MlDsaEnabled()) {
            put("KeyFactory.ML-DSA",
                "com.wolfssl.provider.jce.WolfCryptMlDsaKeyFactory");
            /* Per-set factories reject keys of a different parameter set,
             * matching JDK 24+ SunJCE NamedKeyFactory behavior */
            put("KeyFactory.ML-DSA-44",
                "com.wolfssl.provider.jce.WolfCryptMlDsaKeyFactory$wcMlDsa44");
            put("KeyFactory.ML-DSA-65",
                "com.wolfssl.provider.jce.WolfCryptMlDsaKeyFactory$wcMlDsa65");
            put("KeyFactory.ML-DSA-87",
                "com.wolfssl.provider.jce.WolfCryptMlDsaKeyFactory$wcMlDsa87");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.17", "ML-DSA-44");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.17",
                "ML-DSA-44");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.18", "ML-DSA-65");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.18",
                "ML-DSA-65");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.19", "ML-DSA-87");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.19",
                "ML-DSA-87");
        }
        if (FeatureDetect.SlhDsaEnabled()) {
            put("KeyFactory.SLH-DSA",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory");

            put("KeyFactory.SLH-DSA-SHA2-128s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaSha2_128s");
            put("KeyFactory.SLH-DSA-SHA2-128f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaSha2_128f");
            put("KeyFactory.SLH-DSA-SHA2-192s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaSha2_192s");
            put("KeyFactory.SLH-DSA-SHA2-192f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaSha2_192f");
            put("KeyFactory.SLH-DSA-SHA2-256s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaSha2_256s");
            put("KeyFactory.SLH-DSA-SHA2-256f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaSha2_256f");
            put("KeyFactory.SLH-DSA-SHAKE-128s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaShake_128s");
            put("KeyFactory.SLH-DSA-SHAKE-128f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaShake_128f");
            put("KeyFactory.SLH-DSA-SHAKE-192s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaShake_192s");
            put("KeyFactory.SLH-DSA-SHAKE-192f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaShake_192f");
            put("KeyFactory.SLH-DSA-SHAKE-256s",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaShake_256s");
            put("KeyFactory.SLH-DSA-SHAKE-256f",
                "com.wolfssl.provider.jce.WolfCryptSlhDsaKeyFactory$wcSlhDsaShake_256f");

            /* OID aliases (FIPS 205: 2.16.840.1.101.3.4.3.20-.31) */
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.20",
                "SLH-DSA-SHA2-128s");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.20",
                "SLH-DSA-SHA2-128s");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.21",
                "SLH-DSA-SHA2-128f");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.21",
                "SLH-DSA-SHA2-128f");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.22",
                "SLH-DSA-SHA2-192s");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.22",
                "SLH-DSA-SHA2-192s");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.23",
                "SLH-DSA-SHA2-192f");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.23",
                "SLH-DSA-SHA2-192f");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.24",
                "SLH-DSA-SHA2-256s");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.24",
                "SLH-DSA-SHA2-256s");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.25",
                "SLH-DSA-SHA2-256f");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.25",
                "SLH-DSA-SHA2-256f");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.26",
                "SLH-DSA-SHAKE-128s");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.26",
                "SLH-DSA-SHAKE-128s");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.27",
                "SLH-DSA-SHAKE-128f");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.27",
                "SLH-DSA-SHAKE-128f");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.28",
                "SLH-DSA-SHAKE-192s");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.28",
                "SLH-DSA-SHAKE-192s");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.29",
                "SLH-DSA-SHAKE-192f");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.29",
                "SLH-DSA-SHAKE-192f");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.30",
                "SLH-DSA-SHAKE-256s");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.30",
                "SLH-DSA-SHAKE-256s");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.3.31",
                "SLH-DSA-SHAKE-256f");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.3.31",
                "SLH-DSA-SHAKE-256f");
        }
        if (FeatureDetect.MlKemEnabled()) {
            put("KeyFactory.ML-KEM",
                "com.wolfssl.provider.jce.WolfCryptMlKemKeyFactory");
            put("KeyFactory.ML-KEM-512",
                "com.wolfssl.provider.jce.WolfCryptMlKemKeyFactory$wcMlKem512");
            put("KeyFactory.ML-KEM-768",
                "com.wolfssl.provider.jce.WolfCryptMlKemKeyFactory$wcMlKem768");
            put("KeyFactory.ML-KEM-1024",
                "com.wolfssl.provider.jce.WolfCryptMlKemKeyFactory$wcMlKem1024");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.4.1", "ML-KEM-512");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.4.1",
                "ML-KEM-512");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.4.2", "ML-KEM-768");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.4.2",
                "ML-KEM-768");
            put("Alg.Alias.KeyFactory.2.16.840.1.101.3.4.4.3", "ML-KEM-1024");
            put("Alg.Alias.KeyFactory.OID.2.16.840.1.101.3.4.4.3",
                "ML-KEM-1024");
        }

        /* KEM (javax.crypto.KEM, JDK 21+). The KEMSpi implementation is only
         * compiled into the JAR when built on JDK 21 or later, so probe for
         * both the JDK SPI and our class before registering. On Java 8 this
         * block is skipped and no KEM service is advertised. */
        if (FeatureDetect.MlKemEnabled()) {
            try {
                Class.forName("javax.crypto.KEMSpi");
                Class.forName("com.wolfssl.provider.jce.WolfCryptMlKemKem");
                put("KEM.ML-KEM",
                    "com.wolfssl.provider.jce.WolfCryptMlKemKem");
                put("KEM.ML-KEM-512",
                    "com.wolfssl.provider.jce.WolfCryptMlKemKem$wcMlKem512");
                put("KEM.ML-KEM-768",
                    "com.wolfssl.provider.jce.WolfCryptMlKemKem$wcMlKem768");
                put("KEM.ML-KEM-1024",
                    "com.wolfssl.provider.jce.WolfCryptMlKemKem$wcMlKem1024");
                put("Alg.Alias.KEM.2.16.840.1.101.3.4.4.1", "ML-KEM-512");
                put("Alg.Alias.KEM.OID.2.16.840.1.101.3.4.4.1", "ML-KEM-512");
                put("Alg.Alias.KEM.2.16.840.1.101.3.4.4.2", "ML-KEM-768");
                put("Alg.Alias.KEM.OID.2.16.840.1.101.3.4.4.2", "ML-KEM-768");
                put("Alg.Alias.KEM.2.16.840.1.101.3.4.4.3", "ML-KEM-1024");
                put("Alg.Alias.KEM.OID.2.16.840.1.101.3.4.4.3", "ML-KEM-1024");
            } catch (Throwable t) {
                /* JDK < 21 or KEMSpi class excluded from build, skip KEM */
            }
        }

        /* XMSS / XMSS^MT (RFC 8391) KeyFactory (verify-only). X.509 public-key
         * handling only, private keys are not supported. A single
         * implementation handles both, the parameter set is derived from the
         * encoded public key. */
        if (FeatureDetect.XmssEnabled()) {
            put("KeyFactory.XMSS",
                "com.wolfssl.provider.jce.WolfCryptXmssKeyFactory");
            put("KeyFactory.XMSSMT",
                "com.wolfssl.provider.jce.WolfCryptXmssKeyFactory");

            /* OID aliases (RFC 9802: id-alg-xmss-hashsig 1.3.6.1.5.5.7.6.34,
             * id-alg-xmssmt-hashsig 1.3.6.1.5.5.7.6.35) */
            put("Alg.Alias.KeyFactory.1.3.6.1.5.5.7.6.34", "XMSS");
            put("Alg.Alias.KeyFactory.OID.1.3.6.1.5.5.7.6.34", "XMSS");
            put("Alg.Alias.KeyFactory.1.3.6.1.5.5.7.6.35", "XMSSMT");
            put("Alg.Alias.KeyFactory.OID.1.3.6.1.5.5.7.6.35", "XMSSMT");
        }

        /* LMS / HSS (RFC 8554) KeyFactory (verify-only). X.509 public-key
         * handling only, private keys are not supported. */
        if (FeatureDetect.LmsEnabled()) {
            put("KeyFactory.LMS",
                "com.wolfssl.provider.jce.WolfCryptLmsKeyFactory");
            put("Alg.Alias.KeyFactory.HSS/LMS", "LMS");
            put("Alg.Alias.KeyFactory.1.2.840.113549.1.9.16.3.17", "LMS");
            put("Alg.Alias.KeyFactory.OID.1.2.840.113549.1.9.16.3.17", "LMS");
        }

        /* KeyStore */
        put("KeyStore.WKS",
                "com.wolfssl.provider.jce.WolfSSLKeyStore");

        /* Fake mapping of JKS to WKS type. Use with caution! This is
         * usually used when FIPS compliance is needed but code cannot be
         * changed that creates a JKS KeyStore object type. Any files loaded
         * into this fake JKS KeyStore MUST be of actual type WKS or failures
         * will happen. Remove service first here in case of refresh. */
        remove("KeyStore.JKS");
        mapJksToWks = Security.getProperty("wolfjce.mapJKStoWKS");
        if (mapJksToWks != null && !mapJksToWks.isEmpty() &&
            mapJksToWks.equalsIgnoreCase("true")) {
            put("KeyStore.JKS",
                "com.wolfssl.provider.jce.WolfSSLKeyStore");
        }

        /* Fake mapping of PKCS12 to WKS type. Use with caution! This is
         * usually used when FIPS compliance is needed but code cannot be
         * changed that creates a JKS KeyStore object type. Any files loaded
         * into this fake JKS KeyStore MUST be of actual type WKS or failures
         * will happen. Remove service first here in case of refresh. */
        remove("KeyStore.PKCS12");
        mapPkcs12ToWks = Security.getProperty("wolfjce.mapPKCS12toWKS");
        if (mapPkcs12ToWks != null && !mapPkcs12ToWks.isEmpty() &&
            mapPkcs12ToWks.equalsIgnoreCase("true")) {
            put("KeyStore.PKCS12",
                "com.wolfssl.provider.jce.WolfSSLKeyStore");
        }

        /* Unregister PQC parameter sets not compiled into native wolfSSL */
        removeUnsupportedPQCParamSets();

        /* If using a FIPS version of wolfCrypt, allow private key to be
         * exported for use. Only applicable to FIPS 140-3 */
        if (Fips.enabled) {
            Fips.setPrivateKeyReadEnable(1, Fips.WC_KEYTYPE_ALL);
        }
    }

    /**
     * Remove services for PQC parameter sets that are not compiled into
     * the native wolfSSL library.
     *
     * Native wolfSSL can be built with a subset of ML-DSA levels or
     * SLH-DSA parameter sets (ex: --enable-slhdsa=128f,sha2-128f). The
     * family-level feature detection used at registration time cannot see
     * that granularity, so services for unsupported sets are removed here.
     */
    private void removeUnsupportedPQCParamSets() {

        String[] mlDsaSets = {
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
        };

        int[] mlDsaLevels = {
            MlDsa.ML_DSA_44, MlDsa.ML_DSA_65, MlDsa.ML_DSA_87
        };

        String[] slhDsaSets = {
            "SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s",  "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
        };

        int[] slhDsaParams = {
            SlhDsa.SLH_DSA_SHA2_128S,  SlhDsa.SLH_DSA_SHA2_128F,
            SlhDsa.SLH_DSA_SHA2_192S,  SlhDsa.SLH_DSA_SHA2_192F,
            SlhDsa.SLH_DSA_SHA2_256S,  SlhDsa.SLH_DSA_SHA2_256F,
            SlhDsa.SLH_DSA_SHAKE_128S, SlhDsa.SLH_DSA_SHAKE_128F,
            SlhDsa.SLH_DSA_SHAKE_192S, SlhDsa.SLH_DSA_SHAKE_192F,
            SlhDsa.SLH_DSA_SHAKE_256S, SlhDsa.SLH_DSA_SHAKE_256F
        };

        for (int i = 0; i < mlDsaSets.length; i++) {
            if (!FeatureDetect.MlDsaLevelEnabled(mlDsaLevels[i])) {
                removeParamSetServices(mlDsaSets[i]);
            }
        }
        for (int i = 0; i < slhDsaSets.length; i++) {
            if (!FeatureDetect.SlhDsaParamEnabled(slhDsaParams[i])) {
                removeParamSetServices(slhDsaSets[i]);
            }
        }

        /* Generic KeyPairGenerator services generate their default param
         * set when not explicitly initialized, remove them when that default
         * is not available */
        if (!FeatureDetect.MlDsaLevelEnabled(MlDsa.ML_DSA_65)) {
            remove("KeyPairGenerator.ML-DSA");
        }
        if (!FeatureDetect.SlhDsaParamEnabled(SlhDsa.SLH_DSA_SHA2_128F)) {
            remove("KeyPairGenerator.SLH-DSA");
        }
    }

    /**
     * Remove all services and aliases registered for a single PQC param
     * set name, including pre-hash signature variants.
     *
     * @param paramSet parameter set name (ex: "SLH-DSA-SHA2-128s")
     */
    private void removeParamSetServices(String paramSet) {

        List<Object> toRemove = new ArrayList<Object>();

        for (Map.Entry<Object, Object> entry : entrySet()) {
            Object k = entry.getKey();
            if (!(k instanceof String)) {
                continue;
            }
            String name = (String)k;

            /* Service registrations (Signature. / KeyPairGenerator. /
             * KeyFactory.) and pre-hash signature variants */
            if (name.endsWith("." + paramSet) ||
                name.contains("." + paramSet + "-WITH-")) {
                toRemove.add(k);
                continue;
            }

            /* Aliases resolving to this parameter set */
            if (name.startsWith("Alg.Alias.")) {
                Object v = entry.getValue();
                if (v instanceof String &&
                    (((String)v).equals(paramSet) ||
                     ((String)v).startsWith(paramSet + "-WITH-"))) {
                    toRemove.add(k);
                }
            }
        }

        for (Object k : toRemove) {
            remove(k);
        }
    }
}

