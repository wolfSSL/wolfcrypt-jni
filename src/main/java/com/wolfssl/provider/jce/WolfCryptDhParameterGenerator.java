/* WolfCryptDhParameterGenerator.java
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

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;

import com.wolfssl.wolfcrypt.Dh;
import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfCrypt JCE DH AlgorithmParameterGenerator implementation
 */
public class WolfCryptDhParameterGenerator
    extends AlgorithmParameterGeneratorSpi {

    /* Default size for DH parameters (bits) */
    private static final int DEFAULT_SIZE = 2048;

    /* Size of DH parameters to generate (bits) */
    private int size = DEFAULT_SIZE;

    /* Exponent size in bits, 0 means not specified */
    private int exponentSize = 0;

    /* SecureRandom for parameter generation */
    private SecureRandom random = null;

    /**
     * Create new WolfCryptDhParameterGenerator object
     */
    public WolfCryptDhParameterGenerator() {
    }

    @Override
    protected void engineInit(int size, SecureRandom random) {
        this.size = size;
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec,
        SecureRandom random) throws InvalidAlgorithmParameterException {

        if (genParamSpec == null) {
            throw new InvalidAlgorithmParameterException(
                "genParamSpec cannot be null");
        }

        if (!(genParamSpec instanceof DHGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameterSpec must be DHGenParameterSpec for " +
                "DH parameter generation");
        }

        DHGenParameterSpec dhGenSpec = (DHGenParameterSpec)genParamSpec;
        this.size = dhGenSpec.getPrimeSize();
        this.exponentSize = dhGenSpec.getExponentSize();
        this.random = random;
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {

        AlgorithmParameters algParams = null;
        byte[][] params = null;
        BigInteger p = null;
        BigInteger g = null;

        /* Max retries for prime generation. FIPS 186-4 allows reattempting
         * with a new seed on failure; 5 is a conservative bound to prevent
         * infinite loops while allowing recovery from transient failures. */
        final int MAX_PARAM_GEN_RETRIES = 5;
        int retryCount = 0;
        WolfCryptException lastPrimeGenException = null;

        try {
            /* Check if this is a standard FFDHE size */
            int namedGroup = -1;
            if (size == 2048) {
                namedGroup = Dh.WC_FFDHE_2048;
            }
            else if (size == 3072) {
                namedGroup = Dh.WC_FFDHE_3072;
            }
            else if (size == 4096) {
                namedGroup = Dh.WC_FFDHE_4096;
            }
            else if (size == 6144) {
                namedGroup = Dh.WC_FFDHE_6144;
            }
            else if (size == 8192) {
                namedGroup = Dh.WC_FFDHE_8192;
            }

            if (namedGroup != -1) {
                /* Try to use pre-computed FFDHE parameters for standard
                 * sizes. If the named group is not available (not compiled
                 * into wolfSSL), throw an exception. */
                params = Dh.getNamedDhParams(namedGroup);

                /* Check if the requested FFDHE group is available */
                if (params == null || params.length != 2 ||
                    params[0] == null || params[0].length == 0) {

                    throw new RuntimeException(
                        "FFDHE " + size + "-bit group not available in " +
                        "native wolfSSL library. Only FFDHE groups compiled " +
                        "into wolfSSL can be used.");
                }
            }
            else {
                /* For non-standard sizes, try dynamic parameter generation
                 * using wc_DhGenerateParams(). Retry loop since native
                 * wolfCrypt may return PRIME_GEN_E (-251) if it fails to
                 * find a suitable prime after the NIST FIPS 186-4 mandated
                 * number of attempts. */
                while (retryCount < MAX_PARAM_GEN_RETRIES) {
                    Rng rng = null;
                    try {
                        /* Create and initialize RNG. */
                        rng = new Rng();
                        rng.init();

                        /* Generate DH parameters, may throw exception with
                         * bad function arg if size not supported natively. */
                        params = Dh.generateDhParams(rng, size);

                        /* Success, exit retry loop */
                        break;

                    } catch (WolfCryptException e) {
                        /* Only retry on PRIME_GEN_E error */
                        if (e.getError() == WolfCryptError.PRIME_GEN_E) {
                            lastPrimeGenException = e;
                            retryCount++;
                        }
                        else {
                            throw e;
                        }
                    }
                    finally {
                        if (rng != null) {
                            rng.free();
                            rng.releaseNativeStruct();
                        }
                    }
                }

                /* Check if we exhausted all retries */
                if (params == null && lastPrimeGenException != null) {
                    throw new RuntimeException(
                        "DH parameter generation failed after " +
                        MAX_PARAM_GEN_RETRIES +
                        " attempts due to prime generation failure",
                        lastPrimeGenException);
                }
            }

            if (params == null || params.length != 2) {
                throw new RuntimeException(
                    "Failed to generate DH parameters");
            }

            /* Convert byte arrays to BigInteger */
            p = new BigInteger(1, params[0]);
            g = new BigInteger(1, params[1]);

            /* Create DHParameterSpec with generated parameters.
             * If exponentSize was specified (via DHGenParameterSpec),
             * include it in the DHParameterSpec. */
            DHParameterSpec dhSpec;
            if (this.exponentSize > 0) {
                dhSpec = new DHParameterSpec(p, g, this.exponentSize);
            }
            else {
                dhSpec = new DHParameterSpec(p, g);
            }

            /* Create AlgorithmParameters object and initialize it */
            algParams = AlgorithmParameters.getInstance("DH", "wolfJCE");
            algParams.init(dhSpec);

        } catch (WolfCryptException e) {
            throw new RuntimeException(
                "Failed to generate DH parameters: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new RuntimeException(
                "Failed to create AlgorithmParameters: " + e.getMessage(), e);
        }

        return algParams;
    }
}

