/* WolfCryptECParameterSpec.java
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

package com.wolfssl.provider.jce;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.ECFieldFp;

import com.wolfssl.wolfcrypt.Ecc;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * wolfJCE ECParameterSpec implementation.
 *
 * This class extends ECParameterSpec to store curve name metadata.
 * It also provides static helper methods for working with ECParameterSpec
 * and integrating with system AlgorithmParameters when needed.
 */
public class WolfCryptECParameterSpec extends ECParameterSpec {

    /* Stored ECC curve name */
    private final String curveName;

    /**
     * Create ECParameterSpec with curve name.
     *
     * @param curve the elliptic curve
     * @param generator the generator point
     * @param order the order of the generator point
     * @param cofactor the cofactor
     * @param curveName the wolfCrypt curve name
     */
    public WolfCryptECParameterSpec(EllipticCurve curve, ECPoint generator,
        BigInteger order, int cofactor, String curveName) {

        super(curve, generator, order, cofactor);
        this.curveName = curveName;
    }

    /**
     * Get the stored curve name without needing to do parameter matching.
     *
     * @return curve name
     */
    public String getStoredCurveName() {
        return curveName;
    }

    /**
     * Compares this ECParameterSpec for equality with another object.
     * Two ECParameterSpec objects are equal if they have the same curve,
     * generator point, order, cofactor, and stored curve name (if both
     * are WolfCryptECParameterSpec instances).
     *
     * @param obj the object to compare with
     *
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ECParameterSpec)) {
            return false;
        }

        ECParameterSpec other = (ECParameterSpec) obj;

        /* Compare all ECParameterSpec fields */
        if (!getCurve().equals(other.getCurve())) {
            return false;
        }
        if (!getGenerator().equals(other.getGenerator())) {
            return false;
        }
        if (!getOrder().equals(other.getOrder())) {
            return false;
        }
        if (getCofactor() != other.getCofactor()) {
            return false;
        }

        /* If both are WolfCryptECParameterSpec, compare stored curve names */
        if (obj instanceof WolfCryptECParameterSpec) {
            WolfCryptECParameterSpec otherWolf = (WolfCryptECParameterSpec) obj;
            if (curveName != null) {
                return curveName.equals(otherWolf.curveName);
            } else {
                return otherWolf.curveName == null;
            }
        }

        return true;
    }

    /**
     * Returns a hash code for this ECParameterSpec.
     * The hash code is computed based on the curve, generator, order,
     * cofactor, and stored curve name.
     *
     * @return hash code for this ECParameterSpec
     */
    @Override
    public int hashCode() {

        int result = getCurve().hashCode();

        /* Use 31 as a multiplier for hash code combination, following
         * how Java hashCode() does. (31 is an odd prime) */
        result = 31 * result + getGenerator().hashCode();
        result = 31 * result + getOrder().hashCode();
        result = 31 * result + getCofactor();

        if (curveName != null) {
            result = 31 * result + curveName.hashCode();
        }
        return result;
    }

    /**
     * Returns a string representation of this ECParameterSpec.
     * Includes the stored curve name for easier debugging.
     *
     * @return string representation of this ECParameterSpec
     */
    @Override
    public String toString() {
        return "WolfCryptECParameterSpec{" +
            "curveName='" + curveName + '\'' +
            ", fieldSize=" + getCurve().getField().getFieldSize() + " bits" +
            ", cofactor=" + getCofactor() + '}';
    }

    /**
     * Extract ECParameterSpec from DER-encoded algorithm identifier.
     *
     * @param algoIDDer DER-encoded algorithm identifier
     *
     * @return ECParameterSpec parsed from the algorithm identifier
     *
     * @throws IllegalArgumentException if parsing fails
     */
    public static ECParameterSpec parseFromAlgorithmIdentifier(
        byte[] algoIDDer) throws IllegalArgumentException {

        if (algoIDDer == null || algoIDDer.length == 0) {
            throw new IllegalArgumentException(
                "Algorithm identifier DER cannot be null or empty");
        }

        try {
            /* Use system AlgorithmParameters to parse EC parameters.
             * TODO: switch to wolfJCE EC AlgorithmParameters if/when that
             * implementation happens. For now, we just use the system
             * AlgorithmParameters since there is no crypto done in that
             * class. */
            AlgorithmParameters algParams =
                AlgorithmParameters.getInstance("EC");
            algParams.init(algoIDDer);

            return algParams.getParameterSpec(ECParameterSpec.class);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(
                "EC AlgorithmParameters not available", e);

        } catch (InvalidParameterSpecException e) {
            throw new IllegalArgumentException(
                "Invalid EC algorithm identifier", e);

        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to parse EC algorithm identifier", e);
        }
    }

    /**
     * Extract ECParameterSpec from DER-encoded EC key.
     *
     * This method uses wolfCrypt to load the key and extract curve parameters.
     *
     * @param keyDer DER-encoded EC key (PKCS#8 or X.509)
     * @param isPrivateKey true if this is a private key, false for public key
     *
     * @return ECParameterSpec for the key
     *
     * @throws IllegalArgumentException if parameter extraction fails
     */
    public static ECParameterSpec extractFromKey(byte[] keyDer,
        boolean isPrivateKey) throws IllegalArgumentException {

        Ecc ecc = null;

        if (keyDer == null || keyDer.length == 0) {
            throw new IllegalArgumentException(
                "Key DER cannot be null or empty");
        }

        try {
            /* Load key into Ecc to access curve information */
            ecc = new Ecc();

            if (isPrivateKey) {
                ecc.privateKeyDecode(keyDer);
            } else {
                ecc.publicKeyDecode(keyDer);
            }

            /* Get curve ID from the key */
            int curveId = ecc.getCurveId();
            String curveName = Ecc.getCurveNameFromId(curveId);

            if (curveName == null) {
                throw new IllegalArgumentException(
                    "Unknown curve ID: " + curveId);
            }

            /* Create ECParameterSpec using wolfCrypt Ecc class */
            return createECParameterSpec(curveName);

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "wolfCrypt error during key decode: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to extract EC parameters from key: " +
                e.getMessage(), e);

        } finally {
            if (ecc != null) {
                ecc.releaseNativeStruct();
            }
        }
    }

    /**
     * Get curve name from ECParameterSpec.
     *
     * First checks if the ECParameterSpec is ours, with stored curve name.
     * If so, returns the stored name without parameter matching. Otherwise,
     * falls back to parameter-based identification.
     *
     * @param paramSpec ECParameterSpec to get curve name from
     *
     * @return curve name string, or null if not found
     *
     * @throws InvalidAlgorithmParameterException if parameters are invalid
     */
    public static String getCurveName(ECParameterSpec paramSpec)
        throws InvalidAlgorithmParameterException {

        if (paramSpec == null) {
            return null;
        }

        /* Check if this is our ECParameterSpec with stored curve name */
        if (paramSpec instanceof WolfCryptECParameterSpec) {
            WolfCryptECParameterSpec enhanced =
                (WolfCryptECParameterSpec) paramSpec;
            return enhanced.getStoredCurveName();
        }

        /* Fall back to parameter-based identification for external
         * ECParameterSpec objects */
        return Ecc.getCurveName(paramSpec);
    }

    /**
     * Check if ECParameterSpec has stored curve name metadata.
     *
     * @param paramSpec ECParameterSpec to check
     *
     * @return true if enhanced with stored curve name, false otherwise
     */
    public static boolean hasStoredCurveName(ECParameterSpec paramSpec) {
        return paramSpec instanceof WolfCryptECParameterSpec;
    }

    /**
     * Identify ECC curve name by comparing ECParameterSpec parameters against
     * all curves supported by wolfCrypt.
     *
     * @param paramSpec ECParameterSpec to identify
     *
     * @return curve name string, or null if no match found
     */
    private static String identifyCurveByParameters(ECParameterSpec spec) {

        int targetCofactor;
        int cofactor;

        if (spec == null) {
            return null;
        }

        try {
            /* Get all supported curves from wolfCrypt */
            String[] supportedCurves = Ecc.getAllSupportedCurves();

            /* Extract parameters from the input ECParameterSpec */
            EllipticCurve curve = spec.getCurve();
            if (!(curve.getField() instanceof ECFieldFp)) {
                return null; /* Only support prime fields */
            }

            ECFieldFp field = (ECFieldFp) curve.getField();
            BigInteger targetP = field.getP();
            BigInteger targetA = curve.getA();
            BigInteger targetB = curve.getB();
            BigInteger targetN = spec.getOrder();
            ECPoint targetG = spec.getGenerator();
            targetCofactor = spec.getCofactor();

            /* Compare against each supported curve */
            for (String curveName : supportedCurves) {
                try {
                    String[] curveParams = Ecc.getCurveParameters(curveName);

                    /* Parse wolfCrypt curve parameters */
                    BigInteger p = new BigInteger(curveParams[0], 16);

                    /* Field size check for early exit on curve mismatch */
                    if (targetP.bitLength() != p.bitLength()) {
                        continue;
                    }

                    /* Prime field check for early exit on curve mismatch */
                    if (!targetP.equals(p)) {
                        continue;
                    }

                    BigInteger a = new BigInteger(curveParams[1], 16);
                    BigInteger b = new BigInteger(curveParams[2], 16);
                    BigInteger n = new BigInteger(curveParams[3], 16);

                    cofactor = Integer.parseInt(curveParams[6]);
                    if (targetCofactor != cofactor) {
                        continue;
                    }

                    /* Compare a, b, n, and generator */
                    if (targetA.equals(a) && targetB.equals(b) &&
                        targetN.equals(n)) {

                        BigInteger gx = new BigInteger(curveParams[4], 16);
                        BigInteger gy = new BigInteger(curveParams[5], 16);

                        if (targetG.getAffineX().equals(gx) &&
                            targetG.getAffineY().equals(gy)) {

                            log("identified curve by parameter matching: " +
                                curveName);
                            return curveName;
                        }
                    }

                } catch (Exception e) {
                    /* Continue to next curve */
                    continue;
                }
            }

            log("no curve match found for ECParameterSpec with field size " +
                targetP.bitLength());
            return null;

        } catch (Exception e) {
            log("error during curve parameter matching: " + e.getMessage());
            return null;
        }
    }

    /**
     * Validate if given ECParameterSpec is supported by wolfCrypt.
     *
     * @param spec ECParameterSpec to validate
     *
     * @throws IllegalArgumentException if parameters are not supported
     */
    public static void validateParameters(ECParameterSpec spec)
        throws IllegalArgumentException {

        if (spec == null) {
            throw new IllegalArgumentException(
                "ECParameterSpec cannot be null");
        }

        try {
            String curveName = getCurveName(spec);
            if (curveName == null) {
                throw new IllegalArgumentException(
                    "ECParameterSpec curve not supported by wolfCrypt");
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(
                "ECParameterSpec curve not supported by wolfCrypt: " +
                e.getMessage());
        }
    }

    /**
     * Normalize wolfCrypt curve names to standard format expected by
     * system AlgorithmParameters.
     *
     * @param wolfCryptName curve name from wolfCrypt
     *
     * @return normalized curve name for system use
     */
    private static String normalizeStandardCurveName(String wolfCryptName) {
        if (wolfCryptName == null) {
            return null;
        }

        /* Convert wolfCrypt curve names to standard names for common curves.
         * For most curves, wolfCrypt uses uppercase names while Java standards
         * prefer lowercase. For newer curves like Brainpool, we keep the
         * original wolfCrypt naming. */
        switch (wolfCryptName.toUpperCase()) {
            case "SECP256R1":
                return "secp256r1";
            case "SECP384R1":
                return "secp384r1";
            case "SECP521R1":
                return "secp521r1";
            case "SECP224R1":
                return "secp224r1";
            case "SECP192R1":
                return "secp192r1";
            case "SECP256K1":
                return "secp256k1";
            case "SECP224K1":
                return "secp224k1";
            case "SECP192K1":
                return "secp192k1";
            case "SECP160R1":
                return "secp160r1";
            case "SECP160R2":
                return "secp160r2";
            case "SECP160K1":
                return "secp160k1";
            /* For Brainpool, prime curves, and special curves like SAKKE,
             * keep the original wolfCrypt naming */
            default:
                /* Try lowercase as fallback for consistency */
                return wolfCryptName.toLowerCase();
        }
    }

    /**
     * Create ECParameterSpec directly from wolfCrypt curve parameters.
     *
     * @param curveName name of ECC curve
     *
     * @return newly created ECParameterSpec
     *
     * @throws IllegalArgumentException if curve is not supported or
     *         parameter creation fails
     */
    public static ECParameterSpec createECParameterSpec(String curveName)
        throws IllegalArgumentException {

        if (curveName == null) {
            throw new IllegalArgumentException("Curve name cannot be null");
        }

        try {
            log("creating ECParameterSpec from wolfCrypt for curve: " +
                curveName);

            /* Extract curve parameters directly from wolfCrypt */
            String[] params = Ecc.getCurveParameters(curveName);

            /* Parse parameters from hex strings (radix 16) to BigInteger:
             *     params[0] = p (field prime)
             *     params[1] = a (curve coefficient a)
             *     params[2] = b (curve coefficient b)
             *     params[3] = n (curve order)
             *     params[4] = gx (generator x)
             *     params[5] = gy (generator y)
             *     params[6] = cofactor (integer)
             */
            BigInteger p = new BigInteger(params[0], 16);
            BigInteger a = new BigInteger(params[1], 16);
            BigInteger b = new BigInteger(params[2], 16);
            BigInteger n = new BigInteger(params[3], 16);
            BigInteger gx = new BigInteger(params[4], 16);
            BigInteger gy = new BigInteger(params[5], 16);
            int cofactor = Integer.parseInt(params[6]);

            /* Create EC field (prime field) */
            ECFieldFp field = new ECFieldFp(p);

            /* Create elliptic curve */
            EllipticCurve curve = new EllipticCurve(field, a, b);

            /* Create generator point */
            ECPoint generator = new ECPoint(gx, gy);

            /* Create WolfCryptECParameterSpec with stored curve name */
            WolfCryptECParameterSpec paramSpec =
                new WolfCryptECParameterSpec(curve, generator, n, cofactor,
                    curveName);

            log("successfully created ECParameterSpec for " + curveName +
                " with field size " + p.bitLength() + " (curve name stored)");

            return paramSpec;

        } catch (WolfCryptException e) {
            throw new IllegalArgumentException(
                "wolfCrypt error extracting curve parameters: " +
                e.getMessage(), e);

        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                "Invalid curve parameter format: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Failed to create ECParameterSpec from wolfCrypt: " +
                e.getMessage(), e);
        }
    }

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private static void log(String msg) {
        WolfCryptDebug.log(WolfCryptECParameterSpec.class, WolfCryptDebug.INFO,
            () -> "[WolfCryptECParameterSpec] " + msg);
    }
}

