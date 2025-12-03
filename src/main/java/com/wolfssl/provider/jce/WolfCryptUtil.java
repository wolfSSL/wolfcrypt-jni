/* WolfCryptUtil.java
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Utility class containing helper functions for wolfCrypt JCE provider.
 */
public class WolfCryptUtil {

    /**
     * Maximum size of the keystore buffer to mark. We try to set this
     * high enough to handle any large keystore. Although there is no
     * upper limit on the size of a keystore, looking at the JDK 23 cacerts
     * KeyStore file, that is 190kB. We leave ample room for growth here
     * with 512kB.
     */
    private static final int MAX_KEYSTORE_SIZE = 512 * 1024;

    /**
     * Chunk size for reading the keystore. We use 4kB as a happy medium
     * between memory usage and performance.
     */
    private static final int KEYSTORE_CHUNK_SIZE = 4 * 1024;

    /**
     * Internal method for logging output.
     *
     * @param msg message to be logged
     */
    private static synchronized void log(String msg) {
        WolfCryptDebug.log(WolfCryptUtil.class, WolfCryptDebug.INFO,
            () -> msg);
    }

    /**
     * Converts a Java KeyStore (JKS or PKCS12) to a WolfSSLKeyStore (WKS)
     * format.
     *
     * This method detects the type of the input KeyStore (WKS, JKS, or PKCS12)
     * and converts it to WKS format if needed. All certificates and keys from
     * the source KeyStore are transferred to the destination KeyStore. If the
     * input KeyStore is already of type WKS, the method will return the same
     * InputStream.
     *
     * @param stream Input stream containing a WKS, JKS, or PKCS12 KeyStore
     * @param oldPassword Password used to decrypt KeyStore entries.
     * @param newPassword Password used to encrypt KeyStore entries. When used
     *         with wolfCrypt FIPS, this password needs to meet FIPS minimum
     *         HMAC key size requirements and must be at least 14 characters.
     * @param failOnInsertErrors If true, throw an exception if an error occurs
     *         during the insertion of a certificate or key into the newly
     *         created WKS KeyStore. If false, log the error and continue
     *         inserting the remaining entries. When used with wolfCrypt FIPS,
     *         entries can fail to insert into WKS KeyStore due to FIPS
     *         restrictions on the algorithms used.
     * @return InputStream containing the newly created WKS KeyStore
     * @throws IOException If an I/O error occurs
     * @throws NoSuchProviderException If required security providers are not
     *         available or if reflection operations fail when accessing the
     *         original KeyStore implementations
     */
    public static InputStream convertKeyStoreToWKS(InputStream stream,
            char[] oldPassword, char[] newPassword, boolean failOnInsertErrors)
            throws IOException, NoSuchProviderException {

        boolean mapJksToWks = false;
        boolean mapPkcs12ToWks = false;
        boolean wksFound = false;
        boolean jksFound = false;
        KeyStore sourceStore = null;

        log("converting KeyStore InputStream to WKS format");

        if (stream == null) {
            throw new IllegalArgumentException("Input stream cannot be null");
        }

        if (oldPassword == null) {
            throw new IllegalArgumentException("Old password cannot be null");
        }

        if (newPassword == null) {
            throw new IllegalArgumentException("New password cannot be null");
        }

        /* Make sure wolfJCE provider is available and registered */
        Provider wolfJCE = Security.getProvider("wolfJCE");
        if (wolfJCE == null) {
            Security.addProvider(new WolfCryptProvider());
        }

        try {
            /* Check if wolfJCE has mapped JKS or PKCS12 to WKS */
            String mapJksToWksStr =
                Security.getProperty("wolfjce.mapJKStoWKS");
            if (mapJksToWksStr != null && !mapJksToWksStr.isEmpty() &&
                mapJksToWksStr.equalsIgnoreCase("true")) {
                mapJksToWks = true;
            }

            String mapPkcs12ToWksStr =
                Security.getProperty("wolfjce.mapPKCS12toWKS");
            if (mapPkcs12ToWksStr != null && !mapPkcs12ToWksStr.isEmpty() &&
                mapPkcs12ToWksStr.equalsIgnoreCase("true")) {
                mapPkcs12ToWks = true;
            }

            log("JKS to WKS mapping enabled: " + mapJksToWks);
            log("PKCS12 to WKS mapping enabled: " + mapPkcs12ToWks);

            /* Since we will be doing KeyStore type detection by trying to
             * read the KeyStore, we want to make sure we have the ability
             * to mark() the stream. If we don't have the ability, we copy
             * the stream into a ByteArrayOutputStream and then into a
             * ByteArrayInputStream which is markable. */
            if (!stream.markSupported()) {
                try {
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    int numRead;
                    byte[] data = new byte[KEYSTORE_CHUNK_SIZE];
                    while ((numRead = stream.read(data, 0, data.length)) != -1) {
                        buffer.write(data, 0, numRead);
                    }
                    buffer.flush();
                    stream = new ByteArrayInputStream(buffer.toByteArray());
                } catch (IOException e) {
                    throw new IOException("Failed to read stream contents", e);
                }
            }

            /* Mark the current position in the stream */
            stream.mark(MAX_KEYSTORE_SIZE);

            /* Try WKS */
            try {
                sourceStore = KeyStore.getInstance("WKS", "wolfJCE");
                sourceStore.load(stream, oldPassword);
                wksFound = true;

                log("Input KeyStore is already in WKS format");
            } catch (KeyStoreException | NoSuchAlgorithmException |
                     CertificateException | IOException e) {
                /* Not a WKS KeyStore, continue with other formats */
            } finally {
                stream.reset();
            }

            /* Try JKS */
            if (!wksFound) {
                try {
                    if (mapJksToWks) {
                        /* If JKS is mapped to WKS, use reflection to get the
                         * Sun provider's JKS implementation */
                        try {
                            sourceStore = getJksKeyStoreFromSunProvider();
                        } catch (ReflectiveOperationException |
                                KeyStoreException ex) {
                            throw new NoSuchProviderException(
                                "Failed to get JKS implementation via " +
                                "reflection from Sun provider: " +
                                ex.getMessage());
                        }
                    } else {
                        sourceStore = KeyStore.getInstance("JKS");
                    }
                    sourceStore.load(stream, oldPassword);
                    jksFound = true;

                    log("Input KeyStore is in JKS format");
                } catch (IOException | NoSuchAlgorithmException |
                        CertificateException e) {
                    /* Not a JKS KeyStore, continue with other formats */
                } finally {
                    stream.reset();
                }
            }

            /* Try PKCS12 */
            if (!wksFound && !jksFound) {
                try {
                    if (mapPkcs12ToWks) {
                        /* If PKCS12 is mapped to WKS, use reflection to get
                         * the Sun provider's PKCS12 implementation */
                        try {
                            sourceStore = getPkcs12KeyStoreFromSunProvider();
                        } catch (ReflectiveOperationException |
                                 KeyStoreException ex) {
                            throw new NoSuchProviderException(
                                "Failed to get PKCS12 implementation via " +
                                "reflection from Sun provider: " +
                                ex.getMessage());
                        }
                    } else {
                        sourceStore = KeyStore.getInstance("PKCS12");
                    }
                    sourceStore.load(stream, oldPassword);

                    log("Input KeyStore is in PKCS12 format");
                } catch (KeyStoreException | NoSuchAlgorithmException |
                         CertificateException ex) {
                    throw new IOException(
                        "Input KeyStore is neither WKS, JKS nor " +
                        "PKCS12 KeyStore format", ex);
                } finally {
                    stream.reset();
                }
            }

            /* Create destination WKS KeyStore */
            KeyStore destStore = KeyStore.getInstance("WKS", "wolfJCE");
            destStore.load(null, newPassword);
            log("Creating destination WKS KeyStore to populate");

            /* Copy all entries from source to destination */
            Enumeration<String> aliases = sourceStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                if (sourceStore.isKeyEntry(alias)) {
                    /* Handle key entries (may include a certificate chain) */
                    try {
                        Key key = sourceStore.getKey(alias, oldPassword);
                        Certificate[] chain =
                            sourceStore.getCertificateChain(alias);
                        destStore.setKeyEntry(alias, key, newPassword, chain);
                    } catch (UnrecoverableKeyException | KeyStoreException e) {
                        if (failOnInsertErrors) {
                            throw new IOException("Failed to copy key entry: " +
                                alias, e);
                        } else {
                            log("Failed to copy key entry: " + alias +
                                ", continuing with next entry");
                        }
                    }
                } else if (sourceStore.isCertificateEntry(alias)) {
                    /* Handle certificate-only entries */
                    try {
                        Certificate cert = sourceStore.getCertificate(alias);
                        destStore.setCertificateEntry(alias, cert);
                    } catch (KeyStoreException e) {
                        if (failOnInsertErrors) {
                            throw new IOException(
                                "Failed to copy certificate entry: " +
                                alias, e);
                        } else {
                            log("Failed to copy certificate entry: " + alias +
                                ", continuing with next entry");
                        }
                    }
                }
            }
            log("Copied all entries from source to destination KeyStore");

            /* Write the WKS KeyStore to a byte array and return as
             * InputStream */
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            destStore.store(baos, newPassword);

            return new ByteArrayInputStream(baos.toByteArray());

        } catch (KeyStoreException | NoSuchAlgorithmException |
                 CertificateException e) {
            throw new IOException("Error during KeyStore conversion", e);
        }
    }

    /**
     * Get the Sun provider JKS KeyStore implementation using reflection.
     * This is used when wolfJCE has registered itself as the JKS provider
     * using the Security property "wolfjce.mapJKStoWKS".
     *
     * @return A KeyStore instance from the Sun provider for JKS format
     * @throws ReflectiveOperationException If reflection fails
     * @throws KeyStoreException If the KeyStore cannot be created
     */
    private static KeyStore getJksKeyStoreFromSunProvider()
            throws ReflectiveOperationException, KeyStoreException {
        /* Try to find the Sun provider */
        Provider sunProvider = Security.getProvider("SUN");
        if (sunProvider == null) {
            throw new KeyStoreException("SUN provider not available");
        }

        try {
            /* Try to get the KeyStore from the explicit provider first */
            return KeyStore.getInstance("JKS", sunProvider);

        } catch (Exception e) {
            /* Fallback to using reflection if the first approach fails */
            /* Load the JKS KeyStore class directly from the Sun provider */
            Class<?> jksKeyStoreClass =
                Class.forName("sun.security.provider.JavaKeyStore$JKS");
            Constructor<?> constructor =
                jksKeyStoreClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            KeyStore ks = (KeyStore) constructor.newInstance();

            /* Initialize the KeyStore */
            Method engineInitMethod =
                jksKeyStoreClass.getDeclaredMethod("engineInit");
            engineInitMethod.setAccessible(true);
            engineInitMethod.invoke(ks);

            return ks;
        }
    }

    /**
     * Get the Sun provider PKCS12 KeyStore implementation using reflection.
     * This is used when wolfJCE has registered itself as the PKCS12 provider
     * using the Security property "wolfjce.mapPKCS12toWKS".
     *
     * @return A KeyStore instance from the Sun provider for PKCS12 format
     * @throws ReflectiveOperationException If reflection fails
     * @throws KeyStoreException If the KeyStore cannot be created
     */
    private static KeyStore getPkcs12KeyStoreFromSunProvider()
            throws ReflectiveOperationException, KeyStoreException {
        /* Try to find the SunJSSE provider */
        Provider sunJsseProvider = Security.getProvider("SunJSSE");
        if (sunJsseProvider == null) {
            /* Try Sun provider as fallback */
            sunJsseProvider = Security.getProvider("SUN");
            if (sunJsseProvider == null) {
                throw new KeyStoreException(
                    "Neither SunJSSE nor SUN provider available");
            }
        }

        try {
            /* Try to get the KeyStore through the provider first */
            return KeyStore.getInstance("PKCS12", sunJsseProvider);

        } catch (Exception e) {
            /* Fallback to using reflection if the first approach fails */
            /* Load the PKCS12 KeyStore class */
            Class<?> pkcs12KeyStoreClass =
                Class.forName("sun.security.pkcs12.PKCS12KeyStore");
            Constructor<?> constructor =
                pkcs12KeyStoreClass.getDeclaredConstructor();
            constructor.setAccessible(true);
            KeyStore ks = (KeyStore) constructor.newInstance();

            /* Initialize the KeyStore */
            Method engineInitMethod =
                pkcs12KeyStoreClass.getDeclaredMethod("engineInit");
            engineInitMethod.setAccessible(true);
            engineInitMethod.invoke(ks);

            return ks;
        }
    }

    /**
     * Check if a given algorithm is disabled based on a security property.
     *
     * This method checks both the full algorithm name and decomposed parts.
     * For example, "MD2withRSA" will check for "MD2withRSA", "MD2", and
     * "RSA" in the disabled algorithms list.
     *
     * @param algorithm Algorithm name to check (e.g., "MD2", "MD5",
     *                  "SHA1withRSA", "MD2withRSA")
     * @param propertyName Security property name to check against
     *                     (e.g., "jdk.certpath.disabledAlgorithms")
     *
     * @return true if algorithm is disabled, false otherwise
     */
    public static boolean isAlgorithmDisabled(String algorithm,
        String propertyName) {

        List<String> disabledList = null;
        String disabledAlgos = null;

        if (algorithm == null || algorithm.isEmpty()) {
            return false;
        }

        if (propertyName == null || propertyName.isEmpty()) {
            return false;
        }

        disabledAlgos = Security.getProperty(propertyName);
        if (disabledAlgos == null || disabledAlgos.isEmpty()) {
            return false;
        }

        /* Remove spaces after commas, split into List */
        disabledAlgos = disabledAlgos.replaceAll(", ", ",");
        disabledList = Arrays.asList(disabledAlgos.split(","));

        /* Check full algorithm name first (case-insensitive) */
        for (String disabled : disabledList) {
            if (disabled.equalsIgnoreCase(algorithm)) {
                return true;
            }
        }

        /* Decompose composite algorithm names like "MD2withRSA" into
         * constituent parts and check each. Common formats:
         *   - "MD2withRSA" - ["MD2", "RSA"]
         *   - "SHA1withECDSA" - ["SHA1", "ECDSA"]
         *   - "SHA256withRSA" - ["SHA256", "RSA"]
         * Use case-insensitive matching to match SunJCE behavior */
        String[] parts = decomposeAlgorithmName(algorithm);
        for (String part : parts) {
            for (String disabled : disabledList) {
                if (disabled.equalsIgnoreCase(part)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Decompose a composite algorithm name into constituent parts.
     *
     * - Splits on "/" for algorithm/mode/padding format
     * - Splits on "with", "and", and "in" (case-insensitive)
     * - Avoids splitting "in" when part of "padding"
     *
     * Examples:
     *   "MD2withRSA" - ["MD2", "RSA"]
     *   "SHA1withECDSA" - ["SHA1", "ECDSA"]
     *   "SHA256withRSA/PSS" - ["SHA256", "RSA", "PSS"]
     *   "PBEWithMD5AndDES" - ["PBE", "MD5", "DES"]
     *   "AES/CBC/PKCS5Padding" - ["AES", "CBC", "PKCS5Padding"]
     *
     * @param algorithm Algorithm name to decompose
     *
     * @return Array of algorithm parts, empty array if input is null/empty
     */
    private static String[] decomposeAlgorithmName(String algorithm) {

        ArrayList<String> components = new ArrayList<String>();
        Pattern delimiter = null;
        String[] pathComponents = null;
        int originalSize = 0;

        /* Delimiter pattern matches "with", "and", or "in" (case-insensitive),
         * but not "in" when preceded by "padd" (as in "padding"). Uses
         * negative lookbehind (?<!padd) to preserve "padding". */
        String delimPattern = "with|and|(?<!padd)in";

        if (algorithm == null || algorithm.isEmpty()) {
            return new String[0];
        }

        /* Build delimiter pattern */
        delimiter = Pattern.compile(delimPattern, Pattern.CASE_INSENSITIVE);

        /* Handle algorithm/mode/padding format by splitting on "/" */
        pathComponents = algorithm.split("/");

        /* Process each path component through delimiter pattern */
        for (String pathComponent : pathComponents) {
            if (pathComponent != null && !pathComponent.isEmpty()) {
                /* Apply delimiter pattern to split on "with", "and", "in" */
                String[] delimitedParts = delimiter.split(pathComponent);

                /* Collect non-empty trimmed parts */
                for (String part : delimitedParts) {
                    if (part != null && !part.isEmpty()) {
                        components.add(part.trim());
                    }
                }
            }
        }

        /* Add SHA algorithm name variants. Java accepts both hyphenated and
         * non-hyphenated forms: SHA1 / SHA-1, SHA224 / SHA-224, etc.
         * Iterate only over original components to avoid infinite loop */
        originalSize = components.size();
        for (int i = 0; i < originalSize; i++) {
            String variant = getSHAVariant(components.get(i));
            if (variant != null) {
                components.add(variant);
            }
        }

        /* Return final decomposed components as array */
        return components.toArray(new String[components.size()]);
    }

    /**
     * Get alternate SHA algorithm name variant for a given component.
     *
     * Returns the alternate form between hyphenated and non-hyphenated:
     * "SHA1" - "SHA-1", "SHA-1" - "SHA1", etc.
     * Also handles SHA-3 variants: "SHA3-224" - "SHA3224", etc.
     *
     * @param component Algorithm component to check
     *
     * @return Alternate variant if this is a SHA algorithm, null otherwise
     */
    private static String getSHAVariant(String component) {

        if (component == null) {
            return null;
        }

        /* SHA1 / SHA-1 variants */
        if (component.equalsIgnoreCase("SHA1")) {
            return "SHA-1";
        }
        if (component.equalsIgnoreCase("SHA-1")) {
            return "SHA1";
        }

        /* SHA224 / SHA-224 variants */
        if (component.equalsIgnoreCase("SHA224")) {
            return "SHA-224";
        }
        if (component.equalsIgnoreCase("SHA-224")) {
            return "SHA224";
        }

        /* SHA256 / SHA-256 variants */
        if (component.equalsIgnoreCase("SHA256")) {
            return "SHA-256";
        }
        if (component.equalsIgnoreCase("SHA-256")) {
            return "SHA256";
        }

        /* SHA384 / SHA-384 variants */
        if (component.equalsIgnoreCase("SHA384")) {
            return "SHA-384";
        }
        if (component.equalsIgnoreCase("SHA-384")) {
            return "SHA384";
        }

        /* SHA512 / SHA-512 variants */
        if (component.equalsIgnoreCase("SHA512")) {
            return "SHA-512";
        }
        if (component.equalsIgnoreCase("SHA-512")) {
            return "SHA512";
        }

        /* SHA3-224 / SHA3224 variants */
        if (component.equalsIgnoreCase("SHA3-224")) {
            return "SHA3224";
        }
        if (component.equalsIgnoreCase("SHA3224")) {
            return "SHA3-224";
        }

        /* SHA3-256 / SHA3256 variants */
        if (component.equalsIgnoreCase("SHA3-256")) {
            return "SHA3256";
        }
        if (component.equalsIgnoreCase("SHA3256")) {
            return "SHA3-256";
        }

        /* SHA3-384 / SHA3384 variants */
        if (component.equalsIgnoreCase("SHA3-384")) {
            return "SHA3384";
        }
        if (component.equalsIgnoreCase("SHA3384")) {
            return "SHA3-384";
        }

        /* SHA3-512 / SHA3512 variants */
        if (component.equalsIgnoreCase("SHA3-512")) {
            return "SHA3512";
        }
        if (component.equalsIgnoreCase("SHA3512")) {
            return "SHA3-512";
        }

        /* Not a recognized SHA variant */
        return null;
    }

    /**
     * Get minimum key size limit from disabled algorithms security property
     * for specified algorithm.
     *
     * Parses constraints like "RSA keySize &lt; 1024" from the security
     * property and returns the minimum allowed key size.
     *
     * @param algo Algorithm to search for key size limitation for, options
     *             are "RSA", "DH", "DSA", and "EC".
     * @param propertyName Security property name to check
     *                     (e.g., "jdk.certpath.disabledAlgorithms")
     *
     * @return minimum key size allowed, or 0 if not set in property
     */
    public static int getDisabledAlgorithmsKeySizeLimit(String algo,
        String propertyName) {

        int ret = 0;
        List<String> disabledList = null;
        Pattern p = Pattern.compile("\\d+");
        Matcher match = null;
        String needle = null;
        String disabledAlgos = null;

        if (algo == null || algo.isEmpty()) {
            return ret;
        }

        if (propertyName == null || propertyName.isEmpty()) {
            return ret;
        }

        disabledAlgos = Security.getProperty(propertyName);
        if (disabledAlgos == null) {
            return ret;
        }

        switch (algo) {
            case "RSA":
                needle = "RSA keySize <";
                break;
            case "DH":
                needle = "DH keySize <";
                break;
            case "DSA":
                needle = "DSA keySize <";
                break;
            case "EC":
                needle = "EC keySize <";
                break;
            default:
                return ret;
        }

        /* Remove spaces after commas, split into List */
        disabledAlgos = disabledAlgos.replaceAll(", ", ",");
        disabledList = Arrays.asList(disabledAlgos.split(","));

        for (String s: disabledList) {
            if (s.contains(needle)) {
                match = p.matcher(s);
                if (match.find()) {
                    try {
                        ret = Integer.parseInt(match.group());
                    } catch (NumberFormatException e) {
                        /* Number exceeds Integer.MAX_VALUE, ignore malformed
                         * number and leave ret unchanged. */
                    }
                }
            }
        }

        return ret;
    }

    /**
     * Check if a public key meets the size constraints specified in a
     * security property.
     *
     * Extracts the key size based on key type (RSA, EC, DSA) and compares
     * against minimum size constraints from the security property.
     *
     * @param key PublicKey to check
     * @param propertyName Security property name to check constraints from
     *                     (e.g., "jdk.certpath.disabledAlgorithms")
     *
     * @return true if key is allowed (meets size requirements), false if
     *         key size is too small or key type is unsupported
     */
    public static boolean isKeyAllowed(PublicKey key, String propertyName) {

        int keySize = 0;
        int minSize = 0;
        String algorithm = null;

        if (key == null) {
            return false;
        }

        if (propertyName == null || propertyName.isEmpty()) {
            /* No property set, allow key */
            return true;
        }

        algorithm = key.getAlgorithm();

        /* Extract key size based on key type */
        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey)key;
            keySize = rsaKey.getModulus().bitLength();
            minSize = getDisabledAlgorithmsKeySizeLimit("RSA", propertyName);
        }
        else if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey)key;
            ECParameterSpec params = ecKey.getParams();
            if (params != null) {
                /* EC key size is the order bit length */
                keySize = params.getOrder().bitLength();
            }
            minSize = getDisabledAlgorithmsKeySizeLimit("EC", propertyName);
        }
        else if (key instanceof DSAPublicKey) {
            DSAPublicKey dsaKey = (DSAPublicKey)key;
            if (dsaKey.getParams() != null) {
                keySize = dsaKey.getParams().getP().bitLength();
            }
            minSize = getDisabledAlgorithmsKeySizeLimit("DSA", propertyName);
        }
        else {
            /* Unsupported key type, check if algorithm itself is disabled */
            return !isAlgorithmDisabled(algorithm, propertyName);
        }

        /* If minimum size constraint exists and key is smaller, reject */
        if (minSize > 0 && keySize < minSize) {
            return false;
        }

        /* Check if algorithm name is disabled */
        if (isAlgorithmDisabled(algorithm, propertyName)) {
            return false;
        }

        return true;
    }

    /**
     * Get parsed list of disabled algorithms from security property.
     *
     * @param propertyName Security property name to parse
     *                     (e.g., "jdk.certpath.disabledAlgorithms")
     *
     * @return List of disabled algorithm strings, or empty list if property
     *         not set
     */
    public static List<String> getDisabledAlgorithmsList(String propertyName) {

        String disabledAlgos = null;

        if (propertyName == null || propertyName.isEmpty()) {
            return new ArrayList<String>();
        }

        disabledAlgos = Security.getProperty(propertyName);
        if (disabledAlgos == null || disabledAlgos.isEmpty()) {
            return new ArrayList<String>();
        }

        /* Remove spaces after commas, split into List */
        disabledAlgos = disabledAlgos.replaceAll(", ", ",");
        return Arrays.asList(disabledAlgos.split(","));
    }
}

