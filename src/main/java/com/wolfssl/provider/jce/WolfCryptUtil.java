/* WolfCryptUtil.java
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyFactory;
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
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.crypto.interfaces.DHPublicKey;

import com.wolfssl.wolfcrypt.MlDsa;
import com.wolfssl.wolfcrypt.SlhDsa;

/**
 * Utility class containing helper functions for wolfCrypt JCE provider.
 */
public class WolfCryptUtil {

    /** Default WolfCryptUtil constructor. */
    public WolfCryptUtil() {
    }

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
        WolfCryptDebug.log(WolfCryptUtil.class, WolfCryptDebug.INFO, () -> msg);
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
     * Entries may carry qualifiers after the algorithm name (ex:
     * "SHA1 jdkCA &amp; usage TLSServer"). This method treats all qualifiers
     * as if their conditions hold, keeping the entry active (fail closed).
     * Callers checking algorithms for CertPath validation should use
     * isAlgorithmDisabledForCertPath() instead, which skips entries that can
     * never apply to that context.
     *
     * Include directives (ex: "include jdk.disabled.namedCurves") are
     * expanded to the entries of the referenced property.
     *
     * @param algorithm Algorithm name to check (e.g., "MD2", "MD5",
     *                  "SHA1withRSA", "MD2withRSA")
     * @param propertyName Security property name to check against
     *                     (ex: "jdk.certpath.disabledAlgorithms")
     *
     * @return true if algorithm is disabled, false otherwise
     */
    public static boolean isAlgorithmDisabled(String algorithm,
        String propertyName) {

        return isAlgorithmDisabled(algorithm, propertyName, false);
    }

    /**
     * Check if a given algorithm is disabled for CertPath validation based
     * on a security property.
     *
     * Same as isAlgorithmDisabled(), except entries restricted to usage
     * contexts that can never apply to validation done through the standard
     * CertPath API (TLSServer, TLSClient, SignedJAR) are skipped, matching
     * JDK behavior. All other qualifiers (jdkCA, denyAfter, unrecognized)
     * are treated as if their conditions hold, keeping the entry active
     * (fail closed).
     *
     * @param algorithm Algorithm name to check (e.g., "MD2", "MD5",
     *                  "SHA1withRSA", "MD2withRSA")
     * @param propertyName Security property name to check against
     *                     (ex: "jdk.certpath.disabledAlgorithms")
     *
     * @return true if algorithm is disabled, false otherwise
     */
    public static boolean isAlgorithmDisabledForCertPath(String algorithm,
        String propertyName) {

        return isAlgorithmDisabled(algorithm, propertyName, true);
    }

    /**
     * Internal implementation of the disabled algorithm checks above.
     *
     * @param algorithm Algorithm name to check
     * @param propertyName Security property name to check against
     * @param certPathContext true when checking for CertPath validation,
     *        skips entries scoped to usage contexts that can never apply
     *        there
     *
     * @return true if algorithm is disabled, false otherwise
     */
    private static boolean isAlgorithmDisabled(String algorithm,
        String propertyName, boolean certPathContext) {

        List<String> disabledList = null;

        if (algorithm == null || algorithm.isEmpty()) {
            return false;
        }

        if (propertyName == null || propertyName.isEmpty()) {
            return false;
        }

        /* Get property entries, with include directives expanded */
        disabledList = getExpandedDisabledEntries(propertyName);
        if (disabledList.isEmpty()) {
            return false;
        }

        /* Decompose composite algorithm names like "MD2withRSA" into
         * constituent parts and check each. Common formats:
         *   - "MD2withRSA" - ["MD2", "RSA"]
         *   - "SHA1withECDSA" - ["SHA1", "ECDSA"]
         *   - "SHA256withRSA" - ["SHA256", "RSA"]
         * Use case-insensitive matching to match SunJCE behavior */
        String[] parts = decomposeAlgorithmName(algorithm);

        for (String disabled : disabledList) {
            /* Entries may carry qualifiers, for example the JDK 11+ default
             * "SHA1 jdkCA & denyAfter 2019-01-01". Compare against the
             * leading algorithm name only. */
            String disabledName = extractDisabledAlgorithmName(disabled);
            if (disabledName == null || disabledName.isEmpty()) {
                continue;
            }

            /* Skip key-size constraints such as "RSA keySize < 1024". Those
             * are size limits enforced by isKeyAllowed(), not signature name
             * disables. */
            if (disabled.toLowerCase(Locale.ROOT).contains("keysize")) {
                continue;
            }

            /* For CertPath callers, skip entries scoped to usage contexts
             * that never apply there (ex: "SHA1 jdkCA & usage TLSServer") */
            if (certPathContext && !disabledEntryAppliesToCertPath(disabled)) {
                continue;
            }

            /* Check the full algorithm name (case-insensitive) */
            if (disabledName.equalsIgnoreCase(algorithm)) {
                return true;
            }

            /* Match the full entry too, curve entries can contain a
             * space (ex: "X9.62 c2tnb191v1") */
            if (disabled.trim().equalsIgnoreCase(algorithm)) {
                return true;
            }

            /* Check each decomposed part */
            for (String part : parts) {
                if (disabledName.equalsIgnoreCase(part)) {
                    return true;
                }
            }

            /* Known PQ family entries also disable all of their parameter
             * sets (ex "ML-DSA" disables "ML-DSA-44"). */
            if (isPQFamilyName(disabledName)) {
                String prefix = disabledName + "-";
                if (algorithm.regionMatches(true, 0, prefix, 0,
                    prefix.length())) {
                    return true;
                }
                for (String part : parts) {
                    if (part.regionMatches(true, 0, prefix, 0,
                        prefix.length())) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get the entries of a disabled-algorithms security property, with
     * include directives (ex: "include jdk.disabled.namedCurves") expanded
     * to the entries of the referenced property, matching JDK behavior.
     * Each property is expanded at most once to guard against include
     * cycles.
     *
     * @param propertyName Security property name to read
     *
     * @return list of trimmed entries, empty list if property is not set
     */
    private static List<String> getExpandedDisabledEntries(
        String propertyName) {

        List<String> entries = new ArrayList<String>();
        Deque<String> pending = new ArrayDeque<String>();
        Set<String> expanded = new HashSet<String>();
        String propValue = null;

        pending.add(propertyName);

        while (!pending.isEmpty()) {
            String prop = pending.removeFirst();

            /* Expand each property at most once, guards include cycles */
            if (!expanded.add(prop)) {
                continue;
            }

            propValue = Security.getProperty(prop);
            if (propValue == null || propValue.isEmpty()) {
                continue;
            }

            for (String entry : propValue.split(",")) {
                entry = entry.trim();
                if (entry.regionMatches(true, 0, "include ", 0, 8)) {
                    pending.add(entry.substring(8).trim());
                }
                else if (!entry.isEmpty()) {
                    entries.add(entry);
                }
            }
        }

        return entries;
    }

    /**
     * Extract the leading algorithm name from a single
     * jdk.certpath.disabledAlgorithms list entry, dropping any qualifiers.
     *
     * For example "SHA1 jdkCA ..." returns "SHA1" and
     * "RSA keySize ..." returns "RSA".
     *
     * @param entry a single disabled-algorithms list entry
     *
     * @return the leading algorithm name, or null if none could be extracted
     */
    private static String extractDisabledAlgorithmName(String entry) {

        String[] tokens = null;

        if (entry == null) {
            return null;
        }

        /* Split on the first whitespace or '&' qualifier separator */
        tokens = entry.trim().split("[\\s&]");
        if (tokens.length == 0) {
            return null;
        }

        return tokens[0].trim();
    }

    /**
     * Determine if a single disabled-algorithms list entry applies to generic
     * CertPath validation.
     *
     * Qualifiers after the algorithm name are ANDed together
     * (ex: "SHA1 jdkCA &amp; usage TLSServer"). A usage qualifier that
     * names only contexts which can never apply to CertPath validation
     * (TLSServer, TLSClient, SignedJAR) can never be satisfied, which
     * makes the whole ANDed entry non-applicable, matching JDK behavior.
     * All other qualifiers (jdkCA, denyAfter, malformed or unrecognized) are
     * treated as if their conditions hold (fail closed).
     *
     * @param entry a single disabled-algorithms list entry
     *
     * @return false if the entry can never apply to generic CertPath
     *         validation, true otherwise (fail closed)
     */
    private static boolean disabledEntryAppliesToCertPath(String entry) {

        int idx = 0;
        String qualifiers = null;
        String[] groups = null;
        String[] usageTokens = null;
        boolean allRecognized = false;

        if (entry == null) {
            return true;
        }

        /* Leading algorithm name ends at first space, rest is qualifiers */
        entry = entry.trim();
        idx = entry.indexOf(' ');
        if (idx < 0) {
            /* Bare algorithm name, no qualifiers */
            return true;
        }
        qualifiers = entry.substring(idx + 1).trim();

        /* Split ANDed qualifier groups */
        groups = qualifiers.split("&");

        for (String group : groups) {
            usageTokens = group.trim().split("\\s+");

            if (usageTokens.length < 2 ||
                !usageTokens[0].equalsIgnoreCase("usage")) {
                /* Not a usage qualifier, treat as satisfied (fail closed) */
                continue;
            }

            /* An unrecognized usage context keeps entry active (fail closed) */
            allRecognized = true;
            for (int i = 1; i < usageTokens.length; i++) {
                if (!usageTokens[i].equalsIgnoreCase("TLSServer") &&
                    !usageTokens[i].equalsIgnoreCase("TLSClient") &&
                    !usageTokens[i].equalsIgnoreCase("SignedJAR")) {
                    allRecognized = false;
                    break;
                }
            }

            if (allRecognized) {
                /* Usage condition can never hold here, and conditions are
                 * ANDed, so the entry can never apply */
                return false;
            }
        }

        return true;
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
     * property and returns the minimum allowed key size. Entries are
     * matched on their leading algorithm name, any algorithm name may be
     * used. Only the "&lt;" and "&lt;=" operators are supported, entries
     * using other operators are ignored.
     *
     * @param algo Algorithm to search for key size limitation for
     *             (ex: "RSA", "DH", "DSA", "EC")
     * @param propertyName Security property name to check
     *                     (e.g., "jdk.certpath.disabledAlgorithms")
     *
     * @return minimum key size allowed, or 0 if not set in property
     */
    public static int getDisabledAlgorithmsKeySizeLimit(String algo,
        String propertyName) {

        return getDisabledAlgorithmsKeySizeLimit(algo, propertyName, false);
    }

    /**
     * Internal implementation of getDisabledAlgorithmsKeySizeLimit().
     *
     * Matches entries on their leading algorithm name so that, for
     * example, an "ECDH keySize" entry does not set the "DH" limit.
     *
     * @param algo Algorithm to search for key size limitation for
     *        (ex: "RSA", "DH", "DSA", "EC")
     * @param propertyName Security property name to check
     * @param certPathContext true when checking for CertPath validation,
     *        skips entries scoped to usage contexts that can never apply
     *        there
     *
     * @return minimum key size allowed, or 0 if not set in property
     */
    private static int getDisabledAlgorithmsKeySizeLimit(String algo,
        String propertyName, boolean certPathContext) {

        int ret = 0;
        List<String> disabledList = null;
        Pattern p = Pattern.compile("keySize\\s*<(=?)\\s*(\\d+)",
            Pattern.CASE_INSENSITIVE);
        Matcher match = null;

        if (algo == null || algo.isEmpty()) {
            return ret;
        }

        if (propertyName == null || propertyName.isEmpty()) {
            return ret;
        }

        /* Get property entries, with include directives expanded */
        disabledList = getExpandedDisabledEntries(propertyName);

        for (String s : disabledList) {
            /* Match on the leading algorithm name only, so "ECDH keySize"
             * does not match algo "DH" */
            String disabledName = extractDisabledAlgorithmName(s);
            if (disabledName == null || !disabledName.equalsIgnoreCase(algo)) {
                continue;
            }

            /* For CertPath callers, skip entries scoped to usage contexts
             * that never apply there */
            if (certPathContext && !disabledEntryAppliesToCertPath(s)) {
                continue;
            }

            match = p.matcher(s);
            if (match.find()) {
                try {
                    int limit = Integer.parseInt(match.group(2));
                    if (match.group(1).equals("=") &&
                        limit < Integer.MAX_VALUE) {
                        /* "keySize <= N" disables through N, minimum allowed
                         * size is N + 1 */
                        limit = limit + 1;
                    }
                    /* Keep the strictest of multiple matching entries */
                    ret = Math.max(ret, limit);
                } catch (NumberFormatException e) {
                    /* Number exceeds Integer.MAX_VALUE, ignore malformed
                     * number and leave ret unchanged. */
                }
            }
        }

        return ret;
    }

    /**
     * Check if a public key meets size constraints in a security property.
     *
     * Extracts key size based on key type (RSA, EC, DSA, DH) and compares
     * against minimum size constraints from the security property. ML-DSA
     * and SLH-DSA keys have fixed parameter sets rather than key sizes,
     * and are checked by family and parameter set name (ex: "ML-DSA",
     * "ML-DSA-44").
     *
     * @param key PublicKey to check
     * @param propertyName Security property name to check constraints from
     *                     (ex: "jdk.certpath.disabledAlgorithms")
     *
     * @return true if key is allowed (meets size requirements), false if
     *         key size is too small or key type is unsupported
     */
    public static boolean isKeyAllowed(PublicKey key, String propertyName) {

        return isKeyAllowed(key, propertyName, false);
    }

    /**
     * Check if a public key meets size constraints specified in a security
     * property, for use during CertPath validation.
     *
     * Same as isKeyAllowed(), except algorithm name checks use
     * isAlgorithmDisabledForCertPath() semantics, skipping entries scoped
     * to usage contexts that can never apply to CertPath validation.
     *
     * @param key PublicKey to check
     * @param propertyName Security property name to check constraints from
     *                     (ex: "jdk.certpath.disabledAlgorithms")
     *
     * @return true if key is allowed (meets size requirements), false if
     *         key size is too small or key type is unsupported
     */
    public static boolean isKeyAllowedForCertPath(PublicKey key,
        String propertyName) {

        return isKeyAllowed(key, propertyName, true);
    }

    /**
     * Internal implementation of key constraint checks above.
     *
     * @param key PublicKey to check
     * @param propertyName Security property name to check constraints from
     * @param certPathContext true when checking for CertPath validation
     *
     * @return true if key is allowed, false otherwise
     */
    private static boolean isKeyAllowed(PublicKey key, String propertyName,
        boolean certPathContext) {

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
            minSize = getDisabledAlgorithmsKeySizeLimit("RSA", propertyName,
                certPathContext);
        }
        else if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey)key;
            ECParameterSpec params = ecKey.getParams();
            if (params != null) {
                /* EC key size is the order bit length */
                keySize = params.getOrder().bitLength();
            }

            /* Check named curve against disabled entries when the curve name
             * can be determined, covers curves included from
             * jdk.disabled.namedCurves. Keys whose curve cannot be determined
             * are checked by size only. The "X9.62 " form matches JDK entries
             * like "X9.62 c2tnb191v1". Skip curve resolution when the property
             * has no entries, avoids native key translation with nothing to
             * check against. */
            String disabledProp = Security.getProperty(propertyName);
            if (disabledProp != null && !disabledProp.isEmpty()) {
                String curve = getECCurveName(ecKey);
                if (curve != null &&
                    (isAlgorithmDisabled(curve, propertyName,
                        certPathContext) ||
                     isAlgorithmDisabled("X9.62 " + curve, propertyName,
                        certPathContext))) {
                    return false;
                }
            }

            minSize = getDisabledAlgorithmsKeySizeLimit("EC", propertyName,
                certPathContext);
        }
        else if (key instanceof DSAPublicKey) {
            DSAPublicKey dsaKey = (DSAPublicKey)key;
            if (dsaKey.getParams() != null) {
                keySize = dsaKey.getParams().getP().bitLength();
            }
            minSize = getDisabledAlgorithmsKeySizeLimit("DSA", propertyName,
                certPathContext);
        }
        else if (key instanceof DHPublicKey) {
            DHPublicKey dhKey = (DHPublicKey)key;
            if (dhKey.getParams() != null) {
                keySize = dhKey.getParams().getP().bitLength();
            }
            minSize = getDisabledAlgorithmsKeySizeLimit("DH", propertyName,
                certPathContext);
        }
        else if (key instanceof WolfCryptMlDsaPublicKey) {
            /* ML-DSA uses fixed parameter sets, no key size constraints */
            return isPQKeyAllowed(algorithm,
                MlDsa.getParamSetName(
                    ((WolfCryptMlDsaPublicKey)key).getLevel()),
                propertyName, certPathContext);
        }
        else if (key instanceof WolfCryptSlhDsaPublicKey) {
            /* SLH-DSA uses fixed parameter sets, no key size constraints */
            return isPQKeyAllowed(algorithm,
                SlhDsa.getParamSetName(
                    ((WolfCryptSlhDsaPublicKey)key).getParam()),
                propertyName, certPathContext);
        }
        else {
            /* Unsupported key type, check if algorithm itself is disabled */
            return !isAlgorithmDisabled(algorithm, propertyName,
                certPathContext);
        }

        /* If minimum size constraint exists and key is smaller, reject */
        if (minSize > 0 && keySize < minSize) {
            return false;
        }

        /* Check if algorithm name is disabled */
        if (isAlgorithmDisabled(algorithm, propertyName, certPathContext)) {
            return false;
        }

        return true;
    }

    /**
     * Get the named curve of an EC public key, when determinable.
     *
     * wolfJCE keys carry the curve name in their parameters. Keys from
     * other providers are re-resolved through the wolfJCE EC KeyFactory
     * to detect the curve.
     *
     * @param ecKey EC public key to get curve name of
     *
     * @return curve name (ex: "SECP256R1"), or null if the curve could
     *         not be determined
     */
    private static String getECCurveName(ECPublicKey ecKey) {

        ECParameterSpec params = ecKey.getParams();

        if (params instanceof WolfCryptECParameterSpec) {
            return ((WolfCryptECParameterSpec)params).getStoredCurveName();
        }

        /* Key from other provider, re-resolve through the wolfJCE EC
         * KeyFactory to detect the curve */
        try {
            Key translated =
                new WolfCryptECKeyFactory().engineTranslateKey(ecKey);
            if (translated instanceof ECPublicKey) {
                params = ((ECPublicKey)translated).getParams();
                if (params instanceof WolfCryptECParameterSpec) {
                    return ((WolfCryptECParameterSpec)params)
                        .getStoredCurveName();
                }
            }
        } catch (Exception e) {
            /* Unable to translate key, curve name unknown. */
            log("Unable to resolve EC curve name for disabled algo check:" +
                e.getMessage());
        }

        return null;
    }

    /**
     * Check a post-quantum public key against disabled algorithm entries
     * by family and parameter set name.
     *
     * @param family family algorithm name (ex: "ML-DSA")
     * @param paramSet parameter set name (ex: "ML-DSA-44"), null is
     *        treated as not allowed (fail closed)
     * @param propertyName Security property name to check against
     * @param certPathContext true when checking for CertPath validation
     *
     * @return true if key is allowed, false otherwise
     */
    private static boolean isPQKeyAllowed(String family, String paramSet,
        String propertyName, boolean certPathContext) {

        if (paramSet == null) {
            /* Unknown parameter set, fail closed */
            return false;
        }

        if (isAlgorithmDisabled(family, propertyName, certPathContext)) {
            return false;
        }

        if (isAlgorithmDisabled(paramSet, propertyName, certPathContext)) {
            return false;
        }

        return true;
    }

    /**
     * Check if an algorithm name is a known post-quantum family name.
     * A disabled-algorithms entry with a family name also disables all
     * parameter sets of that family.
     *
     * @param name algorithm name to check
     *
     * @return true if name is a PQ family name, false otherwise
     */
    private static boolean isPQFamilyName(String name) {

        return name.equalsIgnoreCase("ML-DSA") ||
               name.equalsIgnoreCase("SLH-DSA") ||
               name.equalsIgnoreCase("ML-KEM");
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

    /**
     * Get a KeyFactory for the given algorithm, preferring wolfJCE if it
     * registers one and falling back to default Provider lookup otherwise.
     *
     * @param algorithm KeyFactory algorithm name (e.g. "RSA", "EC", "DH")
     *
     * @return KeyFactory instance, never null
     *
     * @throws NoSuchAlgorithmException if no Provider supports the algorithm
     */
    public static KeyFactory getKeyFactoryPreferWolfJCE(String algorithm)
        throws NoSuchAlgorithmException {

        try {
            return KeyFactory.getInstance(algorithm, "wolfJCE");
        } catch (NoSuchAlgorithmException e) {
            return KeyFactory.getInstance(algorithm);
        } catch (NoSuchProviderException e) {
            return KeyFactory.getInstance(algorithm);
        }
    }

    /**
     * Return key.getEncoded(), throwing InvalidKeySpecException if the key
     * has no encoded form.
     *
     * @param key Key to get the encoding from
     * @param expectedFormat encoding format name used in the exception
     *        message (ex: "PKCS#8" or "X.509")
     *
     * @return encoded key bytes
     *
     * @throws InvalidKeySpecException if key.getEncoded() is null or empty
     */
    static byte[] requireEncoded(Key key, String expectedFormat)
        throws InvalidKeySpecException {

        byte[] encoded = key.getEncoded();

        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeySpecException(
                "Key has no encoded form (expected " + expectedFormat + ")");
        }

        return encoded;
    }
}

