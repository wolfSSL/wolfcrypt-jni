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
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

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
}
