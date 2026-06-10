/* WolfSSLKeyStoreExample.java
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.SecureRandom;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.wolfssl.provider.jce.WolfCryptProvider;

public class WolfSSLKeyStoreExample {

    /* KeyStore password */
    static String storePass = "wolfsslpassword";

    /* KeyStore output file */
    static String wksFile = "wolfssl.wks";

    /* KeyStore type */
    static String storeType = "WKS";

    /* RSA server cert and private key */
    static String serverCertRsaDer = "../../certs/server-cert.der";
    static String serverRsaPkcs8Der = "../../certs/server-keyPkcs8.der";

    /* ECC server cert and private key */
    static String serverCertEccDer = "../../certs/server-ecc.der";
    static String serverEccPkcs8Der = "../../certs/ecc-keyPkcs8.der";

    /* RSA server cert chain */
    static String intRsaServerCertDer =
        "../../certs/intermediate/server-int-cert.pem";
    static String intRsaInt1CertDer =
        "../../certs/intermediate/ca-int-cert.pem";
    static String intRsaInt2CertDer =
        "../../certs/intermediate/ca-int2-cert.pem";

    /* ECC server cert chain */
    static String intEccServerCertDer =
        "../../certs/intermediate/server-int-ecc-cert.der";
    static String intEccInt1CertDer =
        "../../certs/intermediate/ca-int-ecc-cert.der";
    static String intEccInt2CertDer =
        "../../certs/intermediate/ca-int2-ecc-cert.der";

    /**
     * Create and return PrivateKey object from file path to DER-encoded
     * private key file.
     *
     * @param derFilePath file path to DER-encoded PKCS#8 private key file
     * @param alg algorithm for KeyFactory instance (ex: "RSA", "EC")
     *
     * @return PrivateKey object created from file path given
     *
     * @throws IllegalArgumentException on bad argument or processing of arg
     * @throws IOException on error converting File to Path
     * @throws NoSuchAlgorithmException on bad "alg" when getting KeyFactory
     * @throws InvalidKeySpecException on error generating PrivateKey object
     * @throws Exception on other error
     */
    private static PrivateKey DerFileToPrivateKey(String derFilePath,
        String alg) throws IllegalArgumentException, IOException,
                           NoSuchAlgorithmException, InvalidKeySpecException,
                           InvalidKeySpecException {

        byte[] fileBytes = null;
        PKCS8EncodedKeySpec spec = null;
        KeyFactory kf = null;
        PrivateKey key = null;

        if (derFilePath == null || derFilePath.isEmpty()) {
            throw new IllegalArgumentException(
                "Input DER file path is null or empty");
        }

        fileBytes = Files.readAllBytes(new File(derFilePath).toPath());
        if (fileBytes == null || fileBytes.length == 0) {
            throw new IllegalArgumentException(
                "Bytes read from DER file is null or empty, bad file path?");
        }

        spec = new PKCS8EncodedKeySpec(fileBytes);
        if (spec == null) {
            throw new InvalidKeySpecException(
                "Unable to create PKCS8EncodedKeySpec");
        }

        kf = KeyFactory.getInstance(alg);
        key = kf.generatePrivate(spec);

        return key;
    }

    /**
     * Read in and convert certificate file to Certificate object.
     *
     * @param certPath path to DER-encoded certificate file
     *
     * @return new Certificate object representing certPath file
     *
     * @throws FileNotFoundException on error reading certPath file
     * @throws CertificateException on error geting CertificateFactory or
     *         generating Certificate object
     */
    private static Certificate CertFileToCertificate(String certPath)
        throws FileNotFoundException, CertificateException {

        CertificateFactory cf = null;
        Certificate cert = null;

        cf = CertificateFactory.getInstance("X.509");
        cert = cf.generateCertificate(new FileInputStream(certPath));

        return cert;
    }

    public static void InsertKeyStoreEntries(KeyStore store)
        throws FileNotFoundException, KeyStoreException, IOException,
               CertificateException, NoSuchAlgorithmException,
               InvalidKeySpecException {

        byte[] fileBytes = null;
        PrivateKey privKey = null;
        Certificate cert = null;
        Certificate[] chain = null;
        KeyGenerator kg = null;
        SecretKey aesKey = null;

        /* INSERT [1]: RSA cert only */
        cert = CertFileToCertificate(serverCertRsaDer);
        store.setCertificateEntry("serverRsa", cert);

        /* INSERT [2]: RSA priv key + single cert */
        privKey = DerFileToPrivateKey(serverRsaPkcs8Der, "RSA");
        store.setKeyEntry("rsaCert", privKey,
            storePass.toCharArray(), new Certificate[] { cert });

        /* INSERT [5]: RSA priv key + cert chain */
        chain = new Certificate[3];
        cert = CertFileToCertificate(intRsaServerCertDer);
        chain[0] = cert;
        cert = CertFileToCertificate(intRsaInt2CertDer);
        chain[1] = cert;
        cert = CertFileToCertificate(intRsaInt1CertDer);
        chain[2] = cert;
        store.setKeyEntry("rsaChain", privKey, storePass.toCharArray(), chain);

        /* INSERT [3]: ECC cert only */
        cert = CertFileToCertificate(serverCertEccDer);
        store.setCertificateEntry("serverEcc", cert);

        /* INSERT [4]: ECC priv key + single cert */
        privKey = DerFileToPrivateKey(serverEccPkcs8Der, "EC");
        store.setKeyEntry("eccCert", privKey,
            storePass.toCharArray(), new Certificate[] { cert });

        /* INSERT [6]: ECC priv key + cert chain */
        chain = new Certificate[3];
        cert = CertFileToCertificate(intEccServerCertDer);
        chain[0] = cert;
        cert = CertFileToCertificate(intEccInt2CertDer);
        chain[1] = cert;
        cert = CertFileToCertificate(intEccInt1CertDer);
        chain[2] = cert;
        store.setKeyEntry("eccChain", privKey, storePass.toCharArray(), chain);

        /* INSERT [7]: AES SecretKey */
        /* If running this example with JKS type, JKS cannot import
         * non-private keys. Only do for WKS type. */
        if (storeType.equals("WKS")) {
            kg = KeyGenerator.getInstance("AES");
            kg.init(256, new SecureRandom());
            aesKey = kg.generateKey();
            store.setKeyEntry("aesKey", aesKey, storePass.toCharArray(), null);
        }
    }

    public static void WriteKeyStoreToFile(KeyStore store)
        throws FileNotFoundException, KeyStoreException, IOException,
               NoSuchAlgorithmException, CertificateException {

        FileOutputStream fos = new FileOutputStream(wksFile);
        store.store(fos, storePass.toCharArray());
        fos.close();
    }

    public static KeyStore ReadKeyStoreFromFile(String fileName)
        throws KeyStoreException, FileNotFoundException, IOException,
               NoSuchAlgorithmException, CertificateException {

        KeyStore store = null;

        store = KeyStore.getInstance(storeType);
        store.load(new FileInputStream(fileName), storePass.toCharArray());

        return store;
    }

    public static void main(String args [])
    {
        KeyStore store = null;
        Provider p = null;

        System.out.println("WolfSSLKeyStore (WKS) Example App\n");

        /* Install wolfJCE */
        Security.insertProviderAt(new WolfCryptProvider(), 1);

        try {
            store = KeyStore.getInstance(storeType);
            store.load(null, storePass.toCharArray());

            p = store.getProvider();
            System.out.println("KeyStore('" + storeType + "') provider = " + p);

            /* Insert variety of entry types */
            System.out.println("\n-------------------------------------------");
            System.out.println("Inserting entries into KeyStore");
            System.out.println("-------------------------------------------");
            InsertKeyStoreEntries(store);

            /* Store KeyStore to file (wolfssl.wks) */
            System.out.println("\n-------------------------------------------");
            System.out.println("Writing KeyStore to file: " + wksFile);
            System.out.println("-------------------------------------------");
            WriteKeyStoreToFile(store);

            /* Read KeyStore back in from file */
            System.out.println("\n-------------------------------------------");
            System.out.println("Reading KeyStore in from file: " + wksFile);
            System.out.println("-------------------------------------------");
            store = ReadKeyStoreFromFile(wksFile);

            System.out.println("\nExample Finished Successfully");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

