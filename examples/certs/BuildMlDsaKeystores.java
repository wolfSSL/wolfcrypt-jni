/* BuildMlDsaKeystores.java
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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Build WKS (WolfSSLKeyStore) files containing ML-DSA cert/key pairs
 * from the wolfssl certs/mldsa/*.pem files.
 *
 * Used by examples/certs/update-jks-wks.sh to generate the
 * ML-DSA-{44,65,87} test keystores used by WolfSSLKeyStoreTest.
 *
 * Compiles and runs on any JDK 8+ with wolfJCE installed; does not
 * require JDK 24's SunJCE ML-DSA support, and does not require keytool
 * or openssl to have ML-DSA awareness.
 *
 * Usage: java -cp <wolfcrypt-jni.jar>:. BuildMlDsaKeystores
 *        (run from examples/certs/)
 *
 * Pass --check to only probe for wolfJCE ML-DSA support: exits 0 when
 * available, 2 when native wolfSSL was built without ML-DSA. Used by
 * update-jks-wks.sh to skip keystore generation gracefully.
 */
public class BuildMlDsaKeystores {

    private static final String[] LEVELS = { "44", "65", "87" };
    private static final char[]   PASSWORD = "wolfsslpassword".toCharArray();
    private static final String   CERT_DIR  = "mldsa";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new WolfCryptProvider());

        if (args.length > 0 && args[0].equals("--check")) {
            try {
                KeyFactory.getInstance("ML-DSA", "wolfJCE");
                System.exit(0);
            }
            catch (Exception e) {
                System.exit(2);
            }
        }

        for (String level : LEVELS) {
            String name = "mldsa" + level;
            String certPath = CERT_DIR + "/" + name + "-cert.pem";
            String keyPath  = CERT_DIR + "/" + name + "-key.pem";

            Certificate cert = loadPemCertificate(certPath);
            PrivateKey  priv = loadPemPkcs8PrivateKey(keyPath);

            /* Server keystore: ML-DSA-N entity cert + key */
            buildWks("server-mldsa" + level + ".wks", "server-mldsa" + level,
                priv, new Certificate[]{ cert });
            /* Client keystore: same pattern (self-signed certs reused) */
            buildWks("client-mldsa" + level + ".wks", "client-mldsa" + level,
                priv, new Certificate[]{ cert });
            /* CA truststore: just the cert as a trusted entry */
            buildWksTrustStore("ca-mldsa" + level + ".wks",
                "ca-mldsa" + level, cert);
        }

        System.out.println(
            "Built ML-DSA WKS keystores for levels 44/65/87");
    }

    private static Certificate loadPemCertificate(String path)
        throws Exception {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream in = new FileInputStream(path);
        try {
            return cf.generateCertificate(in);
        }
        finally {
            in.close();
        }
    }

    private static PrivateKey loadPemPkcs8PrivateKey(String path)
        throws Exception {

        String pem = new String(Files.readAllBytes(Paths.get(path)),
            StandardCharsets.US_ASCII);
        int begin = pem.indexOf("-----BEGIN");
        int end   = pem.indexOf("-----END");
        if (begin < 0 || end < 0) {
            throw new IllegalArgumentException(
                "PEM headers not found in: " + path);
        }
        int contentStart = pem.indexOf('\n', begin) + 1;
        String b64 = pem.substring(contentStart, end).replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(b64);

        KeyFactory kf = KeyFactory.getInstance("ML-DSA", "wolfJCE");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static void buildWks(String fileName, String alias,
        PrivateKey priv, Certificate[] chain) throws Exception {

        KeyStore ks = KeyStore.getInstance("WKS", "wolfJCE");
        ks.load(null, null);
        ks.setKeyEntry(alias, priv, PASSWORD, chain);

        FileOutputStream fos = new FileOutputStream(fileName);
        try {
            ks.store(fos, PASSWORD);
        }
        finally {
            fos.close();
        }
        System.out.println("\tCreated " + fileName);
    }

    private static void buildWksTrustStore(String fileName, String alias,
        Certificate cert) throws Exception {

        KeyStore ks = KeyStore.getInstance("WKS", "wolfJCE");
        ks.load(null, null);
        ks.setCertificateEntry(alias, cert);

        FileOutputStream fos = new FileOutputStream(fileName);
        try {
            ks.store(fos, PASSWORD);
        }
        finally {
            fos.close();
        }
        System.out.println("\tCreated " + fileName);
    }
}
