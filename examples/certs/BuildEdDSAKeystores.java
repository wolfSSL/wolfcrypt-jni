/* BuildEdDSAKeystores.java
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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Build WKS (WolfSSLKeyStore) files containing Ed25519 and Ed448 cert/key
 * pairs from the wolfssl certs/ed25519 and certs/ed448 files copied into
 * examples/certs/ed25519 and examples/certs/ed448.
 *
 * Used by examples/certs/update-jks-wks.sh to generate the EdDSA test
 * keystores used by WolfSSLKeyStoreTest.
 *
 * Compiles and runs on any JDK 8+ with wolfJCE installed. Does not require
 * JDK 15 SunEC EdDSA support, keytool EdDSA awareness, or openssl.
 *
 * Usage: java -cp <wolfcrypt-jni.jar>:. BuildEdDSAKeystores [--check]
 *        (run from examples/certs/)
 *
 * With --check, exits 0 when wolfJCE has EdDSA support and 2 otherwise
 * (used by update-jks-wks.sh to decide whether to regenerate). Ed448
 * keystores are built only when Ed448 is compiled into native wolfSSL.
 */
public class BuildEdDSAKeystores {

    private static final String[] CURVES = { "ed25519", "ed448" };
    private static final char[]   PASSWORD = "wolfsslpassword".toCharArray();

    public static void main(String[] args) throws Exception {

        Security.addProvider(new WolfCryptProvider());

        if (args.length > 0 && args[0].equals("--check")) {
            try {
                KeyFactory.getInstance("EdDSA", "wolfJCE");
                System.exit(0);
            }
            catch (Exception e) {
                System.exit(2);
            }
        }

        int built = 0;

        for (String curve : CURVES) {
            String jcaName = curve.equals("ed25519") ? "Ed25519" : "Ed448";
            KeyFactory kf;
            try {
                kf = KeyFactory.getInstance(jcaName, "wolfJCE");
            }
            catch (Exception e) {
                System.out.println("\tSkipping " + jcaName +
                    ", not compiled into native wolfSSL");
                continue;
            }

            /* update-certs.sh skips missing files one by one. Check all inputs
             * before building anything for this curve */
            String[] inputs = {
                curve + "/server-" + curve + ".der",
                curve + "/server-" + curve + "-priv.der",
                curve + "/client-" + curve + ".der",
                curve + "/client-" + curve + "-priv.der",
                curve + "/ca-" + curve + ".der"
            };
            String missing = null;
            for (String in : inputs) {
                if (!Files.exists(Paths.get(in))) {
                    missing = in;
                    break;
                }
            }
            if (missing != null) {
                System.out.println("\tSkipping " + jcaName + ", " + missing +
                    " not present");
                continue;
            }

            /* server / client entity keystores: cert + private key, built
             * as .tmp so a failure leaves the prebuilt files untouched */
            for (String who : new String[] { "server", "client" }) {
                String name = who + "-" + curve;
                Certificate cert = loadDerCertificate(
                    curve + "/" + name + ".der");
                PrivateKey priv = loadDerPkcs8PrivateKey(kf,
                    curve + "/" + name + "-priv.der");
                buildWks(name + ".wks.tmp", name, priv,
                    new Certificate[] { cert });
            }

            /* CA truststore: the CA cert as a trusted entry */
            buildWksTrustStore("ca-" + curve + ".wks.tmp", "ca-" + curve,
                loadDerCertificate(curve + "/ca-" + curve + ".der"));

            for (String who : new String[] { "server", "client", "ca" }) {
                String name = who + "-" + curve + ".wks";
                Files.move(Paths.get(name + ".tmp"), Paths.get(name),
                    StandardCopyOption.REPLACE_EXISTING);
            }
            built++;
        }

        /* a skipped curve is not an error, update-jks-wks.sh keeps its
         * prebuilt keystores */
        if (built == 0) {
            System.out.println("No EdDSA WKS keystores built");
        }
        else {
            System.out.println("Built EdDSA WKS keystores for " + built +
                " curve(s)");
        }
    }

    private static Certificate loadDerCertificate(String path)
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

    private static PrivateKey loadDerPkcs8PrivateKey(KeyFactory kf,
        String path) throws Exception {

        byte[] der = Files.readAllBytes(Paths.get(path));
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
