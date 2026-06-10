/* WolfSSLKeyStoreGetKeyBenchmark.java
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
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.wolfssl.provider.jce.WolfCryptProvider;

/**
 * Benchmark for WolfSSLKeyStore getKey() performance.
 *
 * This benchmark measures the time taken to repeatedly call getKey() on
 * a single KeyStore object, which exercises the PBKDF2 key derivation path.
 * Use this to establish baseline performance before KEK caching, and to
 * measure improvements after enabling the cache.
 */
public class WolfSSLKeyStoreGetKeyBenchmark {

    /* Default parameters */
    private static int iterations = 100;
    private static boolean enableCache = false;
    private static String cacheTtlSec = "300";
    private static boolean testPrivateKey = true;
    private static boolean testSecretKey = true;

    /* KeyStore configuration */
    private static String storePass = "benchmarkpassword";
    private static String keyPass = "benchmarkpassword";

    /* Test files */
    private static String tmpKeyStoreFile = "getkey_benchmark_tmp.wks";
    private static String serverCertDer = "../../certs/server-cert.der";
    private static String serverKeyPkcs8Der = "../../certs/server-keyPkcs8.der";

    /**
     * Print usage information
     */
    private static void printUsage() {
        System.out.println("WolfSSLKeyStore getKey() Benchmark");
        System.out.println("");
        System.out.println("Usage: java WolfSSLKeyStoreGetKeyBenchmark " +
            "[options]");
        System.out.println("");
        System.out.println("Options:");
        System.out.println("  -iterations <n>    " +
            "Number of getKey() calls (default: 100)");
        System.out.println("  -enableCache       " +
            "Enable KEK caching");
        System.out.println("  -cacheTtl <sec>    " +
            "Cache TTL in seconds (default: 300)");
        System.out.println("  -privateOnly       " +
            "Only test private key retrieval");
        System.out.println("  -secretOnly        " +
            "Only test secret key retrieval");
        System.out.println("  -help              " +
            "Show this help message");
        System.out.println("");
        System.out.println("Examples:");
        System.out.println("  java WolfSSLKeyStoreGetKeyBenchmark");
        System.out.println("  java WolfSSLKeyStoreGetKeyBenchmark " +
            "-iterations 50");
        System.out.println("  java WolfSSLKeyStoreGetKeyBenchmark " +
            "-enableCache -iterations 1000");
    }

    /**
     * Parse command line arguments
     */
    private static void parseArgs(String[] args) {

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-iterations") && i + 1 < args.length) {
                try {
                    iterations = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid iteration count: " + args[i]);
                    printUsage();
                    System.exit(1);
                }
            } else if (args[i].equals("-enableCache")) {
                enableCache = true;
            } else if (args[i].equals("-cacheTtl") && i + 1 < args.length) {
                cacheTtlSec = args[++i];
            } else if (args[i].equals("-privateOnly")) {
                testPrivateKey = true;
                testSecretKey = false;
            } else if (args[i].equals("-secretOnly")) {
                testPrivateKey = false;
                testSecretKey = true;
            } else if (args[i].equals("-help") || args[i].equals("--help")) {
                printUsage();
                System.exit(0);
            } else {
                System.err.println("Unknown argument: " + args[i]);
                printUsage();
                System.exit(1);
            }
        }
    }

    /**
     * Create PrivateKey from DER file
     */
    private static PrivateKey loadPrivateKey(String derPath)
        throws Exception {

        byte[] keyBytes;
        PKCS8EncodedKeySpec spec;
        KeyFactory kf;

        keyBytes = Files.readAllBytes(new File(derPath).toPath());
        spec = new PKCS8EncodedKeySpec(keyBytes);
        kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(spec);
    }

    /**
     * Load Certificate from DER file
     */
    private static Certificate loadCertificate(String derPath)
        throws Exception {

        CertificateFactory cf;
        Certificate cert;

        cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(derPath)) {
            cert = cf.generateCertificate(fis);
        }

        return cert;
    }

    /**
     * Create test KeyStore with entries
     */
    private static KeyStore createTestKeyStore() throws Exception {

        KeyStore store;
        KeyStore loadedStore;
        PrivateKey privKey;
        Certificate cert;
        KeyGenerator keyGen;
        SecretKey secretKey;

        store = KeyStore.getInstance("WKS", "wolfJCE");
        store.load(null, storePass.toCharArray());

        /* Add private key entry */
        privKey = loadPrivateKey(serverKeyPkcs8Der);
        cert = loadCertificate(serverCertDer);
        store.setKeyEntry("testPrivateKey", privKey, keyPass.toCharArray(),
            new Certificate[] { cert });

        /* Add secret key entry */
        keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        secretKey = keyGen.generateKey();
        store.setKeyEntry("testSecretKey", secretKey, keyPass.toCharArray(),
            null);

        /* Save to file */
        try (FileOutputStream fos = new FileOutputStream(tmpKeyStoreFile)) {
            store.store(fos, storePass.toCharArray());
        }

        /* Reload from file to simulate real usage */
        loadedStore = KeyStore.getInstance("WKS", "wolfJCE");
        try (FileInputStream fis = new FileInputStream(tmpKeyStoreFile)) {
            loadedStore.load(fis, storePass.toCharArray());
        }

        return loadedStore;
    }

    /**
     * Run benchmark for a specific key alias
     */
    private static void runBenchmark(KeyStore store, String alias,
        String keyType) throws Exception {

        long[] times = new long[iterations];
        long totalTime = 0;
        long minTime = Long.MAX_VALUE;
        long maxTime = 0;

        System.out.println("\nBenchmarking " + keyType + " retrieval:");
        System.out.println("  Alias: " + alias);
        System.out.println("  Iterations: " + iterations);
        System.out.println("");

        /* Run benchmark */
        for (int i = 0; i < iterations; i++) {
            long startTime = System.nanoTime();
            Key key = store.getKey(alias, keyPass.toCharArray());
            long endTime = System.nanoTime();

            if (key == null) {
                throw new Exception("getKey() returned null for alias: " +
                    alias);
            }

            long elapsed = endTime - startTime;
            times[i] = elapsed;
            totalTime += elapsed;

            if (elapsed < minTime) minTime = elapsed;
            if (elapsed > maxTime) maxTime = elapsed;

            /* Print progress every 10 iterations */
            if ((i + 1) % 10 == 0 || i == 0) {
                System.out.printf("  Iteration %d: %.2f ms%n", i + 1,
                    elapsed / 1_000_000.0);
            }
        }

        /* Calculate statistics */
        double avgTimeMs = (totalTime / (double) iterations) / 1_000_000.0;
        double minTimeMs = minTime / 1_000_000.0;
        double maxTimeMs = maxTime / 1_000_000.0;
        double totalTimeSec = totalTime / 1_000_000_000.0;
        double opsPerSec = iterations / totalTimeSec;

        /* Print results */
        System.out.println("");
        System.out.println("Results for " + keyType + ":");
        System.out.println("  ----------------------------------------");
        System.out.printf("  Total time:      %.3f sec%n", totalTimeSec);
        System.out.printf("  Average time:    %.2f ms/call%n", avgTimeMs);
        System.out.printf("  Min time:        %.2f ms%n", minTimeMs);
        System.out.printf("  Max time:        %.2f ms%n", maxTimeMs);
        System.out.printf("  Throughput:      %.2f ops/sec%n", opsPerSec);
        System.out.println("  ----------------------------------------");

        /* Show first call vs subsequent calls comparison */
        if (iterations > 1) {
            double firstCallMs = times[0] / 1_000_000.0;
            double avgSubsequent = 0;
            for (int i = 1; i < iterations; i++) {
                avgSubsequent += times[i];
            }
            avgSubsequent = (avgSubsequent / (iterations - 1)) / 1_000_000.0;

            System.out.println("");
            System.out.println("  First call vs subsequent:");
            System.out.printf("    First call:        %.2f ms%n", firstCallMs);
            System.out.printf("    Avg subsequent:    %.2f ms%n",
                avgSubsequent);
            if (enableCache && avgSubsequent < firstCallMs / 2) {
                System.out.printf("    Speedup:           %.1fx%n",
                    firstCallMs / avgSubsequent);
            }
        }
    }

    public static void main(String[] args) {
        try {
            parseArgs(args);

            System.out.println("===================================");
            System.out.println("WKS getKey() Performance Benchmark");
            System.out.println("===================================");
            System.out.println("");

            /* Register wolfJCE provider */
            Security.insertProviderAt(new WolfCryptProvider(), 1);

            /* Configure KEK cache if requested */
            if (enableCache) {
                Security.setProperty("wolfjce.keystore.kekCacheEnabled",
                    "true");
                Security.setProperty("wolfjce.keystore.kekCacheTtlSec",
                    cacheTtlSec);
                System.out.println("KEK Cache: ENABLED");
                System.out.println("Cache TTL: " + cacheTtlSec + " seconds");
            } else {
                System.out.println("KEK Cache: DISABLED (default)");
            }
            System.out.println("");

            /* Create test KeyStore */
            System.out.println("Creating test KeyStore...");
            KeyStore store = createTestKeyStore();
            System.out.println("KeyStore created with " + store.size() +
                " entries");

            /* Run benchmarks */
            if (testPrivateKey) {
                runBenchmark(store, "testPrivateKey", "Private Key");
            }

            if (testSecretKey) {
                runBenchmark(store, "testSecretKey", "Secret Key");
            }

            /* Cleanup */
            new File(tmpKeyStoreFile).delete();

            System.out.println("\n===================================");
            System.out.println("Benchmark complete");
            System.out.println("===================================");

        } catch (Exception e) {
            System.err.println("Benchmark failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

