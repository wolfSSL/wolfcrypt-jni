/* KeyStoreBenchmark.java
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
import java.util.Enumeration;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.wolfssl.provider.jce.WolfCryptProvider;

public class KeyStoreBenchmark {

    /* Default test parameters */
    private static final int WARMUP_ITERATIONS = 10;
    private static final int BENCHMARK_ITERATIONS = 1000;
    private static final int MIN_TEST_TIME_MS = 5000; /* 5 seconds minimum */

    /* KeyStore configuration */
    private static String storePass = "wolfsslbenchmarkpassword";
    private static String storeType = "WKS";
    private static String providerName = "wolfJCE";
    private static boolean benchmarkAll = true;
    private static String currentDisplayName = null;
    private static String customIterationCount = "20000";

    /* Test files and data */
    private static String tmpKeyStoreFile = "benchmark_keystore_tmp";
    private static String serverCertRsaDer = "../../certs/server-cert.der";
    private static String serverRsaPkcs8Der = "../../certs/server-keyPkcs8.der";
    private static String serverCertEccDer = "../../certs/server-ecc.der";
    private static String serverEccPkcs8Der = "../../certs/ecc-keyPkcs8.der";

    /* Benchmark results storage */
    private static class BenchmarkResult {
        String operation;
        String provider;
        String type;
        double throughput;
        String units;

        BenchmarkResult(String operation, String provider, String type,
                       double throughput, String units) {
            this.operation = operation;
            this.provider = provider;
            this.type = type;
            this.throughput = throughput;
            this.units = units;
        }
    }

    private static java.util.List<BenchmarkResult> results =
        new java.util.ArrayList<>();

    /**
     * Helper method for string repetition (Java 8 compatibility)
     */
    private static String repeat(String str, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(str);
        }
        return sb.toString();
    }

    /**
     * Print usage and exit
     */
    private static void printUsage() {
        System.out.println("KeyStore Benchmark Tool");
        System.out.println("Usage: java KeyStoreBenchmark [options]");
        System.out.println("");
        System.out.println("Options:");
        System.out.println("  -provider <name>   Use specified provider (default: benchmark all)");
        System.out.println("  -type <type>       Use specified KeyStore type (default: benchmark all)");
        System.out.println("  -iterations <num>  PBKDF2 iteration count for WKS low-iteration test (default: 20000)");
        System.out.println("  -help              Show this help message");
        System.out.println("");
        System.out.println("Examples:");
        System.out.println("  java KeyStoreBenchmark (benchmark all types)");
        System.out.println("  java KeyStoreBenchmark -provider SunJCE -type JKS");
        System.out.println("  java KeyStoreBenchmark -iterations 10000 (use 10k for WKS low test)");
        System.out.println("  java KeyStoreBenchmark -type PKCS12");
    }

    /**
     * Parse command line arguments
     */
    private static void parseArgs(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-provider") && i + 1 < args.length) {
                providerName = args[++i];
                benchmarkAll = false;
            } else if (args[i].equals("-type") && i + 1 < args.length) {
                storeType = args[++i];
                benchmarkAll = false;
            } else if (args[i].equals("-iterations") && i + 1 < args.length) {
                try {
                    int iterCount = Integer.parseInt(args[++i]);
                    if (iterCount < 1000) {
                        System.err.println("Warning: Iteration count " + iterCount +
                                          " is very low, minimum recommended is 1000");
                    }
                    customIterationCount = String.valueOf(iterCount);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid iteration count: " + args[i]);
                    System.exit(1);
                }
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
     * Setup provider for testing
     */
    private static void setupProvider() {
        if (providerName.equals("wolfJCE")) {
            Security.insertProviderAt(new WolfCryptProvider(), 1);
        }
        /* For other providers like SunJCE, JKS, etc., they should already
         * be available in the JVM */
    }

    /**
     * Create and return PrivateKey object from file path to DER-encoded
     * private key file.
     */
    private static PrivateKey DerFileToPrivateKey(String derFilePath,
        String alg) throws Exception {

        byte[] fileBytes = Files.readAllBytes(new File(derFilePath).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(fileBytes);
        KeyFactory kf = KeyFactory.getInstance(alg);
        return kf.generatePrivate(spec);
    }

    /**
     * Read in and convert certificate file to Certificate object.
     */
    private static Certificate CertFileToCertificate(String certPath)
        throws Exception {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(new FileInputStream(certPath));
    }

    /**
     * Create a test KeyStore with various entries for benchmarking
     */
    private static KeyStore createTestKeyStore() throws Exception {
        KeyStore store = KeyStore.getInstance(storeType);
        store.load(null, storePass.toCharArray());

        /* Add RSA certificate entry */
        Certificate rsaCert = CertFileToCertificate(serverCertRsaDer);
        store.setCertificateEntry("rsaCert", rsaCert);

        /* Add RSA private key entry */
        PrivateKey rsaKey = DerFileToPrivateKey(serverRsaPkcs8Der, "RSA");
        store.setKeyEntry("rsaKey", rsaKey, storePass.toCharArray(),
                         new Certificate[] { rsaCert });

        /* Add ECC certificate entry */
        Certificate eccCert = CertFileToCertificate(serverCertEccDer);
        store.setCertificateEntry("eccCert", eccCert);

        /* Add ECC private key entry */
        PrivateKey eccKey = DerFileToPrivateKey(serverEccPkcs8Der, "EC");
        store.setKeyEntry("eccKey", eccKey, storePass.toCharArray(),
                         new Certificate[] { eccCert });

        /* Add secret key entries (only for types that support them) */
        if (storeType.equals("WKS") || storeType.equals("PKCS12")) {
            KeyGenerator aesGen = KeyGenerator.getInstance("AES");
            aesGen.init(256);
            SecretKey aesKey = aesGen.generateKey();
            store.setKeyEntry("aesKey", aesKey, storePass.toCharArray(), null);

            /* Add multiple AES keys for bulk operations */
            for (int i = 0; i < 10; i++) {
                SecretKey key = aesGen.generateKey();
                store.setKeyEntry("aesKey" + i, key, storePass.toCharArray(),
                                 null);
            }
        }

        return store;
    }

    /**
     * Benchmark KeyStore creation (load with null)
     */
    private static void benchmarkKeyStoreCreation() {
        System.out.println("Benchmarking KeyStore creation...");

        long startTime = System.nanoTime();
        int operations = 0;
        double elapsedTime = 0;

        /* Warmup */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            try {
                KeyStore store = KeyStore.getInstance(storeType);
                store.load(null, storePass.toCharArray());
            } catch (Exception e) {
                System.err.println("Warmup failed: " + e.getMessage());
                return;
            }
        }

        /* Benchmark */
        startTime = System.nanoTime();
        do {
            try {
                KeyStore store = KeyStore.getInstance(storeType);
                store.load(null, storePass.toCharArray());
                operations++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } catch (Exception e) {
                System.err.println("Benchmark failed: " + e.getMessage());
                return;
            }
        } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

        double opsPerSec = operations / elapsedTime;
        System.out.printf("  KeyStore creation: %d ops in %.3f sec, " +
                         "%.2f ops/sec%n", operations, elapsedTime, opsPerSec);

        String displayName;
        if (currentDisplayName != null) {
            displayName = currentDisplayName;
        } else {
            displayName = (providerName + " " + storeType);
        }
        results.add(new BenchmarkResult("KeyStore Creation", displayName,
                                       storeType, opsPerSec, "ops/sec"));
    }

    /**
     * Benchmark KeyStore entry insertion
     */
    private static void benchmarkEntryInsertion() {
        System.out.println("Benchmarking KeyStore entry insertion...");

        try {
            /* Prepare test data */
            Certificate rsaCert = CertFileToCertificate(serverCertRsaDer);
            PrivateKey rsaKey = DerFileToPrivateKey(serverRsaPkcs8Der, "RSA");

            KeyGenerator aesGen = null;
            boolean supportsSecretKeys = storeType.equals("WKS") ||
                                       storeType.equals("PKCS12");
            if (supportsSecretKeys) {
                aesGen = KeyGenerator.getInstance("AES");
                aesGen.init(256);
            }

            /* Benchmark certificate insertion */
            long startTime = System.nanoTime();
            int certOps = 0;
            double elapsedTime = 0;

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                KeyStore store = KeyStore.getInstance(storeType);
                store.load(null, storePass.toCharArray());
                store.setCertificateEntry("testCert", rsaCert);
            }

            /* Benchmark */
            startTime = System.nanoTime();
            do {
                KeyStore store = KeyStore.getInstance(storeType);
                store.load(null, storePass.toCharArray());
                store.setCertificateEntry("testCert" + certOps, rsaCert);
                certOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

            double certOpsPerSec = certOps / elapsedTime;
            System.out.printf("  Certificate insertion: %d ops in %.3f sec, " +
                             "%.2f ops/sec%n", certOps, elapsedTime,
                             certOpsPerSec);

            String displayName;
            if (currentDisplayName != null) {
                displayName = currentDisplayName;
            } else {
                displayName = (providerName + " " + storeType);
            }
            results.add(new BenchmarkResult("Certificate Insertion",
                                           displayName, storeType,
                                           certOpsPerSec, "ops/sec"));

            /* Benchmark private key insertion */
            int keyOps = 0;
            startTime = System.nanoTime();
            elapsedTime = 0;

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                KeyStore store = KeyStore.getInstance(storeType);
                store.load(null, storePass.toCharArray());
                store.setKeyEntry("testKey", rsaKey, storePass.toCharArray(),
                                 new Certificate[] { rsaCert });
            }

            /* Benchmark */
            startTime = System.nanoTime();
            do {
                KeyStore store = KeyStore.getInstance(storeType);
                store.load(null, storePass.toCharArray());
                store.setKeyEntry("testKey" + keyOps, rsaKey,
                                 storePass.toCharArray(),
                                 new Certificate[] { rsaCert });
                keyOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

            double keyOpsPerSec = keyOps / elapsedTime;
            System.out.printf("  Private key insertion: %d ops in %.3f sec, " +
                             "%.2f ops/sec%n", keyOps, elapsedTime,
                             keyOpsPerSec);

            if (currentDisplayName != null) {
                displayName = currentDisplayName;
            } else {
                displayName = (providerName + " " + storeType);
            }
            results.add(new BenchmarkResult("Private Key Insertion",
                                           displayName, storeType,
                                           keyOpsPerSec, "ops/sec"));

            /* Benchmark secret key insertion (if supported) */
            if (supportsSecretKeys) {
                int secretOps = 0;
                startTime = System.nanoTime();
                elapsedTime = 0;

                /* Warmup */
                for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                    KeyStore store = KeyStore.getInstance(storeType);
                    store.load(null, storePass.toCharArray());
                    SecretKey aesKey = aesGen.generateKey();
                    store.setKeyEntry("testSecret", aesKey,
                                     storePass.toCharArray(), null);
                }

                /* Benchmark */
                startTime = System.nanoTime();
                do {
                    KeyStore store = KeyStore.getInstance(storeType);
                    store.load(null, storePass.toCharArray());
                    SecretKey aesKey = aesGen.generateKey();
                    store.setKeyEntry("testSecret" + secretOps, aesKey,
                                     storePass.toCharArray(), null);
                    secretOps++;
                    elapsedTime = (System.nanoTime() - startTime) /
                                  1_000_000_000.0;
                } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

                double secretOpsPerSec = secretOps / elapsedTime;
                System.out.printf("  Secret key insertion: %d ops in %.3f sec, " +
                                 "%.2f ops/sec%n", secretOps, elapsedTime,
                                 secretOpsPerSec);

                if (currentDisplayName != null) {
                    displayName = currentDisplayName;
                } else {
                    displayName = (providerName + " " + storeType);
                }
                results.add(new BenchmarkResult("Secret Key Insertion",
                                               displayName, storeType,
                                               secretOpsPerSec, "ops/sec"));
            }

        } catch (Exception e) {
            System.err.println("Entry insertion benchmark failed: " +
                              e.getMessage());
        }
    }

    /**
     * Benchmark KeyStore entry retrieval
     */
    private static void benchmarkEntryRetrieval() {
        System.out.println("Benchmarking KeyStore entry retrieval...");

        try {
            /* Create test KeyStore */
            KeyStore store = createTestKeyStore();

            /* Benchmark certificate retrieval */
            long startTime = System.nanoTime();
            int certOps = 0;
            double elapsedTime = 0;

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                store.getCertificate("rsaCert");
            }

            /* Benchmark */
            startTime = System.nanoTime();
            do {
                store.getCertificate("rsaCert");
                certOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

            double certOpsPerSec = certOps / elapsedTime;
            System.out.printf("  Certificate retrieval: %d ops in %.3f sec, " +
                             "%.2f ops/sec%n", certOps, elapsedTime,
                             certOpsPerSec);

            String displayName;
            if (currentDisplayName != null) {
                displayName = currentDisplayName;
            } else {
                displayName = (providerName + " " + storeType);
            }
            results.add(new BenchmarkResult("Certificate Retrieval",
                                           displayName, storeType,
                                           certOpsPerSec, "ops/sec"));

            /* Benchmark private key retrieval */
            int keyOps = 0;
            startTime = System.nanoTime();
            elapsedTime = 0;

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                store.getKey("rsaKey", storePass.toCharArray());
            }

            /* Benchmark */
            startTime = System.nanoTime();
            do {
                store.getKey("rsaKey", storePass.toCharArray());
                keyOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

            double keyOpsPerSec = keyOps / elapsedTime;
            System.out.printf("  Private key retrieval: %d ops in %.3f sec, " +
                             "%.2f ops/sec%n", keyOps, elapsedTime,
                             keyOpsPerSec);

            if (currentDisplayName != null) {
                displayName = currentDisplayName;
            } else {
                displayName = (providerName + " " + storeType);
            }
            results.add(new BenchmarkResult("Private Key Retrieval",
                                           displayName, storeType,
                                           keyOpsPerSec, "ops/sec"));

            /* Benchmark alias enumeration */
            int enumOps = 0;
            startTime = System.nanoTime();
            elapsedTime = 0;

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    aliases.nextElement();
                }
            }

            /* Benchmark */
            startTime = System.nanoTime();
            do {
                Enumeration<String> aliases = store.aliases();
                while (aliases.hasMoreElements()) {
                    aliases.nextElement();
                }
                enumOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

            double enumOpsPerSec = enumOps / elapsedTime;
            System.out.printf("  Alias enumeration: %d ops in %.3f sec, " +
                             "%.2f ops/sec%n", enumOps, elapsedTime,
                             enumOpsPerSec);

            if (currentDisplayName != null) {
                displayName = currentDisplayName;
            } else {
                displayName = (providerName + " " + storeType);
            }
            results.add(new BenchmarkResult("Alias Enumeration", displayName,
                                           storeType, enumOpsPerSec, "ops/sec"));

        } catch (Exception e) {
            System.err.println("Entry retrieval benchmark failed: " +
                              e.getMessage());
        }
    }

    /**
     * Benchmark KeyStore store/load operations
     */
    private static void benchmarkStoreLoad() {
        System.out.println("Benchmarking KeyStore store/load operations...");

        try {
            /* Create test KeyStore */
            KeyStore store = createTestKeyStore();

            /* Benchmark store operation */
            long startTime = System.nanoTime();
            int storeOps = 0;
            double elapsedTime = 0;

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                FileOutputStream fos = new FileOutputStream(tmpKeyStoreFile +
                                                           "_warmup");
                store.store(fos, storePass.toCharArray());
                fos.close();
                new File(tmpKeyStoreFile + "_warmup").delete();
            }

            /* Benchmark */
            startTime = System.nanoTime();
            do {
                FileOutputStream fos = new FileOutputStream(tmpKeyStoreFile +
                                                           storeOps);
                store.store(fos, storePass.toCharArray());
                fos.close();
                storeOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

            double storeOpsPerSec = storeOps / elapsedTime;
            System.out.printf("  KeyStore store: %d ops in %.3f sec, " +
                             "%.2f ops/sec%n", storeOps, elapsedTime,
                             storeOpsPerSec);

            String displayName;
            if (currentDisplayName != null) {
                displayName = currentDisplayName;
            } else {
                displayName = (providerName + " " + storeType);
            }
            results.add(new BenchmarkResult("KeyStore Store", displayName,
                                           storeType, storeOpsPerSec, "ops/sec"));

            /* Benchmark load operation */
            int loadOps = 0;
            startTime = System.nanoTime();
            elapsedTime = 0;

            /* Use the first stored file for loading */
            String testFile = tmpKeyStoreFile + "0";

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                KeyStore loadStore = KeyStore.getInstance(storeType);
                FileInputStream fis = new FileInputStream(testFile);
                loadStore.load(fis, storePass.toCharArray());
                fis.close();
            }

            /* Benchmark */
            startTime = System.nanoTime();
            do {
                KeyStore loadStore = KeyStore.getInstance(storeType);
                FileInputStream fis = new FileInputStream(testFile);
                loadStore.load(fis, storePass.toCharArray());
                fis.close();
                loadOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < (MIN_TEST_TIME_MS / 1000.0));

            double loadOpsPerSec = loadOps / elapsedTime;
            System.out.printf("  KeyStore load: %d ops in %.3f sec, " +
                             "%.2f ops/sec%n", loadOps, elapsedTime,
                             loadOpsPerSec);

            if (currentDisplayName != null) {
                displayName = currentDisplayName;
            } else {
                displayName = (providerName + " " + storeType);
            }
            results.add(new BenchmarkResult("KeyStore Load", displayName,
                                           storeType, loadOpsPerSec, "ops/sec"));

            /* Cleanup temp files */
            for (int i = 0; i < storeOps; i++) {
                new File(tmpKeyStoreFile + i).delete();
            }

        } catch (Exception e) {
            System.err.println("Store/load benchmark failed: " + e.getMessage());
        }
    }

    /**
     * Benchmark configuration for a specific provider/type combination
     */
    private static class BenchmarkConfig {
        String provider;
        String type;
        String iterationCount;
        String displayName;

        BenchmarkConfig(String provider, String type) {

            this.provider = provider;
            this.type = type;
            this.iterationCount = null;
            this.displayName = provider + " " + type;
        }

        BenchmarkConfig(String provider, String type, String iterationCount,
            String displayName) {

            this.provider = provider;
            this.type = type;
            this.iterationCount = iterationCount;
            this.displayName = displayName;
        }
    }

    /**
     * Run benchmarks for a specific provider/type configuration
     */
    private static void runBenchmarkForConfig(BenchmarkConfig config) {
        String originalProvider = providerName;
        String originalType = storeType;

        providerName = config.provider;
        storeType = config.type;
        currentDisplayName = config.displayName;

        System.out.println("\n" + repeat("=", 60));
        System.out.println("BENCHMARKING: " + config.displayName);
        if (config.iterationCount != null) {
            System.out.println("PBKDF2 Iteration Count: " +
                config.iterationCount);
        }
        System.out.println(repeat("=", 60));

        try {
            setupProvider();

            /* Set PBKDF2 iteration count if specified */
            if (config.iterationCount != null && config.provider.equals("wolfJCE")) {
                Security.setProperty(
                    "wolfjce.wks.iterationCount", config.iterationCount);
                System.out.println("Set wolfjce.wks.iterationCount to " +
                    Security.getProperty("wolfjce.wks.iterationCount"));
            }

            /* Verify KeyStore type is available */
            KeyStore.getInstance(storeType);

            /* Run benchmarks */
            benchmarkKeyStoreCreation();
            benchmarkEntryInsertion();
            benchmarkEntryRetrieval();
            benchmarkStoreLoad();

        } catch (Exception e) {
            System.err.println("Benchmark failed for " + config.displayName +
                              ": " + e.getMessage());
        }

        /* Restore original values */
        providerName = originalProvider;
        storeType = originalType;
    }

    /**
     * Run benchmarks for all supported KeyStore types
     */
    private static void runAllBenchmarks() {
        java.util.List<BenchmarkConfig> configs =
            new java.util.ArrayList<>();

        /* Add configurations to test */
        configs.add(
            new BenchmarkConfig("wolfJCE", "WKS", null, "wolfJCE WKS (210k)"));

        /* Create display name for custom iteration count */
        String iterDisplayName;
        int iterCount = Integer.parseInt(customIterationCount);
        if (iterCount >= 1000) {
            iterDisplayName = String.format("wolfJCE WKS (%dk)",
                iterCount / 1000);
        } else {
            iterDisplayName = String.format("wolfJCE WKS (%d)", iterCount);
        }

        configs.add(new BenchmarkConfig("wolfJCE", "WKS", customIterationCount,
            iterDisplayName));
        configs.add(new BenchmarkConfig("SunJCE", "JKS"));
        configs.add(new BenchmarkConfig("SunJCE", "PKCS12"));

        for (BenchmarkConfig config : configs) {
            runBenchmarkForConfig(config);
        }
    }

    /**
     * Print comparison table of all benchmark results
     */
    private static void printComparisonTable() {
        System.out.println("\n" + repeat("=", 105));
        System.out.println("KEYSTORE PERFORMANCE COMPARISON TABLE");
        System.out.println(repeat("=", 105));

        /* Group results by operation */
        java.util.Map<String, java.util.Map<String, BenchmarkResult>>
            operationMap = new java.util.HashMap<>();

        for (BenchmarkResult result : results) {
            String key = result.provider;
            operationMap.computeIfAbsent(result.operation,
                k -> new java.util.HashMap<>()).put(key, result);
        }

        /* Print header */
        System.out.printf("%-25s %15s %15s %15s %15s%n",
                         "Operation", "WKS (210k)", "WKS (20k)", "JKS",
                         "PKCS12");
        System.out.println(repeat("-", 105));

        /* Print each operation's results across all providers/types */
        String[] operations = {
            "KeyStore Creation",
            "Certificate Insertion",
            "Private Key Insertion",
            "Secret Key Insertion",
            "Certificate Retrieval",
            "Private Key Retrieval",
            "Alias Enumeration",
            "KeyStore Store",
            "KeyStore Load"
        };

        for (String operation : operations) {
            java.util.Map<String, BenchmarkResult> opResults =
                operationMap.get(operation);
            if (opResults != null) {
                System.out.printf("%-25s", operation);

                String[] providerKeys = {
                    "wolfJCE WKS (210k)", "wolfJCE WKS (20k)", "SunJCE JKS",
                    "SunJCE PKCS12"};
                for (String provider : providerKeys) {
                    BenchmarkResult result = opResults.get(provider);
                    if (result != null) {
                        if (result.throughput >= 1000000) {
                            System.out.printf(" %14.2fM",
                                result.throughput / 1000000);
                        } else if (result.throughput >= 1000) {
                            System.out.printf(" %14.2fK",
                                result.throughput / 1000);
                        } else {
                            System.out.printf(" %15.2f", result.throughput);
                        }
                    } else {
                        System.out.printf(" %15s", "N/A");
                    }
                }
                System.out.println();
            }
        }

        System.out.println(repeat("-", 105));
        System.out.println("Units: ops/sec (K=thousands, M=millions)");
        System.out.println(
            "N/A = Not Available/Supported for this KeyStore type");
        System.out.println(repeat("=", 105));
    }

    /**
     * Print benchmark results summary
     */
    private static void printResults() {
        System.out.println("\n" + repeat("=", 70));
        System.out.println("BENCHMARK RESULTS SUMMARY");
        System.out.println(repeat("=", 70));
        System.out.printf("Provider: %s, KeyStore Type: %s%n", providerName,
                         storeType);
        System.out.println(repeat("-", 70));
        System.out.printf("%-25s %15s %15s%n", "Operation", "Throughput",
                         "Units");
        System.out.println(repeat("-", 70));

        for (BenchmarkResult result : results) {
            System.out.printf("%-25s %15.2f %15s%n", result.operation,
                             result.throughput, result.units);
        }
        System.out.println(repeat("=", 70));
    }

    public static void main(String[] args) {
        try {
            /* Parse command line arguments */
            parseArgs(args);

            System.out.println("KeyStore Benchmark Tool");
            System.out.println("Minimum test time per operation: " +
                MIN_TEST_TIME_MS + "ms");

            if (benchmarkAll) {
                System.out.println("Benchmarking all KeyStore types:");
                System.out.println(
                    "  - WKS with 210k PBKDF2 iterations (default)");
                System.out.println("  - WKS with 20k PBKDF2 iterations");
                System.out.println("  - JKS and PKCS12 from SunJCE");
                System.out.println(repeat("=", 60));

                /* Run benchmarks for all types */
                runAllBenchmarks();

                /* Print comparison table */
                printComparisonTable();

            } else {
                System.out.println("Provider: " + providerName);
                System.out.println("KeyStore Type: " + storeType);
                System.out.println(repeat("=", 51));

                /* Setup provider */
                setupProvider();

                /* Verify KeyStore type is available */
                try {
                    KeyStore.getInstance(storeType);
                } catch (KeyStoreException e) {
                    System.err.println("KeyStore type '" + storeType +
                                      "' not available with provider '" +
                                      providerName + "'");
                    System.exit(1);
                }

                /* Run benchmarks */
                benchmarkKeyStoreCreation();
                benchmarkEntryInsertion();
                benchmarkEntryRetrieval();
                benchmarkStoreLoad();

                /* Print results */
                printResults();
            }

        } catch (Exception e) {
            System.err.println("Benchmark failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}

