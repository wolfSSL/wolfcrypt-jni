import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.*;

import com.wolfssl.provider.jce.WolfCryptProvider;
import com.wolfssl.wolfcrypt.FeatureDetect;

public class CryptoBenchmark {
    /* Constants for benchmark configuration */
    private static final int WARMUP_ITERATIONS = 5;
    private static final int TEST_ITERATIONS = 5;
    private static final int DATA_SIZE = 1024 * 1024;
    private static final int AES_BLOCK_SIZE = 16;
    private static final int DES3_BLOCK_SIZE = 8;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int[] RSA_KEY_SIZES = {2048, 3072, 4096};
    private static final int TEST_MIN_TIME_SECONDS = 1;  /* minimum time to run each test */
    private static final int SMALL_MESSAGE_SIZE = 32;   /* small message size for RSA ops */
    private static final String[] ECC_CURVES = {"secp256r1"}; /* Can add more curves benchmark.c only uses secp256r1 */
    private static final int[] DH_KEY_SIZES = {2048}; /* Can add more key sizes benchmark.c only uses 2048 */
    private static final String DH_ALGORITHM = "DiffieHellman";

    /* Class to store benchmark results */
    private static class BenchmarkResult {
        /* Result fields */
        String provider;
        String operation;
        double throughput;

        /* Constructor */
        BenchmarkResult(String provider, String operation, double throughput) {
        this.provider = provider;
        this.operation = operation;
        this.throughput = throughput;
        }
    }

    /* List to store all benchmark results */
    private static final List<BenchmarkResult> results = new ArrayList<>();

    /* Static AES key buffer */
    private static final byte[] STATIC_AES_KEY = new byte[] {
        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
        (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
        (byte)0xfe, (byte)0xde, (byte)0xba, (byte)0x98,
        (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
        (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
        (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3,
        (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7
    };

    /* Static DESede (Triple DES) key buffer */
    private static final byte[] STATIC_DES3_KEY = new byte[] {
        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
        (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
        (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98,
        (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
        (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67
    };

    private static byte[] generateTestData(int size) {
        return new byte[size];
    }

    /* Bytes sizes from WC_*_DIGEST_SIZE for corresponding algorithm in text.c */
    private static int getHmacKeySize(String algorithm) {
        switch (algorithm) {
            case "HmacMD5":
                return 16;
            case "HmacSHA1":
                return 20;
            case "HmacSHA224":
                return 28;
            case "HmacSHA256":
                return 32;
            case "HmacSHA384":
                return 48;
            case "HmacSHA512":
                return 64;
            case "HmacSHA3-224":
                return 28;
            case "HmacSHA3-256":
                return 32;
            case "HmacSHA3-384":
                return 48;
            case "HmacSHA3-512":
                return 64;
            default:
                if (algorithm.contains("224")) return 28;
                if (algorithm.contains("256")) return 32;
                if (algorithm.contains("384")) return 48;
                if (algorithm.contains("512")) return 64;
                if (algorithm.contains("MD5")) return 16;
                if (algorithm.contains("SHA1") || algorithm.contains("SHA-1")) return 20;

                System.out.println("Warning: Unknown HMAC algorithm " + algorithm + ", using default key size 32");
                return 32;
        }
    }

    @SuppressWarnings("deprecation")
    private static void printProviderInfo(Provider provider) {
        System.out.printf("%s version: %s%n", provider.getName(), provider.getVersion());
    }

    private static void setupProvidersForTest(Provider testProvider) {
        /* Remove only our test providers */
        Security.removeProvider(testProvider.getName());
        if (!testProvider.getName().equals("BC")) {
            Security.removeProvider("BC");
        }

        /* Add test provider at priority 1 */
        Security.insertProviderAt(testProvider, 1);

        /* For SunJCE tests, SunEC is typically already available in modern Java versions */
        if (testProvider.getName().equals("SunJCE")) {
            /* SunEC should already be registered in Java 9+ */
            if (Security.getProvider("SunEC") == null) {
                System.out.println("Note: SunEC provider not available, some ECC operations may not work");
            }
        }
    }

    private static void setupDigestProvider(String testProviderName) {
        /* For digest operations, we need special handling */
        if (testProviderName.equals("wolfJCE") || testProviderName.equals("BC")) {
            /* wolfJCE and BC can handle their own digests */
            return;
        } else {
            /* For SunJCE, we need SUN provider for MessageDigest */
            Provider sunProvider = Security.getProvider("SUN");
            if (sunProvider == null) {
                /* SUN provider should be built-in, but let's be safe */
                System.out.println("SUN provider not found for MessageDigest operations");
            }
        }
    }

    private static KeyPairGenerator initializeKeyGenerator(String keyType, String keyGenProvider) throws Exception {
        KeyPairGenerator keyGen;

        if (keyType.equals("EC") && keyGenProvider.equals("SunEC")) {
            keyGen = KeyPairGenerator.getInstance("EC", "SunEC");
            keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        } else {
            keyGen = KeyPairGenerator.getInstance(keyType, keyGenProvider);

            /* Initialize key generator based on type */
            if (keyType.equals("RSA")) {
                keyGen.initialize(2048);
            } else if (keyType.equals("EC")) {
                keyGen.initialize(new ECGenParameterSpec("secp256r1"));
            } else if (keyType.equals("DSA")) {
                keyGen.initialize(1024);
            }
        }

        return keyGen;
    }

    /* Universal method to get algorithms for a specific provider and service type */
    private static Set<String> getAlgorithmsForProvider(String providerName, String serviceType, Set<String> wolfJCEAlgorithms) {
        Set<String> algorithms = new TreeSet<>();

        if (providerName.equals("SunJCE") && serviceType.equals("Signature")) {
            algorithms.addAll(getAlgorithmsForService("SunRsaSign", serviceType));
            algorithms.addAll(getAlgorithmsForService("SunEC", serviceType));
            algorithms.addAll(getAlgorithmsForService("SUN", serviceType));
        } else {
            algorithms.addAll(getAlgorithmsForService(providerName, serviceType));
        }

        if (providerName.equals("BC")) {
            Set<String> normalizedAlgorithms = new TreeSet<>();
            for (String algorithm : algorithms) {
                if (serviceType.equals("Signature")) {
                    String normalized = algorithm.replace("WITH", "with");
                    if (wolfJCEAlgorithms.contains(normalized)) {
                        normalizedAlgorithms.add(algorithm);
                    }
                } else if (serviceType.equals("Mac") || serviceType.equals("KeyGenerator")) {
                    String normalized = algorithm;

                    if (wolfJCEAlgorithms.contains(normalized)) {
                        normalizedAlgorithms.add(algorithm);
                        continue;
                    }

                    for (String wolfAlg : wolfJCEAlgorithms) {
                        if (wolfAlg.equalsIgnoreCase(normalized)) {
                            normalizedAlgorithms.add(algorithm);
                            break;
                        }

                        String bcNormalized = normalized.replace("-", "");
                        String wolfNormalized = wolfAlg.replace("-", "");
                        if (bcNormalized.equalsIgnoreCase(wolfNormalized)) {
                            normalizedAlgorithms.add(algorithm);
                            break;
                        }
                    }
                } else {
                    if (wolfJCEAlgorithms.contains(algorithm)) {
                        normalizedAlgorithms.add(algorithm);
                    }
                }
            }
            return normalizedAlgorithms;
        } else {
            algorithms.retainAll(wolfJCEAlgorithms);
        }

        return algorithms;
    }

    /* Get the baseline algorithms that wolfJCE supports for comparison */
    private static Set<String> getWolfJCEAlgorithmsForService(String serviceType) {
        return getAlgorithmsForService("wolfJCE", serviceType);
    }

    /* Debug method to see what algorithms each provider actually supports */
    private static void debugPrintAlgorithms(String providerName, String serviceType) {
        System.out.println("Debug: " + providerName + " " + serviceType + " algorithms:");
        Set<String> algorithms = getAlgorithmsForService(providerName, serviceType);
        for (String alg : algorithms) {
            System.out.println("  " + alg);
        }
        System.out.println();
    }

    /* Universal method to get algorithms for a specific provider and service type */
    private static Set<String> getAlgorithmsForService(String providerName, String serviceType) {
        Set<String> algorithms = new TreeSet<>();

        Provider provider = Security.getProvider(providerName);
        if (provider == null) {
            System.out.println("Provider " + providerName + " not found.");
            return algorithms;
        }

        for (Provider.Service service : provider.getServices()) {
            if (serviceType.equals(service.getType())) {
                String algorithm = service.getAlgorithm();

                if (serviceType.equals("Mac")) {
                    if (algorithm.startsWith("Hmac") || algorithm.startsWith("HMAC")) {
                        algorithms.add(algorithm);
                    }
                } else {
                    algorithms.add(algorithm);
                }
            }
        }

        return algorithms;
    }

    private static void printDeltaTable() {
        /* Variables for table generation */
        Map<String, Map<String, Double>> groupedResults;
        Map<String, Double> providerResults;
        double wolfSpeed;
        String provider;
        double otherSpeed;
        double deltaValue;
        double deltaPercent;

        System.out.println("\nPerformance Delta (compared to wolfJCE)");
        System.out.println("------------------------------------------------------------------------------------");
        System.out.println("| Operation                                    | Provider     |  Delta   |   Delta  |");
        System.out.println("|                                              |              |  Value*  |   (%)    |");
        System.out.println("|----------------------------------------------|--------------|----------|----------|");

        /* Group results by operation */
        groupedResults = new HashMap<>();
        for (BenchmarkResult result : results) {
            groupedResults
                .computeIfAbsent(result.operation, k -> new HashMap<>())
                .put(result.provider, result.throughput);
        }

        /* Sort operations to group RSA operations together */
        List<String> sortedOperations = new ArrayList<>(groupedResults.keySet());
        Collections.sort(sortedOperations, (a, b) -> {
            boolean aIsRSA = a.startsWith("RSA");
            boolean bIsRSA = b.startsWith("RSA");

            if (aIsRSA && !bIsRSA) return -1;
            if (!aIsRSA && bIsRSA) return 1;
            return a.compareTo(b);
        });

        /* Calculate and print deltas */
        for (String operation : sortedOperations) {
            providerResults = groupedResults.get(operation);
            wolfSpeed = providerResults.getOrDefault("wolfJCE", 0.0);
            boolean isRSAOperation = operation.startsWith("RSA");

            for (Map.Entry<String, Double> providerEntry : providerResults.entrySet()) {
                provider = providerEntry.getKey();
                if (!provider.equals("wolfJCE")) {
                    otherSpeed = providerEntry.getValue();

                    /* Adjust provider name for RSA operations */
                    String displayProvider = provider;
                    if (isRSAOperation) {
                        if (operation.contains("key gen")) {
                            displayProvider = "SunRsaSign"; /* Key generation uses SunRsaSign */
                        } else {
                            displayProvider = "SunJCE"; /* Public/private operations use SunJCE */
                        }
                    }

                    if (isRSAOperation) {
                        deltaValue = wolfSpeed - otherSpeed;
                        deltaPercent = ((wolfSpeed / otherSpeed) - 1.0) * 100;
                    } else {
                        deltaValue = wolfSpeed - otherSpeed;
                        deltaPercent = ((wolfSpeed / otherSpeed) - 1.0) * 100;
                    }

                    /* Ensure unique operation-provider combination */
                    String uniqueKey = operation + "|" + displayProvider;
                    if (!groupedResults.containsKey(uniqueKey)) {
                        System.out.printf("| %-44s | %-12s | %+8.2f | %+8.1f |%n",
                            operation.replace("RSA", "RSA/ECB/PKCS1Padding RSA"),
                            displayProvider,
                            deltaValue,
                            deltaPercent);

                        /* Mark this combination as processed */
                        groupedResults.put(uniqueKey, null);
                    }
                }
            }
        }
        System.out.println("------------------------------------------------------------------------------------");
        System.out.println("* Delta Value: MiB/s for symmetric ciphers, operations/second for RSA and ECC");
    }

    /* Run symmetric encryption/decryption benchmarks */
    private static void runEncDecBenchmark(String algorithm, String mode, String padding,
      String providerName) throws Exception {
        SecretKey key;
        byte[] ivBytes;
        AlgorithmParameterSpec params;
        byte[] testData;
        byte[] encryptedData = null;
        Cipher cipher;
        String cipherName = algorithm + "/" + mode + "/" + padding;

        /* Timing variables */
        long startTime;
        double elapsedTime;
        int encryptOps = 0;
        int decryptOps = 0;
        double encryptThroughput;
        double decryptThroughput;

        /* Use appropriate key based on algorithm */
        if (algorithm.equals("AES")) {
            key = new SecretKeySpec(STATIC_AES_KEY, "AES");
        } else if (algorithm.equals("DESede")) {
            key = new SecretKeySpec(STATIC_DES3_KEY, "DESede");
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        /* Generate random IV */
        SecureRandom secureRandom = new SecureRandom();
        if (algorithm.equals("AES")){
            ivBytes = new byte[AES_BLOCK_SIZE];
            secureRandom.nextBytes(ivBytes);
        } else if (algorithm.equals("DESede")) {
            ivBytes = new byte[DES3_BLOCK_SIZE];
            secureRandom.nextBytes(ivBytes);
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        if (mode.equals("GCM")) {
            params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
        } else {
            params = new IvParameterSpec(ivBytes);
        }

        testData = generateTestData(DATA_SIZE);

        /* Initialize cipher with specific provider */
        cipher = Cipher.getInstance(cipherName, providerName);

        /* Warm up phase */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            if (mode.equals("GCM")) {
                secureRandom.nextBytes(ivBytes);
                params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            encryptedData = cipher.doFinal(testData);

            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.doFinal(encryptedData);
        }

        /* Benchmark encryption - run for 1 second */
        startTime = System.nanoTime();
        elapsedTime = 0;

        do {
            if (mode.equals("GCM")) {
                secureRandom.nextBytes(ivBytes);
                params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            encryptedData = cipher.doFinal(testData);
            encryptOps++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        double dataSizeMiB = (DATA_SIZE * encryptOps) / (1024.0 * 1024.0);
        encryptThroughput = dataSizeMiB / elapsedTime;

        String testName = String.format("%s (%s)", cipherName, providerName);
        System.out.printf(" %-40s  %8.3f MiB took %.3f sec, %8.3f MiB/s%n",
          testName + " enc", dataSizeMiB, elapsedTime, encryptThroughput);

        results.add(new BenchmarkResult(providerName, cipherName + " enc", encryptThroughput));

        /* Benchmark decryption - run for 1 second */
        startTime = System.nanoTime();
        elapsedTime = 0;

        do {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.doFinal(encryptedData);
            decryptOps++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        dataSizeMiB = (DATA_SIZE * decryptOps) / (1024.0 * 1024.0);
        decryptThroughput = dataSizeMiB / elapsedTime;

        System.out.printf(" %-40s  %8.3f MiB took %.3f sec, %8.3f MiB/s%n",
          testName + " dec", dataSizeMiB, elapsedTime, decryptThroughput);

        /* Store decryption result */
        results.add(new BenchmarkResult(providerName, cipherName + " dec", decryptThroughput));
    }

    /* Helper method to check if an algorithm is supported by the provider */
    private static boolean isAlgorithmSupported(String algorithm, String providerName) {
        try {
            MessageDigest.getInstance(algorithm, providerName);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            return false;
        }
    }
    /* Print RSA results in simpler format */
    private static void printKeyGenResults(int operations, double totalTime, String operation,
        String providerName, String mode) {
        /* Variables for result calculations */
        double avgTimeMs;
        double opsPerSec;

        /* Calculate metrics */
        avgTimeMs = (totalTime * 1000.0) / operations;
        opsPerSec = operations / totalTime;

        /* Print formatted results */
        System.out.printf("%-12s  %-8s %8d ops took %.3f sec, avg %.3f ms, %.3f ops/sec%n",
            operation + " (" + mode + ")",
            " ",
            operations,
            totalTime,
            avgTimeMs,
            opsPerSec);

        /* Store results for delta table */
        String fullOperation = operation;
        results.add(new BenchmarkResult(providerName, fullOperation, opsPerSec));
    }

    /* Run RSA benchmarks for specified provider and key size */
    private static void runRSABenchmark(String providerName, int keySize) throws Exception {
        /* Variables for benchmark operations */
        KeyPairGenerator keyGen;
        Cipher cipher;
        byte[] testData;
        int keyGenOps;
        long startTime;
        double elapsedTime;
        KeyPair keyPair;
        int publicOps;
        int privateOps;
        byte[] encrypted;
        String keyGenOp;
        String cipherMode = "RSA/ECB/PKCS1Padding";

        /* Initialize key generator and cipher */
        if (providerName.equals("SunJCE")) {
            keyGen = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            cipher = Cipher.getInstance(cipherMode, "SunJCE");
            providerName = "SunRsaSign";
        } else {
            keyGen = KeyPairGenerator.getInstance("RSA", providerName);
            cipher = Cipher.getInstance(cipherMode, providerName);
        }
        testData = generateTestData(SMALL_MESSAGE_SIZE);

        /* Key Generation benchmark */
        keyGen.initialize(keySize);
        keyGenOps = 0;
        startTime = System.nanoTime();
        elapsedTime = 0;

        /* Run key generation benchmark */
        do {
            keyGen.generateKeyPair();
            keyGenOps++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        keyGenOp = String.format("RSA %d key gen", keySize);
        printKeyGenResults(keyGenOps, elapsedTime, keyGenOp, providerName, cipherMode);

        /* For 2048-bit keys, test public/private operations */
        if (keySize == 2048) {
            /* Generate key pair for public/private operations */
            keyPair = keyGen.generateKeyPair();

            /* Public key operations benchmark */
            publicOps = 0;
            startTime = System.nanoTime();

            do {
                cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                cipher.doFinal(testData);
                publicOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < TEST_MIN_TIME_SECONDS);

            printKeyGenResults(publicOps, elapsedTime, "RSA 2048 public", providerName, cipherMode);

            /* Private key operations benchmark */
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            encrypted = cipher.doFinal(testData);

            privateOps = 0;
            startTime = System.nanoTime();

            do {
                cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                cipher.doFinal(encrypted);
                privateOps++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < TEST_MIN_TIME_SECONDS);

            printKeyGenResults(privateOps, elapsedTime, "RSA 2048 private", providerName, cipherMode);
        }
    }

    /* ECC keygen benchmark */
    private static void runECCBenchmark(String providerName, String curveName) throws Exception {
        KeyPairGenerator keyGen;
        int keyGenOps = 0;
        long startTime;
        double elapsedTime;

        /* Initialize key generator */
        if (providerName.equals("SunJCE")) {
            keyGen = KeyPairGenerator.getInstance("EC", "SunEC");
            keyGen.initialize(new ECGenParameterSpec(curveName));
            providerName = "SunEC";
        } else {
            keyGen = KeyPairGenerator.getInstance("EC", providerName);
            keyGen.initialize(new ECGenParameterSpec(curveName));
        }

        /* Key Generation benchmark */
        startTime = System.nanoTime();
        elapsedTime = 0;

        /* Run key generation benchmark */
        do {
            keyGen.generateKeyPair();
            keyGenOps++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        String keyGenOp = String.format("ECC %s key gen", curveName);
        printKeyGenResults(keyGenOps, elapsedTime, keyGenOp, providerName, "EC");
    }

    /* Get HMAC algorithms for a specific provider */
    private static Set<String> getHmacAlgorithms(String providerName) {
        return getAlgorithmsForService(providerName, "Mac");
    }

    /* Get the baseline HMAC algorithms that wolfJCE supports for comparison */
    private static Set<String> getWolfJCEHmacAlgorithms() {
        return getWolfJCEAlgorithmsForService("Mac");
    }

    /* Enhanced method to get HMAC algorithms for special provider cases, filtered by wolfJCE support */
    private static Set<String> getHmacAlgorithmsForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        return getAlgorithmsForProvider(providerName, "Mac", wolfJCEAlgorithms);
    }

    /* HMAC benchmark runner using the universal methods */
    private static void runHmacBenchmarksForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        System.out.println("\n" + providerName + ":");

        Set<String> supportedAlgorithms;
        if (providerName.equals("wolfJCE")) {
            supportedAlgorithms = wolfJCEAlgorithms;
        } else {
            supportedAlgorithms = getHmacAlgorithmsForProvider(providerName, wolfJCEAlgorithms);
        }

        if (supportedAlgorithms.isEmpty()) {
            System.out.println("  No common HMAC algorithms found for provider " + providerName);
            return;
        }

        for (String algorithm : supportedAlgorithms) {
            try {
                runHmacBenchmark(algorithm, providerName);
            } catch (Exception e) {
                System.out.printf(" %-40s  Error: %s%n",
                    algorithm + " (" + providerName + ")", e.getMessage());
            }
        }
    }

    /* HMAC benchmark */
    private static void runHmacBenchmark(String algorithm, String providerName) throws Exception {
        Mac mac;
        byte[] testData;
        int ops = 0;
        long startTime;
        double elapsedTime;

        /* Generate test data */
        testData = generateTestData(DATA_SIZE);

        /* Initialize Mac with specific provider */
        mac = Mac.getInstance(algorithm, providerName);

        /* Initialize Mac with a random key of appropriate length */
        SecureRandom secureRandom = new SecureRandom();
        int keySize = getHmacKeySize(algorithm);
        byte[] keyBytes = new byte[keySize];
        secureRandom.nextBytes(keyBytes);
        SecretKeySpec key = new SecretKeySpec(keyBytes, algorithm);
        mac.init(key);

        /* Warm up phase */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            mac.update(testData);
            mac.doFinal();
        }

        /* Benchmark phase: run for at least 1 second like other tests */
        startTime = System.nanoTime();
        elapsedTime = 0;

        do {
            mac.update(testData);
            mac.doFinal();
            ops++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        double dataSizeMiB = (DATA_SIZE * ops) / (1024.0 * 1024.0);
        double throughput = dataSizeMiB / elapsedTime;

        System.out.printf(" %-40s  %8.3f MiB took %.3f sec, %8.3f MiB/s%n",
            algorithm + " (" + providerName + ")", dataSizeMiB, elapsedTime, throughput);

        /* Store result */
        results.add(new BenchmarkResult(providerName, algorithm, throughput));
    }

    /* Run DH benchmarks for specified provider and key size */
    private static void runDHBenchmark(String providerName, int keySize) throws Exception {
        /* Variables for benchmark operations */
        KeyPairGenerator keyGen;
        KeyAgreement keyAgreement;
        int keyGenOps;
        int agreementOps;
        long startTime;
        double elapsedTime;
        KeyPair keyPair1 = null;
        KeyPair keyPair2 = null;

        /* Standard DH parameters for 2048-bit key from RFC 3526 */
        BigInteger p = new BigInteger(
          "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
          "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
          "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
          "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
          "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
          "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
          "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
          "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
          "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
          "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
          "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);
        DHParameterSpec dhParams = new DHParameterSpec(p, g);

        /* Get KeyPairGenerator for DH */
        keyGen = KeyPairGenerator.getInstance("DH", providerName);

        /* Initialize with parameters */
        keyGen.initialize(dhParams);

        /* Key Generation benchmark */
        keyGenOps = 0;
        startTime = System.nanoTime();
        elapsedTime = 0;

        /* Run key generation benchmark */
        do {
            keyGen.generateKeyPair();
            keyGenOps++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        String keyGenOp = String.format("DH %d key gen", keySize);
        printKeyGenResults(keyGenOps, elapsedTime, keyGenOp, providerName, DH_ALGORITHM);

        /* Generate key pairs for agreement operations */
        keyPair1 = keyGen.generateKeyPair();
        keyPair2 = keyGen.generateKeyPair();

        /* Key Agreement benchmark */
        keyAgreement = KeyAgreement.getInstance("DH", providerName);
        agreementOps = 0;
        startTime = System.nanoTime();
        elapsedTime = 0;

        /* Run key agreement benchmark */
        do {
          keyAgreement.init(keyPair1.getPrivate());
          keyAgreement.doPhase(keyPair2.getPublic(), true);
          keyAgreement.generateSecret();
          agreementOps++;
          elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        String agreementOp = String.format("DH %d agree", keySize);
        printKeyGenResults(agreementOps, elapsedTime, agreementOp, providerName, DH_ALGORITHM);
    }

    /* PBKDF2 benchmark */
    private static void runPBKDF2Benchmark(String algorithm, String providerName) throws Exception {
        /* Variables for benchmark */
        SecretKeyFactory secretKeyFactory;
        byte[] salt;
        char[] password;
        int iterationCount = 10000;
        int keyLength = 32;
        int processingBytes = 1024;
        SecureRandom secureRandom = new SecureRandom();

        /* Initialize test parameters */
        salt = new byte[16];
        secureRandom.nextBytes(salt);
        password = "wolfCryptBenchmarkTestPassword".toCharArray();

        /* Initialize SecretKeyFactory with specific provider */
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(algorithm, providerName);
        } catch (Exception e) {
            System.out.printf(" %-40s  Not supported by provider %s%n", algorithm, providerName);
            return;
        }

        /* Create PBEKeySpec */
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount, keyLength * 8);

        /* Warm up phase */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            secretKeyFactory.generateSecret(pbeKeySpec);
        }

        /* Benchmark */
        long startTime = System.nanoTime();
        int operations = 0;
        double elapsedTime = 0;

        /* Run for at least 1 second */
        do {
            secretKeyFactory.generateSecret(pbeKeySpec);
            operations++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < 1.0);

        /* Calculate metrics */
        double processedKiB = (operations * processingBytes) / 1024.0;
        double throughput = processedKiB / elapsedTime;

        String testName = String.format("%s (%s)", algorithm, providerName);
        System.out.printf(" %-40s  %8.3f KiB took %.3f seconds, %8.3f KiB/s%n",
            testName, processedKiB, elapsedTime, throughput);

        /* Store result */
        results.add(new BenchmarkResult(providerName, algorithm, throughput));
    }

    /* MessageDigest benchmark */
    private static void runMessageDigestBenchmark(String algorithm, String providerName) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm, providerName);
        byte[] testData = generateTestData(DATA_SIZE);
        long ops = 0;
        long startTime = System.nanoTime();
        double elapsedTime;

        /* Warm up phase */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            md.update(testData);
            md.digest();
        }

        /* Benchmark phase: run for at least 1 second */
        do {
            md.update(testData);
            md.digest();
            ops++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        double dataSizeMiB = (DATA_SIZE * ops) / (1024.0 * 1024.0);
        double throughput = dataSizeMiB / elapsedTime;
        System.out.printf("%-40s %8.3f MiB took %.3f sec, %8.3f MiB/s%n",
            algorithm + " (" + providerName + ")", dataSizeMiB, elapsedTime, throughput);
        results.add(new BenchmarkResult(providerName, algorithm, throughput));
    }

    /* Run signature benchmarks */
    private static void runSignatureBenchmark(String algorithm, String providerName) throws Exception {
        KeyPairGenerator keyGen;
        Signature signature;
        byte[] testData;
        int ops = 0;
        long startTime;
        double elapsedTime;
        KeyPair keyPair;

        /* Generate small test data */
        testData = generateTestData(SMALL_MESSAGE_SIZE);

        /* Determine the correct provider and key type based on algorithm */
        String keyGenProvider = providerName;
        String signatureProvider = providerName;
        String keyType;

        /* Convert algorithm to lowercase for case-insensitive matching */
        String algorithmLower = algorithm.toLowerCase();

        /* Handle both wolfJCE format (withRSA) and BC format (WITHRSA) */
        if (algorithmLower.contains("withrsa")) {
            keyType = "RSA";
            if (providerName.equals("SunJCE")) {
                keyGenProvider = "SunRsaSign";
                signatureProvider = "SunRsaSign";
            }
        } else if (algorithmLower.contains("withecdsa")) {
            keyType = "EC";
            if (providerName.equals("SunJCE")) {
                /* Use SunEC if available, otherwise fall back to what's available */
                Provider sunECProvider = Security.getProvider("SunEC");
                if (sunECProvider != null) {
                    keyGenProvider = "SunEC";
                    signatureProvider = "SunEC";
                } else {
                    throw new Exception("SunEC provider not available for ECDSA operations");
                }
            }
        } else if (algorithmLower.contains("withdsa")) {
            keyType = "DSA";
            if (providerName.equals("SunJCE")) {
                keyGenProvider = "SUN";
                signatureProvider = "SUN";
            }
        } else {
            throw new IllegalArgumentException("Unsupported signature algorithm: " + algorithm);
        }

        try {
            /* Initialize key generator and signature with correct providers */
            keyGen = initializeKeyGenerator(keyType, keyGenProvider);
            signature = Signature.getInstance(algorithm, signatureProvider);

            /* Generate key pair */
            keyPair = keyGen.generateKeyPair();

            /* Test that signing works before benchmarking */
            signature.initSign(keyPair.getPrivate());
            signature.update(testData);
            byte[] sig = signature.sign();

            /* Warm up phase */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                signature.initSign(keyPair.getPrivate());
                signature.update(testData);
                signature.sign();

                signature.initVerify(keyPair.getPublic());
                signature.update(testData);
                signature.verify(sig);
            }

            /* Benchmark signing */
            ops = 0;
            startTime = System.nanoTime();
            elapsedTime = 0;

            do {
                signature.initSign(keyPair.getPrivate());
                signature.update(testData);
                signature.sign();
                ops++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < TEST_MIN_TIME_SECONDS);

            double signOpsPerSec = ops / elapsedTime;
            System.out.printf(" %-40s  %8d ops took %.3f sec, %8.3f ops/sec%n",
                algorithm + " sign (" + signatureProvider + ")", ops, elapsedTime, signOpsPerSec);
            results.add(new BenchmarkResult(signatureProvider, algorithm + " sign", signOpsPerSec));

            /* Benchmark verification */
            ops = 0;
            startTime = System.nanoTime();
            elapsedTime = 0;

            do {
                signature.initVerify(keyPair.getPublic());
                signature.update(testData);
                signature.verify(sig);
                ops++;
                elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
            } while (elapsedTime < TEST_MIN_TIME_SECONDS);

            double verifyOpsPerSec = ops / elapsedTime;
            System.out.printf(" %-40s  %8d ops took %.3f sec, %8.3f ops/sec%n",
                algorithm + " verify (" + signatureProvider + ")", ops, elapsedTime, verifyOpsPerSec);
            results.add(new BenchmarkResult(signatureProvider, algorithm + " verify", verifyOpsPerSec));

        } catch (Exception e) {
            System.err.printf(" %-40s  Not supported: %s (%s)%n",
                algorithm + " (" + signatureProvider + ")", e.getMessage(),
                e.getClass().getName());
        }
    }

    /* Get signature algorithms for a specific provider */
    private static Set<String> getSignatureAlgorithms(String providerName) {
        return getAlgorithmsForService(providerName, "Signature");
    }

    /* Enhanced method to get signature algorithms for special provider cases, filtered by wolfJCE support */
    private static Set<String> getSignatureAlgorithmsForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        return getAlgorithmsForProvider(providerName, "Signature", wolfJCEAlgorithms);
    }

    /* Signature benchmark runner */
    private static void runSignatureBenchmarksForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        System.out.println("\n" + providerName + ":");

        Set<String> supportedAlgorithms;
        if (providerName.equals("wolfJCE")) {
            supportedAlgorithms = wolfJCEAlgorithms;
        } else {
            supportedAlgorithms = getSignatureAlgorithmsForProvider(providerName, wolfJCEAlgorithms);
        }

        if (supportedAlgorithms.isEmpty()) {
            System.out.println("  No common signature algorithms found for provider " + providerName);
            return;
        }

        for (String algorithm : supportedAlgorithms) {
            try {
                runSignatureBenchmark(algorithm, providerName);
            } catch (Exception e) {
                System.out.printf(" %-40s  Error: %s%n",
                    algorithm + " (" + providerName + ")", e.getMessage());
            }
        }
    }

    /* Enhanced method to get cipher algorithms for special provider cases, filtered by wolfJCE support */
    private static Set<String> getCipherAlgorithmsForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        Set<String> providerAlgorithms = getAlgorithmsForService(providerName, "Cipher");
        Set<String> filteredAlgorithms = new TreeSet<>();

        for (String wolfAlg : wolfJCEAlgorithms) {
            if (wolfAlg.equals("RSA") || wolfAlg.startsWith("RSA/")) {
                continue;
            }

            if (providerAlgorithms.contains(wolfAlg)) {
                filteredAlgorithms.add(wolfAlg);
                continue;
            }

            for (String providerAlg : providerAlgorithms) {
                if (providerAlg.equalsIgnoreCase(wolfAlg)) {
                    filteredAlgorithms.add(providerAlg);
                    break;
                }
            }
        }

        return filteredAlgorithms;
    }

    /* Enhanced method to get PBKDF2 algorithms for special provider cases, filtered by wolfJCE support */
    private static Set<String> getPBKDF2AlgorithmsForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        Set<String> providerAlgorithms = getAlgorithmsForService(providerName, "SecretKeyFactory");
        Set<String> filteredAlgorithms = new TreeSet<>();

        for (String wolfAlg : wolfJCEAlgorithms) {
            if (providerAlgorithms.contains(wolfAlg)) {
                filteredAlgorithms.add(wolfAlg);
                continue;
            }

            for (String providerAlg : providerAlgorithms) {
                if (providerAlg.equalsIgnoreCase(wolfAlg)) {
                    filteredAlgorithms.add(providerAlg);
                    break;
                }

                if (providerName.equals("BC")) {
                    String normalizedProviderAlg = providerAlg.replace("WITH", "With").replace("HMAC", "Hmac");
                    if (normalizedProviderAlg.equalsIgnoreCase(wolfAlg)) {
                        filteredAlgorithms.add(providerAlg);
                        break;
                    }
                }
            }
        }

        return filteredAlgorithms;
    }

    /* Cipher benchmark runner using the universal methods */
    private static void runCipherBenchmarksForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        System.out.println("\n" + providerName + ":");

        Set<String> supportedAlgorithms;
        if (providerName.equals("wolfJCE")) {
            supportedAlgorithms = wolfJCEAlgorithms;
        } else {
            supportedAlgorithms = getCipherAlgorithmsForProvider(providerName, wolfJCEAlgorithms);
        }

        if (supportedAlgorithms.isEmpty()) {
            System.out.println("  No common Cipher algorithms found for provider " + providerName);
            return;
        }

        for (String algorithm : supportedAlgorithms) {
            try {
                /* Parse algorithm string to get mode and padding */
                String[] parts = algorithm.split("/");
                if (parts.length != 3) {
                    System.out.printf(" %-40s  Invalid algorithm format: %s%n",
                        algorithm + " (" + providerName + ")", algorithm);
                    continue;
                }

                String baseAlg = parts[0];
                String mode = parts[1];
                String padding = parts[2];

                /* Skip if DESede is not enabled */
                if (baseAlg.equals("DESede") && !FeatureDetect.Des3Enabled()) {
                    System.out.printf(" %-40s  DESede not enabled in wolfCrypt%n",
                        algorithm + " (" + providerName + ")");
                    continue;
                }

                runEncDecBenchmark(baseAlg, mode, padding, providerName);
            } catch (Exception e) {
                System.out.printf(" %-40s  Error: %s%n",
                    algorithm + " (" + providerName + ")", e.getMessage());
            }
        }
    }

    /* Get MessageDigest algorithms for a specific provider */
    private static Set<String> getMessageDigestAlgorithms(String providerName) {
        return getAlgorithmsForService(providerName, "MessageDigest");
    }

    /* Get the baseline MessageDigest algorithms that wolfJCE supports for comparison */
    private static Set<String> getWolfJCEMessageDigestAlgorithms() {
        return getWolfJCEAlgorithmsForService("MessageDigest");
    }

    /* Enhanced method to get MessageDigest algorithms for special provider cases, filtered by wolfJCE support */
    private static Set<String> getMessageDigestAlgorithmsForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        Set<String> algorithms;

        if (providerName.equals("wolfJCE")) {
            algorithms = new TreeSet<>(wolfJCEAlgorithms);
        } else {
            algorithms = getAlgorithmsForProvider(providerName, "MessageDigest", wolfJCEAlgorithms);
        }

        Set<String> filteredAlgorithms = new TreeSet<>();

        /* Normalize wolfJCE algorithms for comparison */
        Set<String> normalizedWolfJCE = new TreeSet<>();
        for (String alg : wolfJCEAlgorithms) {
            String normalized = alg.toUpperCase();
            if (normalized.equals("SHA")) normalized = "SHA-1";
            if (normalized.equals("SHA1")) normalized = "SHA-1";
            normalizedWolfJCE.add(normalized);
        }

        /* Track which algorithms we've already added to avoid duplicates */
        Set<String> addedNormalized = new TreeSet<>();

        /* Normalize algorithm names to avoid duplicates */
        for (String algorithm : algorithms) {
            String normalized = algorithm.toUpperCase();
            if (normalized.equals("SHA")) normalized = "SHA-1";
            if (normalized.equals("SHA1")) normalized = "SHA-1";

            /* For BC, convert their format to standard format */
            if (providerName.equals("BC")) {
                if (normalized.startsWith("SHA3") && !normalized.contains("-")) {
                    if (normalized.equals("SHA3224")) normalized = "SHA3-224";
                    else if (normalized.equals("SHA3256")) normalized = "SHA3-256";
                    else if (normalized.equals("SHA3384")) normalized = "SHA3-384";
                    else if (normalized.equals("SHA3512")) normalized = "SHA3-512";
                }
                normalized = normalized.replace("SHA3", "SHA3-");
                normalized = normalized.replace("SHA3--", "SHA3-");
            }

            if (normalizedWolfJCE.contains(normalized) && !addedNormalized.contains(normalized)) {
                if (normalized.equals("SHA-1")) {
                    if (algorithm.equals("SHA-1")) {
                        filteredAlgorithms.add(algorithm);
                        addedNormalized.add(normalized);
                    } else if (!addedNormalized.contains(normalized)) {
                        boolean hasStandardName = false;
                        for (String alg : algorithms) {
                            if (alg.equals("SHA-1")) {
                                hasStandardName = true;
                                break;
                            }
                        }
                        if (!hasStandardName) {
                            filteredAlgorithms.add(algorithm);
                            addedNormalized.add(normalized);
                        }
                    }
                } else {
                    filteredAlgorithms.add(algorithm);
                    addedNormalized.add(normalized);
                }
            }
        }

        return filteredAlgorithms;
    }

    /* MessageDigest benchmark runner using the universal methods */
    private static void runMessageDigestBenchmarksForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        System.out.println("\n" + providerName + ":");

        Set<String> supportedAlgorithms;
        supportedAlgorithms = getMessageDigestAlgorithmsForProvider(providerName, wolfJCEAlgorithms);

        if (supportedAlgorithms.isEmpty()) {
            System.out.println("  No common MessageDigest algorithms found for provider " + providerName);
            return;
        }

        for (String algorithm : supportedAlgorithms) {
            try {
                /* Check if algorithm is enabled in wolfCrypt */
                boolean isEnabled = true;
                if (algorithm.equals("MD5") && !FeatureDetect.Md5Enabled()) isEnabled = false;
                else if (algorithm.equals("SHA-1") && !FeatureDetect.ShaEnabled()) isEnabled = false;
                else if (algorithm.equals("SHA-224") && !FeatureDetect.Sha224Enabled()) isEnabled = false;
                else if (algorithm.equals("SHA-256") && !FeatureDetect.Sha256Enabled()) isEnabled = false;
                else if (algorithm.equals("SHA-384") && !FeatureDetect.Sha384Enabled()) isEnabled = false;
                else if (algorithm.equals("SHA-512") && !FeatureDetect.Sha512Enabled()) isEnabled = false;
                else if (algorithm.startsWith("SHA3-") && !FeatureDetect.Sha3Enabled()) isEnabled = false;

                if (!isEnabled) {
                    System.out.printf(" %-40s  Not enabled in wolfCrypt%n",
                        algorithm + " (" + providerName + ")");
                    continue;
                }

                runMessageDigestBenchmark(algorithm, providerName);
            } catch (Exception e) {
                System.out.printf(" %-40s  Error: %s%n",
                    algorithm + " (" + providerName + ")", e.getMessage());
            }
        }
    }

    /* Get PBKDF2 algorithms for a specific provider */
    private static Set<String> getPBKDF2Algorithms(String providerName) {
        return getAlgorithmsForService(providerName, "SecretKeyFactory");
    }

    /* PBKDF2 benchmark runner using the universal methods */
    private static void runPBKDF2BenchmarksForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        System.out.println("\n" + providerName + ":");

        Set<String> supportedAlgorithms;
        if (providerName.equals("wolfJCE")) {
            supportedAlgorithms = wolfJCEAlgorithms;
        } else {
            supportedAlgorithms = getPBKDF2AlgorithmsForProvider(providerName, wolfJCEAlgorithms);
        }

        if (supportedAlgorithms.isEmpty()) {
            System.out.println("  No common SecretKeyFactory algorithms found for provider " + providerName);
            return;
        }

        for (String algorithm : supportedAlgorithms) {
            try {
                /* Skip SHA3 algorithms for SunJCE */
                if (providerName.equals("SunJCE") && algorithm.contains("SHA3")) {
                    continue;
                }

                runPBKDF2Benchmark(algorithm, providerName);
            } catch (Exception e) {
                System.out.printf(" %-40s  Error: %s%n",
                    algorithm + " (" + providerName + ")", e.getMessage());
            }
        }
    }

    /* Get the baseline cipher algorithms that wolfJCE supports for comparison */
    private static Set<String> getWolfJCECipherAlgorithms() {
        return getWolfJCEAlgorithmsForService("Cipher");
    }

    /* Get the baseline PBKDF2 algorithms that wolfJCE supports for comparison */
    private static Set<String> getWolfJCEPBKDF2Algorithms() {
        return getWolfJCEAlgorithmsForService("SecretKeyFactory");
    }

    /* Get the baseline signature algorithms that wolfJCE supports for comparison */
    private static Set<String> getWolfJCESignatureAlgorithms() {
        return getWolfJCEAlgorithmsForService("Signature");
    }

    /* KeyGenerator benchmark */
    /* KeyGenerator benchmark */
    private static void runKeyGeneratorBenchmark(String algorithm, String providerName) throws Exception {
        KeyGenerator keyGen;
        int ops = 0;
        long startTime;
        double elapsedTime;

        /* Initialize KeyGenerator with specific provider */
        keyGen = KeyGenerator.getInstance(algorithm, providerName);

        /* Set appropriate key size based on algorithm */
        if (algorithm.equals("AES")) {
            keyGen.init(256);
        } else if (algorithm.equals("DES")) {
            keyGen.init(56);
        } else if (algorithm.equals("DESede")) {
            keyGen.init(168);
        } else if (algorithm.equals("RSA")) {
            keyGen.init(2048);
        } else if (algorithm.startsWith("Hmac") || algorithm.startsWith("HMAC")) {
            try {
                int keySize = getHmacKeySize(algorithm) * 8;
                keyGen.init(keySize);
            } catch (Exception e) {
            }
        } else {
            try {
                keyGen.generateKey();
                keyGen = KeyGenerator.getInstance(algorithm, providerName);
            } catch (Exception e) {
                throw new IllegalArgumentException("Unsupported algorithm or unable to determine key size: " + algorithm);
            }
        }

        /* Warm up phase */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            keyGen.generateKey();
        }

        /* Benchmark phase */
        startTime = System.nanoTime();
        elapsedTime = 0;

        do {
            keyGen.generateKey();
            ops++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        double opsPerSec = ops / elapsedTime;
        System.out.printf(" %-40s  %8d ops took %.3f sec, %8.3f ops/sec%n",
            algorithm + " (" + providerName + ")", ops, elapsedTime, opsPerSec);

        /* Store result */
        results.add(new BenchmarkResult(providerName, algorithm + " keygen", opsPerSec));
    }

    /* Get KeyGenerator algorithms for a specific provider */
    private static Set<String> getKeyGeneratorAlgorithmsForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        return getAlgorithmsForProvider(providerName, "KeyGenerator", wolfJCEAlgorithms);
    }

    /* KeyGenerator benchmark runner */
    private static void runKeyGeneratorBenchmarksForProvider(String providerName, Set<String> wolfJCEAlgorithms) {
        System.out.println("\n" + providerName + ":");

        Set<String> supportedAlgorithms;
        if (providerName.equals("wolfJCE")) {
            supportedAlgorithms = wolfJCEAlgorithms;
        } else {
            supportedAlgorithms = getKeyGeneratorAlgorithmsForProvider(providerName, wolfJCEAlgorithms);
        }

        if (supportedAlgorithms.isEmpty()) {
            System.out.println("  No common KeyGenerator algorithms found for provider " + providerName);
            return;
        }

        for (String algorithm : supportedAlgorithms) {
            try {
                runKeyGeneratorBenchmark(algorithm, providerName);
            } catch (Exception e) {
                System.out.printf(" %-40s  Error: %s%n",
                    algorithm + " (" + providerName + ")", e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        try {
            /* Check if Bouncy Castle is available */
            boolean hasBouncyCastle = false;
            Provider bcProvider = null;
            try {
                Class<?> bcClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                bcProvider = (Provider) bcClass.getDeclaredConstructor().newInstance();
                hasBouncyCastle = true;
            } catch (Exception e) {
                /* Bouncy Castle not available */
            }

            /* Create provider list based on availability */
            java.util.List<Provider> providerList = new java.util.ArrayList<>();
            java.util.List<String> providerNameList = new java.util.ArrayList<>();

            providerList.add(new WolfCryptProvider());
            providerNameList.add("wolfJCE");

            /* Get SunJCE provider using Security.getProvider instead of direct instantiation */
            Provider sunJCE = Security.getProvider("SunJCE");
            if (sunJCE != null) {
                providerList.add(sunJCE);
                providerNameList.add("SunJCE");
            } else {
                System.out.println("Warning: SunJCE provider not available");
            }

            if (hasBouncyCastle && bcProvider != null) {
                providerList.add(bcProvider);
                providerNameList.add("BC");
            }

            Provider[] providers = providerList.toArray(new Provider[0]);
            String[] providerNames = providerNameList.toArray(new String[0]);

            /* Print provider versions */
            for (Provider provider : providers) {
                printProviderInfo(provider);
            }

            /* Run symmetric benchmarks with hardcoded algorithms (temporary fix) */
            System.out.println("-----------------------------------------------------------------------------");
            System.out.println(" Symmetric Cipher Benchmark");
            System.out.println("-----------------------------------------------------------------------------\n");

            setupProvidersForTest(providers[0]);
            Set<String> wolfJCECipherAlgorithms = getWolfJCECipherAlgorithms();

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                String providerName = provider.getName();
                System.out.println("\n" + providerName + ":");

                try {
                    runEncDecBenchmark("AES", "CBC", "NoPadding", providerName);
                    runEncDecBenchmark("AES", "CBC", "PKCS5Padding", providerName);
                    runEncDecBenchmark("AES", "GCM", "NoPadding", providerName);

                    if (FeatureDetect.Des3Enabled()) {
                        runEncDecBenchmark("DESede", "CBC", "NoPadding", providerName);
                    }
                } catch (Exception e) {
                    System.out.printf(" Error testing symmetric ciphers for %s: %s%n", providerName, e.getMessage());
                }
            }

            /* Run RSA benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("RSA Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                System.out.println("\n" + (provider.getName().equals("SunJCE") ? "SunJCE / SunRsaSign" : provider.getName()) + ":");
                for (int keySize : RSA_KEY_SIZES) {
                    try {
                        runRSABenchmark(provider.getName(), keySize);
                    } catch (Exception e) {
                        System.out.printf("Failed to benchmark RSA %d with provider %s: %s%n",
                            keySize, provider.getName(), e.getMessage());
                    }
                }
            }

            /* Run ECC benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("ECC Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            for (Provider provider : providers) {
                if (provider instanceof WolfCryptProvider && !FeatureDetect.EccKeyGenEnabled()) {
                    continue;
                }
                setupProvidersForTest(provider);
                System.out.println("\n" + (provider.getName().equals("SunJCE") ? "SunJCE / SunEC" : provider.getName()) + ":");
                for (String curve : ECC_CURVES) {
                    try {
                        runECCBenchmark(provider.getName(), curve);
                    } catch (Exception e) {
                        System.out.printf("Failed to benchmark %s with provider %s: %s%n",
                            curve, provider.getName(), e.getMessage());
                    }
                }
            }

            /* Run HMAC benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("HMAC Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");


            /* First, set up wolfJCE provider to get its algorithm list */
            setupProvidersForTest(providers[0]);
            Set<String> wolfJCEHmacAlgorithms = getWolfJCEHmacAlgorithms();

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                runHmacBenchmarksForProvider(provider.getName(), wolfJCEHmacAlgorithms);

            }

            /* Run DH benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("DH Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            for (Provider provider : providers) {
                if (provider instanceof WolfCryptProvider && !FeatureDetect.DhEnabled()) {
                    continue;
                }
                setupProvidersForTest(provider);
                System.out.println("\n" + provider.getName() + ":");
                for (int keySize : DH_KEY_SIZES) {
                    try {
                        runDHBenchmark(provider.getName(), keySize);
                    } catch (Exception e) {
                        System.out.printf("Failed to benchmark DH %d with provider %s: %s%n",
                            keySize, provider.getName(), e.getMessage());
                    }
                }
            }

            /* Run PBKDF2 benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("PBKDF2 Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            /* First, set up wolfJCE provider to get its algorithm list */
            setupProvidersForTest(providers[0]);
            Set<String> wolfJCEPBKDF2Algorithms = getWolfJCEPBKDF2Algorithms();

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                runPBKDF2BenchmarksForProvider(provider.getName(), wolfJCEPBKDF2Algorithms);
            }

            /* Run MessageDigest benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("MessageDigest Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            /* First, set up wolfJCE provider to get its algorithm list */
            setupProvidersForTest(providers[0]);
            Set<String> wolfJCEMessageDigestAlgorithms = getWolfJCEMessageDigestAlgorithms();

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                String providerName = provider.getName();
                String digestProviderName = providerName;

                /* Handle special case for digest providers */
                if (!providerName.equals("wolfJCE") && !providerName.equals("BC")) {
                    digestProviderName = "SUN";
                }

                setupDigestProvider(providerName);
                runMessageDigestBenchmarksForProvider(digestProviderName, wolfJCEMessageDigestAlgorithms);
            }

            /* Run Signature benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("Signature Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            /* First, set up wolfJCE provider to get its algorithm list */
            setupProvidersForTest(providers[0]);
            Set<String> wolfJCEAlgorithms = getWolfJCESignatureAlgorithms();

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                runSignatureBenchmarksForProvider(provider.getName(), wolfJCEAlgorithms);
            }

            /* Run KeyGenerator benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("KeyGenerator Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            /* First, set up wolfJCE provider to get its algorithm list */
            setupProvidersForTest(providers[0]);
            Set<String> wolfJCEKeyGenAlgorithms = getWolfJCEAlgorithmsForService("KeyGenerator");

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                runKeyGeneratorBenchmarksForProvider(provider.getName(), wolfJCEKeyGenAlgorithms);
            }

            System.out.println("-----------------------------------------------------------------------------\n");

            /* Print delta table */
            printDeltaTable();

        } catch (Exception e) {
            System.err.println("Benchmark failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}