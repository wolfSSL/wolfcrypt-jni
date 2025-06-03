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
import sun.security.ec.SunEC;
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
                throw new IllegalArgumentException("Unsupported HMAC algorithm: " + algorithm);
        }
    }

    /* List of signature algorithms supported by wolfJCE - must match exactly what's in WolfCryptProvider */
    private static final String[] SIGNATURE_ALGORITHMS = {
        /* RSA algorithms */
        "MD5withRSA",
        "SHA1withRSA",
        "SHA224withRSA",
        "SHA256withRSA",
        "SHA384withRSA",
        "SHA512withRSA",
        "SHA3-224withRSA",
        "SHA3-256withRSA",
        "SHA3-384withRSA",
        "SHA3-512withRSA",
        
        /* ECDSA algorithms */
        "SHA1withECDSA",
        "SHA224withECDSA",
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA512withECDSA",
        "SHA3-224withECDSA",
        "SHA3-256withECDSA",
        "SHA3-384withECDSA",
        "SHA3-512withECDSA"
    };

    /* List of signature algorithms supported by SUN providers - based on screenshot */
    private static final String[] SUN_SIGNATURE_ALGORITHMS = {
        /* RSA algorithms */
        "MD2withRSA",
        "MD5withRSA",
        "SHA1withRSA",
        "SHA224withRSA",
        "SHA256withRSA",
        "SHA384withRSA",
        "SHA512withRSA",
        
        /* ECDSA algorithms */
        "SHA1withECDSA",
        "SHA224withECDSA",
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA512withECDSA",
    };

    private static void printProviderInfo(Provider provider) {
        System.out.printf("%s version: %.1f%n", provider.getName(), provider.getVersion());
    }

    private static void setupProvidersForTest(Provider testProvider) {
        /* Remove only our test providers */
        Security.removeProvider("wolfJCE");
        Security.removeProvider("BC");
        
        /* Add test provider at priority 1 */
        Security.insertProviderAt(testProvider, 1);
        
        /* For SunJCE tests, ensure SunEC is available */
        if (testProvider.getName().equals("SunJCE") && Security.getProvider("SunEC") == null) {
            try {
                Provider sunEC = new sun.security.ec.SunEC();
                Security.addProvider(sunEC);
            } catch (Exception e) {
                System.out.println("Warning: SunEC provider not available: " + e.getMessage());
            }
        }
    }

    private static void setupDigestProvider(String testProviderName) {
        /* For digest operations, we need special handling */
        if (testProviderName.equals("wolfJCE") || testProviderName.equals("BC")) {
            // wolfJCE and BC can handle their own digests
            return;
        } else {
            /* For SunJCE, we need SUN provider for MessageDigest */
            if (Security.getProvider("SUN") == null) {
                try {
                    Provider sunProvider = Security.getProvider("SUN");
                    if (sunProvider == null) {
                        /* SUN provider should be built-in, but let's be safe */
                        System.out.println("SUN provider not found for MessageDigest operations");
                    }
                } catch (Exception e) {
                    System.out.println("Failed to set up SUN provider: " + e.getMessage());
                }
            }
        }
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
        double dataSizeMiB;
        Cipher cipher;
        String cipherName = algorithm + "/" + mode + "/" + padding;

        /* Timing variables */
        long startTime;
        long endTime;
        long encryptTime;
        long decryptTime;
        double encryptThroughput;
        double decryptThroughput;
        double encryptTimeMS;
        double decryptTimeMS;

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

        /* Benchmark encryption */
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            if (mode.equals("GCM")) {
                secureRandom.nextBytes(ivBytes);
                params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            encryptedData = cipher.doFinal(testData);
        }
        endTime = System.nanoTime();
        encryptTime = (endTime - startTime) / TEST_ITERATIONS;

        dataSizeMiB = (DATA_SIZE * TEST_ITERATIONS) / (1024.0 * 1024.0);
        encryptTimeMS = encryptTime / 1000000.0;
        encryptThroughput = (DATA_SIZE / (encryptTime / 1000000000.0)) / (1024.0 * 1024.0);

        String testName = String.format("%s (%s)", cipherName, providerName);
        System.out.printf(" %-40s  %8.3f MiB %8.3f ms %8.3f MiB/s%n",
          testName + " enc", dataSizeMiB, encryptTimeMS, encryptThroughput);

        results.add(new BenchmarkResult(providerName, cipherName + " enc", encryptThroughput));

        /* Benchmark decryption */
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.doFinal(encryptedData);
        }
        endTime = System.nanoTime();
        decryptTime = (endTime - startTime) / TEST_ITERATIONS;

        decryptTimeMS = decryptTime / 1000000.0;
        decryptThroughput = (DATA_SIZE / (decryptTime / 1000000000.0)) / (1024.0 * 1024.0);

        System.out.printf(" %-40s  %8.3f MiB %8.3f ms %8.3f MiB/s%n",
          testName + " dec", dataSizeMiB , decryptTimeMS, decryptThroughput);

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

        /* Benchmark phase: run for at least 1 second */
        startTime = System.nanoTime();
        elapsedTime = 0;
        
        do {
            mac.update(testData);
            mac.doFinal();
            ops++;
            elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
        } while (elapsedTime < TEST_MIN_TIME_SECONDS);

        /* Calculate metrics */
        double dataSizeMiB = (DATA_SIZE * ops) / (1024.0 * 1024.0);
        double throughput = dataSizeMiB / elapsedTime;

        /* Print results in consistent format */
        System.out.printf("%-40s %8.3f MiB took %.3f sec, %8.3f MiB/s%n",
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
        int ops = 0;
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
        
        if (algorithm.contains("withRSA")) {
            keyType = "RSA";
            if (providerName.equals("SunJCE")) {
                keyGenProvider = "SunRsaSign";
                signatureProvider = "SunRsaSign";
            }
        } else if (algorithm.contains("withECDSA")) {
        keyType = "EC";
        if (providerName.equals("SunJCE")) {
            Provider sunECProvider = Security.getProvider("SunEC");
            if (sunECProvider == null) {
                try {
                    Provider sunEC = new sun.security.ec.SunEC();
                    Security.addProvider(sunEC);
                } catch (Exception e) {
                    throw new Exception("SunEC provider not available: " + e.getMessage());
                }
            }
            keyGenProvider = "SunEC";
            signatureProvider = "SunEC";

        }
    }
        else if (algorithm.contains("withDSA")) {
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
          signature = Signature.getInstance(algorithm, signatureProvider);

            /* Initialize key generator based on type */
            if (keyType.equals("RSA")) {
                keyGen.initialize(2048);
            } else if (keyType.equals("EC")) {
                if (keyGenProvider.equals("SunEC")) {
                    keyGen.initialize(new ECGenParameterSpec("secp256r1"));
                } else {
                      keyGen.initialize(new ECGenParameterSpec("secp256r1"));
                }
            } else if (keyType.equals("DSA")) {
                keyGen.initialize(1024);
            }
            
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
            System.out.printf(" %-40s  Not supported: %s%n", 
                algorithm + " (" + signatureProvider + ")", e.getMessage());
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

            providerList.add(new com.sun.crypto.provider.SunJCE());
            providerNameList.add("SunJCE");

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

            System.out.println("-----------------------------------------------------------------------------");
            System.out.println(" Symmetric Cipher Benchmark");
            System.out.println("-----------------------------------------------------------------------------\n");

            /* Run symmetric benchmarks with clean provider setup */
            for (int i = 0; i < providers.length; i++) {
                setupProvidersForTest(providers[i]);

                runEncDecBenchmark("AES", "CBC", "NoPadding", providerNames[i]);
                runEncDecBenchmark("AES", "CBC", "PKCS5Padding", providerNames[i]);
                runEncDecBenchmark("AES", "GCM", "NoPadding", providerNames[i]);

                if (FeatureDetect.Des3Enabled()) {
                    runEncDecBenchmark("DESede", "CBC", "NoPadding", providerNames[i]);
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

            for (int i = 0; i < providers.length; i++) {
                setupProvidersForTest(providers[i]);
                System.out.println("\n" + providerNames[i] + ":");

                if (FeatureDetect.HmacMd5Enabled()) {
                    try {
                        runHmacBenchmark("HmacMD5", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacMD5 (" + providerNames[i] + ")", e.getMessage());
                    }
                }
                if (FeatureDetect.HmacShaEnabled()) {
                    try {
                        runHmacBenchmark("HmacSHA1", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA1 (" + providerNames[i] + ")", e.getMessage());
                    }
                }
                if (FeatureDetect.Sha224Enabled()) {
                    try {
                        runHmacBenchmark("HmacSHA224", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA224 (" + providerNames[i] + ")", e.getMessage());
                    }
                }
                if (FeatureDetect.HmacSha256Enabled()) {
                    try {
                        runHmacBenchmark("HmacSHA256", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA256 (" + providerNames[i] + ")", e.getMessage());
                    }
                }
                if (FeatureDetect.HmacSha384Enabled()) {
                    try {
                        runHmacBenchmark("HmacSHA384", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA384 (" + providerNames[i] + ")", e.getMessage());
                    }
                }
                if (FeatureDetect.HmacSha512Enabled()) {
                    try {
                        runHmacBenchmark("HmacSHA512", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA512 (" + providerNames[i] + ")", e.getMessage());
                    }
                }
                if (FeatureDetect.Sha3Enabled() && !providerNames[i].equals("SunJCE")) {
                    try {
                        runHmacBenchmark("HmacSHA3-224", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA3-224 (" + providerNames[i] + ")", e.getMessage());
                    }
                    try {
                        runHmacBenchmark("HmacSHA3-256", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA3-256 (" + providerNames[i] + ")", e.getMessage());
                    }
                    try {
                        runHmacBenchmark("HmacSHA3-384", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA3-384 (" + providerNames[i] + ")", e.getMessage());
                    }
                    try {
                        runHmacBenchmark("HmacSHA3-512", providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf("%-40s Error: %s%n", 
                            "HmacSHA3-512 (" + providerNames[i] + ")", e.getMessage());
                    }
                }
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

            String[] pbkdf2Algorithms = {
                "PBKDF2WithHmacSHA1",
                "PBKDF2WithHmacSHA224",
                "PBKDF2WithHmacSHA256",
                "PBKDF2WithHmacSHA384", 
                "PBKDF2WithHmacSHA512",
                "PBKDF2WithHmacSHA3-224",
                "PBKDF2WithHmacSHA3-256",
                "PBKDF2WithHmacSHA3-384",
                "PBKDF2WithHmacSHA3-512"
            };

            for (int i = 0; i < providers.length; i++) {
                setupProvidersForTest(providers[i]);
                System.out.println("\n" + providerNames[i] + ":");
                
                for (String algorithm : pbkdf2Algorithms) {
                    try {
                        /* Skip SHA3 algorithms for SunJCE */
                        if (providerNames[i].equals("SunJCE") && algorithm.contains("SHA3")) {
                            continue;
                        }
                        
                        runPBKDF2Benchmark(algorithm, providerNames[i]);
                    } catch (Exception e) {
                        System.out.printf(" %-40s  Error: %s%n", 
                            algorithm + " (" + providerNames[i] + ")", e.getMessage());
                    }
                }
            }

            /* Run MessageDigest benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("MessageDigest Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            for (int i = 0; i < providers.length; i++) {
                setupProvidersForTest(providers[i]);
                String providerName = providerNames[i];
                String digestProviderName = providerName;

                // Handle special case for digest providers
                if (!providerName.equals("wolfJCE") && !providerName.equals("BC")) {
                    digestProviderName = "SUN";  // Use SUN for standard digest algorithms
                }

                setupDigestProvider(providerName);
                System.out.println("\n" + digestProviderName + ":");
                
                try {
                    if (FeatureDetect.Md5Enabled() && isAlgorithmSupported("MD5", digestProviderName)) {
                        runMessageDigestBenchmark("MD5", digestProviderName);
                    }
                    if (FeatureDetect.ShaEnabled() && isAlgorithmSupported("SHA-1", digestProviderName)) {
                        runMessageDigestBenchmark("SHA-1", digestProviderName);
                    }
                    if (FeatureDetect.Sha224Enabled() && isAlgorithmSupported("SHA-224", digestProviderName)) {
                        runMessageDigestBenchmark("SHA-224", digestProviderName);
                    }
                    if (FeatureDetect.Sha256Enabled() && isAlgorithmSupported("SHA-256", digestProviderName)) {
                        runMessageDigestBenchmark("SHA-256", digestProviderName);
                    }
                    if (FeatureDetect.Sha384Enabled() && isAlgorithmSupported("SHA-384", digestProviderName)) {
                        runMessageDigestBenchmark("SHA-384", digestProviderName);
                    }
                    if (FeatureDetect.Sha512Enabled() && isAlgorithmSupported("SHA-512", digestProviderName)) {
                        runMessageDigestBenchmark("SHA-512", digestProviderName);
                    }
                    if (FeatureDetect.Sha3Enabled() && isAlgorithmSupported("SHA3-224", digestProviderName)) {
                        runMessageDigestBenchmark("SHA3-224", digestProviderName);
                    }
                    if (FeatureDetect.Sha3Enabled() && isAlgorithmSupported("SHA3-256", digestProviderName)) {
                        runMessageDigestBenchmark("SHA3-256", digestProviderName);
                    }
                    if (FeatureDetect.Sha3Enabled() && isAlgorithmSupported("SHA3-384", digestProviderName)) {
                        runMessageDigestBenchmark("SHA3-384", digestProviderName);
                    }
                    if (FeatureDetect.Sha3Enabled() && isAlgorithmSupported("SHA3-512", digestProviderName)) {
                        runMessageDigestBenchmark("SHA3-512", digestProviderName);
                    }
                } catch (Exception e) {
                    System.out.println("Failed to benchmark MessageDigest with provider " + digestProviderName + ": " + e.getMessage());
                }
            }

            /* Run Signature benchmarks with clean provider setup */
            System.out.println("\n-----------------------------------------------------------------------------");
            System.out.println("Signature Benchmark Results");
            System.out.println("-----------------------------------------------------------------------------");

            for (Provider provider : providers) {
                setupProvidersForTest(provider);
                String providerName = provider.getName();
                
                System.out.println("\n" + providerName + ":");
                
                if (providerName.equals("wolfJCE") || providerName.equals("BC")) {
                    /* Test wolfJCE/BC signature algorithms */
                    for (String algorithm : SIGNATURE_ALGORITHMS) {
                        try {
                            runSignatureBenchmark(algorithm, providerName);
                        } catch (Exception e) {
                            System.out.printf(" %-40s  Error: %s%n", 
                                algorithm + " (" + providerName + ")", e.getMessage());
                        }
                    }
                } else if (providerName.equals("SunJCE")) {
                    /* For SunJCE, we'll test with the Sun providers */
                    System.out.println("(Using SunRsaSign for RSA, SunEC for ECDSA)");
                    for (String algorithm : SUN_SIGNATURE_ALGORITHMS) {
                        try {
                            runSignatureBenchmark(algorithm, "SunJCE");
                        } catch (Exception e) {
                            System.out.printf(" %-40s  Error: %s%n", 
                                algorithm + " (SunJCE)", e.getMessage());
                        }
                    }
                }
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
