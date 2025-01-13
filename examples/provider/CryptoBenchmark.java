import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

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
  private static final int RSA_MIN_TIME_SECONDS = 1;  /* minimum time to run each test */
  private static final int SMALL_MESSAGE_SIZE = 32;   /* small message size for RSA ops */

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

  private static void printProviderInfo(Provider provider) {
    System.out.printf("%s version: %.1f%n", provider.getName(), provider.getVersion());
  }

  private static void printDeltaTable() {
    /* Variables for table generation */
    Map<String, Map<String, Double>> groupedResults;
    String operation;
    Map<String, Double> providerResults;
    double wolfSpeed;
    String provider;
    double otherSpeed;
    double deltaValue;
    double deltaPercent;
    boolean isRSAOperation;

    System.out.println("\nPerformance Delta (compared to wolfJCE)");
    System.out.println("-----------------------------------------------------------------------------");
    System.out.println("| Operation                                | Provider |  Delta   |   Delta  |");
    System.out.println("|                                          |          |  Value*  |   (%)    |");
    System.out.println("|------------------------------------------|----------|----------|----------|");

    /* Group results by operation */
    groupedResults = new HashMap<>();
    for (BenchmarkResult result : results) {
      groupedResults
        .computeIfAbsent(result.operation, k -> new HashMap<>())
        .put(result.provider, result.throughput);
    }

    /* Calculate and print deltas */
    for (Map.Entry<String, Map<String, Double>> entry : groupedResults.entrySet()) {
      operation = entry.getKey();
      providerResults = entry.getValue();
      wolfSpeed = providerResults.getOrDefault("wolfJCE", 0.0);
      isRSAOperation = operation.startsWith("RSA");

      for (Map.Entry<String, Double> providerEntry : providerResults.entrySet()) {
        provider = providerEntry.getKey();
        if (!provider.equals("wolfJCE")) {
          otherSpeed = providerEntry.getValue();

          if (isRSAOperation) {
            deltaValue = wolfSpeed - otherSpeed;
            deltaPercent = ((wolfSpeed / otherSpeed) - 1.0) * 100;
          } else {
            deltaValue = wolfSpeed - otherSpeed;
            deltaPercent = ((wolfSpeed / otherSpeed) - 1.0) * 100;
          }

          System.out.printf("| %-40s | %-8s | %+8.2f | %+8.1f |%n",
              operation,
              provider,
              deltaValue,
              deltaPercent);
        }
      }
    }
    System.out.println("-----------------------------------------------------------------------------");
    System.out.println("* Delta Value: MiB/s for symmetric ciphers, operations/second for RSA");
  }

  private static void runBenchmark(String algorithm, String mode, String padding,
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
    System.out.printf("| %-40s | %8.3f | %8.3f | %8.3f |%n",
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

    System.out.printf("| %-40s | %8.3f | %8.3f | %8.3f |%n",
        testName + " dec", dataSizeMiB, decryptTimeMS, decryptThroughput);

    /* Store decryption result */
    results.add(new BenchmarkResult(providerName, cipherName + " dec", decryptThroughput));
  }

  /* Print RSA results in simpler format */
  private static void printRSAResults(int operations, double totalTime, String operation,
      String providerName) {
    double avgTimeMs = (totalTime * 1000.0) / operations;
    double opsPerSec = operations / totalTime;
    System.out.printf("%-12s  %-8s %8d ops took %.3f sec, avg %.3f ms, %.3f ops/sec%n",
        operation,
        " ",
        operations,
        totalTime,
        avgTimeMs,
        opsPerSec);

    /* Store results for delta table */
    results.add(new BenchmarkResult(providerName, operation, opsPerSec));
  }

  /* Run RSA benchmarks */
  private static void runRSABenchmark(String providerName, int keySize) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", providerName);
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", providerName);
    byte[] testData = generateTestData(SMALL_MESSAGE_SIZE);

    /* Key Generation benchmark */
    keyGen.initialize(keySize);
    int keyGenOps = 0;
    long startTime = System.nanoTime();
    double elapsedTime;

    do {
      keyGen.generateKeyPair();
      keyGenOps++;
      elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
    } while (elapsedTime < RSA_MIN_TIME_SECONDS);

    String keyGenOp = String.format("RSA %d key gen", keySize);
    printRSAResults(keyGenOps, elapsedTime, keyGenOp, providerName);

    /* For 2048-bit keys, also test public/private operations */
    if (keySize == 2048) {
      KeyPair keyPair = keyGen.generateKeyPair();

      /* Public key operations */
      int publicOps = 0;
      startTime = System.nanoTime();

      do {
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        cipher.doFinal(testData);
        publicOps++;
        elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
      } while (elapsedTime < RSA_MIN_TIME_SECONDS);

      printRSAResults(publicOps, elapsedTime, "RSA 2048 public", providerName);

      /* Private key operations */
      cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
      byte[] encrypted = cipher.doFinal(testData);

      int privateOps = 0;
      startTime = System.nanoTime();

      do {
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        cipher.doFinal(encrypted);
        privateOps++;
        elapsedTime = (System.nanoTime() - startTime) / 1_000_000_000.0;
      } while (elapsedTime < RSA_MIN_TIME_SECONDS);

      printRSAResults(privateOps, elapsedTime, "RSA 2048 private", providerName);
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
      System.out.println("-----------------------------------------------------------------------------");
      System.out.println("| Operation                                | Size MiB |    ms    |   MiB/s  |");
      System.out.println("|------------------------------------------|----------|----------|----------|");

      /* Run symmetric benchmarks */
      for (int i = 0; i < providers.length; i++) {
        Security.insertProviderAt(providers[i], 1);

        runBenchmark("AES", "CBC", "NoPadding", providerNames[i]);
        runBenchmark("AES", "CBC", "PKCS5Padding", providerNames[i]);
        runBenchmark("AES", "GCM", "NoPadding", providerNames[i]);

        if (FeatureDetect.Des3Enabled()) {
          runBenchmark("DESede", "CBC", "NoPadding", providerNames[i]);
        }

        if (i < providers.length - 1) {
          System.out.println("|------------------------------------------|----------|----------|----------|");
        }

        Security.removeProvider(providers[i].getName());
      }

      System.out.println("-----------------------------------------------------------------------------");

      /* Run RSA benchmarks */
      System.out.println("\nRSA Benchmark Results");
      System.out.println("-----------------------------------------------------------------------------");

      for (Provider provider : providers) {
        if (!provider.getName().equals("SunJCE")) {
          Security.insertProviderAt(provider, 1);
          System.out.println("\n" + provider.getName() + ":");

          for (int keySize : RSA_KEY_SIZES) {
            runRSABenchmark(provider.getName(), keySize);
          }

          Security.removeProvider(provider.getName());
        }
      }

      System.out.println("-----------------------------------------------------------------------------");

      /* Print delta table */
      printDeltaTable();

    } catch (Exception e) {
      System.err.println("Benchmark failed: " + e.getMessage());
      e.printStackTrace();
    }
  }
}
