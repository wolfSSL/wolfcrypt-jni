import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import com.wolfssl.provider.jce.WolfCryptProvider;

public class CryptoBenchmark {
    /* Constants for benchmark configuration */
    private static final int WARMUP_ITERATIONS = 1000;
    private static final int TEST_ITERATIONS = 10000;
    private static final int DATA_SIZE = 16384; /* 16KB of data */
    private static final int AES_BLOCK_SIZE = 16;
    private static final int AES_KEY_SIZE = 256;

    private static byte[] generateRandomData(int size) {
        byte[] data = new byte[size];
        new SecureRandom().nextBytes(data);
        return data;
    }

    /* 
     * Benchmarks Cipher class operations using AES-CBC 
     * Returns array containing encrypt and decrypt times in nanoseconds
     */
    private static void benchmarkCipher() throws Exception {
        /* Key generation variables */
        KeyGenerator keyGen;
        SecretKey key;
        
        /* IV generation variables */
        byte[] ivBytes;
        IvParameterSpec iv;
        
        /* Test data variables */
        byte[] testData;
        byte[] encryptedData;
        byte[] encrypted;
        
        /* Cipher variables */
        Cipher cipher;
        
        /* Timing variables */
        long startTime;
        long endTime;
        long encryptTime;
        long decryptTime;
        double encryptThroughput;
        double decryptThroughput;
        
        /* Provider info */
        Provider provider;

        /* Generate a random key and IV */
        keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        key = keyGen.generateKey();
        
        ivBytes = new byte[AES_BLOCK_SIZE];
        new SecureRandom().nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);

        /* Generate random test data */
        testData = generateRandomData(DATA_SIZE);

        /* Initialize cipher for warmup */
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        /* Warm up phase */
        System.out.println("Warming up...");
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            encrypted = cipher.doFinal(testData);
            
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            cipher.doFinal(encrypted);
        }

        System.out.println("\nBenchmarking AES-CBC (" + AES_KEY_SIZE + "-bit key) with " + 
                DATA_SIZE + " bytes:");
        System.out.println("Iterations per test: " + TEST_ITERATIONS);

        /* Benchmark encryption */
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            cipher.doFinal(testData);
        }
        endTime = System.nanoTime();
        encryptTime = (endTime - startTime) / TEST_ITERATIONS;

        /* Benchmark decryption */
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        encryptedData = cipher.doFinal(testData);
        
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            cipher.doFinal(encryptedData);
        }
        endTime = System.nanoTime();
        decryptTime = (endTime - startTime) / TEST_ITERATIONS;

        /* Print results */
        System.out.println("\nResults (average time per operation):");
        System.out.println("  Encryption: " + encryptTime + " ns (" + 
                String.format("%.2f", encryptTime/1000000.0) + " ms)");
        System.out.println("  Decryption: " + decryptTime + " ns (" + 
                String.format("%.2f", decryptTime/1000000.0) + " ms)");

        /* Calculate and print throughput */
        encryptThroughput = (DATA_SIZE / (encryptTime / 1000000000.0)) / (1024 * 1024);
        decryptThroughput = (DATA_SIZE / (decryptTime / 1000000000.0)) / (1024 * 1024);
        
        System.out.println("\nThroughput:");
        System.out.println("  Encryption: " + String.format("%.2f", encryptThroughput) + " MB/s");
        System.out.println("  Decryption: " + String.format("%.2f", decryptThroughput) + " MB/s");

        /* Print provider information */
        provider = Security.getProvider(cipher.getProvider().getName());
        System.out.println("\nProvider Information:");
        System.out.println("  Name: " + provider.getName());
        System.out.println("  Version: " + provider.getVersion());
        System.out.println("  Info: " + provider.getInfo());
    }

    public static void main(String[] args) {
        try {
            /* Register wolfJCE as the default provider */
            Security.insertProviderAt(new WolfCryptProvider(), 1);

            /* Run Cipher benchmark */
            benchmarkCipher();

        } catch (Exception e) {
            System.err.println("Benchmark failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
