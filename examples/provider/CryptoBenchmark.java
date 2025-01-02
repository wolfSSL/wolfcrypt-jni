import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import com.wolfssl.provider.jce.WolfCryptProvider;

public class CryptoBenchmark {
    /* Constants for benchmark configuration */
    private static final int WARMUP_ITERATIONS = 1000;
    private static final int TEST_ITERATIONS = 5;  /* Number of iterations */
    private static final int ENCRYPT_SIZE = 1024 * 1024;
    private static final int DECRYPT_SIZE = 1024 * 1024;
    private static final int AES_BLOCK_SIZE = 16;
    private static final int GCM_TAG_LENGTH = 128;               /* GCM auth tag length in bits */
    private static final int AES_KEY_SIZE = 256;

    private static byte[] generateTestData(int size) {
        return new byte[size]; /* Creates array initialized with zeros */
    }

    private static void runBenchmark(String algorithm, String mode) throws Exception {
        /* Key generation variables */
        KeyGenerator keyGen;
        SecretKey key;
        
        /* IV/Nonce generation variables */
        byte[] ivBytes;
        /* Using specific type instead of Object */
        AlgorithmParameterSpec params;
        /* Test data variables */
        byte[] testData;
        byte[] encryptedData = null;
        double dataSizeMiB;
        
        /* Cipher variables */
        Cipher cipher;
        
        /* Timing variables */
        long startTime;
        long endTime;
        long encryptTime;
        long decryptTime;
        double encryptThroughput;
        double decryptThroughput;
        double encryptTimeMS;
        double decryptTimeMS;

        /* Generate a random key */
        keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        key = keyGen.generateKey();
        
        /* Generate IV/Nonce and parameters based on mode */
        ivBytes = new byte[AES_BLOCK_SIZE];
        new SecureRandom().nextBytes(ivBytes);
        if (mode.equals("GCM")) {
            params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
        } else {
            params = new IvParameterSpec(ivBytes);
        }

        /* Generate test data filled with zeros */
        testData = generateTestData(ENCRYPT_SIZE);

        /* Initialize cipher */
        cipher = Cipher.getInstance(algorithm);
        
        /* Warm up phase */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            encryptedData = cipher.doFinal(testData);
            
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.doFinal(encryptedData);
        }

        /* Benchmark encryption */
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            encryptedData = cipher.doFinal(testData);  // Save the last encrypted result
        }
        endTime = System.nanoTime();
        encryptTime = (endTime - startTime) / TEST_ITERATIONS;

        /* Benchmark decryption using the encrypted data from encryption benchmark */
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.doFinal(encryptedData);
        }
        endTime = System.nanoTime();
        decryptTime = (endTime - startTime) / TEST_ITERATIONS;

        /* Calculate data size in MiB */
        dataSizeMiB = ENCRYPT_SIZE / (1024.0 * 1024.0);

        /* Calculate time in milliseconds */
        encryptTimeMS = encryptTime / 1000000.0;
        decryptTimeMS = decryptTime / 1000000.0;

        /* Calculate throughput using seconds for MiB/s */
        encryptThroughput = (ENCRYPT_SIZE / (encryptTime / 1000000000.0)) / (1024.0 * 1024.0);
        decryptThroughput = (DECRYPT_SIZE / (decryptTime / 1000000000.0)) / (1024.0 * 1024.0);

        /* Print results */
        String testName = "AES-256-" + mode;
        System.out.printf("%s-enc      %4.2f MiB took %1.3f ms, %8.3f MiB/s%n",
            testName, dataSizeMiB, encryptTimeMS, encryptThroughput);
        System.out.printf("%s-dec      %4.2f MiB took %1.3f ms, %8.3f MiB/s%n",
            testName, dataSizeMiB, decryptTimeMS, decryptThroughput);
    }

    public static void main(String[] args) {
        try {
            /* Register wolfJCE as the default provider */
            Security.insertProviderAt(new WolfCryptProvider(), 1);

            System.out.println("------------------------------------------------------------------------------");
            System.out.println(" JCE Crypto Benchmark");
            System.out.println("------------------------------------------------------------------------------");

            /* Run benchmarks for different algorithms */
            runBenchmark("AES/CBC/PKCS5Padding", "CBC");
            runBenchmark("AES/GCM/NoPadding", "GCM");

        } catch (Exception e) {
            System.err.println("Benchmark failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
