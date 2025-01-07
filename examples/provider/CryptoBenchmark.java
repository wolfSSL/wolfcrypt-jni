import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import com.wolfssl.provider.jce.WolfCryptProvider;

public class CryptoBenchmark {
    /* Constants for benchmark configuration */
    private static final int WARMUP_ITERATIONS = 5;
    private static final int TEST_ITERATIONS = 5;      /* Number of iterations */
    private static final int DATA_SIZE = 1024 * 1024;
    private static final int AES_BLOCK_SIZE = 16;
    private static final int GCM_TAG_LENGTH = 128;     /* GCM auth tag length in bits */
    private static final int AES_KEY_SIZE = 256;

    /* Static key buffer */
    private static final byte[] STATIC_KEY = new byte[] {
        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
        (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
        (byte)0xfe, (byte)0xde, (byte)0xba, (byte)0x98,
        (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10,
        (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
        (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
        (byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3,
        (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7
    };

    private static byte[] generateTestData(int size) {
        return new byte[size]; /* Creates array initialized with zeros */
    }

    private static void runBenchmark(String algorithm, String mode, String providerName) throws Exception {
        /* Key generation variables */
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

        /* Use static pre-made key */
        key = new SecretKeySpec(STATIC_KEY, "AES");
        
        /* Generate random IV */
        SecureRandom secureRandom = new SecureRandom();
        ivBytes = new byte[AES_BLOCK_SIZE];
        secureRandom.nextBytes(ivBytes);

        if (mode.equals("GCM")) {
            params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
        } else {
            params = new IvParameterSpec(ivBytes);
        }

        /* Generate test data filled with zeros */
        testData = generateTestData(DATA_SIZE);

        /* Initialize cipher with specific provider */
        cipher = Cipher.getInstance(algorithm, providerName);
        
        /* Warm up phase */
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            /* Generate fresh IV for each warmup iteration when using GCM */
            if (mode.equals("GCM")) {
                secureRandom.nextBytes(ivBytes);
                params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            encryptedData = cipher.doFinal(testData);
            
            /* Use the same params for decryption since we're decrypting what we just encrypted */
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.doFinal(encryptedData);
        }

        /* Benchmark encryption */
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            /* Generate fresh IV for each iteration when using GCM */
            if (mode.equals("GCM")) {
                secureRandom.nextBytes(ivBytes);
                params = new GCMParameterSpec(GCM_TAG_LENGTH, ivBytes);
            }
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
            encryptedData = cipher.doFinal(testData);
        }
        endTime = System.nanoTime();
        encryptTime = (endTime - startTime) / TEST_ITERATIONS;

        /* Calculate data size in MiB */
        dataSizeMiB = (DATA_SIZE * TEST_ITERATIONS) / (1024.0 * 1024.0);

        /* Calculate time in milliseconds */
        encryptTimeMS = encryptTime / 1000000.0;

        /* Calculate throughput using seconds for MiB/s */
        encryptThroughput = (DATA_SIZE / (encryptTime / 1000000000.0)) / (1024.0 * 1024.0);

        /* Store encryption results */
        String testName = String.format("AES-256-%s (%s)", mode, providerName);
        System.out.printf("| %-40s | %8.3f | %8.3f | %8.3f |%n",
            testName + " enc", dataSizeMiB, encryptTimeMS, encryptThroughput);

        /* Benchmark decryption using the encrypted data from encryption benchmark */
        startTime = System.nanoTime();
        for (int i = 0; i < TEST_ITERATIONS; i++) {
            /* Note: For decryption, we use the last IV/params from encryption 
               since we're decrypting the last encrypted data */
            cipher.init(Cipher.DECRYPT_MODE, key, params);
            cipher.doFinal(encryptedData);
        }
        endTime = System.nanoTime();
        decryptTime = (endTime - startTime) / TEST_ITERATIONS;

        /* Calculate time in milliseconds */
        decryptTimeMS = decryptTime / 1000000.0;

        /* Calculate throughput using seconds for MiB/s */
        decryptThroughput = (DATA_SIZE / (decryptTime / 1000000000.0)) / (1024.0 * 1024.0);

        /* Store decryption results */
        System.out.printf("| %-40s | %8.3f | %8.3f | %8.3f |%n",
            testName + " dec", dataSizeMiB, decryptTimeMS, decryptThroughput);
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
                // Bouncy Castle not available
            }

            /* Create provider list based on availability */
            java.util.List<Provider> providerList = new java.util.ArrayList<>();
            java.util.List<String> providerNameList = new java.util.ArrayList<>();
            
            /* Always add wolfJCE first */
            providerList.add(new WolfCryptProvider());
            providerNameList.add("wolfJCE");
            
            /* Always add SunJCE second */
            providerList.add(new com.sun.crypto.provider.SunJCE());
            providerNameList.add("SunJCE");
            
            /* Add Bouncy Castle if available */
            if (hasBouncyCastle && bcProvider != null) {
                providerList.add(bcProvider);
                providerNameList.add("BC");
            }
            
            Provider[] providers = providerList.toArray(new Provider[0]);
            String[] providerNames = providerNameList.toArray(new String[0]);

            System.out.println("-----------------------------------------------------------------------------");
            System.out.println(" JCE Crypto Provider Benchmark");
            System.out.println("-----------------------------------------------------------------------------");
            
            /* Print table header */
            System.out.println("| Operation                                | Size MiB |    ms    |    MiB/s |");
            System.out.println("|------------------------------------------|----------|----------|----------|");

            /* Test each provider */
            for (int i = 0; i < providers.length; i++) {
                Security.insertProviderAt(providers[i], 1);
                
                /* Run benchmarks for different algorithms */
                runBenchmark("AES/CBC/PKCS5Padding", "CBC", providerNames[i]);
                runBenchmark("AES/GCM/NoPadding", "GCM", providerNames[i]);
                
                /* Add separator between providers */
                if (i < providers.length - 1) {
                    System.out.println("|------------------------------------------|----------|----------|----------|");
                }
                
                /* Reset provider after each test */
                Security.removeProvider(providers[i].getName());
            }
            
            System.out.println("-----------------------------------------------------------------------------");

        } catch (Exception e) {
            System.err.println("Benchmark failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
