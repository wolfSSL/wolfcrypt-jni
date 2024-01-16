/* ChachaTest.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

package com.wolfssl.wolfcrypt.test;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.ShortBufferException;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import com.wolfssl.wolfcrypt.Chacha;
import com.wolfssl.wolfcrypt.NativeStruct;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

public class ChachaTest {

    /* 32 byte key */
    private static final byte[] KEY = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };

    /* 12 byte IV */
    private static final byte[] IV = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };

    private static byte[] INPUT = new byte[] {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };

    private static final byte[] EXPECTED = new byte[] {
        (byte)0x76,(byte)0xb8,(byte)0xe0,(byte)0xad,
        (byte)0xa0,(byte)0xf1,(byte)0x3d,(byte)0x90
    };

    @BeforeClass
    public static void checkAvailability() {
        try {
            new Chacha();
        } catch (WolfCryptException e) {
            if (e.getError() == WolfCryptError.NOT_COMPILED_IN)
                System.out.println("Chacha test skipped: " + e.getError());
            Assume.assumeNoException(e);
        }
    }

    @Test
    public void constructorShouldInitializeNativeStruct() {
        assertNotEquals(NativeStruct.NULL, new Chacha().getNativeStruct());
    }

    @Test
    public void checkSetKey() {
        Chacha chacha = new Chacha();

        try {
            chacha.setKey(null);
            fail("key should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        chacha.setKey(KEY);
        chacha.releaseNativeStruct();
    }

    @Test
    public void checkSetIv() {
        Chacha chacha = new Chacha();

        try {
            chacha.setIV(null);
            fail("IV should not be null.");
        } catch (WolfCryptException e) {
            /* test must throw */
        }

        chacha.setIV(IV);
        chacha.releaseNativeStruct();
    }

    @Test
    public void checkProcess() {
        Chacha chacha = new Chacha();

        try {
            chacha.setKey(KEY);
            chacha.setIV(IV);
            chacha.process(null);
            fail("Chacha.process() shouldn't accept null byte array");
        } catch (WolfCryptException e) {
            /* test must throw */
        }
    }

    @Test
    public void checkChachaVectors() {

        int i = 0;
        byte[][] keys = new byte[4][];
        byte[][] ivs  = new byte[4][];
        byte[][] test_chacha = new byte[4][];

        keys[0] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };

        keys[1] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01
        };

        keys[2] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };

        /* 128 bit key */
        keys[3] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };

        ivs[0] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };
        ivs[1] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };
        ivs[2] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01
        };
        ivs[3] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };


        test_chacha[0] = new byte[] {
            (byte)0x76,(byte)0xb8,(byte)0xe0,(byte)0xad,
            (byte)0xa0,(byte)0xf1,(byte)0x3d,(byte)0x90
        };
        test_chacha[1] = new byte[] {
            (byte)0x45,(byte)0x40,(byte)0xf0,(byte)0x5a,
            (byte)0x9f,(byte)0x1f,(byte)0xb2,(byte)0x96
        };
        test_chacha[2] = new byte[] {
            (byte)0xde,(byte)0x9c,(byte)0xba,(byte)0x7b,
            (byte)0xf3,(byte)0xd6,(byte)0x9e,(byte)0xf5
        };
        test_chacha[3] = new byte[] {
            (byte)0x89,(byte)0x67,(byte)0x09,(byte)0x52,
            (byte)0x60,(byte)0x83,(byte)0x64,(byte)0xfd
        };

        for (i = 0; i < 4; i++) {
            Chacha enc = new Chacha();
            Chacha dec = new Chacha();

            enc.setKey(keys[i]);
            dec.setKey(keys[i]);

            enc.setIV(ivs[i]);
            dec.setIV(ivs[i]);

            byte[] cipher = enc.process(INPUT);
            byte[] plain  = dec.process(cipher);

            if (Arrays.equals(cipher, test_chacha[i]) != true) {
                fail("Chacha encrypt does not match expected (i:" + i + ")\n" +
                     "cipher: " + Util.b2h(cipher) + "\n" +
                     "expected: " + Util.b2h(test_chacha[i]));
            }

            if (Arrays.equals(plain, INPUT) != true) {
                fail("Chacha decrypt does not match expected (i:" + i + ")");
            }
        }
    }

    @Test
    public void checkBigProcess() {

        byte cipher_big_result[] = Util.h2b(
        "06a65d31216cdb37487c019d72df0a5b647420ba9ee0267a" +
        "bfdf83343b4f943f3789af00df0f2e751641f67a86949d32" +
        "56f07971686fa66bc65949f61034030316539a982a46de17" +
        "066570ca0a1fab8026963f3e7a3ca887bb65dd5e077b34e0" +
        "56da321330c90cd7bae41fa6914f729fd95c627da6c2bc87" +
        "ae6411943bbc6c23bd7d00b499f268b5597093ad69d0b128" +
        "7092ebec398082de44e28a26b3e945cf83769f6aa0464a3d" +
        "2656af4941261b6a4137659172c4e73c1731ae2e2b3145e4" +
        "93d310aac562d5114b571dad4806d00d98a5c65bd09e22c0" +
        "00325af51c896d5497556b46c5c7c4489cbf47dc03c41bcb" +
        "65a6919d6df1b07a4d3b0395f48b0bae39ff3ff6c014188a" +
        "e519bdc1b4054e292f0b33762816a4a69304b5556b893da5" +
        "0fd3adfad9fd055d4894255a2c9a9480b0e7cb4d77bfcad8" +
        "5548bd66b18581b13779ab52081412accd454d536bca96c7" +
        "3b2f73b15a23bd65d5ea17b3dca1171b2db39cd0db4177ef" +
        "9320523e9df5bf33f752c190a01517cef7f7d03a3bd17256" +
        "3181ae60ab40c1d1287753ac9f110a88364bda57a7285c85" +
        "d3859b79ad051c37145e0dd02303421d485dc53c5a08a90d" +
        "6e827c2e3c41cc968eadee2a610b160fa9244085bc9f288d" +
        "e6684d8f3048d973736c9a7f67f7de4c0a8be4b3082a52da" +
        "54eecdb5624a2620fb40bb393a0f09e800d1249760e98383" +
        "fe9f9c15cf69039f03e1e86ebd875868eeecd82946234992" +
        "72955b49cae04559b2caf4fcb759374928bcf3d761bc4bf3" +
        "a94b2f05a801a5dc006e01b6453cd5497d5c25e83187b2b9" +
        "bfb301620cd04877a2340f162228ee5408933be4de7e63f7" +
        "97165d7158c22ef236a612659417ac66237ec6727924ce8f" +
        "55199744fc55ec852627db38b1420add059928eb036c9ae9" +
        "17f62cb0fee7a4a731da4db029dbdd8d12139cb4cc8397fb" +
        "1adc08d63062e8eb8b61cb1d06e3a54d35db59a82d872744" +
        "6fc03897e485000209f6693acf081b21bb79b1a13409e080" +
        "cab0788a1197d407be1b6a5ddbd61f766b16f058845f59ce" +
        "6234c3df94b82f8468f0b851d96d8e4a1de65cd88625e324" +
        "fd216113483ef67da6719bd26ee6d20894626c98fe2f9c88" +
        "7e78150200f0ba2491f2dc47514d155e915f575b1d352445" +
        "759b8875f12f85e789d101b4c818b797ef4b90f4bf10273c" +
        "60ffc494202f934b4de380f72c71d9e368b4772bc70d3992" +
        "ef910db211500ee8ad3bf6b5c6144d3353a76015c72751dc" +
        "5429a70d6a7b7213ad7d41194e4249cc42e4bd9913d97ff3" +
        "38a4b633ed07487e8e82fe3a9d7593ba254e373c0cd569a9" +
        "2d9efde8bbf50ce286b95e6f28e419b30ba486d724d0b889" +
        "7b76ec05105b68e95866a3c5b663200e0eea3d615eda3d3c" +
        "f9fdeda9db52948a00ca3c8d668fb0f05aca3f6371bfca99" +
        "379b759789106ecff2f5e3d5459bad10716c5f6f7f227718" +
        "2ff999c56958031286823ebfc2123543a3d9184f41116bf3" +
        "67af3d78e4222db34843311defa8ba498ea9a7b6187784ca" +
        "bda2021b6af85fdaffcf016a8669a9e9cb601e15dc8f5d39" +
        "b5ce555f4797b1196e21d61339b224e062829fed1281edee" +
        "abd02f19893f572ec2e267e8ae0356bad4d0a48903065bcc" +
        "f222b80e76794a421d37515aaa466c2add66fec668c338a2" +
        "ae5b98245d4305823812d3d1752d4f61bdb91087442a7807" +
        "fff40fa1f3689fbeaea291f0c7557a52d5a38d6fe4905cf3" +
        "5fce3d23f98eae14fb829aa3045fbfad3ef2970a60407019" +
        "72ad66fb781b846c98bc8cf84fcbb5f6af7ab793ef674802" +
        "2ccbe6770f7bc1eec5b62d7e62a0c0a7a580319250a12822" +
        "950317d10ff608e5ec");

        byte key[] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };

        byte iv[] = new byte[] {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
        };

        int CHACHA_BIG_TEST_SIZE = 1305;
        byte cipher_big[] = new byte[CHACHA_BIG_TEST_SIZE];
        byte plain_big[] = new byte[CHACHA_BIG_TEST_SIZE];
        byte input_big[] = new byte[CHACHA_BIG_TEST_SIZE];

        Chacha enc = new Chacha();
        Chacha dec = new Chacha();

        enc.setKey(key);
        dec.setKey(key);

        enc.setIV(iv);
        dec.setIV(iv);

        byte[] cipher = enc.process(plain_big);
        byte[] plain  = dec.process(cipher);

        if (Arrays.equals(cipher, cipher_big_result) != true) {
            fail("Chacha encrypt does not match expected.");
        }

        if (Arrays.equals(plain, input_big) != true) {
            fail("Chacha decrypt does not match expected.");
        }
    }

    @Test
    public void releaseAndReInitObject() {

        byte[] cipher = null;
        byte[] plain = null;

        Chacha enc = new Chacha();
        enc.setKey(KEY);
        enc.setIV(IV);
        cipher = enc.process(INPUT);
        assertArrayEquals(EXPECTED, cipher);

        Chacha dec = new Chacha();
        dec.setKey(KEY);
        dec.setIV(IV);
        plain = dec.process(cipher);
        assertArrayEquals(INPUT, plain);

        /* free objects */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();

        /* try to re-init and re-use them */
        enc = new Chacha();
        enc.setKey(KEY);
        enc.setIV(IV);
        cipher = enc.process(INPUT);
        assertArrayEquals(EXPECTED, cipher);

        dec = new Chacha();
        dec.setKey(KEY);
        dec.setIV(IV);
        plain = dec.process(cipher);
        assertArrayEquals(INPUT, plain);

        /* free again */
        enc.releaseNativeStruct();
        dec.releaseNativeStruct();
    }
}

