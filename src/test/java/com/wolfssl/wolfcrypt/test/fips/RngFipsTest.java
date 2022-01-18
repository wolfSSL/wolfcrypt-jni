/* RngFipsTest.java
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.wolfcrypt.test.fips;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;

import org.junit.Test;

import com.wolfssl.wolfcrypt.Rng;
import com.wolfssl.wolfcrypt.WolfCrypt;
import com.wolfssl.wolfcrypt.Fips;

import com.wolfssl.wolfcrypt.test.Util;

public class RngFipsTest extends FipsTest {
    private ByteBuffer entropyA = ByteBuffer.allocateDirect(48);
    private ByteBuffer entropyB = ByteBuffer.allocateDirect(32);
    private ByteBuffer expected = ByteBuffer.allocateDirect(128);

    @Test
    public void initShouldReturnZero() {
        Rng rng = new Rng();

        assertEquals(WolfCrypt.SUCCESS, Fips.InitRng_fips(rng));
        assertEquals(WolfCrypt.SUCCESS, Fips.FreeRng_fips(rng));
    }

    @Test
    public void HeathTestShouldReturnZeroUsingByteBuffer() {
        String[] inputA = new String[] {
                "1734476fa80d0c74ee6c77c760223ccbbbebaac8d4f59fe3a1aba7be35a7d8ef5acd22db2cbbac88009c04776f99da06",
                "5eb3049f0b85b3a3a2bfd775ee10b68c4ff232e9695601f7f1b175643960f93f86418d771c91ca3b718aad20160c6bc2",
                "4455f3cb3f4c8c6f4d5414ba6ba474fb32a6830bf0fe1cd894b71cdd15985588c85d0635347903122bd9212ef0c8c0c8",
                "496cc3a8f05a51baa588c6548d59f43aea92c97c2b8b8975b12f2fd964c7e1c0e2b1cae46249d6ac1bf1e784a4b5430c",
                "889e8ff6a538727f7c7aa46ac5b1ea706d4616138c25cd06f20b5561d75a74707ce66863fe16f2d29d89d1dc4462b694" };
        String[] inputB = new String[] {
                "3d4f39adeca63038b8cfe16c8e04c2acfa64b96fe6ede2d6626a5ed148cfe0c0",
                "ded079215d29c0639ce6b5b8e1bea6fb0d5a21580852cdafef947d374bf64ee8",
                "090f998c059f115e8d9607d9272d265ede2b622fa15fa44fdbaee45189f41e0b",
                "925cfd38e3cb45fbb69f6ed66f55a9ff12eb622e8f984510c8d87c728ff97cfd",
                "502850f13897630403ef9ed32ea477ea2c58b54b2fcaa6a04d5f7d135831af3c" };
        String[] result = new String[] {
                "d914aecbb6b93fcc0177f8d7f5010b077ecdadf8817dd0e615149f1c57d2e8abbf1e01ee910ab144334d36dc0a1efa2cda1cb2b4669fe778b19a590316313c3997d6761057a51cff7f3138cd383241d3b75cf0ea8d0978d2ec4b2f272278708200ccc42b8c7c992b59d518b1b7a0a5229d81dd9eb7abdbc6a4709777b07ce361",
                "fb4c46a6cde6b680a56d4aabb45eb5a0e423a64c64997a0cb5df5fd58cc9572684bab9d4de1e5edd03ed0fbb93f44a8ce5a88e800d3c4a3018c72b89939fff5f477af8cdd94a821b671e65f321ca6f8d2e36ebe96da4b9c800d3b7b4911daebda46f0eb5a6c74e866f856087261de6cca4ac6a66584969d9dbf49f16b938adad",
                "aff2d039a019a45a4d874ed208ac7b9a9db68588e0425d1f7b8847a299064522d09642c7ea48185e98f709d4eddb871492aaecd023e0f630e9bd4e3a4a066492ddbaecd635d42d9eb27eff0684dffed537365f0e795559d94beff1e64550d41914d18c7265dbd3e6d82d8d7f2819f1208f79b0d44d37366ad3d1c9d04e39087b",
                "3a1b9b38dde4bd497fa7db0baf94704354a759851c3c748b5476919799453bd03f3f7d2b04fcc5c9f270a4161947288d8e9c80ce4808261e4db64b3728604702df89cb2fdfb6eba20e484965c42ea705365f189c690908552766ce9f349d72c3579368171f8cdb22861c6c90f7758ccadf8b43001969cfc27684b0c2d439ab54",
                "572755b52d9fe379bf808458237900f5f32afb10cdb302dfb2089e651e3b3371e10506591e5f78865844e783780f00dc4852555c085bce4d32c88f1e1b395146ab7e11d5f6b6e134e8e908fafc4e5b54491655ef92102754ecdca68214369ff929cf04fabbc0aba8824e97cca672cd2e8499f6d78b148fdf67b12835eff6d9b7" };

        for (int i = 0; i < inputA.length; i++) {
            entropyA.put(Util.h2b(inputA[i])).rewind();
            entropyB.put(Util.h2b(inputB[i])).rewind();
            expected.put(Util.h2b(result[i])).rewind();

            assertEquals(WolfCrypt.SUCCESS, Fips.RNG_HealthTest_fips(1,
                    entropyA, inputA[i].length() / 2, entropyB,
                    inputB[i].length() / 2, expected, result[i].length() / 2));
        }
    }

    @Test
    public void HeathTestShouldReturnZeroUsingByteArray() {
        String[] inputA = new String[] {
                "1734476fa80d0c74ee6c77c760223ccbbbebaac8d4f59fe3a1aba7be35a7d8ef5acd22db2cbbac88009c04776f99da06",
                "5eb3049f0b85b3a3a2bfd775ee10b68c4ff232e9695601f7f1b175643960f93f86418d771c91ca3b718aad20160c6bc2",
                "4455f3cb3f4c8c6f4d5414ba6ba474fb32a6830bf0fe1cd894b71cdd15985588c85d0635347903122bd9212ef0c8c0c8",
                "496cc3a8f05a51baa588c6548d59f43aea92c97c2b8b8975b12f2fd964c7e1c0e2b1cae46249d6ac1bf1e784a4b5430c",
                "889e8ff6a538727f7c7aa46ac5b1ea706d4616138c25cd06f20b5561d75a74707ce66863fe16f2d29d89d1dc4462b694" };
        String[] inputB = new String[] {
                "3d4f39adeca63038b8cfe16c8e04c2acfa64b96fe6ede2d6626a5ed148cfe0c0",
                "ded079215d29c0639ce6b5b8e1bea6fb0d5a21580852cdafef947d374bf64ee8",
                "090f998c059f115e8d9607d9272d265ede2b622fa15fa44fdbaee45189f41e0b",
                "925cfd38e3cb45fbb69f6ed66f55a9ff12eb622e8f984510c8d87c728ff97cfd",
                "502850f13897630403ef9ed32ea477ea2c58b54b2fcaa6a04d5f7d135831af3c" };
        String[] result = new String[] {
                "d914aecbb6b93fcc0177f8d7f5010b077ecdadf8817dd0e615149f1c57d2e8abbf1e01ee910ab144334d36dc0a1efa2cda1cb2b4669fe778b19a590316313c3997d6761057a51cff7f3138cd383241d3b75cf0ea8d0978d2ec4b2f272278708200ccc42b8c7c992b59d518b1b7a0a5229d81dd9eb7abdbc6a4709777b07ce361",
                "fb4c46a6cde6b680a56d4aabb45eb5a0e423a64c64997a0cb5df5fd58cc9572684bab9d4de1e5edd03ed0fbb93f44a8ce5a88e800d3c4a3018c72b89939fff5f477af8cdd94a821b671e65f321ca6f8d2e36ebe96da4b9c800d3b7b4911daebda46f0eb5a6c74e866f856087261de6cca4ac6a66584969d9dbf49f16b938adad",
                "aff2d039a019a45a4d874ed208ac7b9a9db68588e0425d1f7b8847a299064522d09642c7ea48185e98f709d4eddb871492aaecd023e0f630e9bd4e3a4a066492ddbaecd635d42d9eb27eff0684dffed537365f0e795559d94beff1e64550d41914d18c7265dbd3e6d82d8d7f2819f1208f79b0d44d37366ad3d1c9d04e39087b",
                "3a1b9b38dde4bd497fa7db0baf94704354a759851c3c748b5476919799453bd03f3f7d2b04fcc5c9f270a4161947288d8e9c80ce4808261e4db64b3728604702df89cb2fdfb6eba20e484965c42ea705365f189c690908552766ce9f349d72c3579368171f8cdb22861c6c90f7758ccadf8b43001969cfc27684b0c2d439ab54",
                "572755b52d9fe379bf808458237900f5f32afb10cdb302dfb2089e651e3b3371e10506591e5f78865844e783780f00dc4852555c085bce4d32c88f1e1b395146ab7e11d5f6b6e134e8e908fafc4e5b54491655ef92102754ecdca68214369ff929cf04fabbc0aba8824e97cca672cd2e8499f6d78b148fdf67b12835eff6d9b7" };

        for (int i = 0; i < inputA.length; i++) {
            byte[] entropyA = Util.h2b(inputA[i]);
            byte[] entropyB = Util.h2b(inputB[i]);
            byte[] expected = Util.h2b(result[i]);

            assertEquals(WolfCrypt.SUCCESS, Fips.RNG_HealthTest_fips(1,
                    entropyA, inputA[i].length() / 2, entropyB,
                    inputB[i].length() / 2, expected, result[i].length() / 2));
        }
    }
}
