/* XmssTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import java.util.Arrays;

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.Xmss;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * JNI-level wolfCrypt XMSS/XMSS^MT (RFC 8391) tests. wolfJCE XMSS is
 * verify-only, these exercise the verify-only path (new Xmss() +
 * importPublicRaw() + verify()).
 */
public class XmssTest {

    private static boolean xmssEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {

        xmssEnabled = FeatureDetect.XmssEnabled();

        if (xmssEnabled) {
            System.out.println("JNI Xmss Class");
        }
        else {
            System.out.println("XMSS test skipped: not compiled in");
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("XMSS not compiled in", xmssEnabled);
    }

    /* XMSS-SHA2_10_256 known-answer verify vector.
     *
     * Public key, message and signature generated with the xmss_fast test
     * from the independent xmss-reference repository
     * (https://github.com/XMSS/xmss-reference), the same vector wolfCrypt's
     * native xmss_test_verify_only() uses. RFC 8391 publishes no fixed XMSS
     * KAT (key generation is randomized), so this cross-implementation triple
     * is the reference vector for the verify-only path. The signature is the
     * 5th one-time signature produced by that key. */

    /* 68 bytes */
    private static final byte[] XMSS_SHA2_10_256_PK = Util.h2b(
        "00000001a54131960af9f3b24b2e5b3eca74ad6ca589ad2c0e96b354fb5b6350" +
        "9681e25972100954bb39acee78ef95ec011df03668e2c4a52f60427ed38eaa27" +
        "c9b7394e");

    /* 32 bytes */
    private static final byte[] XMSS_SHA2_10_256_MSG = Util.h2b(
        "079f8086db7627dfed5b2a8160607db4e87a6945206ba296c021a54629639b37");

    /* 2500 bytes */
    private static final byte[] XMSS_SHA2_10_256_SIG = Util.h2b(
        "00000005f01534ba92036ab9a5238611ae650a5c782cc9be7ea6dca28ba99c50" +
        "f6618d9dd7e9c0f867cd8ac49b7496075df2c9cc2805b1be5ea4babeabd8216b" +
        "215fabb76cec2fc8c6743e971bc34557afaa1ea8f286a8aa436d66e98114de09" +
        "39d2afd14ce775180daa29a19253cce9f30b1e3be2ae800ce77a7c138a28c65f" +
        "0aa4a3730a3ac2a63bb43067c03618a158cdad543664cefd52ff707e09fb13a2" +
        "eadf678d6c42b278f57d5c4bf78ecf3eb7c6c123fa65ded2fa4051970d523276" +
        "7e828dd0b91e62d91ec1db4043374a238a1d35faf453115ab56d1e8b22c87d2a" +
        "e494aa25204096db8262ba8f8b45cb4f358833ebefb3baa70972b34cecf2c3c7" +
        "5e026c4193cb3c89120968548eec6a7e20e1703d8cebb436be91be97b5a63416" +
        "950f1026a91380889caa68ec34704a159b5e5705871cf8354529e96ef2701342" +
        "894e77c018c7556de7fa0d63831619012dfd311494ca3e0ed61134815758ec24" +
        "a41763d32500bf7d785dc5d8c6c1bd8cd0940ab133a54b3125f5afe78426aa05" +
        "bbf39aaf583640ef3da2bdcaa18d2f6d54d2623309aee673d644e87c5c392b78" +
        "9414c7c9afec7736a16161f1d009a2eee755d73589899bcffaa6091e3bbd5dd9" +
        "25e7eddd7cf01c57e006bb083959dfd7af4b880d878f4af31cd44bb3e2f31b86" +
        "4fcd3575e203f91dbf3ed17bc72311755f920d98ee14e1da7a0217476b41ea47" +
        "a1af06791a526f19317071bdc2618db7ee6b692ae8217a95be862aa1f4e22f17" +
        "02fdad179f0a0a78a9923021722b28f8f23e05d5acc082f8d2dad0a3bc93dba5" +
        "46de141ed43a5d793d314b06ce22293c98b6188aaef7ba2288a1eec0144c4aa0" +
        "570ad318a23dddc78373fc389b31a3e11776a1a269fcab0880728df5e414b76b" +
        "03ffe8114b06557e36212fd75482c931b4856841ef75b03aea4fe0ec72cc3396" +
        "ce7daddd0d27056ea2d41107d87d27d4808f0022e4fc2c9dd5d8187f4ef4b97f" +
        "efd600085c05041e9ac68dcc19d90b06cc6a17e20323db1cbca2b9a2953c73d8" +
        "ffe60eae04b2fc914fef8a58b731684c1ed05b85cc03dcf4acdb039b35330871" +
        "d0508ddce33a98404180dd35e1a2af149adbd36814e2507a763fe4a41baac106" +
        "879a92f9be9e868c921d74b17f2743c0ee2ec26c6daa0c0e71c956d63a56cb90" +
        "d17e6e1c6a002d022c96f02a373718070bf4b48c30f2a4ab66fb8b22c0007e05" +
        "b6f9954933a1dc970c5c6146e2d7874bc4c75f260684d74705f133ff8585b2bd" +
        "1f44c6c27d51be0eb5c4442ffe735ff4a4efe2f1730bef3e2bd7cc9fda1a7e92" +
        "39a155bf600adb2374fee70563a985529fccc3fff66c1b4e4f01bdc3eb37ec29" +
        "213b2cc92e93203e19c08be833cdc66a6e721315a190200c1466edcca4dd7f58" +
        "53bc4a68fc863eaaf1170f3e205493f498bfb40705bd70e7d734fde369dfcdf5" +
        "1a736ec92b21fbb87e44108356ced5159a75fc918e6b9e1a3a333935b40d74f4" +
        "fb4c0e37fe8295466bd26eeecd4d38af0aaaf1d5a47c04d8b9db1168883541de" +
        "31330cdc2d4ca820cc2c4c63abbadf4884d525bc70e349aa43ca8be79fdd2076" +
        "9b38f4ba4d4e344aaf81e70bece959c135227f694662d2186e1f79d1adc38495" +
        "96b218585e7e0c250a0f69a31dec29cbdaa2d11a10a552c3621ec583ffa356c2" +
        "fd873b5752983695776be549108e39ddca4bb39f4c0c1162f32278db48eb68fe" +
        "e42ae9aa8f7a2f69a5c5032def62a87165064084100ff2edbc70716924a2bf83" +
        "39ddfaa27be5ec3dfe3b526e3d82a62a8601615163bff90a0672f1d5390cbac9" +
        "78c67722e4966eb1486284622dea495650863f90c3014245ede69a6519937f48" +
        "16f250a770b3f5db0e5e229e64042669c116ee6508822765ec3ddf515e2de876" +
        "f2e3e4240488060fb27b9b723d4c7d6a1fb2a2d235d64025c20b25f9df26e4dc" +
        "fbb18484771b455160d5f0b609e6bce31c70962cd39d7d7fb170da79b87499bf" +
        "8495cc93d751dd66d3700c75860906fd661480cdf359b4925fe4ee00a8b08b5c" +
        "3edb8a9c0bb599c20d8109066c28c07ea5077064d741f4c366611ca851f63cba" +
        "e094a3118c2eba13b2474893b41a2c9a6e8e30667bd3bb3b5d970de4ea24289e" +
        "b488ce1d7d6f39b38721e50893f0d49d2d91c9fd0c7434b41ffedadc105b8d2b" +
        "87d342b4ae329cae4c99d8ed444107e08fbda57c5adf912900b54bc33a406c48" +
        "ab2af302cbb369da060c4d5c45c328ac7a01d4f8cb076389093478a71439cf2d" +
        "948d7a4e4ebdc432ab21c9da3f5f046b144018182ff9461757549b287bbdf9a2" +
        "13ac6924b13139bf8d75c3fd03545afdd47ab7564f6643571bfbf9927a83e6ff" +
        "b4ba83d2618e4a8282a8f50cd24353a8850ad4697b04713b8049274712b6b0ea" +
        "900afaa8c87861de3012bbdca65756306ef1a83bf60907ea31e20823310fd434" +
        "e360c22bdb5a99cfd46b4e756535e88b937dca1147f03e115cd1ee4b11b4652b" +
        "6b79c08660a44b24a05c7034c37ce74f97894dfe22893ae907b91a86b87a1238" +
        "e12446bc9b21cdac30ab982131c5173f1e56c318cef0a1ccff9da853af747754" +
        "029a8fa4d4bdb21aba522e19be49114502017abf28d618edbdcee4deb5f1535d" +
        "65f95f838f2df282a02d28d30a9e0f7fc7c4437fc30e06eb4eb42dfadd48abf4" +
        "7d4148335ae67002e7718dd96b0c5a8fa4c1b74e9683d6a71df188b36ef412a9" +
        "f6316966fefe02f2866dbb57518c4ce97c923e3ad32da88253842689bbcc1312" +
        "3d94bbdf3d4cdf279b1fb8b6e4eaa207f84d428f2990fe2120e95502ad90a777" +
        "4e29b6d91494b225a4b20e9631ab9e9349aca9cb6822bab8575c9d65c1f1fc99" +
        "7c3ce9ea4b29222fdb17218db013bfee7de48b6d17e053920b326bb1652ea783" +
        "fd6262e3aa81e8d6f7b13065809f771e4aeae84532123afb22e9a9f6cbaba80c" +
        "20a87cf9f753c1b4c05d0645dd7ea734a121c262ab22453d734c26d11ab2f0b2" +
        "6d117058aaf5a4f5f80b3dc1f6177015cd72027e4e94960a56cca5a3b37edd5a" +
        "72d2fbac3d0e6665e9086cb01ce21a82f6f3348973025b426d4061b6e0e65332" +
        "a572174f3b514fbc00e06926a9ae83e3737f7197e0dc7c639c855fdf7de46cd8" +
        "a93a6f5e4a2eb0e78b45e2900537e8ab49484cc0591d8c465b84e083ceea4bf9" +
        "d4dc63df79b75c11257f902e0a3803eaeaa126522019a3befc9db76ea6588e6d" +
        "c558e9ed2f55438b038be6a4c2254b36bad32748402e87a2d412c60536031151" +
        "d1f2ac712cb6c3a5570faf4bbdcd474c3a526f47e70bb7d5f7a6396382084c41" +
        "0e2a52425aea59c794fbd0884727f697039e29b83a67e6f395a742c196d19aa6" +
        "f0090ceae0ab0f15e9c3eba58986983283ab3033ae908d2eb3aa91a6d9a44a54" +
        "e0d308cc79cee41531a6ce61cf0306ee8ee26429d1549bd05f092b8bd5f8d47d" +
        "f19732d9ea5a0e108c4dfb55e6270cbac173c173e31c09b36fb412faf329dc23" +
        "32ed808783c2f607b5a922de661aa74a86f1399bf4e750154a553c93b9f9fddc" +
        "b35d7352");

    /* 68 bytes */
    private static final byte[] XMSSMT_SHA2_20_2_256_PK = Util.h2b(
        "00000001e10ba1f14edccd6f3234fd5745f027ad5ed98a5652cf66e421ae3856" +
        "6e20819daf80f1c796a85f36764c1b37e5d17ad86106296c2aa53143e748cf96" +
        "71e057b1");

    /* 26 bytes */
    private static final byte[] XMSSMT_SHA2_20_2_256_MSG = Util.h2b(
        "776f6c664a434520584d53534d54207465737420766563746f72");

    /* 4963 bytes */
    private static final byte[] XMSSMT_SHA2_20_2_256_SIG = Util.h2b(
        "0000003b26abaeb1bfc19d6f608ed28f1a6200ce6b4ad05358c04cecdb86ef84" +
        "d529bdd221733fa9f5593edd5471f57707bfce7259f8ce4bb424a88fd9565cfc" +
        "12f83c02644b880fe878ff37afcbe116a8710e3b806ff80fbfa5bddf19c3788a" +
        "80b3eea14e585a1ce31ec8f9db06e2c7dc8fbbc254618dc7089b3cc9d0aeb00c" +
        "79ac8dcb97b237d3a47211ad4532d310f0a140841cb50a335d9907dc40586d1c" +
        "475f4983576a60dd4d9eb4e15ae5a339327489a4351df04eaa370a8bed9e345f" +
        "0598dd16e8d898485efe7feca0291acc28e65723094af1794f340dc38219cf70" +
        "5b5a5080e9f63fd9e9244cb715e508a3b130bf1ed5ee4ca52c866dbea34bad90" +
        "fb5039d62222d8fa22d0a8cb5566ddb5acd90e4e7353a8b84f2fa3ab51f6069b" +
        "dc81ff31bdef053c3e204a45c611954aea4b9d8dcf1d57fcc8ebfa8edf0261eb" +
        "04eb6dc85305913185f826bdd6d49ad98481c1270e13c9e6f5cc82cc4ac2b20d" +
        "5398bce5c4103d1fdf39518efad41b040fc0e8ee3e636479c256de1532d3d6ec" +
        "8f60a8ad83129ab3686ee44179a9c46d9267e842c7278e68bd9163c90c09c622" +
        "225e832a09fc2eae5b307fd0b9b73fe5b9a603adc9f43d7638ec82da5b3c5dc9" +
        "e5f6e6507759901883aa842c11d6e59c699d3e1a0177248b4c6d36c06bde84f9" +
        "9b61ca014de613cb0b80a24122a188767322534d3fd452ccc01ed0b930797840" +
        "65ca6f2f21f5d1bb73065d42c7312df5b8b2a181cee5d1313716f84df049c219" +
        "d0b4e2a553cdcb9df49fab6d21c5213b27c72241bfcf561d4309a55aa90a35e9" +
        "9f1b913a52d0125eea2a4c4088a53a9fc6bf3cb788e16d8c29a000711f092549" +
        "5297b0d34b7167a6ece26efb2fbf17d40a381920ae05e224a7a7e6c246cb369a" +
        "3bcd120f1f1ba32a715a67c337b1ad9f267fa036e01a76221675fb7c574f585d" +
        "208461be37b3cbf7f444661c638112171adad51fffb78fb9c03d5cb4580c5b38" +
        "4971ce514162da6399d53dba2e6d7f8e2315859c778810c58118044caf00d1ba" +
        "a1d85e6a0455d807502c64633855f539dfc3ef476a4b48dc404c9cbe0a0c8130" +
        "637f0dea37dbc5f1274e60768214ce2e7e324b283d7cfe44552238cabe2c9bc6" +
        "9539392c4ce9c93ab3dea643a1ac17a9fbfa364f28ced6fff2901bf996f89bc2" +
        "e3519aac83c93c1ea9fab7f96d9cbc773f033abf6ce9c6f704e757b1de043b29" +
        "72b6481ea6bfc18140c92e3ed5b0bd750f1dab6d92cad50d004e87685de83426" +
        "b3ebf9a73eeabfde84a553d003cfdb424b7685b48fedd7d0c2017569788c6fa8" +
        "041581fb81330e406e4422335ad4d1452e7083ae4f3346151cb51dccedf23447" +
        "e26eab2995d9f1f7916f85bce4d012444335852f868fd709615a0593d55a535c" +
        "656b5f54e340e79823d34df72c6be2bee5e76692428697ad5de9bb5f3b173ee9" +
        "7aabbfcc3f008e084f7be5916a8a96bd11836a8622d60e4bffeaa5ea55674f7b" +
        "9fe433ae86817ac5e50ac8d4fb314a6f8c717fdd3b43e79c8ecff6cbdf304236" +
        "ba67b0dc11e2fd797f2452963f491f28755b33739596c7fd782e01b6ac7f8bd2" +
        "aee341a4817bccff020645ee730279867c5a25b8b2356715bc7aa6e829326f4f" +
        "a71cb00e81c1c771b12b1753cb2e257f94f79046362590063b954251502a3cec" +
        "9b361a79bf8a231d27ceb0115ed870cd87828f7c1090a70287fa0a49fa58448d" +
        "1d746d9b218582ec26ee304c0e60a51cd1eb93b488156f58b44bf65a0bb08cb4" +
        "e4ae2f21cba2153245e585c9dff16409b7da1621a6b8e348ba6a40643ce1f336" +
        "1f4d38e266fc6839ef082605c568ca1d3d4d5227c8b648575dcb1d95355e30df" +
        "f7d377bcb36b2c287e1a30fed2de2ba7fd0b1f2e8a4fce58f8b2714bd41594a0" +
        "452e48f066e9e43be54df814536f70e2039c254d0d49b993a4419276fe1ab50d" +
        "334374e1f914981158d8d5babf339d80197e77a378202a3fe956abac2f41055f" +
        "8929778944cb9262f93b9a66471acc012181055b88843431e9ddfd85a8fa95dd" +
        "66381cc57e6eb6d35e2d7f71cf4df8af48891f989de50acbaf97a0853ffc62b8" +
        "b1a1b26479d7372e6e5a61012cec6c73701996c74accc4738c7d21828e243a51" +
        "235a313dc5d8c93df3bf9f7d2479490f96a1b4822aa18fae041297a1797efd63" +
        "0c025c450635c46f11e28e62c69a5abbee47ed50f4f286cbe72de721979dfde5" +
        "471619e56ec059fee33eb1f5fa601f690450ca39078694fc788a8ab54a7e5dd1" +
        "076dd079f38980e7e073fe74d71fcd0610746568788eeab5598c3dfda7791255" +
        "4d683f4deca43b4ecf74275dda4f6470641aec9b58a5f5d691a61bfb81dc0c1a" +
        "77c9f52e9c83ec3fab25b51e241b8f5bc68e920b6fb456563d44168143e19afa" +
        "da0d2136b6de8f976685331759732b2127352d612bc0321fc2e0c675f1a67da5" +
        "e2c18f1e8a357d9bf64122d895836612d4a7bdf26049b7d8c982222ace3b58a3" +
        "16305f42f06e60655c5e4a5dfecb45b08be88ac5b5df30b6c10ce591fc9aac9a" +
        "8d65c7f14801f0a58b3bfe3b4193dad084659ed54a6fdc465c48728fe15e3838" +
        "4191b69033c18330f655ad2769034f22deab23b8928041bb8c02da62b718c587" +
        "ff4142851db6f8776787426c42fb373f2474f9abf3a3de5c3ab1449de29b5e2d" +
        "a9ff5b66cdaa5e317bdb1e894d1a094b94d2fa335afc43e343c1cca5ed116573" +
        "00987c7713fc6c8c7ed56f7002e6996f184b04c66c020572e617f0168eca8d47" +
        "20289485dce9c8b21aa63fd1248506fbbc1f5b62a78111b726980260d9642e4c" +
        "993e5a87c71586a7864d3ddea73744232b427cbf12c402bb1999d75db5d9b395" +
        "d12e92d94c4419cef43bcc5f4b8c77f8089042e30b7d3c0b5077a9ae0a557cad" +
        "2c978f42ccc1bb68feddc7dea23223bc276466c85a52d1bee452bd217a93bc83" +
        "cb586f50e3107b6825fb2676c4dcf05f067992123b7def0652a1a74a7ce6fd46" +
        "ec907381fcb5f1f3f367066432b05844878b6345f79b9dc0872f0c389dff5546" +
        "8f742eac64b0043f132076be6acc46b579c2a7f1b6b98d8e7dbe53633da20bfa" +
        "d6bd46563d4d0c5937637b7e3c3f5bb7556f9b163cb73b1148f33535c99bfe5e" +
        "b14972cf5834f5c05a88d742d3c2c20c37da7c1a75e99c0e33e4faf242cb304d" +
        "018c92e0692a19dffa1bffdd3979adb901f217fed44a78a1848886ff182987c3" +
        "3b8852ea88ea1e9fb2ea8598812407442ac6337451d18a3f3344b0ec64488ad4" +
        "65f1f507218cc99eb61efeeac9a1a7b5de28d4e4809147e565cc3b63177f53ed" +
        "9d5305333bba4bcea09314b3e2404b3620d0dc43c0cf60b582e6511d1a3baacb" +
        "123d33cbf6282422ce59be5db9fd8a49020a611471d8b6a2debbfd42055e207c" +
        "21f37a1dd4fcd016047e4f5c25e0a4996271b319fd4e0bb644b3443f412e4a39" +
        "5f38febcd94e33409daba3f1da921a2ee355d9d366aeac65f38d00c2e2ec1b2b" +
        "c5de14f22fd87624aa23e3a558dc2347eaad29c19fc94a95ad5f8b192f6bf970" +
        "9486d0173760514b0d2216358420328cfbb0d474dd0688b438e014a3c9ba5e92" +
        "cf5a3026240dc5783b06093f285e7a2456ff72bcb99e447e0feb9e198e276e49" +
        "bdd865bdb8fbe255f10ef8de835f72ecc97b09bbad7cce8b59f7ac63cc3ea097" +
        "5407fa783d4df73195208dcf7b64ebc59be4e2701eef2a8a623b9ba68ad3e605" +
        "8b9074a8e3cdb04897febe6b9d60d6d8d78d952c625d1a15337f7b2b15a0b69f" +
        "80bc4bca3491916af3b820b4af9dcbf459a6f939511d1d6c0e8d57541bb5893a" +
        "b42bbee43cbede66b66064d29beae11a4f4bc0c6544691dd4b6be2baf92ea52f" +
        "1e969d68d4613c6177ebdd69d327f7769bb0fe247c4484fe43634f860599257d" +
        "5cdf3871b24f017d492979ece327e4553b4998be7ad09e789828b8f3c2510d5e" +
        "b3e23e258ff1241444bf05ad2f86a7afe2eb28a5084cad9591ee5296645d93c9" +
        "3f1f3b96fb7f3c96245cdef088d31108490de49c7c26473ec3ca22b266fecfb3" +
        "777c569d9cb6699aeb0074b487645b56749e47c75f3986127638b09715cf2927" +
        "906d2c8b54ef47f7be2a403fef49d8f30695c1ca54286b62ab2f7f81d93783ea" +
        "7704135d8e39e7529e9f5d2cef6566be88c3642305022e115d7fb31580526b6f" +
        "a1ad6dc99546af47a7edec6e90ac3cb02c7755c359cd3272dbe1d856263ca267" +
        "cfd65e30303a11f894a287b09219eda40759dce61bbba225d593246e24c4cdc8" +
        "ec540901eb369f3e94454d79141c964888fc417d016ca345e4e3d20e6ad4a35f" +
        "087f6b9c112b91c9f6afe71ee1546d2e30c854285a7b98cf0951a23ee26b1edf" +
        "05868ecef29d14d1328441287cb5a8c2d59eb91c8a6da106feb86ec990639e19" +
        "4ca66659344f850b90250a4f86733af815b8a9360e4175ab9644df927885d72f" +
        "7021cdcf5da1779903535c0d96203665c7bda4dfa133fc4155a8c939cac4193f" +
        "49fcb23438918b4b121ea0249a7c01a12326dcb9bd11d50073a537a63682a5b8" +
        "b7ddd37315a27d03058dcbd4d23bbcf1f377f7bc1a989e5364321275bbb50449" +
        "18d9dfa49aa27038ac817c633da61edf4830418e2d4c5742ec2beb653cbe58e7" +
        "cf4bf6b6eee8fbae98b2e0a6ff45132b0fa9bb8bb2184c427950fececb7c77a7" +
        "0ba7b8391bb4d9866db66f8e0ed27b2add74480a3da15d5a07f34292ff864cff" +
        "66636bc50a09ebbbdec512967c2a413c6defdf7516b78b742a71b15371a4f360" +
        "66cef4f620a80b64d67edc589779f23af12f585737a16a89ae5a3f0edb765191" +
        "eeea556ea49bb765aa79e22416692bdfbbbc2d1867e7137bd43dc5f7df938aaa" +
        "9736ce2864441d6590084c7d5796bbfb58fc3cd6f023f6e82276f409ba21145e" +
        "709d781a56aee95766bb17b9566ace52ad78c9b5229ac7b47c3c07799e7429bc" +
        "39ddd61f4fca683c226eaed3e61fc1cc26cb08f56d284187c3a1149e9f802400" +
        "f779f25e07b156b69b31eb4075bdd39f85e3c621f82d6c74d2736e80c2a50c22" +
        "8c1fcdc81e60d13a3c90c6fde2c956560c25e340d8ebe699f8f84ba01fab38b6" +
        "d07cffc739e755a0b082dfefa1bc524acd5a0399bc6a21902e63bb2e67e280d0" +
        "d30bf93a3829ed8cf97d3fb4f7262e8017a41f61e9996af1b79fcbe25b8b6aec" +
        "0ae07c7eca622fe66fdf79bef1ac68b77f36b52841cf07ce9046aa4b33ff72b9" +
        "8d13dbbc4cf5f59061a3b970d34426c8b71acb32f8bcd512f85c79fdb4bb012c" +
        "ff3ebd0b0821ee98f4ed9e982d09aa9954f4218ac33a6905028f30f04818bee9" +
        "dfec2d337200d4eaee3493c9b62ef6a9b8bf40ceb65dbb972c3a9ed756f3e600" +
        "f677b86961176f440d8ca8fff26c43888f88aabafa26cb88c69174a9ceabbf3d" +
        "5a864427c8045ff1b951e5375efeecca0614bf945b879fa68a50a3230334879a" +
        "54cca91701c719f14375cd8d6b5466df51acce30e1bece3ac697377095e8df02" +
        "922b0f8d97d45d21f860dde4709cda25be4e334d52a3f341eedfd425467a37d3" +
        "ab2a856ddec3bb8159156a4e717a54dc11f9045dfdca8f2edb324d9223a88296" +
        "cfe614ec371b917df786d636ed25bf3e9b08aab76801069b79c41aeb4f4db7dd" +
        "ae019d7954f367710d6c60c4019e3a77e9b19d581cdf14cf2792cfd5541009c0" +
        "394379f3147b45a226aee35629d92f0475197592d09c4f2e273fe47b49c7229d" +
        "cac43dbdc52fa2fcb4bf2600bc983764e6a901dde7a0d8925c523809da6fc936" +
        "d1fbb3e36cb28b5ae4a183ebed8c8d4170aa397134f23e9e08a6c7899caa68ef" +
        "f27786181c32f744a09444af7f045fd7a264689be18d46ee491e1050da1b60ec" +
        "f47cec3b3362a66a2ba61edf1367f87525c398d05e28cdbe63bf608f7c3b5cf9" +
        "59e28d87e8c14553bc4e9decf93547c097fcc0302baccbfcd99838e92433cbcb" +
        "29769b7cc2bc0a2d91a3d4ecffb0d993a7dd6e2296f6a068f9da467260323f0e" +
        "6b4c3fa2e0a55652ab296c93e282af60057f029a2458efab5d15e21062281d7f" +
        "2738571b81c2d6ca89f5e6b3e1b36687d9f90c914da7e48ca0d64d17a20d7b86" +
        "f897df871704fe2ecbfccf723964d4f0e7b7612f175ccf58a51e63cb9d320040" +
        "6323e09a3b637ae9e7b2034f7e5e11d30dbd502d7a081ed7dba6272a936f45ca" +
        "66996a1963d45d1b6a33070928e47cfcb7b0312a04d0ef6fec282f38b7350975" +
        "abee51e32e10ea2cd1cec31f3df63bbb45bc8300725f14c62ebe573f67cee9c3" +
        "37c54814d5325bd00b6a5564bc4d3e6b14ab575331504afd011b30b3921883a1" +
        "3d0e32efb17d8dafa510c9679384a1b1f1c9536453907f2f67e9bbabf7aa2ca0" +
        "67bf76dcd187f8738edbdeb6993c4408afc2b0d2ad9d296e852e30cd39410ac2" +
        "e408c43038f8691b8f20e6f4590a83e8c6fcdc107fcf3c6beffc7f21187b24da" +
        "cecd56e9fede0e0cb8b24b7123843f5afe74597db4941cc890852b9373592623" +
        "e429bcc4dad45d04fe8b395a0c083b8d33689fcfcc269ce1a3df87243666ac12" +
        "5104739df76b70ee17e38dac21e39f7595e7489ed241080a7ad25b0ddd5edb6b" +
        "fc3f922116c92a6c117dc6586bd2628b0163a33c0f1c190b144404f70b57e0da" +
        "966f975d25692f94ad1261d1078927c2c92a16a8f1c457d6ceb048dda6f6d060" +
        "2c8c1779c19c4d89d0ea2ca1a390eec95234d6efe20ddd737ebecd9901d19ca9" +
        "22919bb7b3e9a1eef29dae0c2e4a91720ecab3a4b25c33a55f3a472494124c7a" +
        "c14f6e1fde39ac0c1d4ea66b39bf3af4b0e7c24d0b7adeaaf8a3ecb7c8c34d8c" +
        "0a71bfc223caeb58d19c7c00c6b703f9106cfb0b2687893012fb73bee89d60e9" +
        "e5b7c629d1904bf0cad21cb87a3b4b0bee803263338b3051522700e92897d0ea" +
        "dabf1563246bc45681fecb336e528eef534a7cb5f813163eb9873919f5ea9221" +
        "7598d65fc6cff9fe2b3cab1878304462b3acec1333b783ca7b5c0b2ae48b9bbf" +
        "ab511752baf46d560f7007eda5569841c52fe77199f2e9b6732a92a7e2e6887d" +
        "ae494e");

    /**
     * Import the XMSS-SHA2_10_256 public key and verify the reference
     * signature. Also checks the derived parameter set string.
     */
    @Test
    public void importPublicRawAndVerify() {

        assumeEnabled();

        Xmss xmss = new Xmss();
        try {
            xmss.importPublicRaw(XMSS_SHA2_10_256_PK, false);

            assertEquals("XMSS-SHA2_10_256", xmss.getParamStr());
            assertFalse("single-tree XMSS, not XMSS^MT", xmss.isXmssMt());

            assertTrue("reference signature must verify",
                xmss.verify(XMSS_SHA2_10_256_SIG, XMSS_SHA2_10_256_MSG));
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * A flipped message bit must fail verification, and flipping it back must
     * pass again (mirrors wolfCrypt xmss_test_verify_only()).
     */
    @Test
    public void verifyFailsOnTamperedMessage() {

        assumeEnabled();

        byte[] badMsg = XMSS_SHA2_10_256_MSG.clone();
        badMsg[badMsg.length / 2] ^= 0x01;

        Xmss xmss = new Xmss();
        try {
            xmss.importPublicRaw(XMSS_SHA2_10_256_PK, false);

            assertFalse("tampered message must not verify",
                xmss.verify(XMSS_SHA2_10_256_SIG, badMsg));

            assertTrue("original message must still verify",
                xmss.verify(XMSS_SHA2_10_256_SIG, XMSS_SHA2_10_256_MSG));
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * Flipping bits at several points across the signature must fail
     * verification (mirrors wolfCrypt xmss_test_verify_only()).
     */
    @Test
    public void verifyFailsOnTamperedSignature() {

        assumeEnabled();

        Xmss xmss = new Xmss();
        try {
            xmss.importPublicRaw(XMSS_SHA2_10_256_PK, false);

            for (int j = 0; j < XMSS_SHA2_10_256_SIG.length; j += 4 * 32) {
                byte[] badSig = XMSS_SHA2_10_256_SIG.clone();
                badSig[j] ^= 0x01;

                assertFalse("tampered signature at offset " + j +
                    " must not verify",
                    xmss.verify(badSig, XMSS_SHA2_10_256_MSG));
            }
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * A signature whose length does not match the parameter set must fail
     * verification (native returns BUFFER_E, surfaced as a failed verify
     * rather than an exception).
     */
    @Test
    public void verifyFailsOnWrongLengthSignature() {

        assumeEnabled();

        byte[] shortSig = Arrays.copyOf(XMSS_SHA2_10_256_SIG,
            XMSS_SHA2_10_256_SIG.length - 1);
        byte[] longSig = Arrays.copyOf(XMSS_SHA2_10_256_SIG,
            XMSS_SHA2_10_256_SIG.length + 1);

        Xmss xmss = new Xmss();
        try {
            xmss.importPublicRaw(XMSS_SHA2_10_256_PK, false);

            assertFalse("short signature must not verify",
                xmss.verify(shortSig, XMSS_SHA2_10_256_MSG));
            assertFalse("long signature must not verify",
                xmss.verify(longSig, XMSS_SHA2_10_256_MSG));
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * Importing a second public key into the same object must throw.
     */
    @Test
    public void importTwiceThrows() {

        assumeEnabled();

        Xmss xmss = new Xmss();
        try {
            xmss.importPublicRaw(XMSS_SHA2_10_256_PK, false);

            try {
                xmss.importPublicRaw(XMSS_SHA2_10_256_PK, false);
                fail("second importPublicRaw should throw");
            }
            catch (IllegalStateException e) {
                /* expected */
            }
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * Verifying before importing a public key must throw.
     */
    @Test
    public void verifyBeforeImportThrows() {

        assumeEnabled();

        Xmss xmss = new Xmss();
        try {
            xmss.verify(XMSS_SHA2_10_256_SIG, XMSS_SHA2_10_256_MSG);
            fail("verify before import should throw");
        }
        catch (IllegalStateException e) {
            /* expected */
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * Importing a malformed (truncated) public key must throw.
     */
    @Test
    public void importInvalidPublicKeyThrows() {

        assumeEnabled();

        byte[] truncated = Arrays.copyOf(XMSS_SHA2_10_256_PK, 10);

        Xmss xmss = new Xmss();
        try {
            xmss.importPublicRaw(truncated, false);
            fail("importing a truncated public key should throw");
        }
        catch (WolfCryptException e) {
            /* expected */
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * Parameter accessors return null/false before a public key is imported.
     */
    @Test
    public void parametersNullBeforeImport() {

        assumeEnabled();

        Xmss xmss = new Xmss();
        try {
            assertNull(xmss.getParamStr());
            assertFalse(xmss.isXmssMt());
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * Import the XMSSMT-SHA2_20/2_256 public key and verify a signature. The
     * vector was generated with the installed wolfSSL (RFC 8391 publishes no
     * fixed XMSS^MT KAT). Note the public key begins with the same 4-byte OID
     * prefix (00000001) as the single-tree XMSS-SHA2_10_256 vector, so the
     * isXmssMt=true flag is what selects the multi-tree interpretation.
     */
    @Test
    public void importXmssMtAndVerify() {

        assumeEnabled();

        Xmss xmss = new Xmss();
        try {
            xmss.importPublicRaw(XMSSMT_SHA2_20_2_256_PK, true);

            assertEquals("XMSSMT-SHA2_20/2_256", xmss.getParamStr());
            assertTrue("multi-tree XMSS^MT", xmss.isXmssMt());

            assertTrue("XMSS^MT signature must verify",
                xmss.verify(XMSSMT_SHA2_20_2_256_SIG,
                    XMSSMT_SHA2_20_2_256_MSG));
        }
        finally {
            xmss.releaseNativeStruct();
        }
    }

    /**
     * The same raw public key bytes are interpreted differently depending on
     * the isXmssMt family flag, because the single-tree and multi-tree
     * parameter-set OID registries overlap. This is why the family must be
     * supplied (normally from the X.509 AlgorithmIdentifier OID) and cannot be
     * inferred from the raw key alone.
     */
    @Test
    public void xmssMtFamilyFlagMatters() {

        assumeEnabled();

        /* OID prefix 0x00000001 as XMSS^MT -> XMSSMT-SHA2_20/2_256 */
        Xmss mt = new Xmss();
        try {
            mt.importPublicRaw(XMSSMT_SHA2_20_2_256_PK, true);
            assertEquals("XMSSMT-SHA2_20/2_256", mt.getParamStr());
        }
        finally {
            mt.releaseNativeStruct();
        }

        /* The same OID prefix as single-tree XMSS -> XMSS-SHA2_10_256 */
        Xmss st = new Xmss();
        try {
            st.importPublicRaw(XMSSMT_SHA2_20_2_256_PK, false);
            assertEquals("XMSS-SHA2_10_256", st.getParamStr());
            assertFalse(st.isXmssMt());
        }
        finally {
            st.releaseNativeStruct();
        }
    }
}
