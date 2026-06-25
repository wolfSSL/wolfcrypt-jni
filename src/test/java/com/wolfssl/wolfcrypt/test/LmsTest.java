/* LmsTest.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TestRule;

import com.wolfssl.wolfcrypt.Lms;
import com.wolfssl.wolfcrypt.FeatureDetect;
import com.wolfssl.wolfcrypt.WolfCryptError;
import com.wolfssl.wolfcrypt.WolfCryptException;

/**
 * JNI-level wolfCrypt LMS/HSS (RFC 8554) tests. wolfJCE LMS is verify-only
 * these are RFC 8554 / RFC 9858 KATs.
 */
public class LmsTest {

    private static boolean lmsEnabled = false;

    @Rule(order = Integer.MIN_VALUE)
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void checkAvailability() {

        lmsEnabled = FeatureDetect.LmsEnabled();

        if (lmsEnabled) {
            System.out.println("JNI Lms Class");
        }
        else {
            System.out.println("LMS test skipped: not compiled in");
        }
    }

    private void assumeEnabled() {
        Assume.assumeTrue("LMS not compiled in", lmsEnabled);
    }

    /* RFC 8554 / RFC 9858 known-answer verify vectors.
     *
     * Independent verify KATs over the RFC-published test vectors, the same
     * vectors the JDK SUN provider uses to test its verify-only HSS/LMS
     * implementation. These exercise the verify-only path (new Lms() +
     * importPublicRaw() + verify()).
     *
     *   RFC 8554 Appendix F Test Case 1   (HSS L2, SHA256  H5/W8)
     *   RFC 9858 Appendix A.1             (LMS_SHA256_M24_H5,  W8)
     *   RFC 9858 Appendix A.2             (LMS_SHAKE_M24_H5,   W8)
     *   RFC 9858 Appendix A.3             (LMS_SHAKE_M32_H5,   W8)
     *   RFC 9858 Appendix A.4             (LMS_SHA256_M24_H20, W4)
     *
     * RFC 8554 Test Case 2 is intentionally omitted: it uses heterogeneous
     * per-level parameters (top tree H10/W4, bottom tree H5/W8), which native
     * wolfCrypt's HSS verify does not support (it returns BUFFER_E). Test
     * Case 1 and every RFC 9858 vector use one parameter set across all
     * levels. */

    /* Short local alias of Util.h2b() to keep KAT declarations readable. */
    private static byte[] hex(String s) {
        return Util.h2b(s);
    }

    private static final byte[] RFC8554_TC1_PK = hex(
        "00000002000000050000000461a5d57d37f5e46bfb7520806b07a1b850650e3b" +
        "31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878");

    private static final byte[] RFC8554_TC1_MSG = hex(
        "54686520706f77657273206e6f742064656c65676174656420746f2074686520" +
        "556e69746564205374617465732062792074686520436f6e737469747574696f" +
        "6e2c206e6f722070726f6869626974656420627920697420746f207468652053" +
        "74617465732c2061726520726573657276656420746f20746865205374617465" +
        "7320726573706563746976656c792c206f7220746f207468652070656f706c65" +
        "2e0a");

    private static final byte[] RFC8554_TC1_SIG = hex(
        "000000010000000500000004d32b56671d7eb98833c49b433c272586bc4a1c8a" +
        "8970528ffa04b966f9426eb9965a25bfd37f196b9073f3d4a232feb69128ec45" +
        "146f86292f9dff9610a7bf95a64c7f60f6261a62043f86c70324b7707f5b4a8a" +
        "6e19c114c7be866d488778a0e05fd5c6509a6e61d559cf1a77a970de927d60c7" +
        "0d3de31a7fa0100994e162a2582e8ff1b10cd99d4e8e413ef469559f7d7ed12c" +
        "838342f9b9c96b83a4943d1681d84b15357ff48ca579f19f5e71f18466f2bbef" +
        "4bf660c2518eb20de2f66e3b14784269d7d876f5d35d3fbfc7039a462c716bb9" +
        "f6891a7f41ad133e9e1f6d9560b960e7777c52f060492f2d7c660e1471e07e72" +
        "655562035abc9a701b473ecbc3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f" +
        "428bab6f3a30f55dd9625563f0a75ee390e385e3ae0b906961ecf41ae073a059" +
        "0c2eb6204f44831c26dd768c35b167b28ce8dc988a3748255230cef99ebf14e7" +
        "30632f27414489808afab1d1e783ed04516de012498682212b07810579b25036" +
        "5941bcc98142da13609e9768aaf65de7620dabec29eb82a17fde35af15ad238c" +
        "73f81bdb8dec2fc0e7f932701099762b37f43c4a3c20010a3d72e2f606be108d" +
        "310e639f09ce7286800d9ef8a1a40281cc5a7ea98d2adc7c7400c2fe5a101552" +
        "df4e3cccfd0cbf2ddf5dc6779cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0" +
        "a750b73ccdcf3c79e6580c154f8a58f7f24335eec5c5eb5e0cf01dcf44394240" +
        "95fceb077f66ded5bec73b27c5b9f64a2a9af2f07c05e99e5cf80f00252e39db" +
        "32f6c19674f190c9fbc506d826857713afd2ca6bb85cd8c107347552f30575a5" +
        "417816ab4db3f603f2df56fbc413e7d0acd8bdd81352b2471fc1bc4f1ef296fe" +
        "a1220403466b1afe78b94f7ecf7cc62fb92be14f18c2192384ebceaf8801afdf" +
        "947f698ce9c6ceb696ed70e9e87b0144417e8d7baf25eb5f70f09f016fc925b4" +
        "db048ab8d8cb2a661ce3b57ada67571f5dd546fc22cb1f97e0ebd1a65926b123" +
        "4fd04f171cf469c76b884cf3115cce6f792cc84e36da58960c5f1d760f32c12f" +
        "aef477e94c92eb75625b6a371efc72d60ca5e908b3a7dd69fef0249150e3eebd" +
        "fed39cbdc3ce9704882a2072c75e13527b7a581a556168783dc1e97545e31865" +
        "ddc46b3c957835da252bb7328d3ee2062445dfb85ef8c35f8e1f3371af34023c" +
        "ef626e0af1e0bc017351aae2ab8f5c612ead0b729a1d059d02bfe18efa971b73" +
        "00e882360a93b025ff97e9e0eec0f3f3f13039a17f88b0cf808f488431606cb1" +
        "3f9241f40f44e537d302c64a4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510" +
        "f150c85fb525bf25703df7209b6066f09c37280d59128d2f0f637c7d7d7fad4e" +
        "d1c1ea04e628d221e3d8db77b7c878c9411cafc5071a34a00f4cf07738912753" +
        "dfce48f07576f0d4f94f42c6d76f7ce973e9367095ba7e9a3649b7f461d9f9ac" +
        "1332a4d1044c96aefee67676401b64457c54d65fef6500c59cdfb69af7b6dddf" +
        "cb0f086278dd8ad0686078dfb0f3f79cd893d314168648499898fbc0ced5f95b" +
        "74e8ff14d735cdea968bee7400000005d8b8112f9200a5e50c4a262165bd342c" +
        "d800b8496810bc716277435ac376728d129ac6eda839a6f357b5a04387c5ce97" +
        "382a78f2a4372917eefcbf93f63bb59112f5dbe400bd49e4501e859f885bf073" +
        "6e90a509b30a26bfac8c17b5991c157eb5971115aa39efd8d564a6b90282c316" +
        "8af2d30ef89d51bf14654510a12b8a144cca1848cf7da59cc2b3d9d0692dd2a2" +
        "0ba3863480e25b1b85ee860c62bf51360000000500000004d2f14ff6346af964" +
        "569f7d6cb880a1b66c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15" +
        "cda93cfec582d7ab0000000a000000040703c491e7558b35011ece3592eaa5da" +
        "4d918786771233e8353bc4f62323185c95cae05b899e35dffd71705470620998" +
        "8ebfdf6e37960bb5c38d7657e8bffeef9bc042da4b4525650485c66d0ce19b31" +
        "7587c6ba4bffcc428e25d08931e72dfb6a120c5612344258b85efdb7db1db9e1" +
        "865a73caf96557eb39ed3e3f426933ac9eeddb03a1d2374af7bf771855774562" +
        "37f9de2d60113c23f846df26fa942008a698994c0827d90e86d43e0df7f4bfcd" +
        "b09b86a373b98288b7094ad81a0185ac100e4f2c5fc38c003c1ab6fea479eb2f" +
        "5ebe48f584d7159b8ada03586e65ad9c969f6aecbfe44cf356888a7b15a3ff07" +
        "4f771760b26f9c04884ee1faa329fbf4e61af23aee7fa5d4d9a5dfcf43c4c26c" +
        "e8aea2ce8a2990d7ba7b57108b47dabfbeadb2b25b3cacc1ac0cef346cbb90fb" +
        "044beee4fac2603a442bdf7e507243b7319c9944b1586e899d431c7f91bcccc8" +
        "690dbf59b28386b2315f3d36ef2eaa3cf30b2b51f48b71b003dfb08249484201" +
        "043f65f5a3ef6bbd61ddfee81aca9ce60081262a00000480dcbc9a3da6fbef5c" +
        "1c0a55e48a0e729f9184fcb1407c31529db268f6fe50032a363c9801306837fa" +
        "fabdf957fd97eafc80dbd165e435d0e2dfd836a28b354023924b6fb7e48bc0b3" +
        "ed95eea64c2d402f4d734c8dc26f3ac591825daef01eae3c38e3328d00a77dc6" +
        "57034f287ccb0f0e1c9a7cbdc828f627205e4737b84b58376551d44c12c3c215" +
        "c812a0970789c83de51d6ad787271963327f0a5fbb6b5907dec02c9a90934af5" +
        "a1c63b72c82653605d1dcce51596b3c2b45696689f2eb382007497557692caac" +
        "4d57b5de9f5569bc2ad0137fd47fb47e664fcb6db4971f5b3e07aceda9ac130e" +
        "9f38182de994cff192ec0e82fd6d4cb7f3fe00812589b7a7ce51544045643301" +
        "6b84a59bec6619a1c6c0b37dd1450ed4f2d8b584410ceda8025f5d2d8dd0d217" +
        "6fc1cf2cc06fa8c82bed4d944e71339ece780fd025bd41ec34ebff9d4270a322" +
        "4e019fcb444474d482fd2dbe75efb20389cc10cd600abb54c47ede93e08c114e" +
        "db04117d714dc1d525e11bed8756192f929d15462b939ff3f52f2252da2ed64d" +
        "8fae88818b1efa2c7b08c8794fb1b214aa233db3162833141ea4383f1a6f120b" +
        "e1db82ce3630b3429114463157a64e91234d475e2f79cbf05e4db6a9407d72c6" +
        "bff7d1198b5c4d6aad2831db61274993715a0182c7dc8089e32c8531deed4f74" +
        "31c07c02195eba2ef91efb5613c37af7ae0c066babc69369700e1dd26eddc0d2" +
        "16c781d56e4ce47e3303fa73007ff7b949ef23be2aa4dbf25206fe45c20dd888" +
        "395b2526391a724996a44156beac808212858792bf8e74cba49dee5e8812e019" +
        "da87454bff9e847ed83db07af313743082f880a278f682c2bd0ad6887cb59f65" +
        "2e155987d61bbf6a88d36ee93b6072e6656d9ccbaae3d655852e38deb3a2dcf8" +
        "058dc9fb6f2ab3d3b3539eb77b248a661091d05eb6e2f297774fe6053598457c" +
        "c61908318de4b826f0fc86d4bb117d33e865aa805009cc2918d9c2f840c4da43" +
        "a703ad9f5b5806163d7161696b5a0adc00000005d5c0d1bebb06048ed6fe2ef2" +
        "c6cef305b3ed633941ebc8b3bec9738754cddd60e1920ada52f43d055b5031ce" +
        "e6192520d6a5115514851ce7fd448d4a39fae2ab2335b525f484e9b40d6a4a96" +
        "9394843bdcf6d14c48e8015e08ab92662c05c6e9f90b65a7a6201689999f32bf" +
        "d368e5e3ec9cb70ac7b8399003f175c40885081a09ab3034911fe125631051df" +
        "0408b3946b0bde790911e8978ba07dd56c73e7ee");

    private static final byte[] RFC9858_A1_PK = hex(
        "000000010000000a00000008202122232425262728292a2b2c2d2e2f2c571450" +
        "aed99cfb4f4ac285da14882796618314508b12d2");

    private static final byte[] RFC9858_A1_MSG = hex(
        "54657374206d65737361676520666f72205348413235362d3139320a");

    private static final byte[] RFC9858_A1_SIG = hex(
        "0000000000000005000000080b5040a18c1b5cabcbc85b047402ec6294a30dd8" +
        "da8fc3dae13b9f0875f09361dc77fcc4481ea463c073716249719193614b835b" +
        "4694c059f12d3aedd34f3db93f3580fb88743b8b3d0648c0537b7a50e433d7ea" +
        "9d6672fffc5f42770feab4f98eb3f3b23fd2061e4d0b38f832860ae76673ad1a" +
        "1a52a9005dcf1bfb56fe16ff723627612f9a48f790f3c47a67f870b81e919d99" +
        "919c8db48168838cece0abfb683da48b9209868be8ec10c63d8bf80d36498dfc" +
        "205dc45d0dd870572d6d8f1d90177cf5137b8bbf7bcb67a46f86f26cfa5a44cb" +
        "caa4e18da099a98b0b3f96d5ac8ac375d8da2a7c248004ba11d7ac775b921835" +
        "9cddab4cf8ccc6d54cb7e1b35a36ddc9265c087063d2fc6742a7177876476a32" +
        "4b03295bfed99f2eaf1f38970583c1b2b616aad0f31cd7a4b1bb0a51e477e94a" +
        "01bbb4d6f8866e2528a159df3d6ce244d2b6518d1f0212285a3c2d4a927054a1" +
        "e1620b5b02aab0c8c10ed48ae518ea73cba81fcfff88bff461dac51e7ab4ca75" +
        "f47a6259d24820b9995792d139f61ae2a8186ae4e3c9bfe0af2cc717f424f41a" +
        "a67f03faedb0665115f2067a46843a4cbbd297d5e83bc1aafc18d1d03b3d894e" +
        "8595a6526073f02ab0f08b99fd9eb208b59ff6317e5545e6f9ad5f9c183abd04" +
        "3d5acd6eb2dd4da3f02dbc3167b468720a4b8b92ddfe7960998bb7a0ecf2a26a" +
        "37598299413f7b2aecd39a30cec527b4d9710c4473639022451f50d01c045712" +
        "5da0fa4429c07dad859c846cbbd93ab5b91b01bc770b089cfede6f651e86dd7c" +
        "15989c8b5321dea9ca608c71fd862323072b827cee7a7e28e4e2b999647233c3" +
        "456944bb7aef9187c96b3f5b79fb98bc76c3574dd06f0e95685e5b3aef3a54c4" +
        "155fe3ad817749629c30adbe897c4f4454c86c490000000ae9ca10eaa811b22a" +
        "e07fb195e3590a334ea64209942fbae338d19f152182c807d3c40b189d3fcbea" +
        "942f44682439b191332d33ae0b761a2a8f984b56b2ac2fd4ab08223a69ed1f77" +
        "19c7aa7e9eee96504b0e60c6bb5c942d695f0493eb25f80a5871cffd131d0e04" +
        "ffe5065bc7875e82d34b40b69dd9f3c1");

    private static final byte[] RFC9858_A2_PK = hex(
        "000000010000001400000010505152535455565758595a5b5c5d5e5fdb54a450" +
        "9901051c01e26d9990e550347986da87924ff0b1");

    private static final byte[] RFC9858_A2_MSG = hex(
        "54657374206d65737361676520666f72205348414b453235362d3139320a");

    private static final byte[] RFC9858_A2_SIG = hex(
        "00000000000000060000001084219da9ce9fffb16edb94527c6d10565587db28" +
        "062deac4208e62fc4fbe9d85deb3c6bd2c01640accb387d8a6093d68511234a6" +
        "a1a50108091c034cb1777e02b5df466149a66969a498e4200c0a0c1bf5d100cd" +
        "b97d2dd40efd3cada278acc5a570071a043956112c6deebd1eb3a7b56f5f6791" +
        "515a7b5ffddb0ec2d9094bfbc889ea15c3c7b9bea953efb75ed648f535b9acab" +
        "66a2e9631e426e4e99b733caa6c55963929b77fec54a7e703d8162e736875cb6" +
        "a455d4a9015c7a6d8fd5fe75e402b47036dc3770f4a1dd0a559cb478c7fb1726" +
        "005321be9d1ac2de94d731ee4ca79cff454c811f46d11980909f047b2005e84b" +
        "6e15378446b1ca691efe491ea98acc9d3c0f785caba5e2eb3c306811c240ba22" +
        "802923827d582639304a1e9783ba5bc9d69d999a7db8f749770c3c04a152856d" +
        "c726d8067921465b61b3f847b13b2635a45379e5adc6ff58a99b00e60ac767f7" +
        "f30175f9f7a140257e218be307954b1250c9b41902c4fa7c90d8a592945c66e8" +
        "6a76defcb84500b55598a1990faaa10077c74c94895731585c8f900de1a1c675" +
        "bd8b0c180ebe2b5eb3ef8019ece3e1ea7223eb7906a2042b6262b4aa25c4b8a0" +
        "5f205c8befeef11ceff1282508d71bc2a8cfa0a99f73f3e3a74bb4b3c0d8ca2a" +
        "bd0e1c2c17dafe18b4ee2298e87bcfb1305b3c069e6d385569a4067ed547486d" +
        "d1a50d6f4a58aab96e2fa883a9a39e1bd45541eee94efc32faa9a94be66dc853" +
        "8b2dab05aee5efa6b3b2efb3fd020fe789477a93afff9a3e636dbba864a5bffa" +
        "3e28d13d49bb597d94865bde88c4627f206ab2b465084d6b780666e952f8710e" +
        "fd748bd0f1ae8f1035087f5028f14affcc5fffe332121ae4f87ac5f1eac90626" +
        "08c7d87708f1723f38b23237a4edf4b49a5cd3d700000014dd4bdc8f928fb526" +
        "f6fb7cdb944a7ebaa7fb05d995b5721a27096a5007d82f79d063acd434a04e97" +
        "f61552f7f81a9317b4ec7c87a5ed10c881928fc6ebce6dfce9daae9cc9dba690" +
        "7ca9a9dd5f9f573704d5e6cf22a43b04e64c1ffc7e1c442ecb495ba265f465c5" +
        "6291a902e62a461f6dfda232457fad14");

    private static final byte[] RFC9858_A3_PK = hex(
        "000000010000000f0000000c808182838485868788898a8b8c8d8e8f9bb7faee" +
        "411cae806c16a466c3191a8b65d0ac31932bbf0c2d07c7a4a36379fe");

    private static final byte[] RFC9858_A3_MSG = hex(
        "54657374206d657361676520666f72205348414b453235362d3235360a");

    private static final byte[] RFC9858_A3_SIG = hex(
        "00000000000000070000000cb82709f0f00e83759190996233d1ee4f4ec50534" +
        "473c02ffa145e8ca2874e32b16b228118c62b96c9c77678b33183730debaade8" +
        "fe607f05c6697bc971519a341d69c00129680b67e75b3bd7d8aa5c8b71f02669" +
        "d177a2a0eea896dcd1660f16864b302ff321f9c4b8354408d06760504f768ebd" +
        "4e545a9b0ac058c575078e6c1403160fb45450d61a9c8c81f6bd69bdfa26a16e" +
        "12a265baf79e9e233eb71af634ecc66dc88e10c6e0142942d4843f70a0242727" +
        "bc5a2aabf7b0ec12a99090d8caeef21303f8ac58b9f200371dc9e41ab956e1a3" +
        "efed9d4bbb38975b46c28d5f5b3ed19d847bd0a737177263cbc1a2262d40e808" +
        "15ee149b6cce2714384c9b7fceb3bbcbd25228dda8306536376f8793ecadd602" +
        "0265dab9075f64c773ef97d07352919995b74404cc69a6f3b469445c9286a6b2" +
        "c9f6dc839be76618f053de763da3571ef70f805c9cc54b8e501a98b98c70785e" +
        "eb61737eced78b0e380ded4f769a9d422786def59700eef3278017babbe5f906" +
        "3b468ae0dd61d94f9f99d5cc36fbec4178d2bda3ad31e1644a2bcce208d72d50" +
        "a7637851aa908b94dc4376120d5beab0fb805e1945c41834dd6085e6db1a3aa7" +
        "8fcb59f62bde68236a10618cff123abe64dae8dabb2e84ca705309c2ab986d4f" +
        "8326ba0642272cb3904eb96f6f5e3bb8813997881b6a33cac0714e4b5e7a882a" +
        "d87e141931f97d612b84e903e773139ae377f5ba19ac86198d485fca97742568" +
        "f6ff758120a89bf19059b8a6bfe2d86b12778164436ab2659ba866767fcc4355" +
        "84125fb7924201ee67b535daf72c5cb31f5a0b1d926324c26e67d4c3836e301a" +
        "a09bae8fb3f91f1622b1818ccf440f52ca9b5b9b99aba8a6754aae2b967c4954" +
        "fa85298ad9b1e74f27a46127c36131c8991f0cc2ba57a15d35c91cf8bc48e8e2" +
        "0d625af4e85d8f9402ec44afbd4792b924b839332a64788a7701a30094b9ec4b" +
        "9f4b648f168bf457fbb3c9594fa87920b645e42aa2fecc9e21e000ca7d3ff914" +
        "e15c40a8bc533129a7fd39529376430f355aaf96a0a13d13f2419141b3cc2584" +
        "3e8c90d0e551a355dd90ad770ea7255214ce11238605de2f000d200104d0c3a3" +
        "e35ae64ea10a3eff37ac7e9549217cdf52f307172e2f6c7a2a4543e143140365" +
        "25b1ad53eeaddf0e24b1f36914ed22483f2889f61e62b6fb78f5645bdbb02c9e" +
        "5bf97db7a0004e87c2a55399b61958786c97bd52fa199c27f6bb4d68c4907933" +
        "562755bfec5d4fb52f06c289d6e852cf6bc773ffd4c07ee2d6cc55f57edcfbc8" +
        "e8692a49ad47a121fe3c1b16cab1cc285faf6793ffad7a8c341a49c5d2dce706" +
        "9e464cb90a00b2903648b23c81a68e21d748a7e7b1df8a593f3894b2477e8316" +
        "947ca725d141135202a9442e1db33bbd390d2c04401c39b253b78ce297b0e147" +
        "55e46ec08a146d279c67af70de256890804d83d6ec5ca3286f1fca9c72abf6ef" +
        "868e7f6eb0fddda1b040ecec9bbc69e2fd8618e9db3bdb0af13dda06c6617e95" +
        "afa522d6a2552de15324d99119f55e9af11ae3d5614b564c642dbfec6c644198" +
        "ce80d2433ac8ee738f9d825e0000000f71d585a35c3a908379f4072d070311db" +
        "5d65b242b714bc5a756ba5e228abfa0d1329978a05d5e815cf4d74c1e547ec4a" +
        "a3ca956ae927df8b29fb9fab3917a7a4ae61ba57e5342e9db12caf6f6dbc5253" +
        "de5268d4b0c4ce4ebe6852f012b162fc1c12b9ffc3bcb1d3ac8589777655e22c" +
        "d9b99ff1e4346fd0efeaa1da044692e7ad6bfc337db69849e54411df8920c228" +
        "a2b7762c11e4b1c49efb74486d3931ea");

    private static final byte[] RFC9858_A4_PK = hex(
        "000000010000000d00000007404142434445464748494a4b4c4d4e4f9c08a50d" +
        "170406869892802ee4142fcdeac990f110c2460c");

    private static final byte[] RFC9858_A4_MSG = hex(
        "54657374206d65737361676520666f72205348413235362f31393220773d34");

    private static final byte[] RFC9858_A4_SIG = hex(
        "000000000000006400000007853fa6e1a65fef076acd2485505b93be9aeb2641" +
        "e3d3805c1887f26f4bcdb6ac0337b76fa5d6603834287e010b20516f7c336df2" +
        "134c0a981f1ec2bb7baee516e91e67d3bd16c8d945a7f2be4fd84a604ae3743e" +
        "fc609ee0e69572e9c6d4a68250e877b75d3cae63e9d5c15a32bb3cd17045f6b3" +
        "e195284fdd1ee3cfbe18f1cbd06ef3e7af34b1844d42dac453115a4507ed525c" +
        "ec120d054b403c61a7e5034fac4be6ef5412d194d4b6bbc0ae6cd3fe9993d583" +
        "ee06f4030bc832efec24d1f713f5088731b91a98491fa3adf1b322bce26df24c" +
        "8415e3a46bdfe07a6fd48e6d951515758cd6434991098bf6949249fca338ec23" +
        "5871dd564998d07d9b1b1b8d644e657fee8039da8fe195d129faddb12d543b86" +
        "b0ab8cf6f26c121783f3b828d03f793b42909272f688e4ef6d46e82bdd1a02b1" +
        "ff86c3b79920b2e6f19faf75c623242f1f2c549f84fb2f4c3ffead3120d97bae" +
        "a507467bb2da79f132bbe15b596fdfcb70983107ebca2597de9d55bd83bcae5c" +
        "28a85259dadb354859986e60c8afa0b10bd08a8f9ed9b1ede3377075fe0ae363" +
        "49f7d2ed7bfc9ece0d4cd6972059329419feaf3b9a1045b6cfa4ae89b1cea895" +
        "0aea4af870d1a3a3909ebc5a3013d6deb927abc0f95093e83cb36a9c1d6f13ad" +
        "d19268ac7a0371f8335b0952a57fdb0141d55d937dd6ebb08fee8a5cf426ac97" +
        "d54ee7aa17e6c57be5e62a52a6b1b986730d3a3aad8a7d327ddf883e6bc7b636" +
        "eb2a5c4f2a635ae5bada5418d43dfedb69c0a0209334fac89d420d6ad5a2e1df" +
        "95d26a1bfeb99a5e8455061bfdf2d6e8394caf8a4be699b8afa38e524d405333" +
        "0af478f85bf33d3ca3a35bc96987282bd513a8f6a52db9ba36aa90882b3bf573" +
        "fa275449d8d49eb30bed2bb17a0ecc7d8a20807f2ea3dd37acd46c713cc2ac9d" +
        "01a20a30d6832eef86a1e26d1cad7761bf4130a6565572766026509deeddaf46" +
        "b605452b218a4e137a7ce063b546a35c52510f0ea2cac879192ec443e43b37c5" +
        "ffa23da7a7fc254324a3de705c771794f10ea356e5a747e5146fd804a4771980" +
        "3c185b380e34b8dcc8269c2b073d86b2307cf90c6c3ef9271f2d53df2579f0c4" +
        "cfb632db37a9025965f70b4616673228e98644be6576417b7a97f104350259e7" +
        "f697408cdf8cf81a3e7741626ccdb87ad8531264cb5ceb7c8c097cec505091a3" +
        "ee3a826c54f78169abc2e7d0a318dac10250ba940e51e79a3f572fb32bf442be" +
        "6fd81267946e6387f9a8c705d945c653f2684655e3fa6b9ee311d8a091bef989" +
        "8292fa272fb8761f066c23d87aa10d67871cc5419c843b796855c51ad1272e92" +
        "64acd2035a82b12c2ddbc85adfcd7c22366a36495349391dbf0001064b8f6b28" +
        "365445d733e48f1b058a6cb3e71bbb8df3e90406299894f4ca682943ceeba410" +
        "b33b07716ffc18d6eab75f2d6372f1133605fa3c3ed66f2d8f7c5abe59e87d45" +
        "00965e347523d73cb356c144827aaa22b1c72a15293c7400e02aaefcf36f68a8" +
        "246900e6e6228e7ad19d1450c23434f1e45043dc2b6db57f20d8f5b344d4162a" +
        "a651333287cd8bf8fac41c78d61fe2929209bfe2dc5a2f80205c043b22e540a2" +
        "9f0ea0a5ff529e55bf1dfe4296fc4bb4ac2e875322ab115db479fe979d64f784" +
        "09af4ec3ad3b758fff83af1b9c48e90ca39366f426c2fb921df55c72786a9217" +
        "723945a1ac1a66af7def4f8b367001732cce0e5bac91ac9d603807f8bab105b4" +
        "6d315d4cb88feb1c8686884b0000000d13d1a8ef00c5811c15c4d774fdcf7515" +
        "5315aff53ebdff8fb6a54f12c165963dd5690cc9842b0e2190afc5443497584c" +
        "832155599d00aced84bb3b59170396f7db4fa84aa8577f76cf9367d6e99d3d5b" +
        "e3555d7156b004f2002f505681b1ad229b9b46a666672aa8ee662c3a0456a9ad" +
        "da7a44fbaca46789577dcd36dc5cdff34b864d0a32492a0acbcaa6c011748f20" +
        "5b91ab2ab84f2333fb3e3b9acaecdac38b58aa5f32e718e225631ed6674cccb8" +
        "c119acbd4992ab3130a6e912deec59835ab52fbc549430f8b403e4a2a51cc7f4" +
        "6fc143d365763aa1708fd25bcd657a790e54718d970906242a3b8a97dff18e91" +
        "a44c4ba818a8dd2d242251265b023b826077eb740f6682e6c4ada2b85a67988d" +
        "406132c2ad899099e44cfe610c3a5af70b406224411a59597e5dda0f31cd16c9" +
        "14b67e96141661f0074f43eb02273481bc324ded26c64f2388559d8c8bd0ef8b" +
        "34ca4afebfac2a689b4246c264241488dcf922350dc44f7bc09d57dc1126291b" +
        "2318810e0f44801c071e572fd032c780f44c9503a4c03c37417dc96422ba0849" +
        "c37956f9fd5d33ea4fcab84276effec652ca77d7d47ac93c633d99e0a236f03d" +
        "5587d1990ffaef737fced1f5cdd8f373844e9f316aad41a0b12302639f83a2d7" +
        "4c9fe30d305a942bc0c30352a5e44dfb");

    /* Import an RFC public-key vector and assert it verifies its message,
     * rejects a tampered signature, and rejects a different message. Skips
     * when the vector's hash family is not compiled into native wolfCrypt. */
    private void assertRfcVerifyKat(String name, byte[] pub, byte[] msg,
        byte[] sig, int levels, int height, int winternitz, int hashType) {

        Lms v = new Lms();
        try {
            try {
                v.importPublicRaw(pub);
            } catch (WolfCryptException e) {
                if (e.getError() == WolfCryptError.NOT_COMPILED_IN) {
                    Assume.assumeTrue(
                        name + ": hash family not compiled in", false);
                }
                throw e;
            }

            assertEquals(name + " levels", levels, v.getLevels());
            assertEquals(name + " height", height, v.getHeight());
            assertEquals(name + " winternitz", winternitz, v.getWinternitz());
            assertEquals(name + " hashType", hashType, v.getHashType());

            assertTrue(name + " verify", v.verify(sig, msg));
            assertFalse(name + " wrong message",
                v.verify(sig, "not the signed message".getBytes()));

            byte[] tampered = sig.clone();
            tampered[tampered.length / 2] ^= (byte) 0xFF;
            assertFalse(name + " tampered signature", v.verify(tampered, msg));
        } finally {
            v.releaseNativeStruct();
        }
    }

    @Test
    public void rfc8554TestCase1Verify() {
        assumeEnabled();
        assertRfcVerifyKat("RFC8554-TC1", RFC8554_TC1_PK, RFC8554_TC1_MSG,
            RFC8554_TC1_SIG, 2, 5, 8, Lms.LMS_SHA256);
    }

    @Test
    public void rfc9858A1Verify() {
        assumeEnabled();
        assertRfcVerifyKat("RFC9858-A.1", RFC9858_A1_PK, RFC9858_A1_MSG,
            RFC9858_A1_SIG, 1, 5, 8, Lms.LMS_SHA256_192);
    }

    @Test
    public void rfc9858A2Verify() {
        assumeEnabled();
        assertRfcVerifyKat("RFC9858-A.2", RFC9858_A2_PK, RFC9858_A2_MSG,
            RFC9858_A2_SIG, 1, 5, 8, Lms.LMS_SHAKE256_192);
    }

    @Test
    public void rfc9858A3Verify() {
        assumeEnabled();
        assertRfcVerifyKat("RFC9858-A.3", RFC9858_A3_PK, RFC9858_A3_MSG,
            RFC9858_A3_SIG, 1, 5, 8, Lms.LMS_SHAKE256);
    }

    @Test
    public void rfc9858A4Verify() {
        assumeEnabled();
        assertRfcVerifyKat("RFC9858-A.4", RFC9858_A4_PK, RFC9858_A4_MSG,
            RFC9858_A4_SIG, 1, 20, 4, Lms.LMS_SHA256_192);
    }
}
